/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

#include "PacketMultiplexer.hpp"

#include "Constants.hpp"
#include "Node.hpp"
#include "Packet.hpp"
#include "RuntimeEnvironment.hpp"
#include "Switch.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__LINUX__)
#include <pthread.h>
#include <sched.h>
#elif defined(__FreeBSD__)
#include <pthread.h>
#include <pthread_np.h>
#include <sched.h>
#endif

namespace ZeroTier {

namespace {

void pinCurrentThread(unsigned int threadIndex, unsigned int concurrency)
{
#if defined(__LINUX__) || defined(__FreeBSD__)
	const int pinCore = (int)(threadIndex % concurrency);
	fprintf(stderr, "Pinning packet thread %u to core %d\n", threadIndex, pinCore);
	pthread_t self = pthread_self();
#if defined(__LINUX__)
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(pinCore, &cpuset);
	int rc = pthread_setaffinity_np(self, sizeof(cpu_set_t), &cpuset);
#else
	cpuset_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(pinCore, &cpuset);
	int rc = pthread_setaffinity_np(self, sizeof(cpuset_t), &cpuset);
#endif
	if (rc != 0) {
		fprintf(stderr, "Failed to pin packet thread %u to core %d: %s\n", threadIndex, pinCore, strerror(errno));
	}
#else
	(void)threadIndex;
	(void)concurrency;
#endif
}

unsigned int bucketForFlow(int32_t flowId, uint64_t source, uint64_t dest, unsigned int concurrency)
{
	if (concurrency <= 1) {
		return 0;
	}
	if (flowId == ZT_QOS_NO_FLOW) {
		return (unsigned int)((source ^ dest) % concurrency);
	}
	return (unsigned int)((uint32_t)flowId % concurrency);
}

}	// namespace

PacketMultiplexer::PacketMultiplexer(const RuntimeEnvironment* renv)
{
	RR = renv;
};

void PacketMultiplexer::putFrame(void* tPtr, uint64_t nwid, void** nuptr, const MAC& source, const MAC& dest, unsigned int etherType, unsigned int vlanId, const void* data, unsigned int len, int32_t flowId)
{
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__WINDOWS__)
	RR->node->putFrame(tPtr, nwid, nuptr, source, dest, etherType, vlanId, (const void*)data, len);
	return;
#endif

	if (! _enabled) {
		RR->node->putFrame(tPtr, nwid, nuptr, source, dest, etherType, vlanId, (const void*)data, len);
		return;
	}

	PacketRecord* packet;
	_rxPacketVector_m.lock();
	if (_rxPacketVector.empty()) {
		packet = new PacketRecord;
	}
	else {
		packet = _rxPacketVector.back();
		_rxPacketVector.pop_back();
	}
	_rxPacketVector_m.unlock();

	packet->tPtr = tPtr;
	packet->nwid = nwid;
	packet->nuptr = nuptr;
	packet->source = source.toInt();
	packet->dest = dest.toInt();
	packet->etherType = etherType;
	packet->vlanId = vlanId;
	packet->len = len;
	packet->flowId = flowId;
	memcpy(packet->data, data, len);

	const unsigned int bucket = bucketForFlow(flowId, packet->source, packet->dest, _concurrency);
	_rxPacketQueues[bucket]->postLimit(packet, 2048);
}

bool PacketMultiplexer::putWirePacket(void* tPtr, int64_t now, int64_t localSocket, const InetAddress& from, const void* data, unsigned int len)
{
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__WINDOWS__)
	return false;
#endif

	if ((! _enabled) || (_concurrency == 0) || (len < ZT_PROTO_MIN_PACKET_LENGTH) || (len > ZT_MAX_PHYSMTU)) {
		return false;
	}

	// Fragments share a ring buffer that is not safe to mutate from multiple
	// threads. Keep that path on the caller (Phy) thread.
	if ((len > ZT_PROTO_MIN_FRAGMENT_LENGTH) && (reinterpret_cast<const uint8_t*>(data)[ZT_PACKET_FRAGMENT_IDX_FRAGMENT_INDICATOR] == ZT_PACKET_FRAGMENT_INDICATOR)) {
		return false;
	}

	WirePacketRecord* packet;
	_rxWireVector_m.lock();
	if (_rxWireVector.empty()) {
		packet = new WirePacketRecord;
	}
	else {
		packet = _rxWireVector.back();
		_rxWireVector.pop_back();
	}
	_rxWireVector_m.unlock();

	packet->tPtr = tPtr;
	packet->now = now;
	packet->localSocket = localSocket;
	packet->from = from;
	packet->len = len;
	memcpy(packet->data, data, len);

	const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data);
	const uint64_t packetId = (((uint64_t)bytes[0]) << 56) | (((uint64_t)bytes[1]) << 48) | (((uint64_t)bytes[2]) << 40) | (((uint64_t)bytes[3]) << 32) | (((uint64_t)bytes[4]) << 24) | (((uint64_t)bytes[5]) << 16)
							  | (((uint64_t)bytes[6]) << 8) | ((uint64_t)bytes[7]);
	const unsigned int bucket = (unsigned int)(packetId % _concurrency);
	_rxWireQueues[bucket]->postLimit(packet, 2048);
	return true;
}

void PacketMultiplexer::setUpPostDecodeReceiveThreads(unsigned int concurrency, bool cpuPinningEnabled)
{
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__WINDOWS__)
	return;
#endif
	_concurrency = concurrency;

	for (unsigned int i = 0; i < _concurrency; ++i) {
		fprintf(stderr, "Reserved queue for thread %d\n", i);
		_rxPacketQueues.push_back(new BlockingQueue<PacketRecord*>());
		_rxWireQueues.push_back(new BlockingQueue<WirePacketRecord*>());
	}
	_enabled = true;

	// Decrypt/decode workers. These take the crypto off the single Phy thread
	// so inbound throughput can scale with `concurrency`.
	for (unsigned int i = 0; i < _concurrency; ++i) {
		_rxWireThreads.push_back(std::thread([this, i, cpuPinningEnabled]() {
			fprintf(stderr, "Created inbound decrypt thread %d\n", i);
			if (cpuPinningEnabled) {
				pinCurrentThread(i, _concurrency);
			}

			WirePacketRecord* packet = nullptr;
			for (;;) {
				if (! _rxWireQueues[i]->get(packet)) {
					break;
				}
				if (! packet) {
					break;
				}
				RR->node->_now = packet->now;
				RR->sw->onRemotePacket(packet->tPtr, packet->localSocket, packet->from, packet->data, packet->len);
				{
					Mutex::Lock l(_rxWireVector_m);
					_rxWireVector.push_back(packet);
				}
			}
		}));
	}

	// Each thread picks from its own queue to feed into the core
	for (unsigned int i = 0; i < _concurrency; ++i) {
		_rxThreads.push_back(std::thread([this, i, cpuPinningEnabled]() {
			fprintf(stderr, "Created post-decode packet ingestion thread %d\n", i);
			if (cpuPinningEnabled) {
				pinCurrentThread(i, _concurrency);
			}

			PacketRecord* packet = nullptr;
			for (;;) {
				if (! _rxPacketQueues[i]->get(packet)) {
					break;
				}
				if (! packet) {
					break;
				}

				MAC sourceMac = MAC(packet->source);
				MAC destMac = MAC(packet->dest);

				RR->node->putFrame(packet->tPtr, packet->nwid, packet->nuptr, sourceMac, destMac, packet->etherType, 0, (const void*)packet->data, packet->len);
				{
					Mutex::Lock l(_rxPacketVector_m);
					_rxPacketVector.push_back(packet);
				}
			}
		}));
	}
}

}	// namespace ZeroTier

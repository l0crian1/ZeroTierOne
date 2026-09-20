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
#include "RuntimeEnvironment.hpp"

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

void PacketMultiplexer::setUpPostDecodeReceiveThreads(unsigned int concurrency, bool cpuPinningEnabled)
{
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__WINDOWS__)
	return;
#endif
	_concurrency = concurrency;

	for (unsigned int i = 0; i < _concurrency; ++i) {
		fprintf(stderr, "Reserved queue for thread %d\n", i);
		_rxPacketQueues.push_back(new BlockingQueue<PacketRecord*>());
	}
	_enabled = true;

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

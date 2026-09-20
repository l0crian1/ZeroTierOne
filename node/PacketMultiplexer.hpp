/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

#ifndef ZT_PACKET_MULTIPLEXER_HPP
#define ZT_PACKET_MULTIPLEXER_HPP

#include "../osdep/BlockingQueue.hpp"
#include "InetAddress.hpp"
#include "MAC.hpp"
#include "Mutex.hpp"
#include "RuntimeEnvironment.hpp"

#include <stdint.h>
#include <thread>
#include <vector>

namespace ZeroTier {

struct PacketRecord {
	void* tPtr;
	uint64_t nwid;
	void** nuptr;
	uint64_t source;
	uint64_t dest;
	unsigned int etherType;
	unsigned int vlanId;
	uint8_t data[ZT_MAX_MTU];
	unsigned int len;
	int32_t flowId;
};

struct WirePacketRecord {
	void* tPtr;
	int64_t now;
	int64_t localSocket;
	InetAddress from;
	unsigned int len;
	uint8_t data[ZT_MAX_PHYSMTU];
};

class PacketMultiplexer {
  public:
	const RuntimeEnvironment* RR;

	PacketMultiplexer(const RuntimeEnvironment* renv);

	void setUpPostDecodeReceiveThreads(unsigned int concurrency, bool cpuPinningEnabled);

	inline bool enabled() const
	{
		return _enabled;
	}

	void putFrame(void* tPtr, uint64_t nwid, void** nuptr, const MAC& source, const MAC& dest, unsigned int etherType, unsigned int vlanId, const void* data, unsigned int len, int32_t flowId);

	/**
	 * Queue an unfragmented wire packet for decrypt/decode on a worker thread.
	 * @return true if the packet was queued, false if the caller should process it inline
	 */
	bool putWirePacket(void* tPtr, int64_t now, int64_t localSocket, const InetAddress& from, const void* data, unsigned int len);

	std::vector<BlockingQueue<PacketRecord*>*> _rxPacketQueues;
	std::vector<BlockingQueue<WirePacketRecord*>*> _rxWireQueues;

	unsigned int _concurrency = 0;
	// pool
	std::vector<PacketRecord*> _rxPacketVector;
	std::vector<WirePacketRecord*> _rxWireVector;
	std::vector<std::thread> _rxPacketThreads;
	Mutex _rxPacketVector_m, _rxPacketThreads_m, _rxWireVector_m;

	std::vector<std::thread> _rxThreads;
	std::vector<std::thread> _rxWireThreads;
	bool _enabled = false;
};

}	// namespace ZeroTier

#endif	 // ZT_PACKET_MULTIPLEXER_HPP

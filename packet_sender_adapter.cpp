#include "packet_sender_adapter.h"
#include "L2.h"
#include "NetworkInterface.h"
#include "sniffer/IP.h"

namespace netlab 
{
	PacketSenderAdapter::PacketSenderAdapter(L2 &datalink, const NetworkInterface &iface = NetworkInterface(), uint32_t recv_timeout, uint32_t usec)
		: Tins::PacketSender(Tins::NetworkInterface(iface.name()), recv_timeout, usec), datalink(datalink) { }

	PacketSenderAdapter::~PacketSenderAdapter() { }
}
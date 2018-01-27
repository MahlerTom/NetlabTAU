#include "IPv4Address.h"
#include "AddressRange.h"
#include "sniffer/endianness.h"
#include <sstream>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#ifndef WS2TCPIP
#define WS2TCPIP
#include <ws2tcpip.h>
#endif
#endif

using std::string;

namespace netlab 
{
	const IPv4Address IPv4Address::broadcast("255.255.255.255");

	const AddressRange<IPv4Address> private_ranges[] = 
	{
		IPv4Address("192.168.0.0") / 16,
		IPv4Address("10.0.0.0") / 8,
		IPv4Address("172.16.0.0") / 12
	};

	const AddressRange<IPv4Address> loopback_range(IPv4Address("127.0.0.0") / 8);
	const AddressRange<IPv4Address> multicast_range(IPv4Address("224.0.0.0") / 4);

	IPv4Address::IPv4Address(uint32_t ip) : ip_addr(Tins::Endian::be_to_host(ip)) { }

	IPv4Address::IPv4Address(const char *ip) : ip_addr(ip ? ip_to_int(ip) : 0) { }

	IPv4Address::IPv4Address(const std::string &ip) : ip_addr(ip_to_int(ip.c_str())) { }

	IPv4Address::operator uint32_t() const { return Tins::Endian::host_to_be(ip_addr); }

	std::string IPv4Address::to_string() const 
	{
		std::ostringstream oss;
		oss << *this;
		return oss.str();
	}

	uint32_t IPv4Address::ip_to_int(const char* ip) 
	{
		in_addr addr;
		if (InetPtonA(AF_INET, ip, &addr))
			return Tins::Endian::be_to_host(addr.s_addr);
		else
			throw std::runtime_error("Invalid ip address");
	}

	std::ostream &operator<<(std::ostream &output, const IPv4Address &addr) 
	{
		int mask(24);
		uint32_t ip_addr = addr.ip_addr;
		while (mask >= 0) {
			output << ((ip_addr >> mask) & 0xff);
			if (mask)
				output << '.';
			mask -= 8;
		}
		return output;;
	}

	bool IPv4Address::is_private() const 
	{
		const AddressRange<IPv4Address> *iter(private_ranges);
		while (iter != private_ranges + 3) {
			if (iter->contains(*this))
				return true;
			++iter;
		}
		return false;
	}

	bool IPv4Address::is_loopback() const { return loopback_range.contains(*this); }

	bool IPv4Address::is_multicast() const { return multicast_range.contains(*this); }

	bool IPv4Address::is_unicast() const { return !is_multicast() && !is_broadcast(); }

	bool IPv4Address::is_broadcast() const { return *this == broadcast; }
}


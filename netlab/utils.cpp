#include "utils.h"

#include <pcap.h>

#include "Sniffer/endianness.h"

namespace netlab 
{
	namespace internals 
	{
		bool increment(IPv4Address &addr) 
		{
			uint32_t addr_int = Tins::Endian::be_to_host<uint32_t>(addr);
			bool reached_end = ++addr_int == 0xffffffff;
			addr = IPv4Address(Tins::Endian::be_to_host<uint32_t>(addr_int));
			return reached_end;
		}

		bool decrement(IPv4Address &addr) 
		{
			uint32_t addr_int = Tins::Endian::be_to_host<uint32_t>(addr);
			bool reached_end = --addr_int == 0;
			addr = IPv4Address(Tins::Endian::be_to_host<uint32_t>(addr_int));
			return reached_end;
		}

		IPv4Address last_address_from_mask(IPv4Address addr, IPv4Address mask) 
		{
			uint32_t addr_int = Tins::Endian::be_to_host<uint32_t>(addr),
				mask_int = Tins::Endian::be_to_host<uint32_t>(mask);
			return IPv4Address(Tins::Endian::host_to_be(addr_int | ~mask_int));
		}
	}
}


/** \cond */
struct InterfaceCollector
{
	std::set<std::string> ifaces;

	bool operator() (PIP_ADAPTER_ADDRESSES addr) 
	{
		ifaces.insert(addr->AdapterName);
		return false;
	}

};

addrinfo *resolve_domain2(const std::string &to_resolve, int family) 
{
	addrinfo *result, hints = addrinfo();
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_family = family;
	if (!getaddrinfo(to_resolve.c_str(), 0, &hints, &result))
		return result;
	else 
		throw std::runtime_error("Could not resolve address");
}

namespace netlab 
{

	/** \endcond */
	namespace utils 
	{

		struct RouteEntry 
		{
			/**
			* This interface's name.
			*/

			std::string interface;

			/**
			* This route entry's destination.
			*/
			IPv4Address destination;

			/**
			* This route entry's gateway.
			*/
			IPv4Address gateway;

			/**
			* This route entry's subnet mask.
			*/
			IPv4Address mask;
		};

		IPv4Address resolve_domain(const std::string &to_resolve) 
		{
			addrinfo *result = ::resolve_domain2(to_resolve, AF_INET);
			IPv4Address addr(((sockaddr_in*)result->ai_addr)->sin_addr.s_addr);
			freeaddrinfo(result);
			return addr;
		}

		std::set<std::string> network_interfaces() 
		{
			InterfaceCollector collector;
			generic_iface_loop(collector);
			return collector.ifaces;
		}

		bool gateway_from_ip(IPv4Address ip, IPv4Address &gw_addr) 
		{
			typedef std::vector<RouteEntry> entries_type;
			entries_type entries;
			uint32_t ip_int = ip;
			route_entries(std::back_inserter(entries));
			for (entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it)
				if ((ip_int & it->mask) == it->destination) {
					gw_addr = it->gateway;
					return true;
				}
			return false;
		}

		template<class ForwardIterator>
		void route_entries(ForwardIterator output) 
		{
			MIB_IPFORWARDTABLE *table;
			ULONG size = 0;
			GetIpForwardTable(0, &size, 0);
			std::vector<uint8_t> buffer(size);
			table = (MIB_IPFORWARDTABLE*)&buffer[0];
			GetIpForwardTable(table, &size, 0);

			for (DWORD i = 0; i < table->dwNumEntries; i++) {
				MIB_IPFORWARDROW *row = &table->table[i];
				if (row->dwForwardType == MIB_IPROUTE_TYPE_INDIRECT) {
					RouteEntry entry;
					entry.interface = NetworkInterface::from_index(row->dwForwardIfIndex).name();
					entry.destination = IPv4Address(row->dwForwardDest);
					entry.mask = IPv4Address(row->dwForwardMask);
					entry.gateway = IPv4Address(row->dwForwardNextHop);
					*output++ = entry;
				}
			}
		}

		std::vector<RouteEntry> route_entries() 
		{
			std::vector<RouteEntry> entries;
			route_entries(std::back_inserter(entries));
			return entries;
		}

		uint32_t crc32(const uint8_t* data, uint32_t data_size) 
		{
			uint32_t i, crc = 0;
			static uint32_t crc_table[] = {
				0x4DBDF21C, 0x500AE278, 0x76D3D2D4, 0x6B64C2B0,
				0x3B61B38C, 0x26D6A3E8, 0x000F9344, 0x1DB88320,
				0xA005713C, 0xBDB26158, 0x9B6B51F4, 0x86DC4190,
				0xD6D930AC, 0xCB6E20C8, 0xEDB71064, 0xF0000000
			};

			for (i = 0; i < data_size; ++i) {
				crc = (crc >> 4) ^ crc_table[(crc ^ data[i]) & 0x0F];
				crc = (crc >> 4) ^ crc_table[(crc ^ (data[i] >> 4)) & 0x0F];
			}

			return crc;
		}

		uint16_t channel_to_mhz(uint16_t channel) { return 2407 + (channel * 5); }

		uint16_t mhz_to_channel(uint16_t mhz) { return (mhz - 2407) / 5; }
	}
}
/** \endcond */



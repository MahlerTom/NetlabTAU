#include "utils.h"
#include "Sniffer/endianness.h"
#include <set>
#include <string>
#include <iphlpapi.h>
#undef interface

struct netlab::NetworkInterface::Info 
{
	IPv4Address ip_addr, netmask, bcast_addr;
	address_type hw_addr;
};

/** \cond */
struct InterfaceInfoCollector 
{
	typedef netlab::NetworkInterface::Info info_type;
	info_type *info;
	int iface_id;
	const char* iface_name;
	bool found_hw;
	bool found_ip;

	InterfaceInfoCollector(info_type *res, int id, const char* if_name) 
		: info(res), iface_id(id), iface_name(if_name), found_hw(false), found_ip(false) { }

	bool operator() (const IP_ADAPTER_ADDRESSES *iface) 
	{
		using netlab::IPv4Address;
		using Tins::Endian::host_to_be;
		if (iface_id == uint32_t(iface->IfIndex)) {
			std::copy(iface->PhysicalAddress, iface->PhysicalAddress + 6, info->hw_addr.begin());
			const IP_ADAPTER_UNICAST_ADDRESS *unicast = iface->FirstUnicastAddress;
			if (unicast) {
				info->ip_addr = netlab::IPv4Address(((const struct sockaddr_in *)unicast->Address.lpSockaddr)->sin_addr.s_addr);
				info->netmask = netlab::IPv4Address(host_to_be<uint32_t>(0xffffffff << (32 - unicast->OnLinkPrefixLength)));
				info->bcast_addr = netlab::IPv4Address((info->ip_addr & info->netmask) | ~info->netmask);
				found_ip = true;
				found_hw = true;
			}
		}
		return found_ip && found_hw;
	}
};
/** \endcond */


namespace netlab 
{

	// static
	NetworkInterface NetworkInterface::default_interface() { return NetworkInterface(IPv4Address(uint32_t(0))); }

	std::vector<NetworkInterface> NetworkInterface::all() 
	{
		const std::set<std::string> interfaces = utils::network_interfaces();
		std::vector<NetworkInterface> output;
		for (std::set<std::string>::const_iterator it = interfaces.begin(); it != interfaces.end(); ++it) 
			output.push_back(*it);
		return output;
	}

	NetworkInterface NetworkInterface::from_index(id_type identifier) 
	{
		NetworkInterface iface;
		iface.iface_id = identifier;
		return iface;
	}
	
	NetworkInterface::NetworkInterface() 
		: iface_id(0) { }

	NetworkInterface::NetworkInterface(const std::string &name) { iface_id = resolve_index(name.c_str()); }


	NetworkInterface::NetworkInterface(const char *name) { iface_id = name ? resolve_index(name) : 0; }

	struct utils::RouteEntry 
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

	NetworkInterface::NetworkInterface(IPv4Address ip)
		: iface_id(0)
	{
		typedef std::vector<utils::RouteEntry> entries_type;

		if (ip == "127.0.0.1")
			iface_id = resolve_index("lo");
		else {
			const utils::RouteEntry *best_match = 0;
			entries_type entries;
			uint32_t ip_int = ip;
			utils::route_entries(std::back_inserter(entries));
			for (entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it)
				if ((ip_int & it->mask) == it->destination)
					if (!best_match || it->mask > best_match->mask)
						best_match = &*it;
			if (!best_match)
				throw std::runtime_error("Error looking up interface");
			iface_id = resolve_index(best_match->interface.c_str());
		}
	}

	NetworkInterface::id_type NetworkInterface::id() const { return iface_id; }

	std::string NetworkInterface::name() const 
	{
		ULONG size;
		::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
		std::vector<uint8_t> buffer(size);
		if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
			PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
			while (iface) {
				if (iface->IfIndex == iface_id) 
					return iface->AdapterName;
				iface = iface->Next;
			}
		}
		throw std::runtime_error("Failed to find interface name");
	}

	NetworkInterface::Info NetworkInterface::addresses() const 
	{
		const std::string &iface_name = name();
		Info info;
		struct InterfaceInfoCollector collector(&info, iface_id, iface_name.c_str());
		netlab::utils::generic_iface_loop(collector);
		// If we didn't event get the hw address, this went wrong
		if (!collector.found_hw) 
			throw std::runtime_error("Error looking up interface address");

		return info;
	}

	NetworkInterface::operator bool() const { return iface_id != 0; }

	bool NetworkInterface::is_loopback() const { return addresses().ip_addr.is_loopback(); }

	bool NetworkInterface::operator==(const NetworkInterface &rhs) const { return iface_id == rhs.iface_id; }

	bool NetworkInterface::operator!=(const NetworkInterface &rhs) const { return !(*this == rhs); }

	NetworkInterface::id_type NetworkInterface::resolve_index(const char *name) 
	{
		ULONG size;
		::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
		std::vector<uint8_t> buffer(size);
		if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
			PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
			while (iface) {
				if (strcmp(iface->AdapterName, name) == 0) 
					return iface->IfIndex;
				iface = iface->Next;
			}
		}
		throw std::runtime_error("Invalid interface");
	}
}
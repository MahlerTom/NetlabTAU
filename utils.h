#ifndef UTILS_H
#define UTILS_H

#ifndef WINSOCK2
#define WINSOCK2
#include <WinSock2.h>
#endif

#ifndef IPHLPAPI
#define IPHLPAPI
#include <iphlpapi.h>
#undef interface
#endif

#include <set>
#include <string>

#include "NetworkInterface.h"
#include "IPv4Address.h"

namespace netlab {

	namespace internals 
	{
		bool increment(IPv4Address &addr);

		bool decrement(IPv4Address &addr);

		IPv4Address last_address_from_mask(IPv4Address addr, IPv4Address mask);

	} // namespace Internals

} // namespace netlab

namespace netlab 
{
	class NetworkInterface;
	class PacketSender;

	/**
	* \brief Network utils namespace.
	*
	* This namespace provides utils to convert between integer IP addresses
	* and dotted notation strings, "net to host" integer conversions,
	* interface listing, etc.
	*/
	namespace utils {
		/**
		* Struct that represents an entry in /proc/net/route
		*/
		struct RouteEntry;

		/**
		* \brief Resolves a domain name and returns its corresponding ip address.
		*
		* If an ip address is given, its integer representation is returned.
		* Otherwise, the domain name is resolved and its ip address is returned.
		*
		* \param to_resolve The domain name/ip address to resolve.
		*/
		IPv4Address resolve_domain(const std::string &to_resolve);

		/** \brief List all network interfaces.
		*
		* Returns a set of strings, each of them representing the name
		* of a network interface. These names can be used as the input
		* interface for Utils::interface_ip, Utils::interface_hwaddr, etc.
		*/
		std::set<std::string> network_interfaces();

		/**
		* \brief Finds the gateway's IP address for the given IP
		* address.
		*
		* \param ip The IP address for which the default gateway will
		* be searched.
		* \param gw_addr This parameter will contain the gateway's IP
		* address in case it is found.
		*
		* \return bool indicating wether the lookup was successfull.
		*/
		bool gateway_from_ip(IPv4Address ip, IPv4Address &gw_addr);


		/**
		* \brief Retrieves entries in the routing table.
		*
		* \brief output ForwardIterator in which entries will be stored.
		*/
		template<class ForwardIterator>
		void route_entries(ForwardIterator output);

		/**
		* \brief Retrieves entries in the routing table.
		*
		* \return a vector which contains all of the route entries.
		*/
		std::vector<RouteEntry> route_entries();

		/** \brief Returns the 32 bit crc of the given buffer.
		*
		* \param data The input buffer.
		* \param data_size The size of the input buffer.
		*/
		uint32_t crc32(const uint8_t* data, uint32_t data_size);

		/**
		* \brief Converts a channel number to its mhz representation.
		* \param channel The channel number.
		* \return The channel's mhz representation.
		*/
		uint16_t channel_to_mhz(uint16_t channel);

		/**
		* \brief Converts mhz units to the appropriate channel number.
		* \param mhz The mhz units to be converted.
		* \return The channel number.
		*/
		uint16_t mhz_to_channel(uint16_t mhz);

		/** \brief Performs the pseudo header checksum used in TCP and UDP PDUs.
		*
		* \param source_ip The source ip address.
		* \param dest_ip The destination ip address.
		* \param len The length to be included in the pseudo header.
		* \param flag The flag to use in the protocol field of the pseudo header.
		* \return The pseudo header checksum.
		*/
		//uint32_t pseudoheader_checksum(IPv4Address source_ip, IPv4Address dest_ip, uint32_t len, uint32_t flag);

		/** \brief Generic function to iterate through interface and collect
		* data.
		*
		* The parameter is applied to every interface found, allowing
		* the object to collect data from them.
		* \param functor An instance of an class which implements operator(struct ifaddrs*).
		*/
		template<class Functor>
		void generic_iface_loop(Functor &functor) {
			ULONG size;
			::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
			std::vector<uint8_t> buffer(size);
			if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
				PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
				while (iface) {
					if (functor(iface))
						break;
					iface = iface->Next;
				}
			}
		}
	}
}

#endif // UTILS_H
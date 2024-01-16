#ifndef IPV4ADDRESS_H_
#define IPV4ADDRESS_H_

#include <stdint.h>
#include <iostream>

namespace netlab 
{
	/**
	* \class IPv4Address
	* \brief Abstraction of an IPv4 address.
	*/
	class IPv4Address 
	{
	public:
		/**
		* The address size.
		*/
		static const size_t address_size = sizeof(uint32_t);

		/**
		* The broadcast address.
		*/
		static const IPv4Address broadcast;

		/**
		* \brief Constructor taking a const char*.
		*
		* Constructs an IPv4Address from a dotted-notation address
		* cstring. If the pointer provided is null, then a default
		* IPv4Address object is constructed, which corresponds to
		* the 0.0.0.0 address.
		*
		* \param ip const char* containing the dotted-notation address.
		*/
		IPv4Address(const char *ip = 0);

		/**
		* \brief Constructor taking a std::string.
		*
		* Constructs an IPv4Address from a dotted-notation std::strings
		*
		* \param ip std::string containing the dotted-notation address.
		*/
		IPv4Address(const std::string &ip);

		/**
		* \brief Constructor taking a IP address represented as a
		* big endian integer.
		*
		* This constructor should be used internally by PDUs that
		* handle IP addresses. The provided integer <b>must</b> be
		* be in big endian.
		*/
		explicit IPv4Address(uint32_t ip);

		/**
		* \brief User defined conversion to big endian integral value.
		*/
		operator uint32_t() const;

		/**
		* \brief Retrieve the string representation of this address.
		*
		* \return std::string containing the representation of this address.
		*/
		std::string to_string() const;

		/**
		* \brief Compare this IPv4Address for equality.
		*
		* \param rhs The address to be compared.
		* \return bool indicating whether this address equals rhs.
		*/
		inline bool operator==(const IPv4Address &rhs) const { return ip_addr == rhs.ip_addr; }

		/**
		* \brief Compare this IPv4Address for inequality.
		*
		* \param rhs The address to be compared.
		* \return bool indicating whether this address is distinct
		* from rhs.
		*/
		inline bool operator!=(const IPv4Address &rhs) const { return !(*this == rhs); }

		/**
		* \brief Compare this IPv4Address for less-than inequality.
		*
		* \param rhs The address to be compared.
		* \return bool indicating whether this address is less-than rhs.
		*/
		inline bool operator< (const IPv4Address &rhs) const { return ip_addr < rhs.ip_addr; }

		/**
		* \brief Returns true if this is a private IPv4 address.
		*
		* This takes into account the private network ranges defined in
		* RFC 1918. Therefore, this method returns true if this address
		* is in any of the following network ranges, false otherwise:
		*
		* - 192.168.0.0/16
		* - 10.0.0.0/8
		* - 172.16.0.0/12
		*/
		bool is_private() const;

		/**
		* \brief Returns true if this is a loopback IPv4 address.
		*
		* This method returns true if this address is in the address range
		* 127.0.0.0/8, false otherwise.
		*/
		bool is_loopback() const;

		/**
		* \brief Returns true if this is a multicast IPv4 address.
		*
		* This method returns true if this address is in the address range
		* 224.0.0.0/4, false otherwise.
		*/
		bool is_multicast() const;

		/**
		* \brief Returns true if this is an unicast IPv4 address.
		*/
		bool is_unicast() const;

		/**
		* \brief Returns true if this is a broadcast IPv4 address.
		*/
		bool is_broadcast() const;

		/**
		* \brief Writes this address to a std::ostream.
		*
		* This method writes addr in a dotted-string notation address
		* to the std::ostream argument.
		*
		* \param output The std::ostream in which to write the address.
		* \param addr The IPv4Address to be written.
		* \return std::stream& pointing to output.
		*/
		friend std::ostream &operator<<(std::ostream &output, const IPv4Address &addr);

		inline uint32_t getIP_ADDR() { return ip_addr; }

	private:
		inline uint32_t ip_to_int(const char* ip);
		uint32_t ip_addr;
	};
} //namespace netlab

#endif /* IPV4ADDRESS_H_ */
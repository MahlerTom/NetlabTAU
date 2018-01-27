#ifndef NETWORKINTERFACE_H_
#define NETWORKINTERFACE_H_

#include <vector>

#include "Types.h"
#include "IPv4Address.h"
#include "HWAddress.hpp"

namespace netlab 
{
	/**
	* \class NetworkInterface
	* \brief Abstraction of a network interface
	*/
	class NetworkInterface 
	{
	public:
		/**
		* \brief The type used to store the interface's identifier.
		*/
		typedef uint32_t id_type;

		/**
		* \brief The type of this interface's address.
		*/
		typedef HWAddress<6> address_type;

		/**
		* \brief Struct that holds an interface's addresses.
		*/
		struct Info;

		/**
		* Returns a NetworkInterface object associated with the default
		* interface.
		*/
		static NetworkInterface default_interface();

		/**
		* Returns all available network interfaces.
		*/
		static std::vector<NetworkInterface> all();

		/**
		* Returns a network interface for the given index.
		*/
		static NetworkInterface from_index(id_type identifier);

		/**
		* Default constructor.
		*/
		NetworkInterface();

		/**
		* \brief Constructor from std::string.
		*
		* \param name The name of the interface this object will abstract.
		*/
		NetworkInterface(const std::string &name);

		/**
		* \brief Constructor from const char*.
		*
		* \param name The name of the interface this object will abstract.
		*/
		NetworkInterface(const char *name);

		/**
		* \brief Constructs a NetworkInterface from an ip address.
		*
		* This abstracted interface will be the one that would be the gateway
		* when sending a packet to the given ip.
		*
		* \param ip The ip address being looked up.
		*/
		NetworkInterface(IPv4Address ip);

		/**
		* \brief Getter for this interface's identifier.
		*
		* \return id_type containing the identifier.
		*/
		id_type id() const;

		/**
		* \brief Retrieves this interface's name.
		*
		* This name can be used as the interface name provided to the
		* Sniffer class when starting a sniffing session.
		*
		* \sa Sniffer
		* \return std::string containing this interface's name.
		*/
		std::string name() const;

		/**
		* \brief Retrieve this interface's addresses.
		*
		* This method iterates through all the interface's until the
		* correct one is found. Therefore it's O(N), being N the amount
		* of interfaces in the system.
		*/
		Info addresses() const;

		/**
		* \brief Tests whether this is a valid interface;
		*
		* An interface will not be valid iff it was created using the
		* default constructor.
		*/
		operator bool() const;

		/**
		* \brief Indicates whether this is a loopback device.
		* @return true iff this is a loopback device.
		*/
		bool is_loopback() const;

		/**
		* \brief Compares this interface for equality.
		*
		* \param rhs The interface being compared.
		*/
		bool operator==(const NetworkInterface &rhs) const;

		/**
		* \brief Compares this interface for inequality.
		*
		* \param rhs The interface being compared.
		*/
		bool operator!=(const NetworkInterface &rhs) const;
	
private:
		id_type resolve_index(const char *name);

		id_type iface_id;
	};
}


#endif /* NETWORKINTERFACE_H_ */
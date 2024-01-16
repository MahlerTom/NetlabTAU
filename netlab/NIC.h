/*!
    \file	NIC.h
	
	\author	Tom Mahler, contact at tommahler@gmail.com
    
	\brief	Declares the NIC class.
*/

#ifndef NIC_H_
#define NIC_H_


//#define NIC_DEBUG
//#define NIC_DEBUG_OUT

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include <ws2tcpip.h>

#include <vector>
#include <memory>

#include "Types.h"
#include "IPv4Address.h"
#include "HWAddress.hpp"

#include <iomanip>
#include <fstream>

/*!
    \class	NIC

    \brief	Represents a virtual Network Interface Card.
*/
class NIC 
{
public:
	friend class inet_os;

	/*!
		\typedef	netlab::HWAddress<> mac_addr

		\brief	Defines an alias representing the MAC address.
	*/
	typedef netlab::HWAddress<>	mac_addr;

	/*!
		\enum	IFF_

		\brief	Flags to represent the NIC's status #ifa_flags, legacy support.
	*/
	enum IFF_
	{
#ifndef IFF_UP
		IFF_UP = 0x1,				/*!< interface is up */
#endif
#ifndef IFF_BROADCAST
		IFF_BROADCAST = 0x2,		/*!< broadcast address valid */
#endif
		IFF_DEBUG = 0x4,			/*!< turn on debugging */
#ifndef IFF_LOOPBACK
		IFF_LOOPBACK = 0x8,			/*!< is a loopback net */
#endif
		IFF_POINTOPOINT = 0x10,		/*!< interface is point-to-point link */
		IFF_NOTRAILERS = 0x20,		/*!< avoid use of trailers */
		IFF_RUNNING = 0x40,			/*!< resources allocated */
		IFF_NOARP = 0x80,			/*!< no address resolution protocol */
		IFF_PROMISC = 0x100,		/*!< receive all packets */
		IFF_ALLMULTI = 0x200,		/*!< receive all multicast packets */
		IFF_OACTIVE = 0x400,		/*!< transmission in progress */
		IFF_SIMPLEX = 0x800,		/*!< can't hear own transmissions */
		IFF_LINK0 = 0x1000,			/*!< per link layer defined bit */
		IFF_LINK1 = 0x2000,			/*!< per link layer defined bit */
		IFF_LINK2 = 0x4000,			/*!< per link layer defined bit */
#ifdef IFF_MULTICAST
#undef IFF_MULTICAST
#endif
		IFF_MULTICAST = 0x8000,		/*!< supports multicast */
		IFF_CANTCHANGE = (IFF_BROADCAST | IFF_POINTOPOINT | IFF_RUNNING | IFF_OACTIVE | IFF_SIMPLEX | IFF_MULTICAST | IFF_ALLMULTI)	/*!< flags set internally only */
	};
	
	/*!
	    \fn NIC::NIC(class inet_os &inet, struct in_addr *my_ip = nullptr, mac_addr my_mac = "", struct in_addr *my_gw = nullptr, bool promisc_mode = true, std::string filter = "");
	
	    \brief
	    Constructs a virtual NIC, with user defined IP address mac address and gw_address.
	
	    \param [in,out]	inet 	The inet_os using this nic.
	    \param [in,out]	my_ip	(Optional) If non-null, my IP.
	    \param	my_mac		 	my MAC address.
	    \param [in,out]	my_gw	(Optional) If non-null, my default gateway.
	    \param	promisc_mode
	    Decides the whether the NIC is in promiscuous mode (which opens the NIC to read any
	    packet that comes in) or not (in which the NIC drops any packet which is not destined for
	    the NIC's MAC address and not a broadcast)
	    Default value is true.
	    \param	filter
	    Enables the use of explicit filters, following the syntax of of pcap filter found in
	    <a href="https://www.winpcap.org/docs/docs_40_2/html/group__language.html">Winpcap
	    filtering expression syntax</a>. Default value is "" which means no filters. \note this
	    is given to you \b ONLY for debugging purposes. Final submission must Support default
	    values.
	*/
	NIC(class inet_os &inet, struct in_addr *my_ip = nullptr, mac_addr my_mac = "", struct in_addr *my_gw = nullptr,
		struct in_addr *my_netmask = nullptr, bool promisc_mode = true, std::string filter = "");

	/*!
	    \fn NIC::NIC(class inet_os &inet, class netlab::IPv4Address my_ip = nullptr, mac_addr my_mac = "", class netlab::IPv4Address my_gw = nullptr, bool promisc_mode = true, std::string filter = "");
	
	    \brief	Constructs a virtual NIC, with user defined IP address mac address and gw_address.
	
	    \param [in,out]	inet	The inet_os using this nic.
	    \param	my_ip			If non-null, my IP.
	    \param	my_mac			my MAC address.
	    \param	my_gw			If non-null, my default gateway.
	    \param	promisc_mode
	    Decides the whether the NIC is in promiscuous mode (which opens the NIC to read any
	    packet that comes in) or not (in which the NIC drops any packet which is not destined for
	    the NIC's MAC address and not a broadcast)
	    Default value is true.
	    \param	filter
	    Enables the use of explicit filters, following the syntax of of pcap filter found in
	    <a href="https://www.winpcap.org/docs/docs_40_2/html/group__language.html">Winpcap
	    filtering expression syntax</a>. Default value is "" which means no filters. \note this
	    is given to you \b ONLY for debugging purposes. Final submission must Support default
	    values.
	*/
	NIC(class inet_os &inet, class netlab::IPv4Address my_ip = nullptr, mac_addr my_mac = "", class netlab::IPv4Address my_gw = nullptr,
		netlab::IPv4Address my_netmask = nullptr, bool promisc_mode = true, std::string filter = "");

	/*!
	    \fn	NIC::~NIC();
	
	    \brief
	    NIC destructor.
	    
	    Disconnects the NIC, destroy print_mutex, destroy cable and deletes the interface. L2_ARP
	    *NICsARP and L2 *upperInterface; are \b not destroyed. That means after calling this
	    function, \b you are responsible to delete them.
	*/
	~NIC();

	/*!
	    \fn void NIC::leread(class std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it);
	
	    \brief
	    NIC input routine. The leread function starts with a contiguous buffer of memory passed
	    to it by the cable and constructs an ether_header structure and an std::vector<byes>
	    smart pointer m. The m contains the data from the Ethernet frame.
	
		\param [in,out]	m 	The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it	The iterator, as the current offset in the vector.
	*/
	void leread(class std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it);

	/*!
	    \fn void NIC::lestart(class std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it);
	
	    \brief
	    NIC output routine. Start output on interface. Get another datagram to send off of the
	    interface queue, and copy it to the interface before starting the output. This method
	    writes the data on the wire.
	
		\param [in,out]	m 	The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it	The iterator, as the current offset in the vector.
	*/
	void lestart(class std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it);

	/*!
	    \fn	bool NIC::in_localaddr(struct in_addr &addr) const;
	
	    \brief	test if the given #addr is in the subnet.
	
	    \param [in,out]	addr	The address.
	
	    \return	true if it succeeds, false if it fails.
	*/
	bool in_localaddr(struct in_addr &addr) const;

	/*!
		\fn	static void NIC::HexDump(byte *m, const size_t &m_len, std::ostream& str = std::cout);

		\brief
		Produces a dump of a buffer in a hexdump way with its code Ascii translation and relative
		buffer address.

		\par For instance:
		*	0000000 - 77 98 21 49 0e 00 05 00 40 1c 01 1c 2f 00 00 00 w.!I....@.../...

		\param [in,out]	m  	buffer to be "hexdumped".
		\param	m_len	   	The length.
		\param [in,out]	str	(Optional) the output string.
	*/
	static void HexDump(byte *m, const size_t &m_len, std::ostream& str = std::cout);

	/*!
		\fn static void NIC::HexDump(class std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, std::ostream& str = std::cout);

		\brief
		Produces a dump of a buffer in a hexdump way with its code Ascii translation and relative
		buffer address.

		\par For instance:
		*	0000000 - 77 98 21 49 0e 00 05 00 40 1c 01 1c 2f 00 00 00 w.!I....@.../...

		\param [in,out]	m  	buffer to be "hexdumped".
		\param	it		   	The length.
		\param [in,out]	str	(Optional) the output string.
	*/
	static void HexDump(class std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, std::ostream& str = std::cout);

	/*!
	    \fn	inline const mac_addr NIC::mac() const
	
	    \brief	Gets the MAC address of this NIC.
	
	    \return	A #_mac.
	*/
	inline const mac_addr mac() const { return _mac; }

	/*!
	    \fn	inline const mac_addr NIC::etherbroadcastaddr() const
	
	    \brief	Gets the etherbroadcastaddr address of this NIC.
	
	    \return	A #_etherbroadcastaddr.
	*/

	inline const mac_addr etherbroadcastaddr() const { return _etherbroadcastaddr; }

	/*!
	    \fn	inline in_addr NIC::ip_addr() const
	
	    \brief	Gets the ip_addr address of this NIC.
	
	    \return	An #_ip_addr.
	*/
	inline struct in_addr ip_addr() const { return _ip_addr; }

	/*!
	    \fn	inline in_addr NIC::netmask_addr() const
	
	    \brief	Gets the network mask of this NIC.
	
	    \return	An #_netmask_addr.
	*/
	inline struct in_addr netmask_addr() const { return _netmask_addr; }

	/*!
	    \fn	inline in_addr NIC::bcast_addr() const
	
	    \brief	Gets the broadcast IP address (in local LAN) of this NIC.
	
	    \return	An #_bcast_addr.
	*/
	inline struct in_addr bcast_addr() const { return _bcast_addr; }

	/*!
	    \fn	inline in_addr NIC::dgw_addr() const
	
	    \brief	Gets the default gateway address of this NIC.
	
	    \return	An #_dgw_addr.
	*/
	inline struct in_addr dgw_addr() const { return _dgw_addr; }

	/*!
	    \fn	inline const u_long NIC::if_mtu() const
	
	    \brief	If MTU.
	
	    \return	An u_long.
	*/
	inline const u_long if_mtu() const { return _if_mtu; }

	/*!
	    \fn	inline const u_short NIC::ifa_flags() const
	
	    \brief	Ifa flags.
	
	    \return	An u_short.
	*/
	inline const u_short ifa_flags() const { return _ifa_flags; }

	/*!
	    \fn	inline void NIC::ifa_flags(const u_short if_mtu)
	
	    \brief	Ifa flags.
	
	    \param	if_mtu	if MTU.
	*/
	inline void ifa_flags(const u_short if_mtu) { _ifa_flags = if_mtu; }

private:

	/*!
	    \fn	void NIC::connect(class L2 &upperInterface, const uint32_t count = 0U);
	
	    \brief
	    Virtually connects the cable to the NIC.
	    
	    In other wards, turns the NIC on.
	
	    \param [in,out]	upperInterface	The upper interface.
	    \param	count
	    Limit the number of packets to read. Default value is 0 meaning constantly
	    reading received packets.
	*/
	void connect(class L2 &upperInterface, class L0_buffer *buf = nullptr, const uint32_t count = 0U);

	/*!
	    \fn	void NIC::disconnect();
	
	    \brief
	    Virtually disconnects the cable from the NIC.
	    
	    In other wards, turns the NIC off.
	*/
	void disconnect(bool from_buf = false);

	mac_addr _mac;   /*!< NIC's MAC address */
	struct in_addr _ip_addr;   /*!< NIC's IP address */
	struct in_addr _netmask_addr;	/*!< NIC's mask address */
	struct in_addr _bcast_addr; /*!< NIC's broadcast IP address (in local LAN) */
	struct in_addr _dgw_addr;	/*!< NIC's Default Gateway address */
	
	const mac_addr _etherbroadcastaddr;   /*!< The etherbroadcastaddr */
	const u_long	_if_mtu = 1500;		/*!< maximum transmission unit */
	u_short	_ifa_flags;		/*!< mostly rt_flags for cloning */

	class inet_os &inet;	/*!< The inet_os owning this protocol. */
};


#endif /* NIC_H_ */
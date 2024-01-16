/*!
	\file	L2.h

	\author	Tom Mahler

	\brief	Declares the 2 class.
*/
#ifndef L2_H_
#define L2_H_

/*!
	\def	NETLAB_L2_DEBUG
	Define in order to printout the L2 packets for debug
*/
//#define NETLAB_L2_DEBUG

#include "L3.h"

struct rtentry;

/*!
    \class	L2

    \brief
    Represents a Layer 2 interface (Ethernet).
    
    \pre	First initialize an instance of inet_os.
    \pre	Must define struct L2::ether_header.
*/
class L2 {
public:

	/*!
	    \struct	ether_header
	
	    \brief
	    Structure of a 10Mb/s Ethernet header. The Ethernet device driver is responsible for
	    converting ether_type between network and host byte order. Outside of the driver, it is
	    always in host byte order.
	    
	    \note The Ethernet CRC is not generally available. It is computed and checked by the
	    interface hardware, which discards frames that arrive with an invalid CRC.
	*/
	struct ether_header;

	/*!
	    \fn	L2::L2(class inet_os &inet)
	
	    \brief	Constructs an L2 interface.
	
	    \param [in,out]	inet	The inet.
	*/
	L2(class inet_os &inet);

	/*!
	    \brief	L2 destructor, updates its #inet that the interface is deleted.
	*/
	virtual ~L2();

	/*!
	    \pure virtual void L2::ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt) = 0;
	
	    \brief
	    We now examine the output of Ethernet frames, which starts when a network-level protocol
	    such as IP calls the \ref inet_os ether_output function, specified in the \ref inet_os
	    nic class. The output function for all Ethernet devices is ether_output (Figure 4.2).
	    ether_output takes the data portion of an Ethernet frame, encapsulates it with the 14-
	    byte Ethernet header, and places it on the interface's send queue. This is a large which
	    sums into four parts:
	    	a.	verification, 
			b.	protocol-specific processing, 
			c.	frame construction, and 
			d.	interface queuing.
	
		\param [in,out]	m 		The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it		The iterator, as the current offset in the vector.
	    \param [in,out]	dst	the destination address of the packet.
	    \param [in,out]	rt 	routing information.
	*/
	virtual void ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt) = 0;

	/*!
	    \pure	virtual void L2::ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh) = 0;
	
	    \brief
	    Process a received Ethernet packet. This method is called by the \ref NIC::leread(). It
	    unwraps the Ethernet header of the received data, drops invalid packets, passes the
	    unwraped data to the correct upper interface (i.e ARP and IP in our case) and possibly
	    prints relevant information.
	
	    \param [in,out]	m 	The received data.
	    \param [in,out]	it	The iterator, as the current offset in the vector.
	    \param [in,out]	eh	pointer to a casted \ref ethernet_header
	*/
	virtual void ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh) = 0;

protected:
	class inet_os &inet; /*!< The inet_os owning this protocol. */
};




/************************************************************************/
/*                         SOLUTION                                     */
/************************************************************************/

#include "HWAddress.hpp"

struct L2::ether_header 
{
public:

	/*!
	    \typedef	netlab::HWAddress<> mac_addr
	
	    \brief	Defines an alias representing the MAC address.
	*/
	typedef netlab::HWAddress<>		mac_addr;

	mac_addr ether_dhost;   /*!< The Ethernet destination host */
	mac_addr ether_shost;   /*!< The Ethernet source host */
	u_short	ether_type;		/*!< Type of the Ethernet \see ETHERTYPE_ */

	/*!
	    \enum	ETHERTYPE_
	
	    \brief
	    The Ethernet type for ::ether_type.
	    
	    \note ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have (type-
	    ETHERTYPE_TRAIL)*512 bytes of data followed by an ETHER type (as given above) and then
	    the (variable-length) header.
	*/
	enum ETHERTYPE_ 
	{
		ETHERTYPE_PUP = 0x0200,		/*!< PUP protocol */
		ETHERTYPE_IP = 0x0800,		/*!< IP protocol */
		ETHERTYPE_ARP = 0x0806,		/*!< Address resolution protocol */
		ETHERTYPE_REVARP = 0x8035,	/*!< reverse Address resolution protocol */
		ETHERTYPE_TRAIL = 0x1000,	/*!< Trailer packet */
		ETHERTYPE_NTRAILER = 16		/*!< The ETHERTYPE ntrailer option */
	};

	/*!
	    \enum	ETH_
	
	    \brief	Values that represent Ethernet header lengths.
	*/

	enum ETH_
	{
		ETH_ALEN = 6,			/*!< Octets in one Ethernet addr	 */
		ETH_HLEN = 14,			/*!< Total octets in header.	 */
		ETH_ZLEN = 60,			/*!< Min. octets in frame sans FCS */
		ETH_DATA_LEN = 1500,	/*!< Max. octets in payload	 */
		ETH_FRAME_LEN = 1514,	/*!< Max. octets in frame sans FCS */
		ETH_FCS_LEN = 4			/*!< Octets in the FCS		 */
	};

	/*!
	    \enum	ETHER_
	
	    \brief	Values that represent Ethernet addresses lengths.
	*/
	enum ETHER_
	{
		ETHER_ADDR_LEN = ETH_ALEN,							/*!< size of Ethernet addr */
		ETHER_TYPE_LEN = 2,									/*!< bytes in type field */
		ETHER_CRC_LEN = 4,									/*!< bytes in CRC field */
		ETHER_HDR_LEN = ETH_HLEN,							/*!< total octets in header */
		ETHER_MIN_LEN = (ETH_ZLEN + ETHER_CRC_LEN),			/*!< min packet length */
		ETHER_MAX_LEN = (ETH_FRAME_LEN + ETHER_CRC_LEN)		/*!< max packet length */
	};

	/*!
	    \fn ether_header(const mac_addr shost, const mac_addr dhost, const ETHERTYPE_ type = ETHERTYPE_IP)
	
	    \brief	Constructor.
	
	    \param	shost	The Ethernet source host
	    \param	dhost	The Ethernet destination host
	    \param	type 	Type of the Ethernet \see ETHERTYPE_
	*/

	ether_header(const mac_addr shost, const mac_addr dhost, const ETHERTYPE_ type = ETHERTYPE_IP);

	/*!
	    \fn	ether_header(const ETHERTYPE_ type = ETHERTYPE_IP)
	
	    \brief	Default constructor from \ref ETHERTYPE_.
	
	    \param	type	The type.
	*/

	ether_header(const ETHERTYPE_ type = ETHERTYPE_IP);

	/*!
	    \fn	friend std::ostream& operator<<(std::ostream &out, const L2::ether_header &eh)
	
	    \brief	Stream insertion operator.
	
	    \param [in,out]	out	The output stream (usually std::cout).
	    \param	eh		   	The ether_header to printout.
	
	    \return	The output stream, when #eh was inserted and printed.
	*/
	friend std::ostream& operator<<(std::ostream &out, const L2::ether_header &eh);
};



class L2_impl
	: public L2
{
public:

	/*!
	    \typedef	netlab::HWAddress<> mac_addr
	
	    \brief	Defines an alias representing the MAC address.
	*/
	typedef netlab::HWAddress<>		mac_addr;

	/*!
	    \enum	L2_DEFAULT
	
	    \brief	Global static default parameters.
	*/
	enum L2_DEFAULT
	{
		ETHERMTU = L2::ether_header::ETH_DATA_LEN,  /*!< The Ethernet MTU */
		ETHERMIN = (L2::ether_header::ETHER_MIN_LEN - L2::ether_header::ETHER_HDR_LEN - L2::ether_header::ETHER_CRC_LEN),   /*!< The Ethernet minimum size */
		EHOSTDOWN = 64		/*!<  The Ethernet Host is down */
	};

	/*!
	    \enum	M_
	
	    \brief
	    Flags from the legacy mbuf struct, used for marking packet as #M_MCAST or #M_BCAST.
	    
	    \note Unused.
	*/
	enum M_
	{
		M_EXT = 0x0001,		/*!< has associated external storage */
		M_PKTHDR = 0x0002,	/*!< start of record */
		M_EOR = 0x0004,		/*!< end of record */
		M_BCAST = 0x0100,	/*!< send/received as link-level broadcast */
		M_MCAST = 0x0200	/*!< send/received as link-level multicast */
	};

	/* make sure Ethernet length is valid */

	/*!
	    \fn	template <typename T> static inline bool L2_impl::ETHER_IS_VALID_LEN(const T t)
	
	    \brief	Ether is valid length.
	
	    \tparam	T	Generic type parameter.
	    \param	t	the size to check.
	
	    \return	true if it succeeds, false if it fails.
	*/
	template <typename T>
	static inline bool ETHER_IS_VALID_LEN(const T t) { return ((t >= static_cast<T>(ETHER_MIN_LEN)) && (t <= static_cast<T>(ETHER_MAX_LEN))); }

	/*!
	    \fn	L2_impl::L2_impl(class inet_os &inet)
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet.
	*/
	L2_impl(class inet_os &inet);

	virtual void ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt);

	virtual void ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh);

};








#endif /* L2_H_ */



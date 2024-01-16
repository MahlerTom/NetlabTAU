#ifndef L2_ARP_H_
#define L2_ARP_H_
#include "NIC.h"
#include "inet_os.hpp"

/*!
    \class	L2_ARP

    \brief
    ARP, the Address Resolution Protocol, handles the translation of 32-bit IP addresses into the
    corresponding hardware address. For an Ethernet, the hardware addresses are 48-bit Ethernet
    addresses. In this class we only consider mapping IP addresses into 48-bit Ethernet addresses,
    although ARP is more general and can work with other types of data links. ARP is specified in
    RFC 826 [Plummer 1982]. When a host has an IP datagram to send to another host on a locally
    attached Ethernet, the local host first looks up the destination host in the ARP cache, a
    table that maps a 32-bit IP address into its corresponding 48-bit Ethernet address. If the
    entry is found for the destination, the corresponding Ethernet address is copied into the
    Ethernet header and the datagram is added to the appropriate interface's output queue. If the
    entry is not found, the ARP functions hold onto the IP datagram, broadcast an ARP request
    asking the destination host for its Ethernet address, and, when a reply is received, send the
    datagram to its destination. This simple overview handles the common case, but there are many
    details that we describe in this chapter as we examine the Net/3 implementation of ARP.
    Chapter 4 of Volume 1 contains additional ARP examples.

    \sa	RFC 826 for protocol description.
*/
class L2_ARP {
public:

	/*!
	    \typedef	netlab::HWAddress<> mac_addr
	
	    \brief	Defines an alias representing the MAC address.
	*/
	typedef netlab::HWAddress<> mac_addr;

	/*!
	    \struct	ether_arp
	
	    \brief
	    ARP packets are variable in size; the arphdr structure defines the fixed-length portion.
	    Protocol type values are the same as those for 10 Mb/s Ethernet. It is followed by the
	    variable-sized fields ar_sha, arp_spa, arp_tha and arp_tpa in that order, according to
	    the lengths specified. Field names used correspond to RFC 826.
	*/
	struct	ether_arp;

	/*!
	    \class	llinfo_arp
	
	    \brief
	    One llinfo_arp structure, exists for each ARP entry. Additionally, one of these
	    structures can be allocated as a global of the same name and used as the head of the
	    linked list of all these structures. We often refer to this list as the ARP cache, since
	    it is the only data structure in Figure 21.1 that has a one-to-one correspondence with
	    the ARP entries.
	    
	    \note can choose other ways to implement the linked list, which is actually more
	    recommended.
	*/
	class llinfo_arp;

	/*!
	    \fn L2_ARP::L2_ARP(class inet_os &inet, bool debug, const unsigned long arp_maxtries, const int arpt_down);
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet.
	    \param	arp_maxtries	The arp max tries before resend, default is 10 (once declared down, don't send for 10 secs).
	    \param	arpt_down   	The arp timeout for an entry.
	*/
	explicit L2_ARP(class inet_os &inet, const unsigned long arp_maxtries = 10, const int arpt_down = 10000)
		: inet(inet), arp_maxtries(arp_maxtries), arpt_down(arpt_down) { inet.arp(this); }

	/*!
	    \fn	L2_ARP::~L2_ARP()
	
	    \brief	notify inet_os that this interface is deleted.
	*/
	~L2_ARP() { inet.arp(nullptr); }

	/*!
	    \pure virtual mac_addr* L2_ARP::arpresolve(std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, short m_flags, struct sockaddr *dst) = 0;
	
	    \brief
	    arpresolve Function: ether_output() calls arpresolve() to obtain the Ethernet address for
	    an IP address. arpresolve() returns the pointer to destination Ethernet address that is
	    known, allowing ether_output to queue the IP datagram on the interface's output queue. A
	    return value of nullptr means arpresolve() does not know the Ethernet address. The
	    datagram is "held" by arpresolve() (using the #la_hold member of the llinfo_arp
	    structure) and an ARP request is sent. When an ARP reply is received, in_arpinput
	    completes the ARP entry and sends the held datagram. arpresolve must also avoid ARP
	    flooding, that is, it must not repeatedly send ARP requests at a high rate when an ARP
	    reply is not received. This can happen when several datagrams are sent to the same
	    unresolved IP address before an ARP reply is received, or when a datagram destined for an
	    unresolved address is fragmented, since each fragment is sent to ether_output as a
	    separate packet. Section 11.9 of Volume 1 contains an example of ARP flooding caused by
	    fragmentation, and discusses the associated problems.
	
	    \param	m		   	The std::shared_ptr&lt;std::vector&lt;byte&gt;&gt; to process.
	    \param	it		   	The iterator.
	    \param	m_flags	   	The flags.
	    \param [in,out]	dst	a pointer to a sockaddr_in containing the destination IP address.
	
	    \return
	    A return value of != "" indicates that desten has been filled in and the packet should be
	    sent normally; a "" return indicates that the packet has been taken over here, either now
	    or for later transmission.
	*/
	virtual mac_addr* arpresolve(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, short m_flags, struct sockaddr *dst) = 0;

	/*!
	    \pure virtual void L2_ARP::in_arpinput(std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it) = 0;
	
	    \brief
	    ARP for Internet protocols on 10 Mb/s Ethernet. Algorithm is that given in RFC 826. In
	    addition, a sanity check is performed on the sender protocol address, to catch
	    impersonators. We no longer handle negotiations for use of trailer protocol: Formerly,
	    ARP replied for protocol type ETHERTYPE_TRAIL sent along with IP replies if we wanted
	    trailers sent to us, and also sent them in response to IP replies. This allowed either
	    end to announce the desire to receive trailer packets. We no longer reply to requests for
	    ETHERTYPE_TRAIL protocol either, but formerly didn't normally send requests.
	
	    \param	m 	The std::shared_ptr<std::vector<byte>> to process.
	    \param	it	The iterator.
	*/
	virtual void in_arpinput(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it) = 0;

	/*!
	    \pure	virtual void L2_ARP::insertPermanent(const u_long ip, const std::string la_mac) = 0;
	
	    \brief	Inserts a permanent arp entry, useful for debugging.
	
	    \param	ip	  	The IP.
	    \param	la_mac	The la MAC.
	*/
	virtual void insertPermanent(const u_long ip, const mac_addr &la_mac) = 0;

	/*!
	    \fn	const unsigned long L2_ARP::getArpMaxtries() const
	
	    \brief	Gets arp maxtries.
	
	    \return	The arp maxtries.
	*/
	const unsigned long getArpMaxtries() const { return arp_maxtries; }

	/*!
	    \fn	const unsigned int L2_ARP::getArptDown() const
	
	    \brief	Gets arpt down.
	
	    \return	The arpt down.
	*/
	const unsigned int getArptDown() const{ return arpt_down; }			/* once declared down, don't send for 10 secs */
	
protected:
	/*!
		\fn	virtual void L2_ARP::arprequest(const u_long &tip) = 0;

		\brief
		Broadcast an ARP request. Caller specifies:
		- arp header source ip address
		- arp header target ip address
		- arp header source Ethernet address

		The arprequest function is called to broadcast an ARP request. It builds an ARP request
		packet and passes it to the interface's output function. We examine the data structures
		built by the function. To send the ARP request the interface output function for the
		Ethernet device (ether_output) is called. One argument to ether_output is an m containing
		the data to send: everything that follows the Ethernet type field. Another argument is a
		socket address structure containing the destination address. Normally this destination
		address is an IP address . For the special case of an ARP request, the sa_family member
		of the socket address structure is set to AF_UNSPEC, which tells ether_output that it
		contains a filled-in Ethernet header, including the destination Ethernet address. This
		prevents ether_output from calling arpresolve, which would cause an infinite loop. We
		don't show this loop, but the "interface output function" below arprequest is
		ether_output. If ether_output were to call arpresolve again, the infinite loop would
		occur.

		\param	tip	The tip.
	*/
	virtual void arprequest(const u_long &tip) = 0;

	/*!
		\pure	virtual llinfo_arp& L2_ARP::arplookup(const u_long addr, bool create) = 0;

		\brief
		We've seen two calls to arplookup: 1. from in_arpinput to look up and possibly create an
		entry corresponding to the source IP address of a received ARP packet, 2. from arpresolve
		to look up or create an entry corresponding to the destination IP address of a datagram
		that is about to be sent.

		\param	addr  	the IP address to search for.
		\param	create
		a flag that is true if a new entry should be created if the entry is not found.

		\return
		succeeds, the corresponding llinfo_arp structure is returned to ;
		otherwise an empty struct is returned. arplookup has three arguments.
	*/
	virtual std::shared_ptr<L2_ARP::llinfo_arp> arplookup(const u_long addr, bool create) = 0;

	/*!
		\pure virtual void L2_ARP::SendArpReply(const struct in_addr& itaddr, const struct in_addr& isaddr, const std::string& hw_tgt, const std::string& hw_snd) const = 0;

		\brief
		Send an ARP Reply.
		Implementation is your's to decide, everything written on this function is only a
		suggestion:
		- You can (and should) add more functions to help creating and maintaining the table.
		- You can add more arguments to the input, or change the existing to whatever you want.

		\param	itaddr	Target ip address.
		\param	isaddr	Sender ip address.
		\param	hw_tgt	Target hardware (MAC) address.
		\param	hw_snd	Sender hardware (MAC) address.
	*/
	virtual void SendArpReply(const struct in_addr& itaddr, const struct in_addr& isaddr, const mac_addr& hw_tgt, const mac_addr& hw_snd) const = 0;

	class inet_os	&inet;			/*!< The inet_os owning this protocol. */

private:
	unsigned long	arp_maxtries;   /*!< The arp max tries before resend, default is 10 (once declared down, don't send for 10 secs). */
	unsigned int	arpt_down;		/*!< The arp timeout for an entry. */
};

/************************************************************************/
/*                         SOLUTION                                     */
/************************************************************************/

#include <map>

struct	L2_ARP::ether_arp 
{
	/*!
	\typedef	netlab::HWAddress<> mac_addr

	\brief	Defines an alias representing the MAC address.
	*/
	typedef netlab::HWAddress<> mac_addr;

	/*!
	    \struct	arphdr
	
	    \brief
	    the arphdr structure defines the fixed-length portion. Protocol type values are the same
	    as those for 10 Mb/s EthernetIt is followed by the variable-sized fields ar_sha, arp_spa,
	    arp_tha and arp_tpa in that order, according to the lengths specified. Field names used
	    correspond to RFC 826.
	
	    \sa	See RFC 826 for protocol description.
	*/
	struct	arphdr 
	{
		/*!
		    \enum	ARPHRD_
		
		    \brief	Values that represent arphrds (Using only #ARPHRD_ETHER).
		*/
		enum ARPHRD_
		{
			ARPHRD_ETHER = 1,	/*!< Ethernet hardware format */
			ARPHRD_FRELAY = 15	/*!< frame relay hardware format */
		};

		/*!
		    \enum	ARPOP_
		
		    \brief	Values that represent arp operations.
		*/
		enum ARPOP_
		{
			ARPOP_REQUEST = 1,		/*!< request to resolve address */
			ARPOP_REPLY = 2,		/*!< response to previous request */
			ARPOP_REVREQUEST = 3,	/*!< request protocol address given hardware */
			ARPOP_REVREPLY = 4,		/*!< response giving protocol address */
			ARPOP_INVREQUEST = 8, 	/*!< request to identify peer */
			ARPOP_INVREPLY = 9		/*!< response identifying peer */
		};

		/*!
		    \fn	arphdr(ARPOP_ op = ARPOP_REQUEST);
		
		    \brief	Constructor from ARPOP_, other values are 0.
		
		    \param	op	The operation.
		*/
		explicit arphdr(ARPOP_ op = ARPOP_REQUEST);

		/*!
		    \fn	std::string ar_op_format() const
		
		    \brief	returns the string representing the object's arp operation for printouts.
		
		    \return	A std::string.
		*/
		inline std::string ar_op_format() const;

		inline std::string hw_addr_format() const;

		inline friend std::ostream& operator<<(std::ostream &out, const struct L2_ARP::ether_arp::arphdr &ea_hdr);

		u_short	ar_hrd;		/*!< format of hardware address */
		u_short	ar_pro;		/*!< format of protocol address */
		u_char	ar_hln;		/*!< length of hardware address */
		u_char	ar_pln;		/*!< length of protocol address */
		u_short	ar_op;		/*!< one of \ref ARPOP_ */
	};

	/*!	Gets the arp's header format of hardware address.
	
	    \return	format of hardware address
	*/
	inline u_short& arp_hrd() { return ea_hdr.ar_hrd; }

	/*!	Gets the arp's header format of protocol address.
	
	    \return	format of protocol address.
	*/
	inline	u_short& arp_pro() { return ea_hdr.ar_pro; }

	/*!	Gets the arp's header length of hardware address
	
	    \return	length of hardware address
	*/
	inline	u_char& arp_hln() { return ea_hdr.ar_hln; }

	/*! Gets the arp's header length of protocol address
	
	    \return	length of protocol address
	*/
	inline	u_char& arp_pln() { return ea_hdr.ar_pln; }

	/*! Gets the arp's header arp operation
	
	    \return	arp operation
	*/
	inline	u_short& arp_op() { return ea_hdr.ar_op; }

	/*!
	    \brief	Full Constructor, arphdr is default-constructed from the op.
	
	    \param	tip  	The target ip.
	    \param	sip  	The source IP.
	    \param	taddr	The target hw addr.
	    \param	saddr	The source hw addr.
	    \param	op   	The arp operation.
	*/
	ether_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, arphdr::ARPOP_ op = arphdr::ARPOP_REQUEST);

	/*!
	    \fn static std::shared_ptr<std::vector<byte>> make_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it, arphdr::ARPOP_ op = arphdr::ARPOP_REQUEST);
	
	    \brief
	    Makes an arp packet (without the ether_header, however allocates the place to hold one).
	
		\param	tip  	The target ip.
		\param	sip  	The source IP.
		\param	taddr	The target hw addr.
		\param	saddr	The source hw addr.
	    \param [in,out]	it	The iterator to return.
	    \param	op   	The arp operation.
	
	    \return	A std::shared_ptr<std::vector<byte>> that holds the data
	*/
	inline static std::shared_ptr<std::vector<byte>> make_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it, arphdr::ARPOP_ op = arphdr::ARPOP_REQUEST);

	/*!
	    \brief
	    Makes an arp request packet (without the ether_header, however allocates the place to hold one).
	
	    \param	tip		  	The target ip.
	    \param	sip		  	The source IP.
	    \param	taddr	  	The target hw addr.
	    \param	saddr	  	The source hw addr.
	    \param [in,out]	it	The iterator to return.
	
	    \return	A std::shared_ptr<std::vector<byte>> that holds the data.
	*/
	inline static std::shared_ptr<std::vector<byte>> make_arp_request(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it);

	/*!
	    \fn
	    static std::shared_ptr<std::vector<byte>> make_arp_reply(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it);
	
	    \brief
	    Makes an arp reply packet (without the ether_header, however allocates the place to
	    hold one).
	
	    \param	tip		  	The target ip.
	    \param	sip		  	The source IP.
	    \param	taddr	  	The target hw addr.
	    \param	saddr	  	The source hw addr.
	    \param [in,out]	it	The iterator to return.
	
	    \return	A std::shared_ptr<std::vector<byte>> that holds the data.
	*/
	inline static std::shared_ptr<std::vector<byte>> make_arp_reply(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it);

	/*!
	    \fn	friend std::ostream& operator<<(std::ostream &out, const struct L2_ARP::ether_arp &ea);
	
	    \brief	Stream insertion operator.
	
	    \param [in,out]	out	The output stream (usually std::cout).
	    \param	ea		   	The ether_arp to printout.
	
	    \return	The output stream, when #ea was inserted and printed.
	*/
	inline friend std::ostream& operator<<(std::ostream &out, const struct L2_ARP::ether_arp &ea);

	struct	arphdr ea_hdr;		/*!< fixed-size header */
	mac_addr	arp_sha;		/*!< sender hardware address */
	u_char		arp_spa[4];		/*!< sender protocol address */
	mac_addr	arp_tha;		/*!< target hardware address */
	u_char		arp_tpa[4];		/*!< target protocol address */

};

class L2_ARP::llinfo_arp
{
public:
	/*!
	    \fn	explicit llinfo_arp(bool permanent = false);
	
	    \brief	Constructor.
	
	    \param	permanent	true to permanent.
	*/
	explicit llinfo_arp(bool permanent = false);

	explicit llinfo_arp(const mac_addr &la_mac, bool permanent = false);
	/*!
	    \fn	inline ~llinfo_arp();
	
	    \brief	Destructor, clears #la_hold, if exists.
	*/
	inline ~llinfo_arp();

	/*!
		\fn	inline bool valid() const;

		\brief	checks if the entry is valid in terms of time.

		\return	true if it succeeds, false if it fails.
	*/
	inline bool valid() const;

	/*!
	    \fn	inline mac_addr& getLaMac();
	
	    \brief	Gets la MAC (non-const).
	
	    \return	The la MAC.
	*/
	inline mac_addr& getLaMac();

	/*!	Test if la_hold is clears to send.
	
	    \param	arp_maxtries	The arp_maxtries (supplied by L2_ARP).
	    \param	arpt_down   	The arpt_down (supplied by L2_ARP).
	
	    \return	true if it succeeds, false if it fails.
	*/
	inline bool clearToSend(const unsigned long arp_maxtries, const unsigned int arpt_down);

	/*!	
	    \brief	Removes the top-of-stack packet, la_hold and its corresponding iterator hold_it.
	*/
	inline void pop();

	/*!
	    \brief	Pushes a packet, la_hold and its corresponding iterator hold_it onto this stack.
	
	    \param	hold   	The packet to hold.
	    \param	hold_it	The iterator of the packet to hold.
	*/
	inline void push(std::shared_ptr<std::vector<byte>> hold, const std::vector<byte>::iterator hold_it);

	/*!
	    \fn	inline std::shared_ptr<std::vector<byte>> front() const;
	
	    \brief	Gets the top-of-stack packet, la_hold.
	
	    \return	the top-of-stack packet, la_hold.
	*/
	inline std::shared_ptr<std::vector<byte>> front() const;

	/*!
	    \fn	inline std::vector<byte>::iterator& front_it();
	
	    \brief	Gets the top-of-stack, iterator.
	
	    \return	the top-of-stack, iterator.
	*/
	inline std::vector<byte>::iterator& front_it();

	/*!
	    \fn	inline bool empty() const;
	
	    \brief	Test if the stack (of la_hold) is empty.
	
	    \return	true if it succeeds, false if it fails.
	*/
	inline bool empty() const;

	/*!
	    \fn	inline void update(const mac_addr la_mac);
	
	    \brief	Updates the entry with the given la_mac.
	
	    \param	la_mac	The la MAC to update.
	*/
	inline void update(const mac_addr la_mac);

	/*!
		\fn	inline unsigned long long getLaTimeStamp() const;

		\brief	Gets la timestamp.

		\return	The la timestamp.
	*/
	inline unsigned long long getLaTimeStamp() const;

private:
	enum time_stamp
	{
		MAX_TIME_STAMP = 1500000	/*!<	25 minutes	*/
	}; 

	mac_addr							la_mac;		/*!< The la MAC address */
	std::shared_ptr<std::vector<byte>>	la_hold;	/*!< last packet until resolved/timeout */
	std::vector<byte>::iterator 		la_hold_it;	/*!< The la hold iterator, as the current offset in the vector. */

	unsigned long			la_asked;		/*!< # times we've queried for this addr */
	unsigned short			la_flags;		/*!< last time we QUERIED for this addr */
	unsigned long long		la_timeStamp;	/*!< last time we QUERIED for this addr */
};

/*!
    \class	L2_ARP_impl

    \brief	A L2_ARP implementation.

    \sa	L2_ARP
*/
class L2_ARP_impl 
	: public L2_ARP 
{
public:

	/*!
	    \fn
	    L2_ARP_impl::L2_ARP_impl(class inet_os &inet, bool debug, const unsigned long arp_maxtries, const int arpt_down);
	
	    \brief	Constructor, initiate the #ArpCache.
	
	    \param [in,out]	inet	The inet.
	    \param	arp_maxtries
	    The arp max tries before resend, default is 10 (once declared down, don't send for 10
	    secs).
	    \param	arpt_down   	The arp timeout for an entry.
	*/
	explicit L2_ARP_impl(class inet_os &inet, const unsigned long arp_maxtries = 10, const int arpt_down = 10000);

	inline virtual mac_addr* arpresolve(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, short m_flags, struct sockaddr *dst);
	inline virtual void in_arpinput(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it);
	inline virtual void insertPermanent(const u_long ip, const mac_addr &la_mac);

private:

	/*!
		\fn	void L2_ARP_impl::arpwhohas(struct in_addr &addr);

		\brief
		arpwhohas Function The arpwhohas function is normally called by arpresolve to broadcast
		an ARP request. It is also called by each Ethernet device driver to issue a gratuitous
		ARP request when the IP address is assigned to the interface. Section 4.7 of Volume 1
		describes gratuitous ARP-it detects if another host on the Ethernet is using the same IP
		address and also allows other hosts eth ARP entries for this host to update their ARP
		entry if this host has changed its Ethernet address. arpwhohas simply calls arprequest,
		shown in the next section, with the correct arguments.

		\param [in,out]	addr	The address.
	*/
	inline void arpwhohas(const struct in_addr &addr);

	inline virtual void arprequest(const u_long &tip);
	inline virtual std::shared_ptr<L2_ARP::llinfo_arp> arplookup(const u_long addr, bool create);
	inline virtual void SendArpReply(const struct in_addr& itaddr, const struct in_addr& isaddr, const mac_addr& hw_tgt, const mac_addr& hw_snd) const;

	/*!
	    \class	ArpCache
	
	    \brief	An ARP cache table, using stl map.
	
	    \sa	std::map<u_long, class llinfo_arp>
	*/
	class ArpCache
		: public std::map < u_long, std::shared_ptr<L2_ARP::llinfo_arp> >
	{
		public:
			typedef std::map < u_long, std::shared_ptr<L2_ARP::llinfo_arp> > _Myt;

			/*!
			    \fn
			    ArpCache::ArpCache(const unsigned long arp_maxtries, const unsigned int arpt_down);
			
			    \brief	Constructor.
			
			    \param	arp_maxtries
			    The arp max tries before resend, default is 10 (once declared down, don't send
			    for 10 secs).
			    \param	arpt_down   	The arp timeout for an entry.
			*/
			explicit ArpCache(const unsigned long arp_maxtries = 10, const unsigned int arpt_down = 10000);

			/*!
			    \fn
			    inline iterator ArpCache::insert(const key_type& _Keyval, bool permanent = false);
			
			    \brief	Inserts.
			
			    \param	_Keyval  	The keyval.
			    \param	permanent	true to permanent.
			
			    \return	An iterator.
			*/
			//inline iterator insert(const key_type& _Keyval, bool permanent = false);

			mapped_type& operator[] (const key_type& k);

			mapped_type& operator[] (key_type&& k);


			/*!
			    \fn	inline iterator ArpCache::find(const key_type& _Keyval);
			
			    \brief	Searches for the first match for the given constant key type;
			
			    \param	_Keyval	The keyval.
			
			    \return	An iterator.
			*/
			inline iterator find(const key_type& _Keyval);

		private:

			/*!
			    \fn	inline void ArpCache::cleanup();
			
			    \brief	Cleanups the table if incounter old entery.
			*/
			inline void		cleanup();

			unsigned long	arp_maxtries;   /*!< The arp max tries before resend, default is 10 (once declared down, don't send for 10 secs). */
			unsigned int	arpt_down;		/*!< The arp timeout for an entry. */
	};


	class ArpCache		arpcache;   /*!< The arpcache */
};








#endif /* L2_ARP_SOL_H_ */
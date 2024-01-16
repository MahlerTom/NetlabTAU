#ifndef NETLAB_PCB_H
#define NETLAB_PCB_H
#include "L3.h"
#include "L5.h"
#include <boost/functional/hash/hash.hpp>

/*!
    \class	inpcb

    \brief
    Common structure pcb for internet protocol implementation. Here are stored pointers to local
    and foreign host table entries, local and foreign socket numbers, and pointers up (to a
    socket structure) and down (to a protocol-specific)
    control block.
*/
class inpcb 
{
public:

	/*!
	    \typedef	u_long tcp_seq
	
	    \brief	For consistency with freeBSD.
	*/
	typedef	u_long						tcp_seq;

	/*!
	    \typedef	class netlab::socket socket
	
	    \brief	Defines an alias representing netlab::sockets.
	*/
	typedef	class netlab::L5_socket		socket;

	/*!
	    \typedef	struct L3::route route
	
	    \brief	Defines an alias representing the L3::route.
	*/
	typedef	struct L3::route			route;

	/*!
	    \typedef	struct L3::iphdr ip
	
	    \brief	Defines an alias representing the L3::iphdr.
	*/
	typedef	struct L3::iphdr			ip;

	/*!
	    \typedef	struct L3::ip_moptions ip_moptions
	
	    \brief	Defines an alias representing the L3::ip_moptions.
	*/
	typedef	struct L3::ip_moptions		ip_moptions;

	/*!
	    \enum	INP_
	
	    \brief	flags in inp_flags
	*/
	enum INP_
	{
		INP_RECVOPTS = 0x01,		/*!< receive incoming IP options */
		INP_RECVRETOPTS = 0x02,		/*!< receive IP options for reply */
		INP_RECVDSTADDR = 0x04,		/*!< receive IP dst address */
		INP_CONTROLOPTS = (INP_RECVOPTS | INP_RECVRETOPTS | INP_RECVDSTADDR),   /*!< The inp controlopts option */
		INP_HDRINCL = 0x08,			/*!< user supplies entire IP header */
		INP_TIMEWAIT = 0x01000000	/*!< in TIMEWAIT, ppcb is tcptw */
	};

	/*!
	    \enum	INPLOOKUP_
	
	    \brief	Flags passed to in_pcblookup*() functions.
	*/
	enum INPLOOKUP_
	{
		INPLOOKUP_WILDCARD = 1,	/*!< Allow wildcard sockets. */
		INPLOOKUP_SETLOCAL = 2  /*!< Use local socket. */
	};

	/*!
		\struct	inpcb_key

		\brief	This struct is defined for future support to the STL hash tables.
	*/
	struct inpcb_key
	{

		inpcb_key(u_short inp_fport = 0, u_short inp_lport = 0)
			: inp_fport(inp_fport), inp_lport(inp_lport),
			inp_faddr(struct in_addr()), inp_laddr(struct in_addr()) { }

		inpcb_key(struct in_addr inp_faddr, u_short inp_fport, struct in_addr inp_laddr, u_short inp_lport)
			: inp_faddr(inp_faddr), inp_fport(inp_fport), inp_laddr(inp_laddr), inp_lport(inp_lport) { }

		friend inline bool operator==(const inpcb_key& lhs, const inpcb_key& rhs)
		{
			return (lhs.inp_faddr.s_addr == rhs.inp_faddr.s_addr &&
				lhs.inp_laddr.s_addr == rhs.inp_laddr.s_addr &&
				lhs.inp_fport == rhs.inp_fport &&
				lhs.inp_lport == rhs.inp_lport);
		}

		friend inline std::size_t hash_value(inpcb_key const& id)
		{
			std::size_t seed(0);
			boost::hash_combine(seed, id.inp_faddr.s_addr);
			boost::hash_combine(seed, id.inp_laddr.s_addr);
			boost::hash_combine(seed, id.inp_fport);
			boost::hash_combine(seed, id.inp_lport);
			return seed;
		}

		struct	in_addr inp_faddr;		/*!< foreign host table entry */
		u_short	inp_fport;				/*!< foreign port */
		struct	in_addr inp_laddr;		/*!< local host table entry */
		u_short	inp_lport;				/*!< local port */

	};

	/*!
	    \fn	inpcb::inpcb(socket &so, inpcb &head)
	
	    \brief
	    An Internet PCB is allocated by TCP, UDP, and raw IP when a socket is created. A
	    PRU_ATTACH request is issued by the socket system call.
	    
	    \note 
	    This is netlab version for the legacy: 
		\code int	 in_pcballoc((class socket *, class inpcb *)); \endcode.
	
	    \param [in,out]	so  	The socket to attach the PCB.
	    \param [in,out]	head	The head of the PCB linked list.
	*/
	inpcb(socket &so, inpcb &head)
		: inp_next(nullptr), inp_prev(nullptr), inp_head(&head), inp_key(struct inpcb_key()), inp_socket(&so),
		inp_ppcb(nullptr), inp_route(&so.inet), inp_flags(0), inp_ip(ip()),	inp_options(nullptr), inp_moptions(nullptr)
	{
		insque(head);
		so.so_pcb = this;
	}

	/*!
	    \fn	inpcb::inpcb(inet_os &inet)
	
	    \brief
	    An empty constructor, that requires the inet (which is regularly given in the socket)
	    This is useful when we want to attach a fresh socket inside inet_os.

	    \note This is netlab version for the legacy: 
	    \code int	 in_pcballoc(nullptr, nullptr); \endcode.
		which is not supported "as-is"

	    \param [in,out]	inet	the inet owning this pcb.
	*/
	inpcb(inet_os &inet, socket *so)
		: inp_next(nullptr), inp_prev(nullptr), inp_head(nullptr), inp_key(struct inpcb_key()), inp_socket(so),
		inp_ppcb(nullptr), inp_route(&inet), inp_flags(0), inp_ip(ip()), inp_options(nullptr), inp_moptions(nullptr) { }

	/*!
	    \fn	inpcb::~inpcb()
	
	    \brief
	    Destruct this object <b> and its coresponding socket </b>, remque() it.
	    
	    \note This is netlab version for the legacy: \code void	 in_pcbdetach((class inpcb *));
	    \endcode.
	*/
	~inpcb() 
	{
		if (inp_socket)
		{
			inp_socket->so_pcb = nullptr;
			delete inp_socket;
		}
		if (inp_route.ro_rt)
			delete inp_route.ro_rt;
		if (inp_moptions)
			delete inp_moptions;
		remque();
	}

	/*!
	    \pure virtual inpcb* inpcb::in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags) const;
	
	    \brief
	    \par 
	    in_pcblookup Function The function in_pcblookup serves four different purposes.
	    	1.	When either TCP or UDP receives an IP datagram, in_pcblookup scans the
	    		protocol's list of Internet PCBs looking for a matching PCB to receive the datagram.
	    		This is transport layer demultiplexing of a received datagram.
	    	2.	When a process executes the bind system call, to assign a local IP address and
	    		local port number to a socket, in_pcbbind is called by the protocol to verify that the
	    		requested local address pair is not already in use.
	    	3.	When a process executes the bind system call, requesting an ephemeral port be
	    		assigned to its socket, the kernel picks an ephemeral port and calls in_pcbbind to
	    		check if the port is in use. If it is in use, the next ephemeral port number is tried,
	    		and so on, until an unused port is located.
	    	4.	When a process executes the connect system call, either explicitly or implicitly,
	    		in_pcbbind verifies that the requested socket pair is unique. (An implicit call to
	    		connect happens when a UDP datagram is sent on an unconnected socket. We'll see this
	    		scenario in Chapter 23.)
	    \par 
		In cases 2, 3, and 4 in_pcbbind calls in_pcblookup. Two options confuse the logic of the
	    function. First, a process can specify either the SO_REUSEADDR or SO_REUSEPORT socket
	    option to say that a duplicate local address is OK. Second, sometimes a wildcard match is
	    OK (e.g., an incoming UDP datagram can match a PCB that has a wildcard for its local IP
	    address, meaning that the socket will accept UDP datagrams that arrive on any local
	    interface), while other times a wildcard match is forbidden (e.g., when connecting to a
	    foreign IP address and port number).
	    
	    \remark 
	    In the original Stanford IP multicast code appears the comment that "The logic of
	    in_pcblookup is rather opaque and there is not a single comment, ... " The adjective
	    opaque is an understatement.
	    
	    \remark 
	    The publicly available IP multicast code available for BSD/386, which is derived
	    from the port to 4.4850 done by Craig Leres, fixed the overloaded semantics of this
	    function by using in_pcblookup only for case 1 above. Cases 2 and 4 are handled by a new
	    function named in_pcbconflict, and case 3 is handled by a new function named
	    in_uniqueport. Dividing the original functionality into separate functions is much
	    clearer, but in the Net/3 release, which we're describing in this text, the logic is
	    still combined into the single function in_pcblookup.
	    
	    \par
	    The function starts at the head of the protocol's PCB list and potentially goes through
	    every PCB on the list. The variable match remembers the pointer to the entry with the
	    best match so far, and matchwild remembers the number of wildcards in that match. The
	    latter is initialized to 3, which is a value greater than the maximum number of wildcard
	    matches that can be encountered. (Any value greater than 2 would work.)
	    Each time around the loop, the variable wildcard starts at 0 and counts the number of
	    wildcard matches for each PCB.

		\param	faddr	 	The foreign host table entry.
	    \param	fport_arg	The foreign port.
	    \param	laddr	 	The local host table entry.
	    \param	lport_arg	The local port.
	    \param	flags	 	The flags \ref INPLOOKUP_.
	
	    \return
	    null if it fails, else the matching inpcb.
	    
	    \note 
		This is netlab version for the legacy: 
	    \code inpcb * in_pcblookup((class inpcb *, struct in_addr, u_int, struct in_addr, u_int, int)); \endcode.
	*/
	virtual class inpcb* in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags) const = 0;

	/*!
	    \pure int inpcb::in_pcbconnect(struct sockaddr_in *nam, const size_t nam_len);
	
	    \brief
	    Connect from a socket to a specified address. Both address and port must be specified in
	    argument sin. If don't have a local address for this socket yet, then pick one.
	    
	    \par 
	    The function in_pcbconnect specifies the foreign IP address and foreign port number
	    for a socket. It is called from four functions:
	    	1.	from connect for a TCP socket (required for a TCP client);
	    	2.	from connect for a UDP socket (optional for a UDP client, rare for a UDP server);
	    	3.	from sendto when a datagram is output on an unconnected UDP socket (common); and 
			4. 	from tcp_input when a connection request (a SYN segment) arrives on a TCP socket
	    		that is in the LISTEN state (standard for a TCP server).
	    \par 
	    In all four cases it is common, though not required, for the local IP address and
	    local port be unspecified when in_pcbconnect is called. Therefore one function of
	    in_pcbconnect is to assign the local values when they are unspecified. We'll discuss the
	    in_pcbconnect function in four sections. Figure 22.25 shows the first section.
	
	    \param [in,out]	nam	If non-null, the nam.
	    \param	nam_len	   	Length of the nam.
	
	    \return
	    An int, for error handling.
	    
	    \note This is netlab version for the legacy: \code int in_pcbconnect((class inpcb *,
	    struct mbuf *)); \endcode.
	*/
	virtual int in_pcbconnect(struct sockaddr_in *nam, const size_t nam_len) = 0;

	/*!
	    \pure	void inpcb::in_pcbdisconnect()
	
		\note
		For UDP future support.

	    \brief
	    \par
	    A UDP socket is disconnected by in_pcbdisconnect. This removes the foreign association by
	    setting the foreign IP address to all 0s (INADDR_ANY) and foreign port number to 0.
		\par
		This is done after a datagram has been sent on an unconnected UDP socket and when connect 
		is called on a connected UDP socket. In the first case the sequence of steps when the
	    process calls sendto is: UDP calls in_pcbconnect to connect the socket temporarily to the
	    destination, udp_output sends the datagram, and then in_pcbdisconnect removes the
	    temporary connection. 
		\par
		in_pcbdisconnect is not called when a socket is closed since in_pcbdetach handles the 
		release of the PCB. A disconnect is required only when the PCB needs to be reused for a 
		different foreign address or port number.

		\note This is netlab version for the legacy: 
		\code void in_pcbdisconnect((class inpcb *)); \endcode.
	*/
	virtual void in_pcbdisconnect() = 0;

	/*!
	    \pure	virtual int inpcb::in_pcbbind(struct sockaddr_in *nam, const size_t nam_len) = 0;
	
	    \brief
	    \par in_pcbbind Function The next function, in_pcbbind, binds a local address and port
	    number to a socket. It is called from five functions:
	    	1.	from bind for a TCP socket (normally to bind a server's well-known port);
	    	2.	from bind for a UDP socket (either to bind a server's well-known port or to
	    		bind an ephemeral port to a client's socket);
	    	3.	from connect for a TCP socket, if the socket has not yet been bound to a
	    		nonzero port (this is typical for TCP clients);
	    	4.	from listen for a TCP socket, if the socket has not yet been bound to a nonzero
	    		port (this is rare, since listen is called by a TCP server, which normally binds a well-
	    		known port, not an ephemeral port); and
	    	5.	from in_pcbconnect (Section 22.8), if the local IP address and local port number
	    		have not been set (typical for a call to connect for a UDP socket or for each call to
	    		sendto for an unconnected UDP socket).
	    
	    \par In cases 3, 4, and 5, an ephemeral port number is bound to the socket and the local
	    IP address is not changed (in case it is already set).
	    
	    \par We call cases t and 2 explicit binds and cases 3, 4, and 5 implicit binds. We also
	    note that although it is normal in case 2 for a server to bind a well known port, servers
	    invoked using remote procedure calls (RPC) often bind ephemeral ports and then register
	    their ephemeral port with another program that maintains a mapping between the server's
	    RPC program number and its ephemeral port (e.g., the Sun port mapper described in Section
	    29.4 of Volume 1).
	
	    \param [in,out]	nam	If non-null, the nam.
	    \param	nam_len	   	Length of the nam.
	
	    \return
	    An int.
	    
	    \note This is netlab version for the legacy: \code int	 in_pcbbind((class inpcb *, struct
	    mbuf *)); \endcode.
	*/
	virtual int in_pcbbind(struct sockaddr_in *nam, const size_t nam_len) = 0;

	/*!
	    \pure	void inpcb::in_setpeeraddr(byte *nam, size_t &nam_len) const;
	
	    \brief	
		copies the foreign IP address and port number from the PCB
	
	    \param [in,out]	nam	   	If non-null, the nam.
	    \param [in,out]	nam_len	Length of the nam.
		
		\note This is netlab version for the legacy:
		\code void in_setpeeraddr((class inpcb *, struct mbuf *)); \endcode.
	*/
	virtual void in_setpeeraddr(struct sockaddr_in *nam, size_t &nam_len) const = 0;

	/*!
	    \pure	virtual void inpcb::in_losing() = 0;
	
	    \brief
	    Check for alternatives when higher level complains about service problems. For now,
	    invalidate cached routing information. If the route was created dynamically (by a
	    redirect), time to try a default gateway again.
	    
	    \note This is netlab version for the legacy: 
	    \code void in_losing((class inpcb *)); \endcode.
	*/
	virtual void in_losing() = 0;
	
	/*!
	    \fn	virtual inline void inpcb::insque(inpcb &head) = 0;
	
	    \brief	Insert the given head to the global PCB linked list.
	
	    \param [in,out]	head	The head.
	*/
	virtual void insque(inpcb &head)
	{
		inp_next = head.inp_next;
		head.inp_next = this;
		inp_prev = &head;
		if (inp_next)
			inp_next->inp_prev = this;
	}

	/*!
	    \fn	virtual inline void inpcb::remque() = 0;
	
	    \brief
	    Remove this object from the linked list.
	    
	    \warning Does not delete the object!
	*/
	virtual void remque()
	{
		if (inp_next)
			inp_next->inp_prev = inp_prev;
		if (inp_prev)
			inp_prev->inp_next = inp_next;
		inp_prev = nullptr;
	}

	/*!
	    \fn	inline in_addr& inpcb::inp_faddr()
	
	    \brief	Gets the foreign host table entry from the \ref inpcb_key struct.
	
	    \return	the foreign host table entry.
	*/
	inline struct in_addr& inp_faddr() { return inp_key.inp_faddr; }
	inline const struct in_addr& inp_faddr() const { return inp_key.inp_faddr; }

	/*!
	    \fn	inline u_short& inpcb::inp_fport()
	
	    \brief	Gets the foreign port from the \ref inpcb_key struct.
	
	    \return	the foreign port.
	*/
	inline u_short& inp_fport() { return inp_key.inp_fport; }
	inline const u_short& inp_fport() const { return inp_key.inp_fport; }
	
	/*!
	    \fn	inline in_addr& inpcb::inp_laddr()
	
	    \brief	Gets local host table entry from the \ref inpcb_key struct.
	
	    \return	the local host table entry.
	*/
	inline struct in_addr& inp_laddr() { return inp_key.inp_laddr; }
	inline const struct in_addr& inp_laddr() const { return inp_key.inp_laddr; }

	/*!
	    \fn	inline u_short& inpcb::inp_lport()
	
	    \brief	Gets the local port from the \ref inpcb_key struct.
	
	    \return	the local port.
	*/
	inline u_short& inp_lport() { return inp_key.inp_lport; }
	inline const u_short& inp_lport() const { return inp_key.inp_lport; }

	/*!
	    \fn	virtual inline inpcb* inpcb::sotoinpcb()
	
	    \brief
	    Gets the sotoinpcb. Virtual allows a derived class to return its pointer and not *inpcb.
	
	    \return	null if it fails, else an inpcb*.
	*/
	virtual inline class inpcb*	sotoinpcb()	const { return inp_socket->so_pcb; }


	class	inpcb			*inp_next, *inp_prev;	/*!< pointers to other pcb's */

	class	inpcb			*inp_head;			/*!< pointer back to chain of inpcb's for this protocol */
	
	struct inpcb_key		inp_key;			/*!< key for the hash table */

	socket					*inp_socket;		/*!< back pointer to socket */
	class	inpcb			*inp_ppcb;			/*!< pointer to per-protocol pcb */
	route					inp_route;			/*!< placeholder for routing entry */
	int						inp_flags;			/*!< generic IP/datagram flags */
	ip						inp_ip;				/*!< header prototype; should have more */
	std::shared_ptr<std::vector<byte>> inp_options;		/*!< IP options */
	ip_moptions				*inp_moptions;		/*!< IP multicast options */

protected:
	enum need_to_change_to_var // remove 
	{
		IPPORT_USERRESERVED = 5000 /*!< Ports greater this value are reserved for (non-privileged) servers.  */
	};
};

/*!
    \class	inpcb

    \brief
    Common structure pcb for internet protocol implementation. Here are stored pointers to local
    and foreign host table entries, local and foreign socket numbers, and pointers up (to a
    socket structure) and down (to a protocol-specific)
    control block.
*/
class inpcb_impl
	: public inpcb
{
public:
	/*!
	    \typedef	class netlab::socket socket
	
	    \brief	Defines an alias representing netlab::sockets.
	*/
	typedef	class netlab::L5_socket_impl socket;
	/*!
		\fn	inpcb_impl::inpcb_impl(socket &so, inpcb &head);

		\brief
		An Internet PCB is allocated by TCP, UDP, and raw IP when a socket is created. A
		PRU_ATTACH request is issued by the socket system call.

		\note This is netlab version for the legacy: \code int	 in_pcballoc((class socket *,
		class inpcb *)); \endcode.

		\param [in,out]	so  	The socket to attach the PCB.
		\param [in,out]	head	The head of the PCB linked list.
		*/
	inpcb_impl(socket &so, inpcb_impl &head);

	/*!
		\fn	inpcb_impl::inpcb_impl(inet_os &inet);

		\brief
		An empty constructor, that requires the inet (which is regularly given in the socket)
		This is useful when we want to attach a fresh socket inside inet_os.

		\note This is netlab version for the legacy: \code int	 in_pcballoc(nullptr, nullptr);
		\endcode. which is not supported "as-is".

		\param [in,out]	inet	the inet owning this pcb.
		*/
	explicit inpcb_impl(inet_os &inet);

	virtual class inpcb_impl* in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags) const;

	virtual int in_pcbconnect(struct sockaddr_in *nam, const size_t nam_len);

	virtual void in_pcbdisconnect();

	virtual int in_pcbbind(struct sockaddr_in *nam, const size_t nam_len);

	virtual void in_setpeeraddr(struct sockaddr_in *nam, size_t &nam_len) const;

	virtual void in_losing();

	struct sockaddr_in* satosin(struct sockaddr *sa)	{ return reinterpret_cast<struct sockaddr_in *>(sa); }

};








#endif /* NETLAB_PCB_H */
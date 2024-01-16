#ifndef NETLAB_L5_H
#define NETLAB_L5_H

#include "Types.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <ws2tcpip.h>
#define BOOST_DISABLE_ASSERTS
#include <boost/circular_buffer.hpp>
#include <condition_variable>
#include <vector>

enum
{
	SB_SIZE_SMALL = 2 * 8 * 1024,
	SB_SIZE_DEFAULT = 8 * 8 * 1024, /*!< largest value for (unscaled) window */
	SB_SIZE_BIG = 32 * 8 * 1024
};

enum 
{ 
	SB_SIZE = 
	//SB_SIZE_SMALL
	SB_SIZE_DEFAULT 
	//SB_SIZE_BIG
}; /*!< Define for large buffer test */


class inet_os;
class inpcb;
class protosw;

/*!
    \namespace	netlab

    \brief	the main netlab namespace
*/
namespace netlab
{


	/*!
		\class	socket

		\brief
		Kernel structure per socket. Contains send and receive buffer queues, handle on protocol
		and pointer to protocol private data and error information.
		*/
	class L5_socket {
	public:
		typedef	int32_t						pid_t;		/* process id */
		typedef	u_long						tcp_seq;



		/*!
			\struct	sockbuf

			\brief	Variables for socket buffering. The buffer is a circular array that can be initiated to any size, and resize in runtime.
			The circular array is an STL container and supports STL container operations and iterators.
		*/
		struct sockbuf;

		/*!
		    \struct	upcallarg
		
		    \brief	For upcall arguments.
		*/
		struct upcallarg { };

		/*!
		    \fn	L5_socket::L5_socket(inet_os &inet)
		
		    \brief	Constructor.
		
		    \param [in,out]	inet	The inet.
		*/
		L5_socket(inet_os &inet) : inet(inet) 
		{
            this->so_type = 0;
            this->so_options = 0;
            this->so_linger = 0;
            this->so_state = 0;

            this->so_pcb = nullptr;            
            this->so_proto = nullptr;
  
            this->so_head = nullptr;     
            this->so_q0 = nullptr;     
            this->so_q = nullptr;       
            this->so_q0len = 0;    
            this->so_qlen = 0;     
            this->so_qlimit = 0;    
            this->so_timeo = 0;    

            this->so_error = 0; 
            this->so_pgid = 0;     
            this->so_oobmark = 0; 

            this->so_tpcb = nullptr; /*!< Wisc. protocol control block XXX */

            this->upcall = false;           /*!< true to upcall */
            this->so_upcallarg = nullptr;   /*!< Arg for above */

       
		}

		/*!
		    \fn	L5_socket::L5_socket(_In_ int af, _In_ int type, _In_ int protocol, inet_os &inet)
		
		    \brief
		    The socket system call creates a new socket and associates it with a protocol as
		    specified by the domain, type, and protocol arguments specified by the process. The
		    function allocates a new descriptor, which identifies the socket in future system
		    calls, and returns the descriptor to the process. Before each system call a structure
		    is defined to describe the arguments passed from the process to the kernel. In this
		    case, the arguments are passed within a socket_args structure. All the socket-layer
		    system calls have three arguments: p, a pointer to the proc structure for the calling
		    process; uap, a pointer to a structure containing the arguments passed by the process
		    to the system call; and retval, a value-result argument that points to the return
		    value for the system call. Normally, we ignore the p and ret val arguments and refer
		    to the contents of the structure pointed to by uap as the arguments to the system
		    call.
		
		    \param	af				The af.
		    \param	type			The type.
		    \param	protocol		The protocol.
		    \param [in,out]	inet	The inet.
		*/
		L5_socket(_In_ int af, _In_ int type, _In_ int protocol, inet_os &inet) : L5_socket(inet) { }
		
		/*!
		    \pure virtual void L5_socket::bind(_In_ const struct sockaddr *addr, _In_ int addr_len) = 0;
		
		    \brief
		    The bind system call associates a local network transport address with a socket. A
		    process acting as a client usually does not care what its local address is. In this
		    case, it isn't necessary to call bind before the process attempts to communicate; the
		    kernel selects and implicitly binds a local address to the socket as needed. A server
		    process almost always needs to bind to a specific well-known address. If so, the
		    process must call bind before accepting connections (TCP) or receiving datagrams
		    (UDP), because the clients establish connections or send datagrams to the well known
		    address. A socket's foreign address is specified by connect or by one of the write
		    calls that allow specification of foreign addresses (sendto or sendmsg). The
		    arguments to bind (passed within a bind_args structure) are: s, the socket descriptor;
		    name, a pointer to a buffer containing the transport address (e.g., a sockaddr_in
		    structure); and narnelen, the size of the buffer.
		
		    \param	addr		The address.
		    \param	addr_len	Length of the address.
		*/
		virtual void bind(_In_ const struct sockaddr *addr, _In_ int addr_len) = 0;

		/*!
		    \pure	virtual void L5_socket::listen(_In_ int backlog) = 0;
		
		    \brief
		    The listen system call, notifies a protocol that the process is prepared to accept
		    incoming connections on the socket. It also specifies a limit on the number of
		    connections that can be queued on the socket, after which the socket layer refuses to
		    queue additional connection requests. When this occurs, TCP ignores incoming
		    connection requests. Queued connections are made available to the process when it
		    calls accept.
		
		    \param	backlog	The backlog.
		*/
		virtual void listen(_In_ int backlog) = 0;

		/*!
		    \pure virtual netlab::L5_socket* L5_socket::accept(_Out_ struct sockaddr *addr, _Inout_ int *addr_len) = 0;
		
		    \brief
		    After calling listen, a process waits for incoming connections by calling accept,
		    which returns a descriptor that references a new socket connected to a client. The
		    original socket, s, remains unconnected and ready to receive additional connections.
		    accept returns the address of the foreign system if name points to a valid buffer.
		    The connection-processing details are handled by the protocol associated with the
		    socket. For TCP, the socket layer is notified when a connection has been established
		    (i.e., when TCP's three-way handshake has completed). The connection is completed
		    when explicitly confirmed by the process by reading or writing on the socket. The
		    three arguments to accept (in the accept_args structure) are: s, the socket
		    descriptor; name, a pointer to a buffer to be filled in by accept with the transport
		    address of the foreign host; and anamelen, a pointer to the size of the buffer.
		
		    \param [in,out]	addr		If non-null, the address.
		    \param [in,out]	addr_len	If non-null, length of the address.
		
		    \return	null if it fails, else a netlab::L5_socket*.
		*/
		virtual netlab::L5_socket* accept(_Out_ struct sockaddr *addr, _Inout_ int *addr_len) = 0;

		/*!
		    \pure virtual void L5_socket::connect(_In_ const struct sockaddr *name, _In_ int name_len) = 0;
		
		    \brief
		    connect System call: A server process calls the listen and accept system calls to
		    wait for a remote process to initiate a connection. If the process wants to initiate
		    a connection itself (i.e., a client), it calls connect.
		    	For connection-oriented protocols such as TCP, connect establishes a connection to
		    the specified foreign address. The kernel selects and implicitly binds an address to
		    the local socket if the process has not already done so with bind.
		    	For connectionless protocols such as UDP or ICMP, connect records the foreign
		    address for use in sending future datagrams. Any previous foreign address is replaced
		    with the new address.
		    	Figure 15.31 shows the functions called when connect is used for UDP or TCP. The
		    	left side of the figure shows connect processing for connectionless protocols,
		    such as UDP. In this case the protocol layer calls soisconnected and the connect
		    system call returns immediately.
		    	The right side of the figure shows connect processing for connection-oriented
		    	protocols,
		    such as TCP. In this case, the protocol layer begins the connection establishment and
		    calls soisconnecting to indicate that the connection will complete some time in the
		    future. Unless the socket is nonblocking, soconnect calls tsleep to wait for the
		    connection to complete. For TCP, when the three-way handshake is complete, the
		    protocol layer calls soisconnected to mark the socket as connected and then calls
		    wakeup to awaken the process and complete the connect system call. The three
		    arguments to connect (in the connect_args structure) are: s, the socket descriptor;
		    name, a pointer to a buffer containing the foreign address; and namelen, the length
		    of the buffer.
		
		    \param	name		The name.
		    \param	name_len	Length of the name.
		*/
		virtual void connect(_In_ const struct sockaddr *name, _In_ int name_len) = 0;

		/*!
		    \pure	virtual void L5_socket::shutdown(_In_ int how = SD_BOTH) = 0;
		
		    \brief	Shuts down this object and frees any resources it is using.
		
		    \param	how	The how.
		*/
		virtual void shutdown(_In_ int how = SD_BOTH) = 0;

		/*!
		    \pure	virtual L5_socket::~L5_socket() = 0;
		
		    \brief	Destructor, should call soclose.
		*/
		virtual ~L5_socket() = 0;

		/*!
		    \pure virtual void L5_socket::send(std::string uio, size_t chunk = 1024, int flags = 0) = 0;
		
		    \brief
		    Send on a socket. If send must go all at once and message is larger than send
		    buffering, then hard error. Lock against other senders. If must go all at once and
		    not enough room now, then inform user that this would block and do nothing. Otherwise,
		    if nonblocking, send as much as possible. The data to be sent is described by "uio"
		    if nonzero, otherwise by the mbuf chain "top" (which must be null if uio is not).
		    Data provided in mbuf chain must be small enough to send all at once. sosend
		    Function: sosend is one of the most complicated functions in the socket layer. Recall
		    from Figure 16.8 that all five write calls eventually call sosend. It is sosend's
		    responsibility to pass the data and control information to the pr_usrreq function of
		    the protocol associated with the socket according to the semantics supported by the
		    protocol and the buffer limits specified by the socket. sosend never places data in
		    the send buffer; it is the protocol's responsibility to store and remove the data.
		    The interpretation of the send buffer's sb_hiwat and sb_lowat values by sosend
		    depends on whether the associated protocol implements reliable or unreliable data
		    transfer semantics.
		    
		    Reliable Protocol Buffering: For reliable protocols, the send buffer holds both data
		    that has not yet been transmitted and data that has been sent, but has not been
		    acknowledged. sb_cc is the number of bytes of data that reside in the send buffer,
		    and 0 &lt;= sb_cc &lt;= sb_hiwat. Remark:	sb_cc may temporarily exceed sb_hiwat when
		    out-of-band data is sent. It is sosend's responsibility to ensure that there is
		    enough space in the send buffer before passing any data to the protocol layer through
		    the pr_usrreq function. The protocol layer adds the data to the send buffer. sosend
		    transfers data to the protocol in one of two ways: a.	If PR_ATOMIC is set, sosend
		    must preserve the message boundaries between the process and the protocol layer. In
		    this case, sosend waits for enough space to become available to hold the entire
		    message. When the space is available, an mbuf chain containing the entire message is
		    constructed and passed to the protocol in a single call through the pr_usrreq
		    function. RDP and SPP are examples of this type of protocol. b.	If PR_ATOMIC is not
		    set, sosend passes the message to the protocol one mbuf at a time and may pass a
		    partial mbuf to avoid exceeding the high-water mark. This method is used with
		    SOCK_STREAM protocols such as TCP and SOCK_SEQPACKET protocols such as TP4. With TP4,
		    record boundaries are indicated explicitly with the MSG_EOR flag (Figure 16.12), so
		    it is not necessary for the message boundaries to be preserved by sosend. TCP
		    applications have no control over the size of outgoing TCP segments. For example, a
		    message of 4096 bytes sent on a TCP socket will be split by the socket layer into two
		    mbufs with external clusters, containing 2048 bytes each, assuming there is enough
		    space in the send buffer for 4096 bytes. Later, during protocol processing, TCP will
		    segment the data according to the maximum segment size for the connection, which is
		    normally less than 2048. When a message is too large to fit in the available buffer
		    space and the protocol allows messages to be split, sosend still does not pass data
		    to the protocol until the free space in the buffer rises above sb_lowat. For TCP,
		    sb_lowat defaults to 2048 (Figure 16.4), so this rule prevents the socket layer from
		    bothering TCP with small chunks of data when the send buffer is nearly full.
		    
		    Unreliable Protocol Buffering: With unreliable protocols (e.g., UDP), no data is ever
		    stored in the send buffer and no acknowledgment is ever expected. Each message is
		    passed immediately to the protocol where it is queued for transmission on the
		    appropriate network device. In this case, sb_cc is always 0, and sb_hiwat specifies
		    the maximum size of each write and indirectly the maximum size of a datagram. Figure
		    16.4 shows that sb_hiwat defaults to 9216(9x1024) for UDP. Unless the process changes
		    sb_hiwat with the SO_SNDBUF socket option, an attempt to write a datagram larger than
		    9216 bytes returns with an error. Even then, other limitations of the protocol
		    implementation may prevent a process from sending large datagrams. Section 11.10 of
		    Volume 1 discusses these defaults and limits in other TCP /IP implementations.
		    Remark:	9216 is large enough for a NFS write, which often defaults to 8192 bytes of
		    data plus protocol headers.
		    
		    The arguments to sosend are: so, a pointer to the relevant socket; addr, a pointer to
		    a destination address; uio, a pointer to a uio structure describing the I/O buffers
		    in user space; top, an mbuf chain that holds data to be sent; control, an mbuf that
		    holds control information to be sent; and flags, which contains options for this
		    write call. Normally, a process provides data to the socket layer through the uio
		    mechanism and top is null. When the kernel itself is using the socket layer (such as
		    with NFS), the data is passed to sosend as an mbuf chain pointed to by top, and uio
		    is null.
		    	    
		    throws nonzero on error, timeout or signal; callers must check for short counts if
		    EINTR/ERESTART are returned. Data and control buffers are freed on return.
		
		    \param	uio  	The uio.
		    \param	chunk	The chunk.
		    \param	flags	The flags.
		*/
		virtual void send(std::string uio, size_t uio_resid, size_t chunk, int flags) = 0;

		/*!
		    \pure virtual int L5_socket::recv(std::string &uio, size_t uio_resid, size_t chunk = 1024, int flags = MSG_WAITALL) = 0;
		
		    \brief
		    Optimized version of soreceive() for stream (TCP) sockets. XXXAO: (MSG_WAITALL |
		    MSG_PEEK) isn't properly handled.
		    
		    Implement receive operations on a socket. We depend on the way that records are added
		    to the sockbuf by sbappend*.  In particular, each record (mbufs linked through m_next)
		    must begin with an address if the protocol so specifies, followed by an optional mbuf
		    or mbufs containing ancillary data, and then zero or more mbufs of data. In order to
		    avoid blocking network interrupts for the entire time here, we splx() while doing the
		    actual copy to user space. Although the sockbuf is locked, new data may still be
		    appended, and thus we must maintain consistency of the sockbuf during that time.
		    
		    The caller may receive the data as a single mbuf chain by supplying an mbuf **mp0 for
		    use in returning the chain.  The uio is then used only for the count in uio_resid.
		    
		    This function transfers data from the receive buffer of the socket to the buffers
		    specified by the process. Some protocols provide an address specifying the sender of
		    the data, and this can be returned along with additional control information that may
		    be present. Before examining the code, we need to discuss the semantics of a receive
		    operation, out-of-band data, and the organization of a socket's receive buffer.
		    
			Figure 16.32 lists the flags that arc recognized by the kernel during soreceive.
			flags			Description											Reference
			MSG_DONTWAIT	do not wait for resources during this call			Figure 16.38
			MSG_OOB			receive out-of-band data instead of regular data	Figure 16.39
			MSG_PEEK		receive a copy of the data without consuming it		Figure 16.43
			MSG_WAITALL		wait for data to fill buffers before returning		Figure 16.50
			Figure 16.32 recvxxx system calls: flag values passed to kernel.

			recvmsg is the only read system call that returns flags to the process. In the other
			calls, the information is discarded by the kernel before control returns to the process.
			Figure 16.33 lists the flags that recvmsg can set in the msghdr structure.
			msg_flags		Description																Reference
			MSG_CTRUNC		the control information received was larger than the butler provided	Figure 16.31
			MSG_EOR			the data received marks the end of a logical record						Figure 16.48
			MSG_OOB			the buffer(s) contains out-of-band data									Figure 16.45
			MSG_TRUNC		the message received was larger than the buffer(s) provided				Figure 16.51
			Figure 16.33 recvmsg system call: rnsg_flag values returned by kernel.
		    
		    Out-of-Band Data: Out-of-band (OOB) data semantics vary widely among protocols. In
		    general, protocols expedite OOB data along a previously established communication
		    link. The OOB data might not remain in sequence with previously sent regular data.
		    The socket layer supports two mechanisms to facilitate handling OOB data in a
		    protocol-independent way: tagging and synchronization. In this chapter we describe
		    the abstract OOB mechanisms implemented by the socket layer. UDP does not support OOB
		    data. The relationship between TCP's urgent data mechanism and the socket OOB
		    n1echanism is described in the TCP chapters. A sending process tags data as OOB data
		    by setting the MSG_OOB flag in any of the sendxxx calls. sosend passes this
		    information to the socket's protocol, which provides any special services, such as
		    expediting the data or using an alternate queuing strategy. When a protocol receives
		    OOB data, the data is set aside instead of placing it in the socket's receive buffer.
		    A process receives the pending OOB data by setting the MSG_OOB flag in one of the
		    recvxxx calls. Alternatively, the receiving process can ask the protocol to place OOB
		    data inline with the regular data by setting the SO_OOBINLINB socket option (Section
		    17.3). When SO_OOBINLINE is set, the protocol places incoming OOB data in the receive
		    buffer with the regular data. In this case, MSG_OOB is not used to receive the OOB
		    data. Read calls return either all regular data or all OOB data. The two types are
		    never mixed in the input buffers of a single input system call. A process that uses
		    recvmsg to receive data can examine the MSG_OOB flag to determine if the returned
		    data is regular data or OOB data that has been placed inline. The socket layer
		    supports synchronization of OOB and regular data by allowing the protocol layer to
		    mark the point in the regular data stream at which OOB data was received. The
		    receiver can determine when it has reached this mark by using the SIOCATMARK ioctl
		    command after each read system call. When receiving regular data, the socket layer
		    ensures that only the bytes preceding the mark are returned in a single message so
		    that the receiver does not inadvertently pass the mark. If additional OOB data is
		    received before the receiver reaches the mark, the mark is silently advanced.
		    
		    soreceive has six arguments. so is a pointer to the socket. A pointer to an mbuf to
		    receive address information is returned in *paddr. If mp0 points to an mbuf pointer,
		    soreceive transfers the receive buffer data to an mbuf chain pointed to by *mp0. In
		    this case, the uio structure is used only for the count in uio_resid. If mp0 is null,
		    soreceive copies the data into buffers described by the uio structure. A pointer to
		    the mbuf containing control information is returned in *controlp, and soreceive
		    returns the flags described in Figure 16.33 in *flagsp.
		
		    \param [in,out]	uio	The uio.
		    \param	uio_resid  	The uio resid.
		    \param	chunk	   	The chunk.
		    \param	flags	   	The flags.
		
		    \return	An int.
		*/
		virtual int recv(std::string &uio, size_t uio_resid, size_t chunk, int flags) = 0;

		/*!
		    \fn	virtual void L5_socket::so_upcall(struct upcallarg *arg, int waitf) = 0;
		
		    \brief	Upcall, called for upper layer implemntation.
		
		    \param [in,out]	arg	If non-null, the argument.
		    \param	waitf	   	The waitf.
		*/
		virtual void so_upcall(struct upcallarg *arg, int waitf) = 0;

		inline class protosw** pffindproto(const int family, const int protocol, const int type) const;

		inline class protosw** pffindtype(const int family, const int type) const;
		
		inline std::mutex& print_mutex();
		
		inline std::mutex& splnet();

		
		
		
		short	so_type;		/*!< generic type, see socket.h */
		short	so_options;		/*!< from socket call, see socket.h */
		short	so_linger;		/*!< time to linger while closing */
		short	so_state;		/*!< internal state flags SS_*, below */

		class inpcb		*so_pcb;	/*!< protocol control block */
		class protosw	*so_proto;	/*!< protocol handle */

		/*
		* Variables for connection queueing.
		* Socket where accepts occur is so_head in all subsidiary sockets.
		* If so_head is 0, socket is not related to an accept.
		* For head socket so_q0 queues partially completed connections,
		* while so_q is a queue of connections ready to be accepted.
		* If a connection is aborted and it has so_head set, then
		* it has to be pulled out of either so_q0 or so_q.
		* We allow connections to queue up based on current queue lengths
		* and limit on number of queued connections for this socket.
		*/
		L5_socket *so_head;	/*!< back pointer to accept socket */
		L5_socket *so_q0;		/*!< queue of partial connections */
		L5_socket *so_q;		/*!< queue of incoming connections */
		short	so_q0len;		/*!< partials on so_q0 */
		short	so_qlen;		/*!< number of connections on so_q */
		short	so_qlimit;		/*!< max number queued connections */
		short	so_timeo;		/*!< connection timeout */

		u_short	so_error;		/*!< error affecting connection */
		pid_t	so_pgid;		/*!< pgid for signals */
		u_long	so_oobmark;		/*!< chars to oob mark */

		class inpcb	*so_tpcb;		/*!< Wisc. protocol control block XXX */

		bool upcall;	/*!< true to upcall */
		struct upcallarg *so_upcallarg;		/*!< Arg for above */

		class inet_os			&inet; /*!< The owner os */
	};
}

	/************************************************************************/
	/*                         SOLUTION                                     */
	/************************************************************************/

class inpcb_impl;

namespace netlab 
{
	struct L5_socket::sockbuf
			{
				/*!
					\typedef	boost::circular_buffer_space_optimized<byte> mbuf
		
					\brief	Defines an alias representing the mbuf, which is a circular buffer from boost library.
				*/
				typedef boost::circular_buffer_space_optimized<byte> mbuf;

				/*!
					\typedef	mbuf::capacity_type capacity_type
		
					\brief	Defines an alias representing type of the capacity so we can private access operations to the buffer.
				*/
				typedef mbuf::capacity_type  capacity_type;

				/*!
					\typedef	mbuf::size_type size_type
		
					\brief	Defines an alias representing type of the size so we can private access operations to the buffer.
				*/
				typedef mbuf::size_type size_type;

				/*!
					\typedef	mbuf::const_iterator const_iterator
		
					\brief	Defines an alias representing the constant iterator so we can private access operations to the buffer.
				*/
				typedef mbuf::const_iterator const_iterator;

				/*!
					\typedef	std::mutex mutex
		
					\brief	Defines an alias representing the mutex to lock the buffer.
				*/
				typedef std::mutex				mutex;

				/*!
					\typedef	std::condition_variable cond
		
					\brief	Defines an alias representing the condition variable for a wait operation.
				*/
				typedef std::condition_variable	cond;

				/*!
					\typedef	std::unique_lock<mutex> lock
		
					\brief
					Defines an alias representing the lock that can be created to atomically lock and
					unlock the mutex, inside the scope.
				*/
				typedef std::unique_lock<mutex>	lock;

				/*!
					\typedef	int32_t pid_t
		
					\brief	Defines an alias representing the process id for consistency with freeBSD.
				*/
				typedef	int32_t	pid_t;		/* process id */
		


				/*!
					\enum	SB_
		
					\brief	Flags for the socket buffer #sb_flags.
				*/
				enum SB_
				{
					SB_MAX = (256 * 1024),						/*!< default for max chars in sockbuf */
					SB_LOCK = 0x01,								/*!< lock on data queue */
					SB_WANT = 0x02,								/*!< someone is waiting to lock */
					SB_WAIT = 0x04,								/*!< someone is waiting for data/space */
					SB_SEL = 0x08,								/*!< someone is selecting */
					SB_ASYNC = 0x10,							/*!< ASYNC I/O, need signals */
					SB_NOTIFY = (SB_WAIT | SB_SEL | SB_ASYNC),  /*!< The notify option */
					SB_NOINTR = 0x40							/*!< operations not interruptible */
				};

				/*!
					\struct	select information

					\brief
					Used to maintain information about processes that wish to be notified when I/O
					becomes possible.

					\note Unused, implemented to support future development for the select function.
				*/
				struct selinfo
				{
					/*!
						\enum	SI_

						\brief	Flags for select information
					*/
					enum SI_
					{
						SI_COLL = 0x0001 /*!< collision occurred */
					};

					/*!
						\fn	selinfo()

						\brief	Default constructor.
					*/
					selinfo();

					/*!
						\fn	void selwakeup()

						\brief	Do a wakeup when a selectable event occurs.

						\note This is netlab version for the legacy:
						\code void	selwakeup __P((struct selinfo *)); \endcode.
					*/
					inline void selwakeup();

					pid_t	si_pid;		/*!< process to be notified */
					short	si_flags;	/*!< \see SI_ */
				};

				/*!
					\fn	explicit sockbuf(size_t n = SB_MAX)
		
					\brief	Constructor.
		
					\param	n	The initial size of #sb_mb.
				*/
				explicit sockbuf(size_t n = SB_SIZE);

				struct	selinfo sb_sel;	/*!< process selecting read/write */
				short	sb_flags;		/*!< flags, \see SB_ */



				//short	sb_timeo;		/* timeout for read/write */

				/*
				* Free mbufs held by a socket, and reserved mbuf space.
				*/
				~sockbuf();
		
				/** @defgroup group1 Socket buffer (struct sockbuf) utility routines.
				* Each socket contains two socket buffers: one for sending data and
				* one for receiving data. Each buffer contains a queue of mbufs,
				* information about the number of mbufs and amount of data in the
				* queue, and other fields allowing select() statements and notification
				* on data availability to be implemented.
				*
				* Data stored in a socket buffer is maintained as a list of records.
				* Each record is a list of mbufs chained together with the m_next
				* field. Records are chained together with the m_nextpkt field. The upper
				* level routine soreceive() expects the following conventions to be
				* observed when placing information in the receive buffer:
				*
				* 1. If the protocol requires each message be preceded by the sender's
				*    name, then a record containing that name must be present before
				*    any associated data (mbuf's must be of type MT_SONAME).
				* 2. If the protocol supports the exchange of "access rights" (really
				*    just additional data associated with the message), and there are
				*    "rights" to be received, then a record containing this data
				*    should be present (mbuf's must be of type MT_RIGHTS).
				* 3. If a name or rights record exists, then it must be followed by
				*    a data record, perhaps of zero length.
				*
				*  @{
				*/
		
				/*!
					\fn	bool sbreserve(u_long cc)

					\brief
					Attempt to scale max capacity to a new size. Before using a new socket structure it
					is first necessary to reserve buffer space to the socket, by calling sbreserve().
					This should commit some of the available buffer space in the system buffer pool for
					the socket (currently, it does nothing but enforce limits).  The space should be
					released by calling sbrelease() when the socket is destroyed.

					\param	cc	new capacity.

					\return	true if it succeeds, false if it fails.
				*/
				inline bool sbreserve(u_long cc);


				//! Get the capacity of the <code>circular_buffer_space_optimized</code>.
				/*!
					\return The capacity controller representing the maximum number of elements which can be stored in the
							<code>circular_buffer_space_optimized</code> and the minimal allocated size of the internal buffer.
					\throws Nothing.
					\par Exception Safety
						No-throw.
					\par Iterator Invalidation
						Does not invalidate any iterators.
					\par Complexity
						Constant (in the size of the <code>circular_buffer_space_optimized</code>).
					\sa <code>sbspace()</code>, <code>size()</code>, <code>sbreserve(u_long cc)</code>
				*/
				inline const capacity_type& capacity() const;

				/*!
					\fn	size_type size() const
		
					\brief	Gets the size.
		
					\return	length of sequence.
				*/
				inline size_type size() const;

				/*!
					\fn	bool empty() const
		
					\brief	is the mbuf empty?.
		
					\return	true if it succeeds, false if it fails.
				*/
				inline bool empty() const;

				/*!
					\fn	const_iterator begin() const
		
					\brief	const_iterator pointing to the beginning of this range.
		
					\return	An iterator to the beginning of this range.
				*/
				inline const_iterator begin() const;

				/*! \brief Get the maximum number of elements which can be inserted into the
							<code>circular_buffer_space_optimized</code> without overwriting any of already stored elements.
					\return <code>capacity().%capacity() - size()</code>
					\throws Nothing.
					\par Exception Safety
						No-throw.
					\par Iterator Invalidation
						Does not invalidate any iterators.
					\par Complexity
						Constant (in the size of the <code>circular_buffer_space_optimized</code>).
					\sa <code>capacity()</code>, <code>size()</code>, <code>max_size()</code>
				*/
				inline size_type sbspace() const;

				/** @} */ // end of group1


				/** @defgroup group2 Routines to add and remove data from an mbuf queue.
				 * The routine sbappend() is normally called to
				 * append new mbufs to a socket buffer, after checking that adequate
				 * space is available, comparing the function sbspace() with the amount
				 * of data to be added. 
				 *
				 * Reliable protocols may use the socket send buffer to hold data
				 * awaiting acknowledgment. Data is normally copied from a socket
				 * send buffer in a protocol with m_copy for output to a peer,
				 * and then removing the data from the socket buffer with sbdrop()
				 * when the data is acknowledged by the peer.
				*  @{
				*/		
				  //! Insert the range <code>[first, last)</code> at the specified position.
				/*!
					\pre <code>pos</code> is a valid iterator pointing to the <code>circular_buffer_space_optimized</code> or its
						 end.<br>Valid range <code>[first, last)</code> where <code>first</code> and <code>last</code> meet the
						 requirements of an <a href="http://www.sgi.com/tech/stl/InputIterator.html">InputIterator</a>.
					\post Elements from the range
						  <code>[first + max[0, distance(first, last) - (pos - begin()) - reserve()], last)</code> will be
						  inserted at the position <code>pos</code>.<br>The number of <code>min[pos - begin(), max[0,
						  distance(first, last) - reserve()]]</code> elements will be overwritten at the beginning of the
						  <code>circular_buffer_space_optimized</code>.<br>(See <i>Example</i> for the explanation.)<br><br>
						  The amount of allocated memory in the internal buffer may be predictively increased.
					\param pos An iterator specifying the position where the range will be inserted.
					\param first The beginning of the range to be inserted.
					\param last The end of the range to be inserted.
					\throws "An allocation error" if memory is exhausted (<code>std::bad_alloc</code> if the standard allocator is
							used).
							Whatever <code>T::T(const T&)</code> throws or nothing if <code>T::T(T&&)</code> is noexcept.
					\par Exception Safety
						 Basic.
					\par Iterator Invalidation
						 Invalidates all iterators pointing to the <code>circular_buffer_space_optimized</code> (except iterators
						 equal to <code>end()</code>).
					\par Complexity
						 Linear (in <code>[size() + std::distance(first, last)]</code>; in
						 <code>min[capacity().%capacity(), size() + std::distance(first, last)]</code> if the
						 <code>InputIterator</code> is a
						 <a href="http://www.sgi.com/tech/stl/RandomAccessIterator.html">RandomAccessIterator</a>).
					\par Example
						 Consider a <code>circular_buffer_space_optimized</code> with the capacity of 6 and the size of 4. Its
						 internal buffer may look like the one below.<br><br>
						 <code>|1|2|3|4| | |</code><br>
						 <code>p ___^</code><br><br>After inserting a range of elements at the position <code>p</code>:<br><br>
						 <code>int array[] = { 5, 6, 7, 8, 9 };</code><br><code>insert(p, array, array + 5);</code><br><br>
						 actually only elements <code>6</code>, <code>7</code>, <code>8</code> and <code>9</code> from the
						 specified range get inserted and elements <code>1</code> and <code>2</code> are overwritten. This is due
						 to the fact the insert operation preserves the capacity. After insertion the internal buffer looks like
						 this:<br><br><code>|6|7|8|9|3|4|</code><br><br>For comparison if the capacity would not be preserved the
						 internal buffer would then result in <code>|1|2|5|6|7|8|9|3|4|</code>.
				*/
				void sbappend(std::vector<byte>::iterator first, std::vector<byte>::iterator last);

				//! Remove all stored elements from the space optimized circular buffer.
				/*!
					\post <code>size() == 0</code><br><br>
							The amount of allocated memory in the internal buffer may be predictively decreased.
					\throws "An allocation error" if memory is exhausted (<code>std::bad_alloc</code> if the standard allocator is
							used).
					\par Exception Safety
						Basic.
					\par Iterator Invalidation
						Invalidates all iterators pointing to the <code>circular_buffer_space_optimized</code> (except iterators
						equal to <code>end()</code>).
					\par Complexity
						Linear (in the size of the <code>circular_buffer_space_optimized</code>).
				*/
				void sbflush();

				//! Remove first <code>n</code> elements (with constant complexity for scalar types).
				/*!
					\pre <code>n \<= size()</code>
					\post The <code>n</code> elements at the beginning of the <code>circular_buffer</code> will be removed.
					\param n The number of elements to be removed.
					\throws <a href="circular_buffer/implementation.html#circular_buffer.implementation.exceptions_of_move_if_noexcept_t">Exceptions of move_if_noexcept(T&)</a>.
					\par Exception Safety
						Basic; no-throw if the operation in the <i>Throws</i> section does not throw anything. (I.e. no throw in
						case of scalars.)
					\par Iterator Invalidation
						Invalidates iterators pointing to the first <code>n</code> erased elements.
					\par Complexity
						Constant (in <code>n</code>) for scalar types; linear for other types.
					\note This method has been specially designed for types which do not require an explicit destructruction (e.g.
						integer, float or a pointer). For these scalar types a call to a destructor is not required which makes
						it possible to implement the "erase from beginning" operation with a constant complexity. For non-sacalar
						types the complexity is linear (hence the explicit destruction is needed) and the implementation is
						actually equivalent to
					<code>\link circular_buffer::rerase(iterator, iterator) rerase(begin(), begin() + n)\endlink</code>.
					\sa <code>notify_all()</code>, <code>sbflush()</code>,
				*/
				inline void sbdrop(const size_type len);

				/*!
					\fn	void notify_all()
		
					\brief	If sockbuf is waiting (the flag is up) clears the flag and wake up all waiters.
				*/
				inline void notify_all();

				/** @} */ // end of group2

				/*!
					\fn	inline void sbwait_for_write(size_type chunk = 1024)
		
					\brief	Wait for a #chunk of data to drain from a socket buffer.
		
					\param	chunk	The min chunk we can send.
				*/
				inline void sbwait_for_write(size_type chunk);

				/*!
					\fn	inline void sbwait_for_read(size_type chunk = 1024)
		
					\brief	Wait for a #chunk of data to arrive at a socket buffer.
		
					\param	chunk	The min chunk we can receive.
				*/
				inline void sbwait_for_read(size_type chunk);

				mutex	sb_process_mutex;   /*!< The process mutex to support proccess locks */
		

				
			private:			
					mbuf	sb_mb;		/*!< The mbuf ring buffer */
					cond	sb_cond;	/*!< The condition variable to wait on */
					mutex	sb_read_mutex;  /*!< The read mutex to lock */
					mutex	sb_write_mutex; /*!< The write mutex  to lock  */
			};

	/*!
	    \class	L5_socket_impl
	
	    \brief	A L5 socket implementation.
	
	    \sa	L5_socket
	*/

	class L5_socket_impl : public L5_socket 
	{
		
	public:
		typedef std::mutex				mutex;
		typedef std::condition_variable	cond;
		typedef std::unique_lock<mutex>	lock;

		enum SO_
		{
			SO_REUSEPORT = 0x0200	/*!< allow local address & port reuse */
		};

		/*!
		    \enum	SS_
		
		    \brief	Socket state bits.
		*/
		enum SS_
		{
			SS_NOFDREF = 0x001,	/*!< no file table ref any more */
			SS_ISCONNECTED = 0x002,	/*!< socket connected to a peer */
			SS_ISCONNECTING = 0x004,	/*!< in process of connecting to peer */
			SS_ISDISCONNECTING = 0x008,	/*!< in process of disconnecting */
			SS_CANTSENDMORE = 0x010,	/*!< can't send more data to peer */
			SS_CANTRCVMORE = 0x020,	/*!< can't receive more data from peer */
			SS_RCVATMARK = 0x040,	/*!< at mark on input */
			SS_PRIV = 0x080,	/*!< privileged for broadcast, raw... */
			SS_NBIO = 0x100,	/*!< non-blocking ops */
			SS_ASYNC = 0x200,	/*!< async i/o notify */
			SS_ISCONFIRMING = 0x400		/*!< deciding to accept connection req */
		};

		enum MSG_
		{
			MSG_EOR = 0x8,						/*!< data completes record */
			MSG_TRUNC_2 = MSG_TRUNC >> 1,		/*!< data discarded before delivery */
			MSG_CTRUNC_2 = MSG_CTRUNC >> 1,		/*!< control data lost before delivery */
			MSG_WAITALL_2 = 0x40, 				/*!< wait for full request or error */
			MSG_DONTWAIT = 0x80					/*!< this message should be nonblocking */
		};

		L5_socket_impl(inet_os &inet);

		L5_socket_impl(_In_ int af, _In_ int type, _In_ int protocol, inet_os &inet);

		~L5_socket_impl();

		virtual void so_upcall(struct upcallarg *arg, int waitf);

		virtual void bind(_In_ const struct sockaddr *addr, _In_ int addr_len);

		virtual void listen(_In_ int backlog);

		virtual class L5_socket_impl* accept(_Out_ struct sockaddr *addr, _Inout_ int *addr_len);

		virtual void connect(_In_ const struct sockaddr *name, _In_ int name_len);
		
		virtual void shutdown(_In_ int how = SD_BOTH);	

		virtual void send(std::string uio, size_t uio_resid = 0, size_t chunk = 0, int flags = 0);

		virtual int recv(std::string &uio, size_t uio_resid, size_t chunk = 0, int flags = MSG_WAITALL);

		/*!
		    \fn	inline void L5_socket_impl::soisconnecting()
		
		    \brief
		    Procedures to manipulate state flags of socket and do appropriate wakeups.  Normal
		    sequence from the active (originating) side is that soisconnecting() is called during
		    processing of connect() call, resulting in an eventual call to soisconnected()
		    if/when the connection is established.  When the connection is torn down
		    soisdisconnecting() is called during processing of disconnect() call, and
		    soisdisconnected() is called when the connection to the peer is totally severed.  The
		    semantics of these routines are such that connectionless protocols can call
		    soisconnected() and soisdisconnected()
		    only, bypassing the in-progress calls when setting up a ``connection'' takes no time.
		    
		    From the passive side, a socket is created with two queues of sockets: so_q0 for
		    connections in progress and so_q for connections already made and awaiting user
		    acceptance. As a protocol is preparing incoming connections, it creates a socket
		    structure queued on so_q0 by calling sonewconn().  When the connection is established,
		    soisconnected() is called, and transfers the socket structure to so_q, making it
		    available to accept().
		    
		    If a socket is closed with sockets on either so_q0 or so_q, these sockets are dropped.
		    
		    If higher level protocols are implemented in the kernel, the wakeups done here will
		    sometimes cause software-interrupt process scheduling.
		*/
		inline void soisconnecting() 
		{
			so_state &= ~(SS_ISCONNECTED | SS_ISDISCONNECTING);
			so_state |= SS_ISCONNECTING;
		}

		inline void soisconnected() 
		{
			so_state &= ~(SS_ISCONNECTING | SS_ISDISCONNECTING | SS_ISCONFIRMING);
			so_state |= SS_ISCONNECTED;
			L5_socket_impl *head(dynamic_cast<L5_socket_impl*>(so_head));
			if (head && soqremque(0)) {
				soqinsque(*head, 1);
				head->sorwakeup();
				head->so_q_cond.notify_all();
			}
			else {
				so_q_cond.notify_all();
				sorwakeup();
				sowwakeup();
			}
		}

		inline void soisdisconnecting() 
		{
			so_state &= ~SS_ISCONNECTING;
			so_state |= (SS_ISDISCONNECTING | SS_CANTRCVMORE | SS_CANTSENDMORE);
			sowwakeup();
			sorwakeup();
		}

		inline void soisdisconnected() 
		{
			so_state &= ~(SS_ISCONNECTING | SS_ISCONNECTED | SS_ISDISCONNECTING);
			so_state |= (SS_CANTRCVMORE | SS_CANTSENDMORE);
			sowwakeup();
			sorwakeup();
		}

		inline void sorwakeup()	{ sowakeup(false); }

		inline void sowwakeup()	{ sowakeup(true); }

		/*!
		    \fn	inline void L5_socket_impl::socantsendmore()
		
		    \brief
		    Socantsendmore indicates that no more data will be sent on the socket; it would
		    normally be applied to a socket when the user informs the system that no more data is
		    to be sent, by the protocol code (in case PRU_SHUTDOWN).
		*/
		inline void socantsendmore() 
		{
			so_state |= SS_CANTSENDMORE;
			sowwakeup();
		}

		/*!
		    \fn	inline void L5_socket_impl::socantrcvmore()
		
		    \brief
		    Socantrcvmore indicates that no more data will be received, and will normally be
		    applied to the socket by a protocol when it detects that the peer will send no more
		    data. Data queued for reading in the socket may yet be read.
		*/
		inline void socantrcvmore() 
		{
			so_state |= SS_CANTRCVMORE;
			sorwakeup();
		}

		/*!
		    \fn	void L5_socket_impl::soabort();
		
		    \brief	aborts this object.
		*/
		void soabort();
		
		/*!
		    \fn L5_socket_impl* L5_socket_impl::sonewconn(class L5_socket_impl &head, const int connstatus);
		
		    \brief
		    The protocol layer passes head, a pointer to the socket that is accepting the
		    incoming connection, and connstatus, a flag to indicate the state of the new
		    connection. For TCP, connstatus is always 0. Remark:	For TP4, connstatus is always
		    SS_ISCOHFIRMING. The connection is implicitly confirmed when a process begins reading
		    from or writing to the socket.
		    
		    When an attempt at a new connection is noted on a socket which accepts connections,
		    sonewconn is called.  If the connection is possible (subject to space constraints,
		    etc.)
		    then we allocate a new structure, properly linked into the data structure of the
		    original socket, and return this. Connstatus may be 0, or SO_ISCONFIRMING, or
		    SO_ISCONNECTED.
		
		    \param [in,out]	head	The head.
		    \param	connstatus  	The connstatus.
		
		    \return	null if it fails, else a L5_socket_impl*.
		*/
		L5_socket_impl* sonewconn(class L5_socket_impl &head, const int connstatus);

		/*
		* Socket buffer (struct sockbuf) utility routines.
		*
		* Each socket contains two socket buffers: one for sending data and
		* one for receiving data.  Each buffer contains a queue of mbufs,
		* information about the number of mbufs and amount of data in the
		* queue, and other fields allowing select() statements and notification
		* on data availability to be implemented.
		*
		* Data stored in a socket buffer is maintained as a list of records.
		* Each record is a list of mbufs chained together with the m_next
		* field.  Records are chained together with the m_nextpkt field. The upper
		* level routine soreceive() expects the following conventions to be
		* observed when placing information in the receive buffer:
		*
		* 1. If the protocol requires each message be preceded by the sender's
		*    name, then a record containing that name must be present before
		*    any associated data (mbuf's must be of type MT_SONAME).
		* 2. If the protocol supports the exchange of ``access rights'' (really
		*    just additional data associated with the message), and there are
		*    ``rights'' to be received, then a record containing this data
		*    should be present (mbuf's must be of type MT_RIGHTS).
		* 3. If a name or rights record exists, then it must be followed by
		*    a data record, perhaps of zero length.
		*
		* Before using a new socket structure it is first necessary to reserve
		* buffer space to the socket, by calling sbreserve().  This should commit
		* some of the available buffer space in the system buffer pool for the
		* socket (currently, it does nothing but enforce limits).  The space
		* should be released by calling sbrelease() when the socket is destroyed.
		*/
		int	soreserve(u_long sndcc, u_long rcvcc);

		cond	so_q_cond;
		mutex	so_q_mutex;

		struct	L5_socket::sockbuf so_rcv;
		struct	L5_socket::sockbuf so_snd;

	private:

		/*!
		    \enum	F_
		
		    \brief	Flags for f_flag
		*/
		enum F_
		{
			FREAD = 0x01,   /*!< shut down the read-half of the connection */
			FWRITE = 0x02,  /*!< shut down the write-half of the connection */
			FREAD_FWRITE = FREAD | FWRITE   /*!< shut down both halves of the connection */
		};

		static inline  void winsock_socket_init(const int dom, SOCKET &sd, const short type, const int proto);
	
		static inline void winsock_socket_bind(SOCKET &sd, _In_ const struct sockaddr *name, _In_ int name_len);

		/*!
			\fn
			inline void L5_socket_impl::socreate(_In_ int af, _In_ SOCKET &sd, _In_ int type, _In_ int protocol);
	
			\brief
			Socket operation routines. These routines are called by the routines in sys_socket.c or
			from a system process, and implement the semantics of socket operations by switching out
			to the protocol specific routines. The four arguments to socreate are: dom, the requested
			protocol domain (e.g., PF INET);
			aso, in which a pointer to a new socket structure is returned type, the requested socket
			type (e.g., SOCK_STREAM);
			and proto, the requested protocol .
	
			\param	af		  	The af.
			\param [in,out]	sd	The SD.
			\param	type	  	The type.
			\param	protocol  	The protocol.
		*/
		inline void socreate(_In_ int af, _In_ SOCKET &sd, _In_ int type, _In_ int protocol);
	
		inline void sobind(_In_ SOCKET &sd, _In_ const struct sockaddr *name, _In_ int name_len);
	
		inline void solisten(_In_ int backlog);

		/*!
			\fn
			inline void L5_socket_impl::soaccept(_Out_ struct sockaddr *addr, _Inout_ int &addr_len);
	
			\brief
			soaccept ensures that the socket is associated with a descriptor and issues the
			PRU_ACCEPT request to the protocol. After pr_usrreq returns, nam contains the name of the
			foreign socket.
	
			\param [in,out]	addr		If non-null, the address.
			\param [in,out]	addr_len	Length of the address.
		*/
		inline void soaccept(_Out_ struct sockaddr *addr, _Inout_ int &addr_len);
	
		inline void soconnect(_In_ const struct sockaddr *nam, _In_ int nam_len);

		/*!
			\fn	inline void L5_socket_impl::soshutdown(_In_ int how);
	
			\brief
			soshutdown and sorflush Functions: The shut down of the read-half of a connection is
			handled in the socket layer by sorflush, and the shut down of the write-half of a
			connection is processed by the PRU_SHUTDOWN request in the protocol layer. The soshutdown
			function is shown in Figure 15.36.
	
			\param	how	The how.
		*/
		inline void soshutdown(_In_ int how);
	
		inline void sorflush();

		/*!
			\fn	inline void L5_socket_impl::soclose();
	
			\brief
			Close a socket on last file table reference removal. Initiate disconnect if connected.
			Free socket when disconnect complete.
	    
			This function aborts any connections that are pending on the socket (i.e., that have not
			yet been accepted by a process), waits for data to be transmitted to the foreign system,
			and releases the data structures that are no longer needed. soclose is shown in Figure
			15.39.
	    
			 Close a socket on last file table reference removal. Initiate disconnect if connected.
			 Free socket when disconnect complete.
		*/
		inline void soclose();

		inline void sodisconnect();

		inline void sofree();
		
		inline int soqremque(const int q);

		inline void soqinsque(L5_socket_impl &head, const int q);

		/*!
			\fn	inline bool L5_socket_impl::sosendallatonce() const;
	
			\brief	 do we have to send all at once on a socket?
	
			\return	true if it succeeds, false if it fails.
		*/
		inline bool sosendallatonce() const;

		/*!
			\fn	inline void L5_socket_impl::sowakeup(const bool sosnd);
	
			\brief
			Wakeup processes waiting on a socket buffer. Do asynchronous notification via SIGIO if
			the socket has the SS_ASYNC flag set.
	
			\param	sosnd	The sosnd.
		*/
		inline void sowakeup(const bool sosnd);
	
		SOCKET	sd; /*!< The windows socket */
		u_char f_flag;  /*!< The flag \see F_ */
	};

}

#endif
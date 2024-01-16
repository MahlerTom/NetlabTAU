#include "L5.h"
#include <algorithm>
#include <sstream>
#include <iostream>
#include <Shlobj.h>
#include "inet_os.hpp"

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif


namespace netlab
{
	inline L5_socket::~L5_socket() { }

	inline class protosw** L5_socket::pffindproto(const int family, const int protocol, const int type) const { return inet.pffindproto(family, protocol, type); }

	inline class protosw** L5_socket::pffindtype(const int family, const int type) const { return inet.pffindtype(family, type); }

	inline std::mutex& L5_socket::print_mutex() { return inet.print_mutex; }
	
	inline std::mutex& L5_socket::splnet() { return inet._splnet; }
}

/************************************************************************/
/*				           L5_socket::sockbuf							*/
/************************************************************************/

namespace netlab 
{
	L5_socket::sockbuf::selinfo::selinfo() : si_pid(0), si_flags(0) { }

	void L5_socket::sockbuf::selinfo::selwakeup()
	{
		if (si_pid == 0)
			return;
		if (si_flags & SI_COLL)
			si_flags &= ~SI_COLL;
		si_pid = 0;
	}

	L5_socket::sockbuf::sockbuf(size_t n) : sb_mb(mbuf(n)), sb_sel(), sb_flags(0) { }

	L5_socket::sockbuf::~sockbuf() { sb_cond.notify_all(); }

	bool L5_socket::sockbuf::sbreserve(u_long cc)
	{
		if (cc > static_cast<u_long>(SB_MAX))
			return (false);
		std::lock_guard<std::mutex> guard(sb_write_mutex);
		sb_mb.set_capacity(cc);
		return (true);
	}

	inline const L5_socket::sockbuf::capacity_type& L5_socket::sockbuf::capacity() const { return sb_mb.capacity(); }

	inline L5_socket::sockbuf::size_type L5_socket::sockbuf::size() const { return sb_mb.size(); }

	inline bool L5_socket::sockbuf::empty() const { return sb_mb.empty(); }

	inline L5_socket::sockbuf::const_iterator L5_socket::sockbuf::begin() const { return sb_mb.begin(); }

	inline L5_socket::sockbuf::size_type L5_socket::sockbuf::sbspace() const { return sb_mb.reserve(); }

	void L5_socket::sockbuf::sbappend(std::vector<byte>::iterator first, std::vector<byte>::iterator last)
	{
		if (std::distance(first, last) > 0)
		{
			std::lock_guard<std::mutex> guard(sb_write_mutex);
			/*
			* Put the first mbuf on the queue.
			* Note this permits zero length records.
			*/
			sb_mb.insert(sb_mb.end(), first, last);
		}
	}

	void L5_socket::sockbuf::sbflush()
	{
		std::lock_guard<std::mutex> read_guard(sb_read_mutex);
		std::lock_guard<std::mutex> write_guard(sb_write_mutex);
		sb_mb.clear();
	}

	inline void L5_socket::sockbuf::sbdrop(const size_type len)
	{
		std::lock_guard<std::mutex> guard(sb_read_mutex);
		if (len > size())
			sb_mb.clear();
		else {
			//sb_mb.erase_begin(len);
			sb_mb.erase(sb_mb.begin(), sb_mb.begin() + len);
			notify_all();
		}
	}

	inline void L5_socket::sockbuf::notify_all()
	{
		if (sb_flags & sockbuf::SB_WAIT)
		{
			sb_flags &= ~sockbuf::SB_WAIT;
			sb_cond.notify_all();
		}
	}

	inline void L5_socket::sockbuf::sbwait_for_write(size_type chunk)
	{
		sb_flags |= sockbuf::SB_WAIT;
		lock sb_write_lock(sb_write_mutex);
		sb_cond.wait(sb_write_lock, [this, chunk]() -> bool { return chunk <= sbspace(); });
	}

	inline void L5_socket::sockbuf::sbwait_for_read(size_type chunk)
	{
		sb_flags |= sockbuf::SB_WAIT;
		lock sb_read_lock(sb_read_mutex);
		sb_cond.wait(sb_read_lock, [this, chunk]() -> bool { return (chunk <= size()) || chunk == 1; });
		sb_flags &= ~sockbuf::SB_WAIT;
	}
}

/************************************************************************/
/*                         L5_socket_impl								*/
/************************************************************************/

namespace netlab 
{

	L5_socket_impl::L5_socket_impl(inet_os &inet) : L5_socket(inet) { }

	L5_socket_impl::L5_socket_impl(_In_ int af, _In_ int type, _In_ int protocol, inet_os &inet) 
		: L5_socket(af, type, protocol, inet) 
	{
		try
		{
			winsock_socket_init(af, sd, type, protocol);
		}
		catch (const std::runtime_error &e)
		{
			std::lock_guard<std::mutex> lock(inet.print_mutex);
			std::cout << "[@] Warning! Not using windows socket because " << e.what() << std::endl;
		}
		socreate(af, sd, type, protocol);
	}

	L5_socket_impl::~L5_socket_impl() { soclose(); }

	void L5_socket_impl::so_upcall(struct upcallarg *arg, int waitf) { }

	void L5_socket_impl::bind(_In_ const struct sockaddr *name, _In_ int name_len) 
	{
		try
		{
			winsock_socket_bind(sd, name, name_len);
		}
		catch (const std::runtime_error &e)
		{
			std::lock_guard<std::mutex> lock(print_mutex());
			std::cout << "[@] Warning! Not using windows bind because " << e.what() << std::endl;
		}
		sobind(sd, name, name_len);
	}

	void L5_socket_impl::listen(_In_ int backlog) { solisten(backlog); }

	class L5_socket_impl* L5_socket_impl::accept(_Out_ struct sockaddr *addr, _Inout_ int *addr_len) 
	{
		lock inet_splnet(splnet());

		/*
		*	Validate arguments:
		*	If the socket is not ready to accept connections (i.e., listen has not been called)
		*	or nonblocking 1/0 has been requested and no connections are queued,
		*	EINVAL or EWOULDBLOCK are returned respectively.
		*/
		if ((so_options & SO_ACCEPTCONN) == 0)
			throw std::runtime_error("accept failed with error EINVAL = " + std::to_string(EINVAL));
		if ((so_state & SS_NBIO) && so_qlen == 0)
			throw std::runtime_error("accept failed with error EWOULDBLOCK = " + std::to_string(EWOULDBLOCK));

		/*
		*	Wait for a connection
		*	The while loop continues until a connection is available, an error occurs, or the
		*	socket can no longer receive data. accept is not automatically restarted after a signal is
		*	caught (tsleep returns EINTR). The protocol layer wakes up the process when it
		*	inserts a new connection on the queue with sonewconn.
		*	Within the loop, the process waits in tsleep, which returns 0 when a connection is
		*	available. If tsleep is interrupted by a signal or the socket is set for nonblocking
		*	semantics, accept returns EINTR or EWOULDBLOCK (Figure 15.25).
		*/
		lock so_q_lock(so_q_mutex);
		while (so_qlen == 0 && so_error == 0) {
			if (so_state & SS_CANTRCVMORE) {
				so_error = ECONNABORTED;
				break;
			}
			inet_splnet.unlock();
			so_q_cond.wait(so_q_lock);
			inet_splnet.lock();
		}

		/*
		*	Asynchronous errors:
		*	If an error occurred on the socket during the sleep, the error code is moved from the
		*	socket to the return value for accept, the socket error is cleared, and accept returns.
		*		It is common for asynchronous events to change the state of a socket. The protocol
		*	processing layer notifies the socket layer of the change by setting so_error and waking
		*	any process waiting on the socket. Because of this, the socket layer must always
		*	examine so_error after waking to see if an error occurred while the process was sleeping
		*/
		if (so_error) {
			int error(so_error);
			so_error = 0;
			throw std::runtime_error("accept failed with error" + std::to_string(error));
		}

		L5_socket_impl *so(this);
		{
			L5_socket_impl *aso(dynamic_cast<L5_socket_impl*>(so_q));
			if (dynamic_cast<L5_socket_impl*>(so_q)->soqremque(1) == 0)
				throw std::runtime_error("accept: soqremque failed!");
			so = aso;
		}

		f_flag = FREAD | FWRITE;
	
		/*
		*	Protocol processing:
		*	accept allocates a new mbuf to hold the foreign address and calls soaccept to do
		*	protocol processing. The allocation and queuing of new sockets created during connection
		*	processing is described in Section 15.12. If the process provided a buffer to
		*	receive the foreign address, copyout copies the address from nam and the length from
		*	namelen to the process. If necessary, copyout silently truncates the name to fit in the
		*	process's buffer. Finally, the mbuf is released, protocol processing enabled, and accept
		*	returns.
		*	Because only one mbuf is allocated for the foreign address, transport addresses
		*	must fit in one mbuf. Unix domain addresses, which are pathnames in the filesystem
		*	(up to 1023 bytes in length), may encounter this limit, but there is no problem with the
		*	16-byte sockaddr_in structure for the Internet domain. The comment on line 170
		*	indicates that this limitation could be removed by allocating and copying an mbuf
		*	chain.
		*/
		struct sockaddr nam;
		int nam_len(sizeof(nam));
		so->soaccept(&nam, nam_len);
		if (addr && addr_len) {
			if (*addr_len > nam_len)
				*addr_len = nam_len;
			/* SHOULD COPY OUT A CHAIN HERE */
			std::memcpy(addr, &nam, *addr_len);
		}
		return so;
	}

	void L5_socket_impl::connect(_In_ const struct sockaddr *name, _In_ int name_len) 
	{
		if ((so_state & SS_NBIO) && (so_state & SS_ISCONNECTING))
			throw std::runtime_error("connect failed with error EALREADY = " + std::to_string(EALREADY));

		/*
		*	Start connection processing:
		*	The connection attempt is started by calling soconnect. If soconnect reports an
		*	error, connect jumps to bad. If a connection has not yet completed by the time
		*	soconnect returns and nonblocking 1/0 is enabled, EINPROGRESS is returned immediately
		*	to avoid waiting for the connection to complete. Since connection establishment
		*	normally involves exchanging several packets with the remote system, it may take a
		*	while to complete. Further calls to connect return EALREADY until the connection
		*	completes. EISCONN is returned when the connection is complete.
		*/
		soconnect(name, name_len);

		if ((so_state & SS_NBIO) && (so_state & SS_ISCONNECTING))
			throw std::runtime_error("connect failed with error EINPROGRESS = " + std::to_string(EINPROGRESS));

		/*
		*	Wait for connection establishment:
		*	The while loop continues until the connection is established or an error occurs.
		*	splnet prevents connect from missing a wakeup between testing the state of the
		*	socket and the call to tsleep. After the loop, error contains 0, the error code from
		*	tsleep, or the error from the socket.
		*/
		lock so_q_lock(so_q_mutex);
		while ((so_state & SS_ISCONNECTING) && so_error == 0)
			so_q_cond.wait(so_q_lock);

		/*
		*	The ss_ISCONNECTING flag is cleared since the connection has completed or the
		*	attempt has failed. The mbuf containing the foreign address is released and any error is
		*	returned.
		*/
		so_state &= ~SS_ISCONNECTING;
	}

	void L5_socket_impl::shutdown(_In_ int how) { soshutdown(how); }

	void L5_socket_impl::send(std::string uio, size_t uio_resid, size_t chunk, int flags)
	{
		if (uio_resid == 0)
			uio_resid = uio.size();
		if (chunk == 0)
			chunk = uio_resid;
		/*
		*	If requested, disable routing:
		*	dontroute is set when the routing tables should be bypassed for this message only.
		*	clen is the number of bytes in the optional control mbuf.
		*/
		int dontroute((flags & MSG_DONTROUTE) && (so_options & SO_DONTROUTE) == 0 && (so_proto->pr_flags() & protosw::PR_ATOMIC)),
			error;
		const int atomic(sosendallatonce());

		/*
		*	resid is the number of bytes in the iovec buffers or the number of bytes in the
		*	top mbuf chain. Exercise 16.1 discusses why res id might be negative.
		*/
		long resid(uio_resid);

		bool restart(true);
		lock process_lock(so_snd.sb_process_mutex);
		for (size_t i = 0; i < uio_resid;) {
			if (i + chunk > uio_resid)
				chunk = uio_resid - i;
			if (restart) 
				restart = false;

			/*
			*	Protocol processing is suspended to prevent the buffer from changing while it is
			*	being examined. Before each transfer, sosend checks several conditions:
			*/
			lock inet_splnet(splnet());
			/*
			*	If output from the socket is prohibited (e.g., the write-half of a TCP connection
			*	has been closed), EPIPE is returned.
			*/
			if (so_state & SS_CANTSENDMORE)
				throw std::runtime_error("sosend failed with error EPIPE = " + std::to_string(EPIPE));

			/*
			*	If the socket is in an error state (e.g., an ICMP port unreachable may have been
			*	generated by a previous datagram), so_error is returned. sendit discards
			*	the error if some data has been sent before the error occurs (Figure 16.21, line 389).*/
			else if (so_error)
				throw std::runtime_error("sosend failed with so_error = " + std::to_string(so_error));

			/*
			*	If the protocol requires connections and a connection has not been established or
			*	a connection attempt has not been started, ENOTCONN is returned. sosend permits
			*	a write consisting of control information and no data even when a connection
			*	has not been established.
			*		Remark:	The Internet protocols do not use this feature, but it is used by TP4 to send data with a
			*				connection request, to confirm a COMection request, and to send data with a disconnect request.
			*/
			else if ((so_state & SS_ISCONNECTED) == 0) {
				if (so_proto->pr_flags() & protosw::PR_CONNREQUIRED) {
					if ((so_state & SS_ISCONFIRMING) == 0)
						throw std::runtime_error("sosend failed with error ENOTCONN = " + std::to_string(ENOTCONN));
				}
				/*
				*	If a destination address is not specified for a connectionless protocol (e.g., the
				*	process calls send without establishing a destination with connect),
				*	EDESTADDREQ is returned.
				*/
				else
					throw std::runtime_error("sosend failed with error EDESTADDRREQ = " + std::to_string(EDESTADDRREQ));
			}

			/*
			*	Compute available space:
			*	sbspace computes the amount of free space remaining in the send buffer. This is
			*	an administrative limit based on the buffer's high-water mark, but is also limited by
			*	sb_mbmax to prevent many small messages from consuming too many mbufs (Figure
			*	16.6). sosend gives out-of-band data some priority by relaxing the limits on the
			*	buffer size by 1024 bytes.
			*/
			sockbuf::size_type space(so_snd.sbspace());
			if (flags & MSG_OOB)
				space += 1024;

			/*
			*	Enforce message size limit:
			*	If atomic is set and the message is larger than the high-water mark, EMSGSIZE is
			*	returned; the message is too large to be accepted by the protocol-even if the buffer
			*	were empty. If the control information is larger than the high-water mark, EMSGSIZE is
			*	also returned. This is the test that limits the size of a datagram or record.
			*/
			if (atomic && (resid > static_cast<long>(so_snd.capacity())))
				throw std::runtime_error("sosend failed with error EMSGSIZE = " + std::to_string(EMSGSIZE));

			/*
			*	Wilt for more space?
			*	If there is not enough space in the send buffer, the data is from a process (versus
			*	from the kernel in top), and one of the following conditions is true, then sosend must
			*	wait for additional space before continuing:
			*		a.	the message must be passed to protocol in a single request (atomic is set), or
			*		b.	the message may be split, but the free space has dropped below the low-water mark, or
			*		c.	the message may be split, but the control information does not fit in the available space.
			*
			*	When the data is passed to sosend in top (i.e., when uio is null), the data is
			*	already located in mbufs. Therefore sosend ignores the high- and low-water marks
			*	since no additional mbuf allocations are required to pass the data to the protocol.
			*		If the send buffer low-water mark is not used in this test, an interesting interaction
			*	occurs between the socket layer and the transport layer that leads to performance
			*	degradation. [Crowcroft et al. 1992] provides details on this scenario.
			*/
			else if (static_cast<long>(space) < resid && !uio.empty() && space < chunk ) {

				/*
				*	Wait for space:
				*	If sosend must wait for space and the socket is nonblocking, EWOULDBLOCK is
				*	returned. Otherwise, the buffer lock is released and sosend waits with sbwait until
				*	the status of the buffer changes. When sbwait returns, sosend reenables protocol processing
				*	and jumps back to restart to obtain a lock on the buffer and to check the error
				*	and space conditions again before continuing.
				*		By default, sbwait blocks until data can be sent. By changing sb_timeo in the
				*	buffer through the so_SNDTIMEO socket option, the process selects an upper bound for
				*	the wait time. If the timer expires, sbwait returns EWOULDBLOCK. Recall from Figure
				*	16.21 that this error is discarded by sendit if some data has already been transferred
				*	to the protocol. This timer does not limit the length of the entire call, just the
				*	inactivity time between filling mbufs.
				*/
				if (so_state & SS_NBIO)
					throw std::runtime_error("sosend failed with error EWOULDBLOCK = " + std::to_string(EWOULDBLOCK));


				inet_splnet.unlock();
				process_lock.unlock();
				so_snd.sbwait_for_write(chunk);
				process_lock.lock();

				restart = true;
				continue;

				
			}

			/*
			*	At this point, sosend has determined that some data may be passed to the protocol.
			*	splx enables interrupts since they should not be blocked during the relatively long
			*	time it takes to copy data from the process to the kernel. mp holds a pointer used to construct
			*	the mbuf chain. The size of the control information (clen) is subtracted from the
			*	space available before sosend transfers any data from the process.
			*/
			inet_splnet.unlock();

			/*
			*	The socket's SO_DONTROUTE option is toggled if necessary before and after passing
			*	the data to the protocol layer to bypass the routing tables on this message. This is the
			*	only option that can be enabled for a single message and, as described with Figure 16.23,
			*	it is controlled by the MSG_DONTROUTE flag during a write.
			*		pr_usrreq is bracketed with splnet and splx to block interrupts while the
			*	protocol is processing the message. This is a paranoid assumption since some protocols
			*	{such as UDP) may be able to do output processing without blocking interrupts, but this
			*	information is not available at the socket layer.
			*		If the process tagged this message as out-of-band data, sosend issues the
			*	PRU_SENOOOB request; othenvise it issues the PRU_SEND request. Address and control
			*	mbufs are also passed to the protocol at this time.
			*/
			if (dontroute)
				so_options |= SO_DONTROUTE;
			std::shared_ptr<std::vector<byte>> top(new std::vector<byte>(uio.begin() + i, uio.begin() + i + chunk));
			inet_splnet.lock();
			try{
				error = so_proto->pr_usrreq(
					this,
					((flags & MSG_OOB) ? protosw::PRU_SENDOOB : protosw::PRU_SEND),
					top,
					nullptr,
					0,
					std::shared_ptr<std::vector<byte>>(nullptr));
			}
			catch (std::runtime_error &e)
			{
				std::cout << e.what() << std::endl;
			}
			inet_splnet.unlock();

			resid -= top->size();

			if (dontroute)
				so_options &= ~SO_DONTROUTE;

			/*
			*	clen, control, top, and mp are reset, since control information is passed to the
			*	protocol only once and a new mbuf chain is constructed for the next part of the message.
			*	res id is nonzero only when atomic is not set (e.g., TCP). In that case, if space
			*	remains in the buffer, sosend loops back to fill another mbuf. If there is no more space,
			*	sosend loops back to wait for more space (Figure 16.24).
			*		We'll see in Chapter 23 that unreliable protocols, such as UDP, immediately queue
			*	the data for transmission on the network. Chapter 26 describes how reliable protocols,
			*	such as TCP, add the data to the socket's send buffer where it remains until it is sent to,
			*	and acknowledged by, the destination.
			*/
			if (error)
				throw std::runtime_error("sosend failed with error = " + std::to_string(error));
			i += chunk;
		}
	}

	int L5_socket_impl::recv(std::string &uio, size_t uio_resid, size_t chunk, int flags)
	{
		if (chunk == 0)
			chunk = uio_resid;
		/* We only do stream sockets. */
		if (so_type != SOCK_STREAM)
			throw std::runtime_error("soreceive_stream failed with error: EINVAL = " + std::to_string(EINVAL));
		else if (flags & MSG_OOB)
			throw std::runtime_error("OOB not supported.");
		else if (so_state & SS_CANTRCVMORE)
			throw std::runtime_error("Cant receive!");
		/* Easy one, no space to copyout anything. */
		else if (uio_resid == 0)
			throw std::runtime_error("soreceive_stream failed with error: EINVAL = " + std::to_string(EINVAL));

		/* We will never ever get anything unless we are or were connected. */
		else if (!(so_state & (SS_ISCONNECTED | SS_ISDISCONNECTING)))
			throw std::runtime_error("soreceive_stream failed with error: ENOTCONN = " + std::to_string(ENOTCONN));
		else {
			bool restart(true);

			/* Prevent other readers from entering the socket. */
			lock so_rcv_lock(so_rcv.sb_process_mutex);
			while (restart) {
				bool deliver(false);
				/* Abort if socket has reported problems. */
				if (so_error)
					if (so_rcv.size() > 0)
					{
						chunk = so_rcv.size();
						deliver = true;
					}
					else
					{
						int error(so_error);
						if (!(flags & MSG_PEEK))
							so_error = 0;
						throw std::runtime_error("soreceive_stream failed with error = " + std::to_string(error));
					}

				/* Door is closed.  Deliver what is left, if any. */
				else if (so_state & SS_CANTRCVMORE)
					if (so_rcv.size() > 0)
					{
						chunk = so_rcv.size();
						deliver = true;
					}
					else
						return 0;

				/* Socket buffer is empty and we shall not block. */
				else if (so_rcv.empty() &&
					((so_state & SS_NBIO) || (flags & (MSG_DONTWAIT))))
					return 0;

				/* Socket buffer got some data that we shall deliver now. */
				else if (so_rcv.size() >= chunk)
					deliver = true;

				/* On MSG_WAITALL we must wait until all data or error arrives. */
				else if ((flags & MSG_WAITALL) &&
					(so_rcv.size() >= uio_resid || so_rcv.size() >= so_rcv.capacity()))
					deliver = true;
				else {
					/*
					* Wait and block until (more) data comes in.
					* NB: Drops the sockbuf lock during wait.
					*/
					so_rcv_lock.unlock();
					so_rcv.sbwait_for_read(chunk);
					so_rcv_lock.lock();
					continue;
				}
				if (deliver)
				{
					/* Fill uio until full or current end of socket buffer is reached. */
					size_t len(std::min<size_t>(uio_resid, so_rcv.size()));

					/* NB: Must unlock socket buffer as uiomove may sleep. */
					uio += std::string(so_rcv.begin(), so_rcv.begin() + len);
					uio_resid -= len;

					/*
					* Remove the delivered data from the socket buffer unless we
					* were only peeking.
					*/
					if (len > 0)
						so_rcv.sbdrop(len);

					/*
					* For MSG_WAITALL we may have to loop again and wait for
					* more data to come in.
					*/
					if ((flags & MSG_WAITALL) && uio_resid > 0)
						continue;

					break;
				}
			}
		}
		return uio.size();
	}

	void L5_socket_impl::soabort() 
	{
		int error(so_proto->pr_usrreq(this, protosw::PRU_ABORT, std::shared_ptr<std::vector<byte>>(nullptr), nullptr, 0, std::shared_ptr<std::vector<byte>>(nullptr)));
		if (error)
			throw std::runtime_error("soabort failed with error" + std::to_string(error));
	}

	class L5_socket_impl* L5_socket_impl::sonewconn(class L5_socket_impl &head, const int connstatus) 
	{
		/*
		*	Limit Incoming connections:
		*	sonewconn prohibits additional connections when the following inequality is true:
		*					so_qlen + so_qOlen > 3*so_qlimit/2
		*	This formula provides a fudge factor for connections that never complete and guarantees
		*	that listen(fd, 0) allows one connection.
		*/
		if (head.so_qlen + head.so_q0len > 3 * head.so_qlimit / 2)
			return (nullptr);

		/*	Allocate new socket:
		*	A new socket structure is allocated and initialized. If the process calls
		*	setsockopt for the listening socket, the connected socket inherits several socket
		*	options because so_options, so_linger, so_pgid, and the sb_hiwat values are
		*	copied into the new socket structure.
		*/
		L5_socket_impl *so(new L5_socket_impl(inet));
		try
		{
			winsock_socket_init(this->so_proto->dom_family(), so->sd, this->so_type, this->so_proto->pr_protocol());
		}
		catch (const std::runtime_error &e)
		{
			std::cout << e.what() << std::endl;
			delete so;
			return (nullptr);
		}

		so->so_type = head.so_type;
		so->so_options = head.so_options &~SO_ACCEPTCONN;
		so->so_linger = head.so_linger;
		so->so_state = head.so_state | SS_NOFDREF;
		so->so_proto = head.so_proto;
		so->so_timeo = head.so_timeo;
		so->so_pgid = head.so_pgid;
		(void)so->soreserve(head.so_snd.capacity(), head.so_rcv.capacity());

		/*
		*	Queue connection:
		*	soqueue was set from connstatus on line 129. The new socket is inserted onto
		*	so_qO if soqueue is 0 (e.g., TCP connections) or onto so_q if connstatus is nonzero
		*	(e.g., TP4 connections).
		*/
		int soqueue(connstatus ? 1 : 0);
		so->soqinsque(head, soqueue);

		/*
		*	Protocol processing:
		*	The PRU_ATTACH request is issued to perform protocol layer processing on the new
		*	connection. If this fails, the socket is dequeued and discarded, and sonewconn returns
		*	a null pointer.
		*/
		if (so->so_proto->pr_usrreq(so, protosw::PRU_ATTACH, std::shared_ptr<std::vector<byte>>(nullptr), nullptr, 0, std::shared_ptr<std::vector<byte>>(nullptr))) {
			(void)so->soqremque(soqueue);
			delete so;
			return (nullptr);
		}
		if (connstatus) {
			head.sorwakeup();
			so->so_state |= connstatus;
		}
		return (so);
	}

	int	L5_socket_impl::soreserve(u_long sndcc, u_long rcvcc) 
	{
		if (so_snd.sbreserve(sndcc) == 0)
			return (ENOBUFS);
		if (so_rcv.sbreserve(rcvcc) == 0)
			return (ENOBUFS);
		return (0);
	}

	void L5_socket_impl::winsock_socket_init(const int dom, SOCKET &sd, const short type, const int proto) 
	{
		if ((sd = ::socket(dom, type, proto)) == INVALID_SOCKET)
			throw std::runtime_error("winsock_socket_init failed with error" + std::to_string(WSAGetLastError()));
	}

	void L5_socket_impl::winsock_socket_bind(SOCKET &sd, _In_ const struct sockaddr *name, _In_ int name_len) 
	{

		if (::bind(sd, name, name_len) == SOCKET_ERROR)
			throw std::runtime_error("winsock_socket_bind failed with error" + std::to_string(WSAGetLastError()));
	}

	void L5_socket_impl::socreate(_In_ int af, _In_ SOCKET &sd, _In_ int type, _In_ int protocol) 
	{
	
		/*	
		 *	Find protocol switch table:
		 *	If proto is nonzero, pffindproto looks for the specific protocol requested by the
		 *	process. If pro to is 0, pf find type looks for a protocol within the specified domain
		 *	with the semantics specified by type. Both functions return a pointer to a protosw
		 *	structure of the matching protocol or a null pointer (Section 7.6).
		 */
		class protosw **prp = protocol ? pffindproto(af, protocol, type) : pffindtype(af, type);
		if (*prp == nullptr /*|| (*prp)->pr_def(protosw::PR_USRREQ) == 0*/)
			throw std::runtime_error("socreate failed with error: EPROTONOSUPPORT = " + std::to_string(EPROTONOSUPPORT));
		if ((*prp)->pr_type() != type)
			throw std::runtime_error("socreate failed with error: EPROTOTYPE = " + std::to_string(EPROTOTYPE));
	
		/*	
		 *	Initialize socket structure:
		 *	fills with Os, records the type, and, if the calling process has superuser privileges, 
		 *	turns on ss_PRIV in the socket structure.
		 */
		so_type = type;
		if (IsUserAnAdmin())
			so_state = SS_PRIV;
		so_proto = *prp;

		/*	
		 *	PRU_ATTACH request:
		 *	The first example of the protocol-independent socket layer making a protocol specific
		 *	request appears in socreate. Recall from Section 7.4 and Figure 15.13 that
		 *	so->so_proto->pr_usrreq is a pointer to the user request function of the protocol
		 *	associated with socket so. Every protocol provides this function in order to handle
		 *	communication requests from the socket layer. The prototype for the function is:
		 *		int pr_usrreq(class socket *so, int req, scruct mbuf *mO, *ml, *m2);
		 *		
		 *	The first argument, so, is a pointer to the relevant socket and req is a constant identifying
		 *	the particular request. The next three arguments (mO, ml, and m2) are different for
		 *	each request. They are always passed as pointers to mbuf structures, even if they have
		 *	another type. Casts are used when necessary to avoid warnings from the compiler.
		 */
		int error((*prp)->pr_usrreq(this, protosw::PRU_ATTACH, std::shared_ptr<std::vector<byte>>(nullptr), reinterpret_cast<struct sockaddr *>(static_cast<long>(protocol)), sizeof(long), std::shared_ptr<std::vector<byte>>(nullptr)));

		/*	
		 *	Cleanup and return
		 *	the function attaches the protocol switch table to the new
		 *	socket and issues the PRU_ATTACH request to notify the protocol of the new end point.
		 *	This request causes most protocols, including TCP and UDP, to allocate and initialize
		 *	any structures required to support the new end point.
		 */
		if (error) {
			so_state |= SS_NOFDREF;
			sofree();
			throw std::runtime_error("socreate failed with error" + std::to_string(error));
		}
	}

	void L5_socket_impl::sobind(_In_ SOCKET &sd, _In_ const struct sockaddr *name, _In_ int name_len) 
	{
		std::lock_guard<std::mutex> lock(splnet());
		int error(so_proto->pr_usrreq(this, protosw::PRU_BIND, std::shared_ptr<std::vector<byte>>(nullptr), const_cast<struct sockaddr *>(name), static_cast<size_t>(name_len), std::shared_ptr<std::vector<byte>>(nullptr)));
		if (error)
			throw std::runtime_error("sobind failed with error" + std::to_string(error));
	}

	void L5_socket_impl::solisten(_In_ int backlog) 
	{
		std::lock_guard<std::mutex> lock(splnet());

		int error(so_proto->pr_usrreq(this, protosw::PRU_LISTEN, std::shared_ptr<std::vector<byte>>(nullptr), nullptr, 0, std::shared_ptr<std::vector<byte>>(nullptr)));
		if (error) 
			throw std::runtime_error("solisten failed with error" + std::to_string(error));
	
		if (so_q == nullptr)
			so_options |= SO_ACCEPTCONN;
	
		so_qlimit = std::min(backlog < 0 ? 0 : backlog, SOMAXCONN);
	}

	void L5_socket_impl::soaccept(_Out_ struct sockaddr *addr, _Inout_ int &addr_len) 
	{
		if ((so_state & SS_NOFDREF) == 0)
			throw std::runtime_error("soaccept: !NOFDREF");
	
		so_state &= ~SS_NOFDREF;
	
		int error(so_proto->pr_usrreq(this, protosw::PRU_ACCEPT, std::shared_ptr<std::vector<byte>>(nullptr), addr, static_cast<size_t>(addr_len), std::shared_ptr<std::vector<byte>>(nullptr)));
		if (error)
			throw std::runtime_error("soaccept failed with error" + std::to_string(error));
	}

	void L5_socket_impl::soconnect(_In_ const struct sockaddr *nam, _In_ int nam_len) 
	{
		if (so_options & SO_ACCEPTCONN)
			throw std::runtime_error("soconnect failed with error EOPNOTSUPP = " + std::to_string(EOPNOTSUPP));

		std::lock_guard<std::mutex> lockguard(splnet());
	
		/*
		* If protocol is connection-based, can only connect once.
		* Otherwise, if connected, try to disconnect first.
		* This allows user to disconnect by connecting to, e.g.,
		* a null address.
		*/
		int error(0);
		if (so_state & (SS_ISCONNECTED | SS_ISCONNECTING))
			if (so_proto->pr_flags() & protosw::PR_CONNREQUIRED)
				throw std::runtime_error("soconnect failed with error EISCONN = " + std::to_string(EISCONN));
			else
			{
				try
				{
					sodisconnect();
				}
				catch (const std::runtime_error &e)
				{
					std::cout << e.what() << std::endl;
					throw std::runtime_error("soconnect failed with error EISCONN = " + std::to_string(EISCONN));
				}
			}
		else
			error = so_proto->pr_usrreq(this, protosw::PRU_CONNECT, std::shared_ptr<std::vector<byte>>(nullptr), const_cast<struct sockaddr*>(nam), nam_len, std::shared_ptr<std::vector<byte>>(nullptr));
	
		if (error)
			throw std::runtime_error("soconnect failed with error = " + std::to_string(error));
	}

	void L5_socket_impl::soshutdown(_In_ int how) 
	{
		/*
		*	If the read-half of the socket is being closed, sorflush, shown in Figure 15.37, discards
		*	the data in the socket's receive buffer and disables the read-half of the connection.
		*	If the write-half of the socket is being closed, the PRU_SHUTDOWN request is issued to
		*	the protocol.
		*/
		if (++how & FREAD)
			sorflush();
		if (how & FWRITE) {
			int error(so_proto->pr_usrreq(this, protosw::PRU_SHUTDOWN, std::shared_ptr<std::vector<byte>>(nullptr), nullptr, 0, std::shared_ptr<std::vector<byte>>(nullptr)));
			if (error)
				throw std::runtime_error("soaccept failed with error" + std::to_string(error));
		}
	}

	void L5_socket_impl::sorflush() 
	{
		/*
		*	The process waits for a lock on the receive buffer. Because of SB_NOINTR, sblock
		*	does not return when an interrupt occurs. splimp blocks network interrupts and
		*	protocol processing while the socket is modified, since the receive buffer may be
		*	accessed by the protocol layer as it processes incoming packets.
		*/
		so_rcv.sb_flags |= sockbuf::SB_NOINTR;

		/*
		*	socantrcvmore marks the socket to reject incoming packets. A copy of the
		*	sockbuf structure is saved in asb to be used after interrupts are restored by splx.
		*	The original sockbuf structure is cleared by bzero, so that the receive queue appears
		*	to be empty.
		*/
		socantrcvmore();

		so_rcv.sbreserve(0);

	}

	void L5_socket_impl::soclose()
{		
	std::lock_guard<std::mutex> guard(inet._splnet);
	/*	
	 *	Discard pending connections
	 *	If the socket was accepting connections, soclose traverses the two connection
	 *	queues and calls soabort for each pending connection. U the protocol control block is
	 *	null, the protocol has already been detached from the socket and soclose jumps to the
	 *	cleanup code at discard.
	 *	soabort issues the PRU_ABORT request to the socket's protocol and returns the result.
	 *	soabort is not shown in this text. Figures 23.38 and 30.7 discuss how UDP and TCP handle
	 *	this request.
	 */
	if (so_options & SO_ACCEPTCONN) {
		while (so_q0)
			(void)dynamic_cast<L5_socket_impl*>(so_q0)->soabort();
		while (so_q)
			(void)dynamic_cast<L5_socket_impl*>(so_q)->soabort();
	}

	if (so_pcb) {
		if (so_state & SS_ISCONNECTED) {
			bool drop(false);
			if ((so_state & SS_ISDISCONNECTING) == 0) {
				try
				{
					sodisconnect();
				}
				catch (const std::runtime_error &e)
				{
					std::cout << e.what() << std::endl;
					drop = true;
				}
			}
			if (!drop)
				if (so_options & SO_LINGER) 
					if (!((so_state & SS_ISDISCONNECTING) && (so_state & SS_NBIO)))
						while (so_state & SS_ISCONNECTED)
							int i(0);			
		}

		if (so_pcb) {
			int error(so_proto->pr_usrreq(this, protosw::PRU_DETACH, std::shared_ptr<std::vector<byte>>(nullptr), nullptr, 0, std::shared_ptr<std::vector<byte>>(nullptr)));
			if (error)
				throw std::runtime_error("soclose failed with error" + std::to_string(error));
		}
	}

	if (so_state & SS_NOFDREF)
		throw std::runtime_error("soclose panic(''soclose: NOFDREF'')");
	
	so_state |= SS_NOFDREF;
	
	try
	{
		sofree();
	}
	catch (const std::runtime_error &e)
	{
		std::cout << e.what() << std::endl;
	}
}

	void L5_socket_impl::sodisconnect() 
	{
		if ((so_state & SS_ISCONNECTED) == 0)
			throw std::runtime_error("accept failed with error ENOTCONN = " + std::to_string(ENOTCONN));
		if (so_state & SS_ISDISCONNECTING) 
			throw std::runtime_error("accept failed with error EALREADY = " + std::to_string(EALREADY));
		
		int error(so_proto->pr_usrreq(this, protosw::PRU_DISCONNECT, std::shared_ptr<std::vector<byte>>(nullptr), nullptr, 0, std::shared_ptr<std::vector<byte>>(nullptr)));
		if (error)
			throw std::runtime_error("soaccept failed with error" + std::to_string(error));
	}

	void L5_socket_impl::sofree() 
	{
		if (so_pcb || (so_state & SS_NOFDREF) == 0)
			return;
		if (so_head) {
			if (!soqremque(0) && !soqremque(1))
				throw std::runtime_error("sofree dq");
			so_head = nullptr;
		}
		sorflush();
	}

	int L5_socket_impl::soqremque(const int q) 
	{
		L5_socket_impl *head(dynamic_cast<L5_socket_impl*>(so_head)),
			*prev,
			*next(nullptr);
		if (prev = head) {
			for (;;) {
				if ((next = dynamic_cast<L5_socket_impl*>(q ? prev->so_q : prev->so_q0)) == this)
					break;
				if (next == nullptr)
					return 0;
				prev = next;
			}
			if (q == 0) {
				prev->so_q0 = next->so_q0;
				head->so_q0len--;
			}
			else {
				prev->so_q = next->so_q;
				head->so_qlen--;
			}
		}
		if (next) {
			next->so_q0 = next->so_q = nullptr;
			next->so_head = nullptr;
			return 1;
		}
		return 0;
	}

	void L5_socket_impl::soqinsque(L5_socket_impl &head, const int q) 
	{
		L5_socket **prev;
		so_head = &head;
		if (q == 0) {
			head.so_q0len++;
			so_q0 = 0;
			for (prev = &(head.so_q0); *prev;)
				prev = &((*prev)->so_q0);
		}
		else {
			head.so_qlen++;
			so_q = 0;
			for (prev = &(head.so_q); *prev;)
				prev = &((*prev)->so_q);
		}
		*prev = this;
	}

	inline bool L5_socket_impl::sosendallatonce() const { return so_proto->pr_flags() & protosw::PR_ATOMIC; }

	void L5_socket_impl::sowakeup(const bool sosnd) 
	{
		struct sockbuf &sb = sosnd ? so_snd : so_rcv;
		sb.sb_sel.selwakeup();
		sb.sb_flags &= ~sockbuf::SB_SEL;
		sb.notify_all();
	}



































}






#include "pcb.h"
#include "NIC.h"
#include "L3.h"
#include <Shlobj.h>

const struct in_addr zeroin_addr;

inline class NIC* ifatoia(class inet_os *ifa) { return ifa->nic(); }

inpcb_impl::inpcb_impl(socket &so, inpcb_impl &head) : inpcb(so, head) { }

inpcb_impl::inpcb_impl(inet_os &inet) : inpcb(inet, new socket(inet)) { }
	
void inpcb_impl::in_pcbdisconnect()
{
	inp_faddr().s_addr = INADDR_ANY;
	inp_fport() = 0;

	if (inp_socket->so_state & socket::SS_NOFDREF)
		delete this;
}

int inpcb_impl::in_pcbbind(struct sockaddr_in *nam, const size_t nam_len)
{	
	/*
	*	The first two tests verify that at least one interface has been assigned an IP address
	*	and that the socket is not already bound. You can't bind a socket twice.
	*/
	if (&inp_socket->inet == nullptr)
		return EADDRNOTAVAIL;
	else if (inp_lport() || inp_laddr().s_addr != INADDR_ANY)
		return EINVAL;

	/*
	*	This if statement is confusing. The net result sets the variable wild to
	*	INPLOOKUP_WILDCARD if neither SO_REUSEADDR or so_REUSEPORT are set.
	*		The second test is true for UDP sockets since PR_CONNREQUIRED is false for connectionless
	*	sockets and true for connection-oriented sockets.
	*		The third test is where the confusion lies [Torek 1992]. The socket flag
	*	SO_ACCEPTCONN is set only by the listen system call (Section 15.9), which is valid
	*	only for a connection-oriented server. In the normal scenario, a TCP server calls
	*	socket, bind, and then listen. Therefore, when in_pcbbind is called by bind, this
	*	socket flag is cleared. Even if the process calls socket and then listen, without calling
	*	bind, TCP's PRU_LISTEN request calls in_pcbbind to assign an ephemeral port
	*	to the socket "'-fore the socket layer sets the SO_ACCEPTCONN flag. This means the third
	*	test in the if statement, testing whether SO_ACCEPTCONN is not set, is always true. The
	*	if statement is therefore equivalent to
	*		if	((so->so_options & (SO_REUSEADDR | SO_REUSEPORT)) == 0 &&
	*			((so->so_proto->pr_flags & PR_CONNREQUIRED) == 0 || 1)
	*				wild = INPLOOKUP_WILDCARD:
	*	Since anything logically ORed with 1 is always true, this is equivalent to
	*		if ((so->so_options & (SO_REUSEADDR | SO_REUSEPORT)) == 0)
	*			wild = INPLOOKUP_WILDCARD;
	*	which is simpler to understand: if either of the REUSE socket options is set, wild is left
	*	as 0. If neither of the REUSE socket options are set, wild is set to
	*	INPLOOKUP_WILDCARD. In other words, when in_pcblookup is called later in the
	*	function, a wildcard match is allowed only if 11eitl1er of the REUSE socket options are on.
	*/
	int wild(0);
	if ((inp_socket->so_options & (SO_REUSEADDR | socket::SO_REUSEPORT)) == 0 &&
		((inp_socket->so_proto->pr_flags() & protosw::PR_CONNREQUIRED) == 0 ||
		(inp_socket->so_options & SO_ACCEPTCONN) == 0))
		wild = INPLOOKUP_WILDCARD;

	/*
	*	The nam argument is a nonnull pointer only when the process calls bind explicitly.
	*	For an implicit bind (a side effect of connect, 1 i st en, or in_pcbconnect, cases 3, 4,
	*	and 5 from the beginning of this section), nam is a null pointer. When the argument is
	*	specified, it is an mbuf containing a sockaddr_in structure. Figure 22.21 shows the
	*	four cases for the nonnull nam argument.
	*/
	u_short lport(0);
	if (nam) {
		if (nam_len != sizeof(*nam))
			return EINVAL;

		/*
		* We should check the family, but old programs
		* incorrectly fail to initialize it.
		*/
		else if (nam->sin_family != AF_INET)
			return EAFNOSUPPORT;
		
		lport = nam->sin_port;

		/*
		*	Net/3 tests whether the IP address being bound is a multicast group. If so, the
		*	SO_REUSEADDR option is considered identical to SO_REUSEPORT.
		*/
		int reuseport(inp_socket->so_options & socket::SO_REUSEPORT);
		if (IN_MULTICAST(ntohl(nam->sin_addr.s_addr))) {

			/*
			* Treat SO_REUSEADDR as SO_REUSEPORT for multicast;
			* allow complete duplication of binding if
			* SO_REUSEPORT is set, or if SO_REUSEADDR is set
			* and a multicast address is bound on both
			* new and duplicated sockets.
			*/
			if (inp_socket->so_options & SO_REUSEADDR)
				reuseport = SO_REUSEADDR | socket::SO_REUSEPORT;
		}

		/*
		*	Otherwise, if the local address being bound by the caller is not the wildcard,
		*	ifa_ifwithaddr verifies that the address corresponds to a local interface.
		*		Remark:	The comment "yech" is probably because the port number in the socket address structure
		*				must be 0 because ifa_ifwithaddr does a binary comparison of the entire structure, not just
		*				a comparison of the IP addresses.
		*
		*				This ls one of the few instances where the process must zero the socket address structure before
		*				issuing the system call U bind is called and the final 8 bytes of the socket address structure
		*				(sin_zero[8]) are nonzero, ifa_ifwithaddr will not find the requested interface, and
		*				in_pcbbind will return an error.
		*/
		else if (nam->sin_addr.s_addr != INADDR_ANY)
			nam->sin_port = 0;		/* yech... */

		/*
		*	The next if statement is executed when the caller is binding a nonzero port, that is,
		*	the process wants to bind one particular port number (the second and fourth scenarios
		*	from Figure 22.21). If the requested port is less than 1024 (IPPORT_RESERVED) the process
		*	must have superuser privilege. This is not part of the Internet protocols, but a
		*	Berkeley convention. A port number less than 1024 is called a reserved port and is used,
		*	for example, by the rcmd function [Stevens 1990], which in turn is used by the rlogin
		*	and rsh client programs as part of their authentication with their servers.
		*/
		if (lport) {

			/* GROSS */
			if (ntohs(lport) < IPPORT_RESERVED && !IsUserAnAdmin())
				return EACCES;

			/*
			*	The function in_pcblookup (Figure 22.16) is then called to check whether a PCB
			*	already exists with the same local IP address and local port number. The second argument
			*	is the wildcard IP address (the foreign IP address) and the third argument is a port
			*	number of 0 (the foreign port). The wildcard value for the second argument causes
			*	in_pcblookup to ignore the foreign IP address and foreign port in the PCB-only the
			*	local IP address and local port are compared to sin->sin_addr and lport, respectively.
			*	We mentioned earlier that wild is set to INPLOOKUP WILDCARD only if neither
			*	of the REUSE socket options are set.
			*/
			class inpcb_impl *t(dynamic_cast<class inpcb_impl *>(inp_head)->in_pcblookup(zeroin_addr, 0, nam->sin_addr, lport, wild));
			if (t && (reuseport & t->inp_socket->so_options) == 0)
				return EADDRINUSE;
		}
		inp_laddr() = nam->sin_addr;
	}

	if (lport == 0)
		if (IsUserAnAdmin())
		{
			do {
				if (inp_head->inp_lport()++ < IPPORT_RESERVED || inp_head->inp_lport() > IPPORT_USERRESERVED)
					inp_head->inp_lport() = IPPORT_RESERVED;
				lport = htons(inp_head->inp_lport());
			} while (inp_head->in_pcblookup(zeroin_addr, 0, inp_laddr(), lport, wild));
		}
		else
		{
			do {
				if (inp_head->inp_lport()++ < IPPORT_USERRESERVED)
					inp_head->inp_lport() = IPPORT_USERRESERVED;
				lport = htons(inp_head->inp_lport());
			} while (inp_head->in_pcblookup(zeroin_addr, 0, inp_laddr(), lport, wild));
		}
	
	inp_lport() = lport;
	return (0);
}

int inpcb_impl::in_pcbconnect(struct sockaddr_in *nam, const size_t nam_len) 
{
	/*
	*	Validate argument:
	*	The nam argument points to an mbuf containing a sockaddr_in structure with the
	*	foreign IP address and port number. These lines validate the argument and verify that
	*	the caller is not trying to connect to a port number of 0.
	*/
	if (nam == nullptr)
		return (EINVAL);

	else if (nam->sin_family != AF_INET)
		return (EAFNOSUPPORT);
	
	else if (nam->sin_port == 0)
		return (EADDRNOTAVAIL);

	/*
	*	Handle connection to 0.0.0.0 and 255.255.255.255 specially
	*	The test of the global in_ifaddr verifies that an IP interface has been configured.
	*	If the foreign IP address is 0.0.0.0 (INADDR_ANY), then 0.0.0.0 is replaced with the IP
	*	address of the primary IP interface. This means the calling process is connecting to a
	*	peer on this host. If the foreign IP address is 255.255.255.255 (INADDR_BROADCAST)
	*	and the primary interface supports broadcasting, then 255.255.255.255 is replaced with
	*	the broadcast address of the primary interface. This allows a UDP application to broadcast
	*	on the primary interface without having to figure out its W address-it can simply
	*	send datagrams to 255.255.255.255, and the kernel converts this to the appropriate IP
	*	address for the interface.
	*/
	if (&inp_socket->inet)
		/*
		* If the destination address is INADDR_ANY,
		* use the primary local address.
		* If the supplied address is INADDR_BROADCAST,
		* and the primary interface supports broadcast,
		* choose the broadcast address for that interface.
		*/
		if (nam->sin_addr.s_addr == INADDR_ANY)
			nam->sin_addr.s_addr = inp_socket->inet.nic()->ip_addr().s_addr;		
		else if (nam->sin_addr.s_addr == static_cast<u_long>(INADDR_BROADCAST) && (inp_socket->inet.nic()->ifa_flags() & IFF_BROADCAST))
			nam->sin_addr.s_addr = inp_socket->inet.nic()->bcast_addr().s_addr;
	
	struct sockaddr_in ifaddr = struct sockaddr_in();
	
	if (inp_laddr().s_addr == INADDR_ANY) {
		/*
		* If route is known or can be allocated now,
		* our src addr is taken from the i/f, else punt.
		*/
		struct L3::route *ro(&inp_route);
		if (ro->ro_rt && (satosin(&ro->ro_dst)->sin_addr.s_addr != nam->sin_addr.s_addr || inp_socket->so_options & SO_DONTROUTE)) {
			delete ro->ro_rt;
			ro->ro_rt = nullptr;
		}

		if ((inp_socket->so_options & SO_DONTROUTE) == 0 && /*XXX*/
			(ro->ro_rt == nullptr || ro->ro_rt->rt_ifp == nullptr)) {
			/* No route yet, so try to acquire one */
			ro = new struct L3::route(&inp_socket->inet);
			ro->ro_rt->rt_ifp = &inp_socket->inet;
			ro->ro_dst.sa_family = AF_INET;
			reinterpret_cast<struct sockaddr_in *>(&ro->ro_dst)->sin_addr = nam->sin_addr;
		}

		/*
		* If we found a route, use the address
		* corresponding to the outgoing interface
		* unless it is the loopback (in case a route
		* to our address on another net goes to loopback).
		*/
		NIC *ia(nullptr);
		
		if (ro->ro_rt && !(ro->ro_rt->rt_ifp->nic()->ifa_flags() & IFF_LOOPBACK))
			ia = ifatoia(ro->ro_rt->rt_ifp);

		/*
		* If the destination address is multicast and an outgoing
		* interface has been set as a multicast option, use the
		* address of that interface as our source address.
		*/
		if (IN_MULTICAST(ntohl(nam->sin_addr.s_addr)) &&
			inp_moptions != nullptr && 
			inp_moptions->imo_multicast_ifp != nullptr) 
				return 0;

		ifaddr.sin_addr = 
			ia ? 
			ia->ip_addr() :
			IN_ADDR();
	}
	
	if (inp_head->in_pcblookup(nam->sin_addr, nam->sin_port, inp_laddr().s_addr ? inp_laddr() : ifaddr.sin_addr, inp_lport(), 0))
		return (EADDRINUSE);
	
	else if (inp_laddr().s_addr == INADDR_ANY) {
		if (inp_lport() == 0)
			(void)in_pcbbind(nullptr, 0);
		inp_laddr() = ifaddr.sin_addr;
	}

	inp_faddr() = nam->sin_addr;
	inp_fport() = nam->sin_port;
	return 0;
}

void inpcb_impl::in_setpeeraddr(struct sockaddr_in *nam, size_t &nam_len) const
{
	if (nam) {
		nam_len = sizeof(*nam);
		memset(nam, 0, nam_len);
		nam->sin_family = AF_INET;
		nam->sin_port = inp_fport();
		nam->sin_addr = inp_faddr();
	}
	else
		nam_len = 0;
}

class inpcb_impl* inpcb_impl::in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags) const {
	class inpcb_impl *match(nullptr);
	int matchwild(3),
		wildcard;
	u_short fport(fport_arg),
		lport(lport_arg);

	for (class inpcb_impl *inp = dynamic_cast<class inpcb_impl*>(this->inp_next); inp != this; inp = dynamic_cast<class inpcb_impl*>(inp->inp_next)) {
		/*
		* Compare local port number:
		* The first comparison is the local port number. If the PCB's local port doesn't match
		* the lport argument, the PCB is ignored.
		*/
		if (inp->inp_lport() != lport)
			continue;
	
		wildcard = 0;

		/*
		*	Compare local address:
		*	in_pcblookup compares the local address in the PCB with the laddr argument.
		*	If one is a wildcard and the other is not a wildcard,
		*		the wildcard counter is incremented.
		*	If both are not wildcards,
		*		then they must be the same, or this PCB is ignored.
		*	If both are wildcards, nothing changes:
		*		they can't be compared and the wildcard counter isn't incremented.
		*
		*	Figure 22.17 summarizes the four different conditions.
		*		PCB local IP	laddr argument		Description
		*			not *			*				wildcard++
		*			not *			not *			compare IP addresses, skip PCB if not equal
		*			*				*				can't compare
		*			*				not *			wildcard++
		*		Figure 22.17 Four scenarios for the local IP address comparison done by in_pcblookup.
		*/
		if (inp->inp_laddr().s_addr != INADDR_ANY) {
			if (laddr.s_addr == INADDR_ANY)
				wildcard++;
			else if (inp->inp_laddr().s_addr != laddr.s_addr)
				continue;
		}
		else if (laddr.s_addr != INADDR_ANY)
			wildcard++;

		/*
		*	Compare foreign address and foreign port number:
		*	These lines perform the same test that we just described, but using the foreign
		*	addresses instead of the local addresses. Also, if both foreign addresses are not wildcards
		*	then not only must the two IP addresses be equal, but the two foreign ports must
		*	also be equal.
		*	Figure 22.18 summarizes the foreign IP comparisons.
		*		PCB foreign IP		faddr argument		Description
		*			not	*				*				wildcard++
		*			not *				not *			compnre IP addresses and ports, skip PCB if not equal
		*			*					*				can't compare
		*			*					not	*			wildcard++
		*		Figure 22.18 Four scenarios for the foreign IP address comparison done by in_peblookup.
		*	The additional comparison of the foreign port numbers can be performed for the
		*	second line of Figure 22.18 because it is not possible to have a PCB with a nonwildcard
		*	foreign address and a foreign port number of 0. This restriction is enforced by
		*	connect, which we'll see shortly requires a nonwildcard foreign IP address and a
		*	nonzero foreign port. It is possible, however, and common, to have a wildcard local
		*	address with a nonzero local port. We saw this in Figures 22.10 and 22.13.
		*/
		if (inp->inp_faddr().s_addr != INADDR_ANY) {
			if (faddr.s_addr == INADDR_ANY)
				wildcard++;
			else if (inp->inp_faddr().s_addr != faddr.s_addr || inp->inp_fport() != fport)
				continue;
		}
		else if (faddr.s_addr != INADDR_ANY)
			wildcard++;

		/*
		*	Check If wildcard match allowed:
		*	The flags argument can be set to INPLOOKUP WILOCARD, which means a match
		*	containing wildcards is OK. If a match is found containing wildcards (wildcard is
		*	nonzero) and this flag was not specified by the caller, this PCB is ignored. When TCP
		*	and UDP call this function to demultiplex an incoming datagram,
		*	INPLOOKUP_WILDCARD is always set, since a wildcard match is OK. (Recall our examples
		*	using Figures 22.10 and 22.13.) But when this function is called as part of the
		*	connect system call, in order to verify that a socket pair is not already in use, the
		*	flags argument is set to 0.
		*/
		if (wildcard && (flags & INPLOOKUP_WILDCARD) == 0)
			continue;

		/*
		*	Remember best match, return if exact match found:
		*	These statements remember the best match found so far. Again, the best match is
		*	considered the one with the fewest number of wildcard matches. If a match is found
		*	with one or two wildcards, that match is remembered and the loop continues. But if an
		*	exact match is found (wildcard is 0), the loop terminates, and a pointer to the PCB
		*	with that exact match is returned.
		*/
		if (wildcard < matchwild) {
			match = inp;
			if ((matchwild = wildcard) == 0)
				break;
		}
	}
	return (match);
}

void inpcb_impl::in_losing() 
{
	struct L3::rtentry *rt(inp_route.ro_rt);
	if (rt) {
		inp_route.ro_rt = nullptr;
		struct L3_impl::rt_addrinfo info;
		memset(&info, 0, sizeof(info));
		info.rti_info[L3_impl::rt_addrinfo::RTAX_DST] = reinterpret_cast<struct sockaddr *>(&inp_route.ro_dst);
		info.rti_info[L3_impl::rt_addrinfo::RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[L3_impl::rt_addrinfo::RTAX_NETMASK] = rt->rt_mask();
		/*	
		 *	A new route can be allocated the next time output is attempted.
		 */
		delete rt;
	}
}



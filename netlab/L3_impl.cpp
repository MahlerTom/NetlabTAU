/*!
    \file	L3_impl.cpp

	\author	Tom Mahler, contact at tommahler@gmail.com

    \brief	Implements the L3 class.
*/

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "L3.h"

#include <iomanip>

#include "L2.h"
#include "NIC.h"

/************************************************************************/
/*                         ip_output_args                               */
/************************************************************************/

L3_impl::ip_output_args::ip_output_args(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it,
	std::shared_ptr<std::vector<byte>> &opt, struct L3::route *ro, int flags, struct  L3::ip_moptions *imo)
	: m(m), it(it), opt(opt), ro(ro), flags(flags), imo(imo) { }

/************************************************************************/
/*                         rt_metrics	                                */
/************************************************************************/

L3_impl::rt_metrics::rt_metrics()
	: rmx_locks(0), rmx_mtu(0), rmx_hopcount(0), rmx_expire(0),
	rmx_recvpipe(0), rmx_sendpipe(0), rmx_ssthresh(0), rmx_rtt(0),
	rmx_rttvar(0), rmx_pksent(0) { }

/************************************************************************/
/*                         radix_node	                                */
/************************************************************************/

L3_impl::radix_node::radix_node()
	: rn_mklist(nullptr), rn_p(nullptr), rn_b(0), rn_bmask(0), rn_flags(0)
{
	rn_u.rn_leaf.rn_Dupedkey = nullptr;
	rn_u.rn_leaf.rn_Key = nullptr;
	rn_u.rn_leaf.rn_Mask = nullptr;
	rn_u.rn_node.rn_L = nullptr;
	rn_u.rn_node.rn_R = nullptr;
	rn_u.rn_node.rn_Off = 0;
}

/************************************************************************/
/*                         L3::rtentry	                                */
/************************************************************************/

L3::rtentry::rtentry(struct sockaddr *dst, int report, inet_os *inet)
	: rt_gateway(nullptr), rt_flags(0), rt_refcnt(0), rt_use(0), rt_ifp(inet), rt_genmask(nullptr), rt_llinfo(nullptr), rt_gwroute(nullptr)
{
#ifdef NETLAB_L3_FORWARDING
	struct rtentry *rt;
	struct rtentry *newrt = nullptr;
	struct rt_addrinfo info;
	inet_t::splnet();
	int err = 0, msgtype = RTM_MISS;
	struct radix_node *rn;
	struct radix_node_head *rnh = rt_tables[dst->sa_family];
	if (rnh && (rn = rnh->rnh_matchaddr((caddr_t)dst, rnh)) && ((rn->rn_flags & RNF_ROOT) == 0)) {
		newrt = rt = (struct rtentry *)rn;
		if (report && (rt->rt_flags & RTF_CLONING)) {
			err = rtrequest(RTM_RESOLVE, dst, SA(0), SA(0), 0, &newrt);
			if (err) {
				newrt = rt;
				rt->rt_refcnt++;
				goto miss;
			}
			if ((rt = newrt) && (rt->rt_flags & RTF_XRESOLVE)) {
				msgtype = RTM_RESOLVE;
				goto miss;
			}
		}
		else
			rt->rt_refcnt++;
	}
	else {
	miss:
		if (report) {
			/*bzero((caddr_t)&info, sizeof(info));*/
			info.rti_info[rt_addrinfo::RTAX_DST] = dst;
			info.rt_missmsg(msgtype, 0, err);
		}
	}
	inet_t::splx();
	return (newrt);
#endif
}

L3::rtentry::~rtentry()
{
	/*register struct ifaddr *ifa;*/
	rt_refcnt--;
	if (rt_refcnt <= 0 && (rt_flags & RTF_UP) == 0)
		if (rt_nodes->rn_flags & (L3_impl::radix_node::RNF_ACTIVE | L3_impl::radix_node::RNF_ROOT))
			//Throw std::runtime_error("rtfree 2");  // remove
		//else if (rt_refcnt < 0)
			return;
	
}

void L3::rtentry::RTFREE() 
{
	if (rt_refcnt <= 1)
		delete this;
	else
		rt_refcnt--;
}

/************************************************************************/
/*                         L3::route	                                */
/************************************************************************/

L3::route::route(inet_os *inet) { ro_rt = new L3::rtentry(&ro_dst, 1, inet); }

void L3::route::rtalloc(inet_os *inet) 
{
	if (ro_rt && ro_rt->rt_ifp && (ro_rt->rt_flags & L3::rtentry::RTF_UP))
		return;				 /* XXX */
	ro_rt = new L3::rtentry(&ro_dst, 1, inet);
}

/************************************************************************/
/*                         L3::iphdr		                            */
/************************************************************************/

std::ostream& operator<<(std::ostream &out, const L3::iphdr &ip) 
{
	std::ios::fmtflags f(out.flags());
	out << "< IP (" << static_cast<uint32_t>(ip.ip_hl() << 2) <<
		" bytes) :: Version = 0x" << std::hex << static_cast<USHORT>(ip.ip_v()) <<
		" , HeaderLength = 0x" << static_cast<USHORT>(ip.ip_hl()) <<
		" , DiffServicesCP = 0x" << std::setfill('0') << std::setw(2) << ((static_cast<uint8_t>(ip.ip_tos) >> 2) << 2) <<
		" , ExpCongestionNot = 0x" << (static_cast<uint8_t>(ip.ip_tos) << 6) <<
		" , TotalLength = " << std::dec << static_cast<uint16_t>(ip.ip_len) <<
		" , Identification = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<uint16_t>(ip.ip_id) <<
		" , FragmentOffset = " << std::dec << static_cast<uint16_t>(ip.ip_off) <<
		" , TTL = " << static_cast<uint16_t>(ip.ip_ttl) <<
		" , Protocol = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint16_t>(ip.ip_p) <<
		" , Checksum = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<uint16_t>(ip.ip_sum) <<
		" , SourceIP = " << inet_ntoa(ip.ip_src);
	out << " , DestinationIP = " << inet_ntoa(ip.ip_dst) <<
		" , >";
	out.flags(f);
	return out;
}

const u_char L3::iphdr::ip_v() const { return ip_v_hl.hb; }
const u_char L3::iphdr::ip_hl() const { return ip_v_hl.lb; }
void L3::iphdr::ip_v(const u_char& ip_v) { ip_v_hl.hb = ip_v; }
void L3::iphdr::ip_hl(const u_char& ip_hl) { ip_v_hl.lb = ip_hl; }

/************************************************************************/
/*                         L3_impl				                        */
/************************************************************************/

L3_impl::L3_impl(class inet_os &inet, const short &pr_type, const short &pr_protocol, const short &pr_flags)
	: L3(inet, pr_type, pr_protocol, pr_flags) { }

void L3_impl::pr_init() { ip_init(); }

int L3_impl::pr_output(const struct pr_output_args &args) { return ip_output(*reinterpret_cast<const struct ip_output_args*>(&args)); };		

void L3_impl::ip_insertoptions(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, std::shared_ptr<std::vector<byte>> &opt, int &phlen) 
{
	struct iphdr *ip(reinterpret_cast<struct iphdr *>(&m->data()[it - m->begin()]));
	struct ipoption *p(reinterpret_cast<struct ipoption *>(&opt->data()[0]));
	unsigned optlen(opt->size() - sizeof(p->ipopt_dst));
	if (optlen + static_cast<u_short>(ip->ip_len) > IP_MAXPACKET)
		/*!
			\bug \code optlen + static_cast<u_short>(ip->ip_len) > IP_MAXPACKET  \endcode should fail
		*/
		return;
	if (p->ipopt_dst.s_addr)
		ip->ip_dst = p->ipopt_dst;

	m->resize(m->size() + optlen);
	std::move_backward(it += sizeof(struct iphdr *), m->end(), m->end());
	std::copy(p->ipopt_list, p->ipopt_list + optlen, it);
	phlen = sizeof(struct iphdr) + optlen;
	ip->ip_len += optlen;
	return;
}

void L3_impl::ip_stripoptions(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it) 
{
	struct L3::iphdr *ip(reinterpret_cast<struct L3::iphdr *>(&m->data()[it - m->begin()]));
	int olen((ip->ip_hl() << 2) - sizeof(struct L3::iphdr));
	std::move(it + olen, m->end(), it);
	m->resize(m->size() - olen);
	ip->ip_hl(sizeof(struct L3::iphdr) >> 2);
}

void L3_impl::pr_input(const struct pr_input_args &args) 
{
	std::shared_ptr<std::vector<byte>> &m(args.m);
	std::vector<byte>::iterator &it(args.it);

	/*
	*	Verification:
	*	We start with Figure 8.12: dequeuing packets from ipintrq and verifying their contents.
	*	Damaged or erroneous packets are silently discarded.
	*/
	if (m->end() - it < sizeof(struct iphdr))
		return;

	/*
	*	IP version
	*	Before pr_input accesses any IP header fields, it must verify that ip_v is 4
	*	(IPVERSION). RFC 1122 requires an implementation to silently discard packets with
	*	unrecognized version numbers.
	*		Remark:	Net/2 didn't check ip_v. Most IP implementations in use today, including Net/2, were created
	*				after IP version 4 was standardized and have never needed to distinguish between packets from
	*				different IP versioM. Since revisions to IP are now in progress, implementations in the near
	*				future will have to check ip_v.
	*
	*				IEN 119 [Forgie1979] and RFC 1190 (Topolcic 1990) describe experimental protocols using IP
	*				versions 5 and 6. Version 6 has also been selected as the version for the next revision to the
	*				official IP standard (IPv6). Versions 0 and 15 are reserved, and the remaining versions are unassigned.
	*/
	struct iphdr &ip(*reinterpret_cast<struct iphdr *>(&m->data()[it - m->begin()]));
	if (ip.ip_v() != IPVERSION)
		return;

	/*
	*	In C, the easiest way to process data located in an untyped area of memory is to
	*	overlay a structure on the area of memory and process the structure members instead of
	*	the raw bytes. As described in Chapter 2, an mbuf chain stores a logical sequence of
	*	bytes, such as an IP packet, into many physical mbufs connected to each other on a
	*	linked list. Before the overlay technique can be applied to the IP packet headers, the
	*	header must reside in a contiguous area of memory (i.e., it isn't split between two
	*	mbufs).
	*
	*	The following steps ensure that the IP header (including options) is in a contiguous
	*	area of memory:
	*		a.	If the data within the first mbuf is smaller than a standard IP header (20 bytes),
	*			m_pullup relocates the standard header into a contiguous area of memory.
	*			Remark:	It is improbable that the link layer would split even the largest (60 bytes) IP header into
	*					two mbufs necessitating the use of m_pullup as described.
	*		b.	ip_hl is multiplied by 4 to get the header length in bytes, which is saved in hlen.
	*		c.	If hlen, the length of the IP packet header in bytes, is less than the length of a
	*			standard header (20 bytes), it is invalid and the packet is discarded.
	*		d.	If the entire header is still not in the first mbuf (i.e., the packet contains IP
	options), m_pul 1 up finishes the job.
	Again, this should not be neces.sary.
	*/
	int hlen(ip.ip_hl() << 2);
	if (hlen < sizeof(struct iphdr)) 	/* minimum header length */
		return;

	/*
	*	Checksum processing is an important part of all the Internet protocols. Each protocol
	*	uses the same algorithm (implemented by the function in_cksum) but on different
	*	parts of the packet. For IP, the checksum protects only the IP header (and options if
	*	present). For transport protocols, such as UDP or TCP, the checksum covers the data
	*	portion of the packet and the transport header.
	*
	*	IP checksum:
	*	pr_input stores the checksum computed by in_cksum in the ip_sum field of the
	*	header. An undamaged header should have a checksum of 0.
	*	As we'll see in Section 8.7, ip_sum must be cleared before the checksum on an outgoing
	*	packet is computed. By storing the result from in_cksum in ip_sum the packet is prepared
	*	for forwarding (although the TIL has not been decremented yet). The ip_output function
	*	does not depend on this behavior; it recomputes the checksum for the forwarded packet.
	*/
	const uint16_t checksum(ip.ip_sum);
	if (((ip.ip_sum = 0) = checksum ^ in_cksum(&m->data()[it - m->begin()], hlen)) != 0)
		/*	If the result is nonzero the packet is silently discarded.*/
		return;

	/*
	*	Byte ordering:
	*	The Internet standards are careful to specify the byte ordering of multibyte integer
	*	values in protocol headers. NTOHS converts all the 16-bit values in the IP header from
	*	from network byte order to host byte order: the packet length (ip_len), the datagram
	*	identifier (ip_id), and the fragment offset (ip_of f). NTOHS is a null macro if the two
	*	formats are the same. Conversion to host byte order here obviates the need to perform
	*	a conversion every time Net/3 examines the fields.
	*
	* Convert fields to host representation.
	*/
	if ((ip.ip_len = htons(ip.ip_len)) < hlen)
		return;
	ip.ip_id = htons(ip.ip_id);
	ip.ip_off = htons(ip.ip_off);

#ifdef NETLAB_L3_DEBUG
	print(ip, htons(checksum));
#endif

	/*
	*	Packet length:
	*	If the logical size of the packet (ip_len) is greater than the amount of data stored
	*	in the mbuf chain (m_pkthdr. len), some bytes are missing and the packet is dropped.
	*	If the mbuf chain is larger than the packet, the extra bytes are trimmed.
	*		Remark: A common cause for lost bytes is data arriving on a serial device with little or no buffering.
	*				such as on many personal computers. The incoming bytes are discarded by the device and IP
	*				discards the resulting packet.
	*				These extra bytes may arise, for example, on an Ethernet device when an IP packet is smaller
	*				than the minimum size required by Ethernet. The frame is transmitted with extra bytes that
	*				are discarded here. This is one reason why the length of the IP packet is stored in the header;
	*				IP allows the link layer to pad packets.
	*
	* Check that the amount of data in the buffers
	* is as at least much as the IP header would have us expect.
	* Trim mbufs if longer than we expect.
	* Drop packet if shorter than we expect.
	*/
	short diff_size(static_cast<short>(m->end() - it) - ip.ip_len);
	if (diff_size < 0)
		return;
	else if (diff_size > 0)
		m->resize(m->size() - diff_size);

	/*
	*	At this point, the complete IP header is available, the logical size and the physical
	*	size of the packet are the same, and the checksum indicates that the header arrived
	*	undamaged.
	*
	*	To Forward or Not To Forward?
	*	The next section of pr_input, shown in Figure 8.13, calls ip_dooptions (Chapter 9) to
	*	process IP options and then determines whether or not the packet has reached its final
	*	destination. If it hasn't reached its final destination, Net/3 may attempt to forward the
	*	packet (if the system is configured as a router). If it has reached its final destination, it is
	*	passed to the appropriate transport-level protocol.
	*	Option processing
	*	The source route from the previous packet is discarded by clearing ip_nhops (Section
	*	9.6). If the packet header is larger than a default header, it must include options
	*	that are processed by ip_dooptions. If ip_dooptions returns 0, pr_input should
	*	continue processing the packet; otherwise ip_dooptions has completed processing of
	*	the packet by forwarding or discarding it, and pr_input can process the next packet on
	*	the input queue. We postpone further discussion of option processing until Chapter 9.
	*
	* Process options and, if not destined for us,
	* ship it on.  ip_dooptions returns 1 when an
	* error was detected (causing an icmp message
	* to be sent and the original packet to be freed).
	*/
	if (hlen > sizeof(struct iphdr) && ip_dooptions(m, it))
		return;

	/*
	*	Final destination?
	*	pr_input starts by traversing in_ifaddr (Figure 6.5), the list of configured Internet
	*	addresses, to see if there is a match with the destination address of the packet. A series
	*	of comparisons arc made for each in_ifaddr structure found in the list. There are
	*	four general cases to consider:
	*		a.	an exact match with one of the interface addresses (first row of Figure 8.14),
	*		b.	a match with the one of the broadcast addresses associated with the receiving
	*			interface (middle four rows of Figure 8.14),
	*		c.	a match with one of the multicast groups associated with the receiving interface
	*			(Figure 12.39), or
	*		d.	a match with one of the two limited broadcast addresses (last row of Figure	8.14).
	*
	*	Figure 8.14 illustrates the addresses that would be tested for a packet arriving on
	*	the Ethernet interface of the host sun in our sample network, excluding multicast
	*	addresses, which we discuss in Chapter 12.
	*
	* Check our list of addresses, to see if the packet is for us.
	*/
	else if (inet.nic()->ip_addr().s_addr == ip.ip_dst.s_addr)
		return ours(m, it, ip, hlen);
	else if ((inet.nic()->ifa_flags() & IFF_BROADCAST) && inet.nic()->bcast_addr().s_addr == ip.ip_dst.s_addr)
		return ours(m, it, ip, hlen);
	else if (IN_MULTICAST(ntohl(ip.ip_dst.s_addr))) {
#ifdef NETLAB_L3_MULTICAST
		struct in_multi *inm;
#ifdef MROUTING
		extern struct socket *ip_mrouter;

		if (ip_mrouter) {
			/*
			* If we are acting as a multicast router, all
			* incoming multicast packets are passed to the
			* kernel-level multicast forwarding function.
			* The packet is returned (relatively) intact; if
			* ip_mforward() returns a non-zero value, the packet
			* must be discarded, else it may be accepted below.
			*
			* (The IP ident field is put in the same byte order
			* as expected when ip_mforward() is called from
			* ip_output().)
			*/
			ip->ip_id = htons(ip->ip_id);
			if (ip_mforward(m, m->m_pkthdr.rcvif) != 0) {
				ipstat.ips_cantforward++;
				m_freem(m);
				goto next;
			}
			ip->ip_id = ntohs(ip->ip_id);

			/*
			* The process-level routing demon needs to receive
			* all multicast IGMP packets, whether or not this
			* host belongs to their destination groups.
			*/
			if (ip->ip_p == IPPROTO_IGMP)
				goto ours;
			ipstat.ips_forward++;
		}
#endif
		/*
		* See if we belong to the destination multicast group on the
		* arrival interface.
		*/
		IN_LOOKUP_MULTI(ip->ip_dst, m->m_pkthdr.rcvif, inm);
		if (inm == NULL) {
			ipstat.ips_cantforward++;
			m_freem(m);
			goto next;
		}
		goto ours;
#endif
	}
	else if (ip.ip_dst.s_addr == static_cast<u_long>(INADDR_BROADCAST))
		return ours(m, it, ip, hlen);
	else if (ip.ip_dst.s_addr == INADDR_ANY)
		return ours(m, it, ip, hlen);
	else
		
		/*	
		 *	Forwarding
		 *	If ip_dst does not match any of the addresses, the packet has not reached its final
		 *	destination. If ipforwarding is not set, the packet is discarded. Otherwise,
		 *	ip_forward attempts to route the packet toward its final destination.
		 *	A host ma}' discard packets thcit arrive on an interface other than the one specified by the destination
		 *	address of the packet. In this case, Net/3 would not search the entire in_i f addr list;
		 *	only addresses assigned to the receiving interface would be considered. Rf<: 1122 calls this a
		 *	slrong e1ul system model.
		 *	For a multihomed host, it is uncommon for a packet to arrh•e at an interface that does not correspond
		 *	to the packet's destination address, unless specific host routes have been configured.
		 *	The host routes force neighboring routers to consider the multihomed host as the next-hop
		 *	router for the packets. The wtak t11d systmr modcl requires that the host accept these packets.
		 *	An implementor is free to choose either model. Net/3 implements the weak end system
		 *	model.
		 *	
		* Not for us; forward if possible and desirable.
		*/
#ifdef NETLAB_L3_FORWARDING
		if (NETLAB_L3_FORWARDING == 0)
			return;
		else
			return ip_forward(m, it, 0);
#endif
	return;
}

void L3_impl::print(struct iphdr& ip, uint16_t checksum, std::ostream& str) 
{
	std::swap(checksum, ip.ip_sum);
	std::lock_guard<std::mutex> lock(inet.print_mutex);
	str << "[#] IP packet received!" << std::endl << ip << std::endl;
	std::swap(checksum, ip.ip_sum);
}

void L3_impl::ip_init() 
{
	/*
	*	pffindproto returns a pointer to the raw protocol (inetsw[3], Figure 7.14).
	*	Net/3 panics if the raw protocol cannot be located, since it is a required part of the kernel.
	*	If it is missing, the kernel has been mis configured. IP delivers packets that arrive
	*	for an unknown transport protocol to this protocol where they may be handled by a
	*	process outside the kernel.
	*/
	class protosw **pr = inet.pffindproto(AF_INET, IPPROTO_RAW, SOCK_RAW);
	if (pr == nullptr)
		throw std::runtime_error("ip_init");

	/*
	*	The next two loops initialize the ip_protox array. The first loop sets each entry in
	*	the array to pr, the index of the default protocol (3 from Figure 7.22). The second loop
	*	examines each protocol in inetsw (other than the entries with protocol numbers of 0 or
	*	IPPROTO_RAW) and sets the matching entry in ip_protox to refer to the appropriate
	*	inetsw entry. Therefore, pr_protocol in each protosw structure must be the protocol
	*	number expected. to appear in the incoming datagram.
	*/
	const u_char protocol((*pr)->to_swproto());
	for (int i(0); i < IPPROTO_MAX; i++)
		ip_protox[i] = protocol;
	for (pr = reinterpret_cast<class protosw **>(inet.inetdomain()->dom_protosw); pr < inet.inetdomain()->dom_protoswNPROTOSW; pr++)
		if ((*pr) && (*pr)->dom_family() == AF_INET && (*pr)->pr_protocol() && (*pr)->pr_protocol() != IPPROTO_RAW)
			ip_protox[(*pr)->pr_protocol()] = (*pr)->to_swproto();

	/*
	*	ip_init initializes the IP reassembly queue, ipq (Section 10.6), seeds ip_id from
	*	the system clock, and sets the maximum size of the IP input queue (ipintrq) to SO
	*	(ipqmaxlen). ip_id is set from the system clock to provide a random starting point
	*	for datagram identifiers (Section 10.6). Finally, ip_ini t allocates a two-dimensional
	*	array, ip_ifmatrix, to count packets routed between the interfaces in the system.
	*		Remark:	There are many variables within Net/3 that may be modified by a system administrator. To
	*				allow these variables to be changed at run time and without recompiling the kernel, the
	*				default value represented by a constant (IF(LMAXLEN in this case) is assigned to a variable
	*				ipqmaxlen) at compile time. A system administrator can use a kernel debugger such as adb
	*				to change ipqmaxlen and reboot the kernel with the new value. If Figure 7.23 used
	*				IFQ_MAXLEN directly, it would require a recompile of the kernel to change the limit.
	*/
	ipq_t.next = ipq_t.prev = &ipq_t;
	ip_id = static_cast<u_short>(GetTickCount64()) & 0xffff;
}

int L3_impl::ip_output(const struct ip_output_args &args) 
{
	/*	
	 *	Header initialization:
	 *	The first section of ip_output, shown in Figure 8.22, merges options into the outgoing
	 *	packet and completes the IP header for packets that are passed from the transport protocols
	 *	(not those from ip_forward).
	 *	
	 *	The arguments to ip_output are: mo, the packet to send; opt, the IP options to
	 *	include; ro, a cached route to the destination; flags, described in Figure 8.23; and imo,
	 *	a pointer to multicast options described in Chapter 12.
	 */
	int flags(args.flags),
		hlen(sizeof(struct iphdr));

	std::shared_ptr<std::vector<byte>> &m(args.m), &opt(args.opt);
	std::vector<byte>::iterator &it(args.it);

	/*	
	 *	Construct IP header
	 *	If the caller provides any IP options they are merged with the packet by
	 *	ip_insertoptions (Section 9.8), which returns the new header length.
	 *		We'll see in Section 8.8 that a process can set the IP_OPTIONS socket option to specify
	 *	the IP options for a socket. The transport layer for the socket (TCP or UDP) always
	 *	passes these options to ip_output.
	 *		The IP header of a forwarded packet (IP_FORWARDING) or a packet with a preconstructed
	 *	header (IP_RAWOUTPUT) should not be modified by ip_output. Any other
	 *	packet (e.g., a UDP or TCP packet that originates at this host) needs to have several IP
	 *	header fields initialized. ip_output sets ip_v to 4 (IPVERSION), clears ip_off
	 *	except for the DF bit, which is left as provided by the caller (Chapter 10), and assigns a
	 *	unique identifier to ip->ip_id from the global integer ip_id, which is immediately
	 *	incremented. Remember that ip_id was seeded from the system clock during protocol
	 *	initialization (Section 7.8). ip_hl is set to the header length measured in 32-bit words.
	 *		Most of the remaining fields in the IP header-length, offset, TIL, protocol, TOS,
	 *	and the destination address-have already been initialized by the transport protocol.
	 *	The source address may not be set, in which case it is selected after a route to the destination
	 *	has been located (Figure 8.25).
	 */
	if (opt) 
		ip_insertoptions(m, it, opt, hlen);

	struct iphdr *ip(reinterpret_cast<struct iphdr *>(&m->data()[it - m->begin()]));

	/*
	* Fill in IP header.
	*/
	if ((flags & (IP_FORWARDING | IP_RAWOUTPUT)) == 0) 
	{
		ip->ip_v(IPVERSION);
		ip->ip_off &= iphdr::IP_DF;
		ip->ip_id = htons(ip_id++);
		ip->ip_hl(hlen >> 2);
	}

	/*	
	 *	Packet already Includes header:
	 *	For a forwarded packet (or a raw IP packet with a header), the header length (in
	 *	bytes) is saved in hlen for use by the fragmentation algorithm.
	 */
	else 
		hlen = ip->ip_hl() << 2;

	/*	
	 *	Route Selection:
	 *	After completing the IP header, the next task for ip_output is to locate a route to the
	 *	destination.
	 *	
	 *	Verify cached route:
	 *	A cached route may be provided to ip_output as the ro argument. In Chapter 24
	 *	we'll see that UDP and TCP maintain a route cache associated with each socket. If a
	 *	route has not been provided, ip_output sets ro to point to the temporary route 
	 *	structure iproute.
	 *	
	* Route packet.
	*/
	struct route iproute(&inet),
		*ro(args.ro);;
	if (ro == nullptr) 
		memset(ro = &iproute, 0, sizeof(*ro));

	/*	
	 *	If the cached destination is not to the current packet's destination, the route is discarded
	 *	and the new destination address placed in dst.
	 */
	struct sockaddr_in *dst(reinterpret_cast<struct sockaddr_in *>(&ro->ro_dst));

	/*
	* If there is a cached route,
	* check that it is to the same destination
	* and is still up.  If not, free it and try again.
	*/
	if (ro->ro_rt && ((ro->ro_rt->rt_flags & L3::rtentry::RTF_UP) == 0 || dst->sin_addr.s_addr != ip->ip_dst.s_addr)) {
		ro->ro_rt->RTFREE();
		ro->ro_rt = nullptr;
	}

	if (ro->ro_rt == nullptr) {
		dst->sin_family = AF_INET;
		dst->sin_addr = ip->ip_dst;
	}
	inet_os *ifp(&inet);
	
	/*	
	 *	Bypass routing
	 *	A caller can prevent packet routing by setting the IP_ROUTETOIF flag (Section 8.8).
	 *	If this flag is set, ip_output must locate an interface directly connected to the destination
	 *	network specified in the packet. if a_ifwithdstaddr searches point-to-point
	 *	interfaces, while in_ifwithnet searches all the others. If neither function finds an
	 *	interface connected to the destination network, ENETUNREACH is returned; othenvise,
	 *	if p points to the selected interface.
	 *	This option allows routing protocols to bypass the local routing tables and force the packets to
	 *	exit the system by a particular interface. In this way, routing information can be exchanged
	 *	with other routers even when the local routing tables are incorrect.
	 *	
	* If routing to interface only,
	* short circuit routing lookup.
	*/
	if (flags & IP_ROUTETOIF)
		throw std::runtime_error("IP Routing is disabled!");

	/*	
	 *	Locate route
	 *	If the packet is being routed (IP_ROUTETOIF is off) and there is no cached route,
	 *	rtalloc locates a route to the address specified by dst. ip_output returns
	 *	EHOSTUNREACH if rtalloc fails to find a route. If ip_forward called ip_output,
	 *	EHOSTUNREACH is converted to an ICMP error. If a transport protocol called
	 *	ip_output, the error is passed back to the process (Figure 8.21).
	 */
	else {
		if (ro->ro_rt == nullptr)
			ro->rtalloc(&inet);
		if (ro->ro_rt == nullptr)
			done(ro, iproute, flags, EHOSTUNREACH);

		ifp = ro->ro_rt->rt_ifp;
		ro->ro_rt->rt_use++;
		if (ro->ro_rt->rt_flags & L3::rtentry::RTF_GATEWAY)
			dst = reinterpret_cast<struct sockaddr_in *>(ro->ro_rt->rt_gateway);
	}
	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
#ifndef NETLAB_L3_MULTICAST
		throw std::runtime_error("Multicast is not supported, discarding packet");
#else
		struct in_multi *inm;

		//m->m_flags |= M_MCAST;
		/*
		* IP destination address is multicast.  Make sure "dst"
		* still points to the address in "ro".  (It may have been
		* changed to point to a gateway address, above.)
		*/
		dst = reinterpret_cast<struct sockaddr_in *>(&ro->ro_dst);
		/*
		* See if the caller provided any multicast options
		*/
		if (imo != nullptr) {
			ip->ip_ttl = imo->imo_multicast_ttl;
			if (imo->imo_multicast_ifp != nullptr)
				ifp = imo->imo_multicast_ifp;
		}
		else
			ip->ip_ttl = IP_DEFAULT_MULTICAST_TTL;
		
		/*
		* Confirm that the outgoing interface supports multicast.
		*/
		if ((ifp->nic()->ifa_flags & NIC::IFF_MULTICAST) == 0)
			done(ro, iproute, flags, ENETUNREACH);

		/*
		* If source address not specified yet, use address
		* of outgoing interface.
		*/
		if (ip->ip_src.s_addr == INADDR_ANY)	
			ip->ip_src = ifp->nic()->ip_addr;

		//IN_LOOKUP_MULTI(ip->ip_dst, ifp, inm);
		if (inm != nullptr &&
			(imo == nullptr || imo->imo_multicast_loop)) {
			/*
			* If we belong to the destination multicast group
			* on the outgoing interface, and the caller did not
			* forbid loopback, loop back a copy.
			*/
			//ip_mloopback(ifp, m, dst);
		}
#ifdef MROUTING
		else {
			/*
			* If we are acting as a multicast router, perform
			* multicast forwarding as if the packet had just
			* arrived on the interface to which we are about
			* to send.  The multicast forwarding function
			* recursively calls this function, using the
			* IP_FORWARDING flag to prevent infinite recursion.
			*
			* Multicasts that are looped back by ip_mloopback(),
			* above, will be forwarded by the ip_input() routine,
			* if necessary.
			*/
			extern struct socket *ip_mrouter;
			if (ip_mrouter && (flags & IP_FORWARDING) == 0) {
				if (ip_mforward(m, ifp) != 0) {
					m_freem(m);
					goto done;
				}
			}
		}
#endif
		/*
		* Multicasts with a time-to-live of zero may be looped-
		* back, above, but must not be transmitted on a network.
		* Also, multicasts addressed to the loopback interface
		* are not sent -- the above call to ip_mloopback() will
		* loop back a copy if this host actually belongs to the
		* destination group on the loopback interface.
		*/
		if (ip->ip_ttl == 0 /*|| ifp == &loif*/)
			done(ro, iproute, flags, 0);

		//goto sendit;
#endif
	}

	/*
	* If source address not specified yet, use address
	* of outgoing interface.
	*/
	if (ip->ip_src.s_addr == INADDR_ANY)
		ip->ip_src = inet.nic()->ip_addr();
	
	short m_flags = 0;
	
	/*
	* Look for broadcast address and
	* and verify user is allowed to send
	* such a packet.
	*/
	if (dst->sin_addr.s_addr == ifp->nic()->bcast_addr().s_addr)
		if ((ifp->nic()->ifa_flags() & IFF_BROADCAST) == 0)
			return done(ro, iproute, flags, EADDRNOTAVAIL);
		else if ((flags & IP_ALLOWBROADCAST) == 0)
			return done(ro, iproute, flags, EACCES);
	/* don't allow broadcast messages to be fragmented */
		else if (static_cast<u_short>(ip->ip_len) > ifp->nic()->if_mtu())
			return done(ro, iproute, flags, EMSGSIZE);
		else
			m_flags |= L2_impl::M_BCAST;
	else
		m_flags &= ~L2_impl::M_BCAST;

	/*
	* If small enough for interface, can just send directly.
	*/
	if (static_cast<u_short>(ip->ip_len) <= inet.nic()->if_mtu()) 
	{
		ip->ip_len = htons(static_cast<u_short>(ip->ip_len));
		ip->ip_off = htons(static_cast<u_short>(ip->ip_off));
		(ip->ip_sum = 0) = inet.in_cksum(&m->data()[it - m->begin()], hlen);

		inet.datalink()->ether_output(m, it, reinterpret_cast<struct sockaddr *>(dst), ro->ro_rt);
		return done(ro, iproute, flags, 0);
	}

	/*
	* Too large for interface; fragment if possible.
	* Must be able to put at least 8 bytes per fragment.
	*/
	if (ip->ip_off & iphdr::IP_DF)
		return done(ro, iproute, flags, EMSGSIZE);
	
	int len((inet.nic()->if_mtu() - hlen) & ~7);
	if (len < 8)
		return done(ro, iproute, flags, EMSGSIZE);

#ifdef NETLAB_L3_FRAGMENTATION
	{
		int mhlen, firstlen = len;
		/*
		* Loop through length of segment after first fragment,
		* make new header and copy data of each part and link onto chain.
		*/
		m0 = m;
		mhlen = sizeof(struct iphdr);
		for (off = hlen + len; off < (u_short)ip->ip_len; off += len) {
			MGETHDR(m, M_DONTWAIT, MT_HEADER);
			if (m == 0) {
				error = ENOBUFS;
				goto sendorfree;
			}
			m->m_data += max_linkhdr;
			mhip = mtod(m, struct iphdr *);
			*mhip = *ip;
			if (hlen > sizeof(struct iphdr)) {
				mhlen = ip_optcopy(ip, mhip) + sizeof(struct iphdr);
				mhip->ip_hl = mhlen >> 2;
			}
			m->m_len = mhlen;
			mhip->ip_off = ((off - hlen) >> 3) + (ip->ip_off & ~IP_MF);
			if (ip->ip_off & IP_MF)
				mhip->ip_off |= IP_MF;
			if (off + len >= (u_short)ip->ip_len)
				len = (u_short)ip->ip_len - off;
			else
				mhip->ip_off |= IP_MF;
			mhip->ip_len = htons((u_short)(len + mhlen));
			m->m_next = m_copy(m0, off, len);
			if (m->m_next == 0) {
				(void)m_free(m);
				error = ENOBUFS;	/* ??? */
				ipstat.ips_odropped++;
				goto sendorfree;
			}
			m->m_pkthdr.len = mhlen + len;
			m->m_pkthdr.rcvif = (struct ifnet *)0;
			mhip->ip_off = htons((u_short)mhip->ip_off);
			mhip->ip_sum = 0;
			mhip->ip_sum = in_cksum(m, mhlen);
			*mnext = m;
			mnext = &m->m_nextpkt;
			ipstat.ips_ofragments++;
		}
		/*
		* Update first fragment by trimming what's been copied out
		* and updating header, then send each fragment (in order).
		*/
		m = m0;
		m_adj(m, hlen + firstlen - (u_short)ip->ip_len);
		m->m_pkthdr.len = hlen + firstlen;
		ip->ip_len = htons((u_short)m->m_pkthdr.len);
		ip->ip_off = htons((u_short)(ip->ip_off | IP_MF));
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum(m, hlen);
	sendorfree:
		for (m = m0; m; m = m0) {
			m0 = m->m_nextpkt;
			m->m_nextpkt = 0;
			if (error == 0)
				error = (*ifp->if_output)(ifp, m,
				(struct sockaddr *)dst, ro->ro_rt);
			else
				m_freem(m);
		}
		if (error == 0)
			ipstat.ips_fragmented++;
	}
#endif
	
	return done(ro, iproute, flags, 0);
}

int L3_impl::done(struct route *ro, struct route &iproute, const int &flags, const int error) 
{
	if (ro == &iproute && (flags & IP_ROUTETOIF) == 0 && ro->ro_rt)
		ro->ro_rt->RTFREE();
	return (error);
}

int L3_impl::ip_dooptions(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it) 
{
#ifndef NETLAB_L3_OPTIONS
	return 0;
#else
	struct ip_timestamp *ipt;
	struct in_ifaddr *ia;
	int off, code, type = ICMP_PARAMPROB, forward = 0;
	struct in_addr *sin;
	n_time ntime;

	struct iphdr &ip(*reinterpret_cast<struct iphdr *>(&m->data()[it - m->begin()]));
	struct in_addr dst(ip.ip_dst);
	u_char *cp = reinterpret_cast<u_char *>(&ip + 1);
	int cnt((ip.ip_hl() << 2) - sizeof(struct iphdr)), optlen, opt;
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		if ((opt = cp[IPOPT_OPTVAL]) == IPOPT_EOL) 
			break;
		if (opt == IPOPT_NOP) 
			optlen = 1;
		else if ((optlen = cp[IPOPT_OLEN]) <= 0 || optlen > cnt) {
			code = &cp[IPOPT_OLEN] - reinterpret_cast<u_char *>(&ip);
			goto bad;
		}
		
		switch (opt) {

		default:
			break;

			/*
			* Source routing with record.
			* Find interface with current destination address.
			* If none on this machine then drop if strictly routed,
			* or do nothing if loosely routed.
			* Record interface address and bring up next address
			* component.  If strictly routed make sure next
			* address is on directly accessible net.
			*/
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)&ip;
				goto bad;
			}
			ipaddr.sin_addr = ip.ip_dst;
			ia = (struct in_ifaddr *)
				ifa_ifwithaddr((struct sockaddr *)&ipaddr);
			if (ia == 0) {
				if (opt == IPOPT_SSRR) {
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_SRCFAIL;
					goto bad;
				}
				/*
				* Loose routing, and not at next destination
				* yet; nothing to do except forward.
				*/
				break;
			}
			off--;			/* 0 origin */
			if (off > optlen - sizeof(struct in_addr)) {
				/*
				* End of source route.  Should be for us.
				*/
				save_rte(cp, ip.ip_src);
				break;
			}
			/*
			* locate outgoing interface
			*/
			bcopy((caddr_t)(cp + off), (caddr_t)&ipaddr.sin_addr,
				sizeof(ipaddr.sin_addr));
			if (opt == IPOPT_SSRR) {
#define	INA	struct in_ifaddr *
#define	SA	struct sockaddr *
				if ((ia = (INA)ifa_ifwithdstaddr((SA)&ipaddr)) == 0)
					ia = (INA)ifa_ifwithnet((SA)&ipaddr);
			}
			else
				ia = ip_rtaddr(ipaddr.sin_addr);
			if (ia == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_SRCFAIL;
				goto bad;
			}
			ip->ip_dst = ipaddr.sin_addr;
			bcopy((caddr_t)&(IA_SIN(ia)->sin_addr),
				(caddr_t)(cp + off), sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			/*
			* Let ip_intr's mcast routing check handle mcast pkts
			*/
			forward = !IN_MULTICAST(ntohl(ip->ip_dst.s_addr));
			break;

		case IPOPT_RR:
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			/*
			* If no space remains, ignore.
			*/
			off--;			/* 0 origin */
			if (off > optlen - sizeof(struct in_addr))
				break;
			bcopy((caddr_t)(&ip->ip_dst), (caddr_t)&ipaddr.sin_addr,
				sizeof(ipaddr.sin_addr));
			/*
			* locate outgoing interface; if we're the destination,
			* use the incoming interface (should be same).
			*/
			if ((ia = (INA)ifa_ifwithaddr((SA)&ipaddr)) == 0 &&
				(ia = ip_rtaddr(ipaddr.sin_addr)) == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_HOST;
				goto bad;
			}
			bcopy((caddr_t)&(IA_SIN(ia)->sin_addr),
				(caddr_t)(cp + off), sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			break;

		case IPOPT_TS:
			code = cp - (u_char *)ip;
			ipt = (struct ip_timestamp *)cp;
			if (ipt->ipt_len < 5)
				goto bad;
			if (ipt->ipt_ptr > ipt->ipt_len - sizeof(long)) {
				if (++ipt->ipt_oflw == 0)
					goto bad;
				break;
			}
			sin = (struct in_addr *)(cp + ipt->ipt_ptr - 1);
			switch (ipt->ipt_flg) {

			case IPOPT_TS_TSONLY:
				break;

			case IPOPT_TS_TSANDADDR:
				if (ipt->ipt_ptr + sizeof(n_time) +
					sizeof(struct in_addr) > ipt->ipt_len)
					goto bad;
				ipaddr.sin_addr = dst;
				ia = (INA)ifaof_ifpforaddr((SA)&ipaddr,
					m->m_pkthdr.rcvif);
				if (ia == 0)
					continue;
				bcopy((caddr_t)&IA_SIN(ia)->sin_addr,
					(caddr_t)sin, sizeof(struct in_addr));
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			case IPOPT_TS_PRESPEC:
				if (ipt->ipt_ptr + sizeof(n_time) +
					sizeof(struct in_addr) > ipt->ipt_len)
					goto bad;
				bcopy((caddr_t)sin, (caddr_t)&ipaddr.sin_addr,
					sizeof(struct in_addr));
				if (ifa_ifwithaddr((SA)&ipaddr) == 0)
					continue;
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			default:
				goto bad;
			}
			ntime = iptime();
			bcopy((caddr_t)&ntime, (caddr_t)cp + ipt->ipt_ptr - 1,
				sizeof(n_time));
			ipt->ipt_ptr += sizeof(n_time);
		}
	}
	if (forward) {
		ip_forward(m, 1);
		return (1);
	}
	return (0);
bad:
	ip->ip_len -= ip->ip_hl << 2;   /* XXX icmp_error adds in hdr length */
	icmp_error(m, type, code, 0, 0);
	ipstat.ips_badoptions++;
	return (1);
#endif
}

void L3_impl::ip_forward(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, const int &srcrt) 
{
#ifdef NETLAB_L3_FORWARDING
	register struct ip *ip = mtod(m, struct ip *);
	register struct sockaddr_in *sin;
	register struct rtentry *rt;
	int error, type = 0, code;
	struct mbuf *mcopy;
	n_long dest;
	struct ifnet *destifp;

	dest = 0;
	if (m->m_flags & M_BCAST || in_canforward(ip->ip_dst) == 0) {
		ipstat.ips_cantforward++;
		m_freem(m);
		return;
	}
	HTONS(ip->ip_id);
	if (ip->ip_ttl <= IPTTLDEC) {
		icmp_error(m, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
		return;
	}
	ip->ip_ttl -= IPTTLDEC;

	sin = (struct sockaddr_in *)&ipforward_rt.ro_dst;
	if ((rt = ipforward_rt.ro_rt) == 0 ||
		ip->ip_dst.s_addr != sin->sin_addr.s_addr) {
		if (ipforward_rt.ro_rt) {
			RTFREE(ipforward_rt.ro_rt);
			ipforward_rt.ro_rt = 0;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr = ip->ip_dst;

		rtalloc(&ipforward_rt);
		if (ipforward_rt.ro_rt == 0) {
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, dest, 0);
			return;
		}
		rt = ipforward_rt.ro_rt;
	}

	/*
	* Save at most 64 bytes of the packet in case
	* we need to generate an ICMP message to the src.
	*/
	mcopy = m_copy(m, 0, imin((int)ip->ip_len, 64));

#ifdef GATEWAY
	ip_ifmatrix[rt->rt_ifp->if_index +
		if_index * m->m_pkthdr.rcvif->if_index]++;
#endif
	/*
	* If forwarding packet using same interface that it came in on,
	* perhaps should send a redirect to sender to shortcut a hop.
	* Only send redirect if source is sending directly to us,
	* and if packet was not source routed (or has any options).
	* Also, don't send redirect if forwarding using a default route
	* or a route modified by a redirect.
	*/
#define	satosin(sa)	((struct sockaddr_in *)(sa))
	if (rt->rt_ifp == m->m_pkthdr.rcvif &&
		(rt->rt_flags & (RTF_DYNAMIC | RTF_MODIFIED)) == 0 &&
		satosin(rt_key(rt))->sin_addr.s_addr != 0 &&
		ipsendredirects && !srcrt) {
#define	RTA(rt)	((struct in_ifaddr *)(rt->rt_ifa))
		u_long src = ntohl(ip->ip_src.s_addr);

		if (RTA(rt) &&
			(src & RTA(rt)->ia_subnetmask) == RTA(rt)->ia_subnet) {
			if (rt->rt_flags & RTF_GATEWAY)
				dest = satosin(rt->rt_gateway)->sin_addr.s_addr;
			else
				dest = ip->ip_dst.s_addr;
			/* Router requirements says to only send host redirects */
			type = ICMP_REDIRECT;
			code = ICMP_REDIRECT_HOST;
		}
	}

	error = ip_output(m, (struct mbuf *)0, &ipforward_rt, IP_FORWARDING
#ifdef DIRECTED_BROADCAST
		| IP_ALLOWBROADCAST
#endif
		, 0);
	if (error)
		ipstat.ips_cantforward++;
	else {
		ipstat.ips_forward++;
		if (type)
			ipstat.ips_redirectsent++;
		else {
			if (mcopy)
				m_freem(mcopy);
			return;
		}
	}
	if (mcopy == NULL)
		return;
	destifp = NULL;

	switch (error) {

	case 0:				/* forwarded, but need redirect */
		/* type, code set above */
		break;

	case ENETUNREACH:		/* shouldn't happen, checked above */
	case EHOSTUNREACH:
	case ENETDOWN:
	case EHOSTDOWN:
	default:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_HOST;
		break;

	case EMSGSIZE:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_NEEDFRAG;
		if (ipforward_rt.ro_rt)
			destifp = ipforward_rt.ro_rt->rt_ifp;
		ipstat.ips_cantfrag++;
		break;

	case ENOBUFS:
		type = ICMP_SOURCEQUENCH;
		code = 0;
		break;
	}
	icmp_error(mcopy, type, code, dest, destifp);
#endif
}

void L3_impl::ours(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct iphdr &ip, int &hlen) 
{

	/*
	*	Recall that ip_off contains the DF bit, the MF bit, and the fragment offset. The DF
	*	bit is masked out and if either the MF bit or fragment offset is nonzero, the packet is a
	*	fragment that must be reassembled. If both are zero, the packet is a complete datagram,
	*	the reassembly code is skipped and the else clause at the end of Figure 10.11 is executed,
	*	which excludes the header length from the total datagram length.
	*
	* If offset or IP_MF are set, must reassemble.
	* Otherwise, nothing need be done.
	* (We could look in the reassembly queue to see
	* if the packet was previously fragmented,
	* but it's not worth the time; just let them time out.)
	*/
	if (ip.ip_off & ~iphdr::IP_DF) {

		/*
		*	Net/3 keeps incomplete datagrams on the global doubly linked list, ipq. The name
		*	is somewhat confusing since the data structure isn't a queue. That is, insertions and
		*	deletions can occur anywhere in the list, not just at the ends. We'll use the term list to
		*	emphasize this fact.
		*		ours performs a linear search of the list to locate the appropriate datagram for
		*	the current fragment. Remember that fragments are uniquely identified by the 4-tuple:
		*	{ip_id, ip_src, ip_dst, ip_p}. Each entry in ipq is a list of fragments and fp points
		*	to the appropriate list if ours finds a match.
		*		Remark:	Net/3 uses linear searches to access many of its data structures. While simple,
		*		this method can	become a bottleneck in hosts supporting large numbers of network connections.
		*
		* Look for queue of fragments
		* of this datagram.
		*/
		struct ipq *fp;
		bool found(false);
		for (fp = ipq_t.next; fp != &ipq_t; fp = fp->next)
			if (ip.ip_id == fp->ipq_id &&
				ip.ip_src.s_addr == fp->ipq_src.s_addr &&
				ip.ip_dst.s_addr == fp->ipq_dst.s_addr &&
				ip.ip_p == fp->ipq_p) 
			{
				found = true;
				break;
			}
		if (!found)
			fp = nullptr;

		/*
		*	At found, the packet is modified by ours to facilitate reassembly:
		*		a.	ours changes ip_len to exclude the standard IP header and any options.
		*			We must keep this in mind to avoid confusion with the standard interpretation
		*			of ip_len, which includes the standard header, options, and data. ip_len is
		*			also changed if the reassembly code is skipped because this is not a fragment.
		*
		* Adjust ip_len to not reflect header,
		* set ip_mff if more fragments are expected,
		* convert offset of this to bytes.
		*/
		ip.ip_len -= hlen;

		/*
		*	ours copies the MF flag into the low-order bit of ipf_mff, which overlays
		*	ip_tos (&= ~1 clears the low-order bit only). Notice that ip must be cast to a
		*	pointer to an ipasfrag structure before ipf_mff is a valid member. Section
		*	10.6 and Figure 10.14 describe the ipasfrag structure.
		*		Remark:	Although RFC 1122 requires the IP layer to provide a mechanism that enables the transport
		*				layer to set ip_tos for every outgoing datagram, it only recommends that the IP layer pass
		*				ip_tos values to the transport layer at the destination host. Since the low-order bit of the
		*				TOS field must always be 0, it is availabJe to hold the MF bit while ip_of f (where the MF bit
		*				is normally found) is used by the reassembly algorithm.
		*	ip_off can now be accessed as a 16-bit offset instead of 3 flag bits and a 13-bit
		*	offset.
		*/
		reinterpret_cast<struct ipasfrag *>(&ip)->ipf_mff &= ~1;
		if (ip.ip_off & iphdr::IP_MF)
			reinterpret_cast<struct ipasfrag *>(&ip)->ipf_mff |= 1;

		/*
		*	ip_off is multiplied by 8 to convert from 8-byte to 1-byte units.
		*/
		ip.ip_off <<= 3;

		/*
		*	ipf_mff and ip_off determine if ours should attempt reassembly. Figure
		*	10.12 describes the different cases and the corresponding actions. Remember that
		*	fp points to the list of fragments the system has previously received for the datagram.
		*	Most of the work is done by ip_reass.
		*	If ip_reass is able to assemble a complete datagram by combining the current
		*	fragment with previously received fragments, it returns a pointer to the reassembled
		*	datagram. If reassembly is not possible, ip_reass saves the fragment and ours
		*	jumps to next to process the next packet (Figure 8.12).
		*
		* If datagram marked as having more fragments
		* or if this is not the first fragment,
		* attempt reassembly; if it succeeds, proceed.
		*/
		if (reinterpret_cast<struct ipasfrag *>(&ip)->ipf_mff & 1 || ip.ip_off) 
		{
#ifdef NETLAB_L3_FRAGMENTATION
			ip = ip_reass((struct ipasfrag *)&ip, fp);
			if (ip == 0)
				goto next;
			m = dtom(ip);
#endif
		}
	}
	else
		ip.ip_len -= hlen;

	/*
	*	Transport demultiplexing:
	*	The protocol specified in the datagram (ip_p) is mapped with the ip_protox
	*	array (Figure 7.22) to an index into the inetsw array. ours calls the pr_input
	*	function from the selected protosw structure to process the transport message contained
	*	within the datagram. When pr_input returns, ours proceeds with the next
	*	packet on oursq.
	*	It is important to notice that transport-level processing for each packet occurs
	*	within the processing loop of ours. There is no queuing of incoming packets
	*	between IP and the transport protocols, unlike the queuing in SVR4 streams implementations
	*	of TCP/IP.
	* Switch out to protocol's input routine.
	*/
	return inet.inetsw(static_cast<protosw::SWPROTO_>(ip_protox[ip.ip_p]))->pr_input(protosw::pr_input_args(m, it, hlen));
}







#include "L2.h"

#include <iomanip>
#include <string>

#include "L2_ARP.h"
#include "L3.h"
#include "NIC.h"

/************************************************************************/
/*                         L2			                                */
/************************************************************************/

L2::L2(class inet_os &inet) : inet(inet) { inet.datalink(this); }

L2::~L2() { inet.datalink(nullptr); }

std::ostream& operator<<(std::ostream &out, const L2::ether_header &eh) {
	std::ios::fmtflags f(out.flags());
	out << "< Ethernet (" << sizeof(struct L2::ether_header) <<
		" bytes) :: DestinationMAC = " << std::hex << eh.ether_dhost <<
		" , SourceMAC = " << std::hex << eh.ether_shost <<
		" , Type = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<u_short>(eh.ether_type) <<
		" , >";
	out.flags(f);
	return out;
}

/************************************************************************/
/*                         L2::ether_header		                        */
/************************************************************************/

L2::ether_header::ether_header(const mac_addr shost, const mac_addr dhost, const ETHERTYPE_ type)
	: ether_type(type), ether_dhost(dhost), ether_shost(shost) { }

L2::ether_header::ether_header(const ETHERTYPE_ type)
	: ether_type(type), ether_dhost(), ether_shost() { }

/************************************************************************/
/*                         L2_impl		                                */
/************************************************************************/

L2_impl::L2_impl(class inet_os &inet) : L2(inet) { }

void L2_impl::ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh) 
{
#ifdef NETLAB_L2_DEBUG
	{
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "[#] Ethernet packet received!" << std::endl << *eh << std::endl;
	}
#endif

	/*
	*	Broadcast and muHlcast recognition:
	*	Any packets that arrive on an inoperative interface are silently discarded. The
	*	interface may not have been configured with a protocol address, or may have been disabled
	*	by an explicit request.
	*/
	if ((inet.nic()->ifa_flags() & IFF_UP) == 0)
		return;

	/*
	*	The variable time is a global timeval structure that the kernel maintains with the
	*	current time and date, as the number of seconds and microseconds past the Unix Epoch
	*	(00:00:00 January 1, 1970, Coordinated Universal Tune [UTC]). A brief discussion of
	*	UTC can be found in [Itano and Ramsey 1993]. We'll encounter the timeval structure
	*	throughout the Net/3 sources:
	*		struct timeval {
	*			long tv_sec;	//	seconds
	*			long tv_usec;	//	and microseconds
	*		};
	*
	*		ether_input updates if_lastchange with the current time and increments
	*	if_ibytes by the size of the incoming packet(the packet length plus the 14 - byte
	*	Ethernet header).
	*/
	short m_flags(0); // Unused
	
	/*
	*	Next, ether_input repeats the tests done by leread to determine if the packet is
	*	a broadcast or multicast packet.
	*		Remark:	Some kernels may not have been compiled with the BPF code, so the test must also be done in
	*				ether_input.
	*/
	if (eh->ether_dhost == inet.nic()->etherbroadcastaddr())
		m_flags |= M_BCAST;
	else if (eh->ether_dhost[0] & 1)
		m_flags |= M_MCAST;

	/*
	*	Link-level demultiplexing:
	*	ether_input jumps according to the Ethernet type field. For an IP packet,
	*	schednetisr schedules an IP software interrupt and the IP input queue, ipintrq, is
	*	selected. For an ARP packet, the ARP software interrupt is scheduled and arpintrq is
	*	selected.
	*		Remark:	An isr is an interrupt service routine.
	*
	*				In previous BSD releases, ARP packets were processed immediately while at the network interrupt
	*				level by calling arpinput directly. By queuing the packets, they can be processed at the
	*				software interrupt level.
	*
	*				If other Ethernet types are to be handled, a kernel programmer would add additional cases
	*				here. Alternately, a process can receive other Ethernet types using BPF. For example, RARP
	*				senders are normally implemented using BPF under Net/3.
	*/
	switch (eh->ether_type) {
	case ether_header::ETHERTYPE_IP:
		return inet.inetsw(protosw::SWPROTO_IP_RAW)->pr_input(protosw::pr_input_args(m, it, 0));
		break;

	case ether_header::ETHERTYPE_ARP:
		return inet.arp()->in_arpinput(m, it);
		break;
	}
}

void L2_impl::ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt0) 
{

	/*
	*	The macro senderr is called throughout ether_output.
	*		#define senderr(e) { error= (e); goto bad;}
	*	senderr saves the error code and jumps to bad at the end of the function, where the
	*	packet is discarded and ether_output returns error.
	*	If the interface is up and running, ether_output updates the last change time for
	*	the interface. Otherwise, it returns ENETDOWN.
	*/
	if ((inet.nic()->ifa_flags() & (IFF_UP | NIC::IFF_RUNNING)) != (IFF_UP | NIC::IFF_RUNNING))
		throw std::runtime_error("Ethernet_output failed with error: ENETDOWN = " + std::to_string(ENETDOWN));

	struct L3::rtentry *rt(rt0);
	if (rt != nullptr) {
		if ((rt->rt_flags & L3::rtentry::RTF_UP) == 0) {
			if ((rt0 = rt = new struct L3::rtentry(dst, 1, &inet)) != nullptr)
				rt->rt_refcnt--;
			else
				throw std::runtime_error("Ethernet_output failed with error: EHOSTUNREACH = " + std::to_string(EHOSTUNREACH));
		}
		if (rt->rt_flags & L3::rtentry::RTF_GATEWAY) {
			bool lookup(false);
			if (rt->rt_gwroute == nullptr)
				lookup = true;
			else if (((rt = rt->rt_gwroute)->rt_flags & L3::rtentry::RTF_UP) == 0) {
				delete rt;
				rt = rt0;
				lookup = true;
			}
			if (lookup && ((rt = rt->rt_gwroute = new struct L3::rtentry(rt->rt_gateway, 1, &inet)) == nullptr))
				throw std::runtime_error("Ethernet_output failed with error: EHOSTUNREACH = " + std::to_string(EHOSTUNREACH));
		}
		if (rt->rt_flags &L3::rtentry::RTF_REJECT)
			if (rt->rt_rmx.rmx_expire == 0 /*|| time.tv_sec < rt->rt_rmx.rmx_expire*/)
				throw (rt == rt0) ?
				std::runtime_error("Ethernet_output failed with error: EHOSTDOWN = " + std::to_string(EHOSTDOWN)) :
				std::runtime_error("Ethernet_output failed with error: EHOSTUNREACH = " + std::to_string(EHOSTUNREACH));
	}
	struct ether_header *eh;
	mac_addr *edst(nullptr);
	short type;
	switch (dst->sa_family) {
	case AF_INET:
		if ((edst = inet.arp()->arpresolve(m, it, 0, dst)) == nullptr)
			return;	/* if not yet resolved */
		type = ether_header::ETHERTYPE_IP;
		break;

	case AF_UNSPEC:
		eh = reinterpret_cast<struct ether_header *>(dst->sa_data);
		edst = &eh->ether_dhost;
		type = eh->ether_type;
		break;

	default:
	{
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "can't handle af" << dst->sa_family << std::endl;
	}
	throw std::runtime_error("Ethernet_output failed with error: EAFNOSUPPORT = " + std::to_string(EAFNOSUPPORT));
	break;
	}

	/*
	* Add local net header.  If no space in first mbuf,
	* allocate another.
	*/
	if ((it -= sizeof(struct ether_header)) < m->begin())
		throw std::runtime_error("Ethernet_output failed with error: ENOBUFS = " + std::to_string(ENOBUFS));

	eh = reinterpret_cast<struct ether_header*>(&m->data()[it - m->begin()]);
	std::memcpy(&eh->ether_type, &(type = htons(static_cast<u_short>(type))), sizeof(eh->ether_type));
	eh->ether_dhost = *edst;
	eh->ether_shost = inet.nic()->mac();

	return (void)inet.nic()->lestart(m, it);
}









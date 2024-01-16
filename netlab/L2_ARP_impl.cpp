#include "L2_ARP.h"	

#include <list>
#include <iomanip>

#include "L3.h"
#include "L2.h"


/************************************************************************/
/*                    L2_ARP::ether_arp::arphdr			                */
/************************************************************************/

L2_ARP::ether_arp::arphdr::arphdr(ARPOP_ op)
	: ar_hrd(htons(ARPHRD_ETHER)), ar_pro(htons(L2::ether_header::ETHERTYPE_IP)), ar_hln(6 * sizeof(u_char)),
	ar_pln(4 * sizeof(u_char)), ar_op(htons(op)) { }

std::string L2_ARP::ether_arp::arphdr::ar_op_format() const 
{
	switch (ar_op)
	{
	case L2_ARP::ether_arp::arphdr::ARPOP_REQUEST:
		return "ARPOP_REQUEST";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_REPLY:
		return "ARPOP_REPLY";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_REVREQUEST:
		return "ARPOP_REVREQUEST";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_REVREPLY:
		return "ARPOP_REVREPLY";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_INVREQUEST:
		return "ARPOP_INVREQUEST";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_INVREPLY:
		return "ARPOP_INVREPLY";
		break;
	default:
		return "";
		break;
	}
}

std::string L2_ARP::ether_arp::arphdr::hw_addr_format() const 
{
	switch (ar_hrd)
	{
	case ARPHRD_ETHER:
		return "ARPHRD_ETHER";
		break;
	case ARPHRD_FRELAY:
		return "ARPHRD_FRELAY";
		break;
	default:
		return "NOT_SET";
		break;
	}
}

std::ostream& operator<<(std::ostream &out, const struct L2_ARP::ether_arp::arphdr &ea_hdr) 
{
	std::ios::fmtflags f(out.flags());
	out << "HardwareType = " << ea_hdr.hw_addr_format() <<
		"(= 0x" << std::setfill('0') << std::setw(2) << std::hex << ea_hdr.ar_hrd << ")" <<
		" , ProtocolType = 0x" << std::setw(2) << std::hex << ea_hdr.ar_pro <<
		" , HardwareAddressLength  = " << std::dec << static_cast<u_char>(ea_hdr.ar_hln) <<
		" , ProtocolAddressLength  = " << std::dec << static_cast<u_char>(ea_hdr.ar_pln) <<
		" , Operation = " << ea_hdr.ar_op_format() <<
		"(= 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<u_short>(ea_hdr.ar_op) << ")";
	out.flags(f);
	return out;
}

/************************************************************************/
/*                    L2_ARP::ether_arp					                */
/************************************************************************/

L2_ARP::ether_arp::ether_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, arphdr::ARPOP_ op)
	: ea_hdr(op), arp_sha(saddr), arp_tha(taddr) 
{
	std::memcpy(arp_spa, &sip, sizeof(arp_spa));
	std::memcpy(arp_tpa, &tip, sizeof(arp_tpa));
}

std::ostream& operator<<(std::ostream &out, const struct L2_ARP::ether_arp &ea) 
{
	std::ios::fmtflags f(out.flags());
	out << "< ARP (" << static_cast<uint32_t>(sizeof(struct	L2_ARP::ether_arp)) <<
		" bytes) :: " << ea.ea_hdr <<
		" , SenderHardwareAddress = " << ea.arp_sha <<
		" , SenderProtocol Address = " << inet_ntoa(*reinterpret_cast<struct in_addr *>(const_cast<u_char *>(ea.arp_spa)));
	out << " , TargetHardwareAddress = " << ea.arp_tha <<
		" , TargetProtocol Address = " << inet_ntoa(*reinterpret_cast<struct in_addr *>(const_cast<u_char *>(ea.arp_tpa))) <<
		" , >";
	out.flags(f);
	return out;
}

std::shared_ptr<std::vector<byte>> L2_ARP::ether_arp::make_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it, arphdr::ARPOP_ op) 
{
	/*
	*	Allocate and Initialize mbuf
	*	A packet header mbuf is allocated and the two length fields are set. MH_ALIGN
	*	allows room for a 28-byte ether_arp structure at the end of the mbuf, and sets the
	*	m_data pointer accordingly. The reason for moving this structure to the end of the
	*	mbuf is to allow ether_output to prepend the 14-byte Ethernet header in the same
	*	mbuf.
	*/
	std::shared_ptr<std::vector<byte>> m(new std::vector<byte>(sizeof(struct L2::ether_header) + sizeof(struct L2_ARP::ether_arp)));
	if (m == nullptr)
		throw std::runtime_error("make_arp_request failed! allocation failed!");

	/*
	* As above, for mbufs allocated with m_gethdr/MGETHDR
	* or initialized by M_COPY_PKTHDR.
	*/
	it = m->begin() + sizeof(struct L2::ether_header);
	memcpy(&m->data()[it - m->begin()], &struct L2_ARP::ether_arp(tip, sip, taddr, saddr, op), sizeof(struct L2_ARP::ether_arp));
	return m;
}

std::shared_ptr<std::vector<byte>> L2_ARP::ether_arp::make_arp_request(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it) 
{
	return make_arp(tip, sip, taddr, saddr, it);
}

std::shared_ptr<std::vector<byte>> L2_ARP::ether_arp::make_arp_reply(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it) 
{
	return make_arp(tip, sip, taddr, saddr, it, ether_arp::arphdr::ARPOP_REPLY);
}

//std::lock_guard<std::mutex> lock(inet.print_mutex);
//str << intro << ea << std::endl;

/************************************************************************/
/*                    L2_ARP::llinfo_arp				                */
/************************************************************************/

L2_ARP::llinfo_arp::llinfo_arp(bool permanent)
	: la_asked(0), la_flags(0), la_timeStamp(static_cast<unsigned long long>(permanent ? 0 : floor(GetTickCount64()))),
	la_hold(), la_hold_it(), la_mac("") { }

L2_ARP::llinfo_arp::llinfo_arp(const mac_addr &la_mac, bool permanent) : llinfo_arp(permanent) { update(la_mac); }

L2_ARP::llinfo_arp::~llinfo_arp() { pop(); }

bool L2_ARP::llinfo_arp::valid() const 
{
	unsigned long long cmp(static_cast<unsigned long long>(floor(GetTickCount64())));
	return la_timeStamp == 0 || (cmp > la_timeStamp && cmp < MAX_TIME_STAMP + la_timeStamp);
}

L2_ARP::mac_addr& L2_ARP::llinfo_arp::getLaMac() { return la_mac; }

unsigned long long L2_ARP::llinfo_arp::getLaTimeStamp() const { return la_timeStamp; }

bool L2_ARP::llinfo_arp::clearToSend(const unsigned long arp_maxtries, const unsigned int arpt_down) 
{
	if (la_timeStamp) {
		la_flags &= ~L3::rtentry::RTF_REJECT;
		if (la_asked == 0 || (la_timeStamp != floor(GetTickCount64()))) {
			la_timeStamp = static_cast<unsigned long long>(std::floor(GetTickCount64()));
			if (la_asked++ < arp_maxtries)
				return true;
			else {
				la_flags |= L3::rtentry::RTF_REJECT;
				la_timeStamp += arpt_down;
				la_asked = 0;
			}
		}
	}
	return false;
}

void L2_ARP::llinfo_arp::pop() 
{
	if (la_hold != nullptr) {
		la_hold.reset(new std::vector<byte>());
		la_hold_it = std::vector<byte>::iterator();
	}
}

void L2_ARP::llinfo_arp::push(std::shared_ptr<std::vector<byte>> hold, const std::vector<byte>::iterator hold_it) 
{
	pop();
	la_hold = hold;
	la_hold_it = hold_it;
}

std::shared_ptr<std::vector<byte>> L2_ARP::llinfo_arp::front() const { return la_hold; }

std::vector<byte>::iterator& L2_ARP::llinfo_arp::front_it() { return la_hold_it; }

bool L2_ARP::llinfo_arp::empty() const { 
	return la_hold ? la_hold->empty() : true;
}

void L2_ARP::llinfo_arp::update(const mac_addr la_mac) 
{
	/*	The sender's hardware address is copied into a UCHAR array.	*/
	this->la_mac = la_mac;

	/*	When the sender's hardware address is resolved, the following steps occur. If the expiration
	*	time is nonzero, it is reset to the current time in the future. This test exists because
	*	the arp command can create permanent entries: entries that never time out. These entries
	*	are marked with an expiration time of 0. When an ARP request is sent (i.e., for a non
	*	permanent ARP entry) the expiration time is set to the current time, which is nonzero. */
	if (la_timeStamp != 0)
		la_timeStamp = GetTickCount64();

	/*	The RTF_REECT flag is cleared and the la_asked counter is set to 0. We'll see that these
	*	last two steps are used in arpresolve to avoid ARP flooding.	*/
	la_flags &= ~L3::rtentry::RTF_REJECT;
	la_asked = 0;
}

/************************************************************************/
/*                    L2_ARP_impl::ArpCache						        */
/************************************************************************/

L2_ARP_impl::ArpCache::ArpCache(const unsigned long arp_maxtries, const unsigned int arpt_down) 
	: arp_maxtries(arp_maxtries), arpt_down(arpt_down) { }

void L2_ARP_impl::ArpCache::cleanup()
{
	u_long oldest;
	unsigned long long oldestTime(0);
	for (auto it = begin(); it != end();) {
		if (!it->second->valid())
			erase(it);
		else if (oldestTime < it->second->getLaTimeStamp()) {
			oldest = it->first;
			oldestTime = (it)->second->getLaTimeStamp();
		}
		it++;
	}

	if (size() == arp_maxtries)
		erase(find(oldest));
	else if (size() > arp_maxtries)
		throw std::runtime_error("ArpCache:: Too Many elements inserted to ARP Cache!");
}

L2_ARP_impl::ArpCache::mapped_type& L2_ARP_impl::ArpCache::operator[] (const key_type& k) {
	if (size() >= arp_maxtries)
		cleanup();
	return _Myt::operator[](k);
}

L2_ARP_impl::ArpCache::mapped_type& L2_ARP_impl::ArpCache::operator[] (key_type&& k) {
	if (size() >= arp_maxtries)
		cleanup();
	return _Myt::operator[](k);
}

//L2_ARP_impl::ArpCache::iterator L2_ARP_impl::ArpCache::insert(const key_type& _Keyval, bool permanent) {
//	if (size() >= arp_maxtries)
//		cleanup();
//	return std::map<key_type, mapped_type>::insert(std::pair<key_type, mapped_type>(_Keyval, mapped_type(new L2_ARP::llinfo_arp(permanent)))).first;
//}

L2_ARP_impl::ArpCache::iterator L2_ARP_impl::ArpCache::find(const key_type& _Keyval) {
	iterator it(_Myt::find(_Keyval));
	if (it != end())
		if (it->second->valid())
			return it;
		else
			erase(it);
	return end();
}

/************************************************************************/
/*                    L2_ARP_impl						                */
/************************************************************************/

L2_ARP_impl::L2_ARP_impl(inet_os &inet, const unsigned long arp_maxtries, const int arpt_down)
	: L2_ARP(inet, arp_maxtries, arpt_down), arpcache(ArpCache(arp_maxtries, arpt_down)) { }

void L2_ARP_impl::insertPermanent(const u_long ip, const mac_addr &la_mac) {
	arpcache[ip] = std::shared_ptr<L2_ARP::llinfo_arp>(new L2_ARP::llinfo_arp(la_mac, true));
} //arpcache.insert(ip, true)->second->update(la_mac); }

void L2_ARP_impl::arpwhohas(const struct in_addr &addr) { return arprequest(addr.s_addr); }

void L2_ARP_impl::arprequest(const u_long &tip)
{
	std::vector<byte>::iterator it;
	std::shared_ptr<std::vector<byte>> m(ether_arp::make_arp_request(tip, inet.nic()->ip_addr().s_addr, "", inet.nic()->mac(), it));
	//byte *m(ether_arp::make_arp_request(tip, inet.nic->ip_addr.s_addr, "", inet.nic->mac, m_len));
	struct sockaddr sa;
	struct L2::ether_header *eh = reinterpret_cast<struct L2::ether_header *>(sa.sa_data);
	eh->ether_dhost = inet.nic()->etherbroadcastaddr();
	eh->ether_type = L2::ether_header::ETHERTYPE_ARP;		/* if_output will swap */
	sa.sa_family = AF_UNSPEC;
	inet.datalink()->ether_output(m, it, &sa, nullptr);
}

L2_ARP_impl::mac_addr* L2_ARP_impl::arpresolve(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, short m_flags, struct sockaddr *dst)
{
	/*	
	 *	Handle broadcast and multicast destinations
	 *	If the M_BCAST flag of the mbuf is set, the destination is filled in with the Ethernet
	 *	broadcast address and the function returns 1. If the M_MCAST flag is set, the
	 *	ETHER_MAP_IP_MULTICAST macro (Figure 12.6) converts the class D address into the
	 *	corresponding Ethernet address.
	 */
	//if (m_flags & L2_impl::M_BCAST)	/* broadcast */
		//return &mac_addr(inet.nic()->etherbroadcastaddr()); // will not work return address of stack variable
	
	//if (m_flags & L2_impl::M_MCAST)	/* multicast */ 
		//return &mac_addr::ETHER_MAP_IP_MULTICAST(&reinterpret_cast<struct sockaddr_in *>(dst)->sin_addr); // same here
	
	/*	
	 *	Get pointer to llinfo_arp structure:
	 *	The destination address is a unicast address. If a pointer to a routing table entry is
	 *	passed by the caller, la is set to the corresponding llinfo_arp structure. Otherwise
	 *	arplookup searches the routing table for the specified IP address. The second argument
	 *	is 1, telling arplookup to create the entry if it doesn't already exist; the third
	 *	argument is 0, which means don't look for a proxy ARP entry.
	 */
	struct in_addr &sin(reinterpret_cast<struct sockaddr_in *>(dst)->sin_addr);	
	std::shared_ptr<L2_ARP::llinfo_arp> &la(arplookup(sin.s_addr, true));
	
	/*	
	 *	If either rt or la are null pointers, one of the allocations failed, since arplookup
	 *	should have created an entry if one didn't exist. An error message is logged, the packet
	 *	released, and the function returns 0.
	 */
	if (la)
	{
		/*	
		 *	Even though an ARP entry is located, it must be checked for validity. The entry is valid if the entry is
		*	permanent (the expiration time is 0) or the expiration time is greater than the current time
		*	If the entry is valid, the address is resolved; otherwise, try to resolve.
		*/
		if (la->getLaMac() != "")
			return &la->getLaMac();

		/*	
		 *	At this point an ARP entry exists but it does not contain a valid Ethernet address. An ARP request
		*	must be sent. First the pointer to the Packet is saved in la_hold, after releasing any Packet
		*	that was already pointed to by la_hold. This means that if multiple IP datagrams are sent quickly
		*	to a given destination, and an ARP entry does not already exist for the destination, during the
		*	time it takes to send an ARP request and receive a reply only the last datagram is held, and all
		*	prior ones are discarded.
		*
		*	An example that generates this condition is NFS. If NFS sends an 8500-byte IP datagram that is
		*	fragmented into six IP fragments, and if all six fragments are sent by ip_output to ether_output
		*	in the time it takes to send an ARP request and receive a reply, the first five fragments are
		*	discarded and only the final fragment is sent when the reply is received. This in turn causes an
		*	NFS timeout, and a retransmission of all six fragments.
		*
		* There is an arptab entry, but no Ethernet address response yet.  Replace the held mbuf with this
		* latest one. 
		*/
		la->push(m, it);

		/*	RFC 1122 requires ARP to avoid sending ARP requests to a given destination at a high rate when a
		*	reply is not received. The technique used by Net/3 to avoid ARP flooding is as follows:
		*
		*	•	Net/3 never sends more than one ARP request in any given second to a destination.
		*
		*	•	If a reply is not received after five ARP requests (i.e., after about 5 seconds), the RTF_REJECT
		*		flag in the routing table is set and the expiration time is set for 20 seconds in the future.
		*		This causes ether_output to refuse to send IP datagrams to this destination for 20 seconds,
		*		returning EHOSTDOWN or EHOSTUNREACH instead (Figure 4.15).
		*
		*	•	After the 20-second pause in ARP requests, arpresolve will send ARP requests to that destination
		*		again. 
		*
		*	If the expiration time is nonzero (i.e., this is not a permanent entry) the RTF_REJECT flag is cleared,
		*	in case it had been set earlier to avoid flooding. The counter la_asked counts the number of consecutive
		*	times an ARP request has been sent to this destination. If the counter is 0 or if the expiration time
		*	does not equal the current time (looking only at the seconds portion of the current time), an ARP request
		*	might be sent. This comparison avoids sending more than one ARP request during any second. The expiration
		*	time is then set to the current time in seconds (i.e., the millisecond portion, time is ignored).
		*
		*	The counter is compared to the limit of 5 (arp_maxtries) and then incremented. If the value was less
		*	than 5, arpwhohas sends the request. If the request equals 5, however, ARP has reached its limit: the
		*	RTF_REJECT flag is set, the expiration time is set to 20 seconds in the future, and the counter
		*	la_asked is reset to 0.	*/
		if (la->clearToSend(getArpMaxtries(), getArptDown()))
			arpwhohas(sin);
	}

	return nullptr;
}

std::shared_ptr<L2_ARP::llinfo_arp> L2_ARP_impl::arplookup(const u_long addr, bool create)
{
	ArpCache::iterator it(arpcache.find(addr));
	if (it != arpcache.end())
		return it->second;
	else if (create) 
		return arpcache[addr] = std::shared_ptr < L2_ARP::llinfo_arp >(new L2_ARP::llinfo_arp());
	return nullptr;
}

/*	
 *	in_arpinput Function:
 *	This function is called by arpintr to process each received ARP request or ARP reply.
 *	While ARP is conceptually simple, numerous rules add complexity to the implementation.
 *	The following two scenarios are typical:
 *		1.	If a request is received for one of the host's IP addresses, a reply is sent. This is
 *			the normal case of some other host on the Ethernet wanting to send this host a
 *			packet. Also, since we're about to receive a packet from that other host, and
 *			we'll probably send a reply, an ARP entry is created for that host (if one doesn't
 *			already exist) because we have its IP address and hard\vare address. This optimization
 *			avoids another ARP exchange when the packet is received from the other host.
 *		2.	If a reply is received in response to a request sent by this host, the corresponding
 *			ARP entry is now complete (the hardware address is known). The other host's
 *			hardware address is stored in the sockaddr_dl structure and any queued
 *			packet for that host can now be sent. Again, this is the normal case.
 *	ARP requests are normally broadcast so each host sees all ARP requests on the Ethernet,
 *	even those requests for which it is not the target. Recall from arprequest that when a
 *	request is sent, it contains the sender's IP address and hardware address. This allows the
 *	following tests also to occur.
 *		3.	If some other host sends a request or reply with a sender IP address that equals
 *			this host's IP address, one of the two hosts is misconfigured. Net/3 detects this
 *			error and logs a message for the administrator. (We say "request or reply" here
 *			because in_arpinput doesn't examine the operation type. But ARP replies are
 *			normally unicast, in which case only the target host of the reply receives the reply.)
 *		4.	If this host receives a request or reply from some other host for which an ARP
 *			entry already exists, and if the other host's hard\vare address has changed, the
 *			hardware address in the ARP entry is updated accordingly. This can happen if
 *			the other host is shut down and then rebooted with a different Ethernet interface
 *			(hence a different hardware address) before its ARP entry times out. The
 *			use of this technique, along with the other host sending a gratuitous ARP
 *			request when it reboots, prevents this host from being unable to communicate
 *			with the other host after the reboot because of an ARP entry that is no longer
 *			valid.
 *		5.	This host can be configured as a proxy ARP server. This means it responds to
 *			ARP requests for some other host, supplying the other host's hardware address
 *			in the reply. The host whose hardware address is supplied in the proxy ARP
 *			reply must be one that is able to forward IP datagrams to the host that is the target
 *			of the ARP request. Section 4.6 of Volume 1 discusses proxy ARP.
 *			A Net/3 system can be configured as a proxy ARP server. These ARP entries
 *			are added with the arp command, specifying the IP address, hardware address,
 *			and the keyword pub. We'll see the support for this in Figure 21.20 and we
 *			describe it in Section 21.12.
 *			
* ARP for Internet protocols on 10 Mb/s Ethernet.
* Algorithm is that given in RFC 826.
* In addition, a sanity check is performed on the sender
* protocol address, to catch impersonators.
* We no longer handle negotiations for use of trailer protocol:
* Formerly, ARP replied for protocol type ETHERTYPE_TRAIL sent
* along with IP replies if we wanted trailers sent to us,
* and also sent them in response to IP replies.
* This allowed either end to announce the desire to receive
* trailer packets.
* We no longer reply to requests for ETHERTYPE_TRAIL protocol either,
* but formerly didn't normally send requests.
*/
void L2_ARP_impl::in_arpinput(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it) {
	struct ether_arp *ea(reinterpret_cast<struct ether_arp *>(&m->data()[it - m->begin()]));
	struct in_addr *isaddr(reinterpret_cast<struct in_addr *>(ea->arp_spa));
	struct in_addr *itaddr(reinterpret_cast<struct in_addr *>(ea->arp_tpa));
	bool out(false);
	std::shared_ptr<L2_ARP::llinfo_arp> la;
	
	if (ea->arp_sha == inet.nic()->mac())
		out = true;	/* it's from me, ignore it. */
	
	/*	
	 *	If the sender's hardware address is the Ethernet broadcast address, this is an error. The error is printed and
	 *	the packet is discarded. 
	 */
	else if (ea->arp_sha == inet.nic()->etherbroadcastaddr()) {
		out = true;
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "arp: ether address is broadcast for IP address " << inet_ntoa(*isaddr) << "!" << std::endl;
	}

	else if ((*isaddr).s_addr == inet.nic()->ip_addr().s_addr) {
		*itaddr = inet.nic()->ip_addr();
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "arp: duplicate IP address " << inet_ntoa(*isaddr) << "! sent from Ethernet address : " << ea->arp_sha << std::endl;
	}
		
	/*
	*	arplookup searches the ARP cache for the sender's IP address (isaddr). The second argument is 1 if the target
	*	IP address equals myaddr (meaning create a new entry if an entry doesn't exist), or not 0 otherwise (do not create
	*	a new entry). An entry is always created for the sender if this host is the target; otherwise the host is
	*	processing a broadcast intended for some other target, so it just looks for an existing entry for the sender.
	*	As mentioned earlier, this means that if a host receives an ARP request for itself from another host, an ARP
	*	entry is created for that other host on the assumption that, since another host is about to send us a packet,
	*	we'll probably send a reply. The return value is a pointer to a PMY_LLINFO_ARP structure, or a null pointer if an
	*	entry is not found or created.
	*/
	else if (la = arplookup((*isaddr).s_addr, (*itaddr).s_addr == inet.nic()->ip_addr().s_addr)) {
		/*
		*	If the link-level address length (sdl_alen) is nonzero (meaning that an existing entry
		*	is being referenced and not a new entry that was just created), the link-level address
		*	is compared to the sender's hardware address. If they are different, the sender's
		*	Ethernet address has changed. This can happen if the sending host is shut down, its
		*	Ethernet interface card replaced, and it reboots before the ARP entry times out. While
		*	not common, this is a possibility that must be handled. An informational message is
		*	printed and the code continues, which will update the hardware address with its new value.
		*/
		if (la->getLaMac() != "" && la->getLaMac() != ea->arp_sha) {
			std::lock_guard<std::mutex> lock(inet.print_mutex);
			std::cout << "arp info overwritten for " << inet_ntoa(*isaddr) << " by " << ea->arp_sha << std::endl;
		}

		la->update(ea->arp_sha);

		/*	If ARP is holding onto a Packet awaiting ARP resolution of that host's hardware address
		*	(the la_hold pointer), the Packet is passed. Since this Packet was being held by ARP the
		*	destination address must be on a local Ethernet so the function is ether_output. This
		*	function again calls arpresolve, but the hardware address was just filled in, allowing
		*	the Packet to be sent.	*/
		if (!la->empty()) {
			struct sockaddr sa;
			struct L2::ether_header *eh(reinterpret_cast<struct L2::ether_header *>(sa.sa_data));
			eh->ether_shost = inet.nic()->mac();
			eh->ether_dhost = la->getLaMac();
			eh->ether_type = L2::ether_header::ETHERTYPE_IP;		/* if_output will swap */
			sa.sa_family = AF_UNSPEC;
			inet.datalink()->ether_output(la->front(), la->front_it(), &sa, nullptr);
			la->pop();
		}
	}

	int op(ntohs(ea->arp_op()));
	if (op != ether_arp::arphdr::ARPOP_REQUEST || out)
		return ;

	/*
	*	If the target IP address equals myIPaddr, this host is the target of the request. The source hardware
	*	address is copied into the target hardware address (i.e., whoever sent it becomes the target) and
	*	the Ethernet address of the interface is copied from myMACaddr into the source hardware address.
	*	The remainder of the ARP reply is constructed after.
	*/
	if ((*itaddr).s_addr == inet.nic()->ip_addr().s_addr) 

		/*	
		 *	I am the target so construct the ARP reply. The sender and target hardware addresses have
		 *	been filled in. The sender and target IP addresses are now swapped. The	target IP address
		 *	is contained in itaddr 
		 */
		 return SendArpReply(*isaddr, *itaddr, ea->arp_sha, inet.nic()->mac());

	/* I am the target */
	ea->arp_tha = ea->arp_sha;
	ea->arp_sha = inet.nic()->mac();
	
	memcpy(ea->arp_tpa, ea->arp_spa, sizeof(ea->arp_spa));
	memcpy(ea->arp_spa, &itaddr, sizeof(ea->arp_spa));

	ea->arp_op() = htons(ether_arp::arphdr::ARPOP_REPLY);
	ea->arp_pro() = htons(L2::ether_header::ETHERTYPE_IP); /* let's be sure! */
	
	struct sockaddr sa;
	struct L2::ether_header *eh(reinterpret_cast<struct L2::ether_header *>(sa.sa_data));
	eh->ether_shost = inet.nic()->mac();
	eh->ether_dhost = ea->arp_tha;
	eh->ether_type = L2::ether_header::ETHERTYPE_ARP;		/* if_output will swap */
	
	sa.sa_family = AF_UNSPEC;
	return inet.datalink()->ether_output(m, it, &sa, nullptr);
}

void L2_ARP_impl::SendArpReply(const struct in_addr& itaddr, const struct in_addr& isaddr, const mac_addr& hw_tgt, const mac_addr& hw_snd) const
{
	std::vector<byte>::iterator it;
	std::shared_ptr<std::vector<byte>> m(ether_arp::make_arp_reply(itaddr.s_addr, isaddr.s_addr, hw_tgt, hw_snd, it));

	struct sockaddr sa;
	struct L2::ether_header *eh(reinterpret_cast<struct L2::ether_header *>(sa.sa_data));
	eh->ether_shost = hw_snd;
	eh->ether_dhost = hw_tgt;
	eh->ether_type = L2::ether_header::ETHERTYPE_ARP;		/* if_output will swap */
	
	sa.sa_family = AF_UNSPEC;
	inet.datalink()->ether_output(m, it, &sa, nullptr);
}






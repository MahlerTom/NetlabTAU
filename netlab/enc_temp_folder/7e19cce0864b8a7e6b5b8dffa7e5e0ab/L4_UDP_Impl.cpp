#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

#include "L4_UDP_Impl.hpp"

L4_UDP::L4_UDP(class inet_os& inet) : protosw(inet, SOCK_DGRAM, NULL, IPPROTO_UDP) { }


/************************************************************************/
/*                         udp_output_args                               */
/************************************************************************/

L4_UDP_Impl::udp_output_args::udp_output_args(L4_UDP::udpcb &up) : up(up){ }

/************************************************************************/
/*                         L4_UDP::udpcb                                */
/************************************************************************/

L4_UDP::udpcb::udpcb(inet_os& inet)
	: inpcb_impl(inet), udp_ip_template(nullptr), udp_inpcb(dynamic_cast<inpcb_impl*>(this)),
	log(udpcb_logger()) { }

L4_UDP::udpcb::udpcb(socket& so, inpcb_impl& head)
	: inpcb_impl(so, head), udp_ip_template(nullptr), udp_inpcb(dynamic_cast<inpcb_impl*>(this)),
	log(udpcb_logger()) { }

/************************************************************************/
/*                         L4_UDP_Impl::udphdr                          */
/************************************************************************/

std::ostream& operator<<(std::ostream& out, const struct L4_UDP_Impl::udphdr& udp) {

	std::ios::fmtflags f(out.flags());
	out << "< UDP (" << "SourcePort = " << std::dec << ntohs(static_cast<uint16_t>(udp.src_port_number)) <<
		" , DestinationPort = " << std::dec << ntohs(static_cast<uint16_t>(udp.dst_port_number)) <<
		" , HeaderLength = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint16_t>(udp.udp_datagram_length) <<
		" , Checksum = 0x" << std::setfill('0') << std::setw(3) << std::hex << static_cast<uint16_t>(udp.udp_checksum) <<
		" )";
	out.flags(f);
	return out;
}

/************************************************************************/
/*                         L4_UDP_Impl::pseudo_header                   */
/************************************************************************/

L4_UDP_Impl::pseudo_header::pseudo_header(const in_addr& ip_src_addr, const in_addr& ip_dst_addr, const u_char& protocol, const short& udp_length) 
	: ip_src_addr(ip_src_addr), ip_dst_addr(ip_dst_addr), protocol(protocol), udp_length(udp_length) { } 

/************************************************************************/
/*                         L4_UDP_Impl			                        */
/************************************************************************/

L4_UDP_Impl::L4_UDP_Impl(class inet_os &inet)
	: L4_UDP(inet), ucb(inet), udp_last_inpcb(nullptr) { }

L4_UDP_Impl::~L4_UDP_Impl() {
	if (udp_last_inpcb)
		delete udp_last_inpcb;
}

void L4_UDP_Impl::pr_init() {

	udp_last_inpcb = nullptr;
	udp_last_inpcb = dynamic_cast<class inpcb_impl*>(&ucb);
}

void L4_UDP_Impl::pr_input(const struct pr_input_args& args) {
	
	std::shared_ptr<std::vector<byte>>& m(args.m);
	std::vector<byte>::iterator& it(args.it);
	const int& iphlen(args.iphlen);
}

uint16_t ones_complement_add(uint16_t a, uint16_t b) {
	uint32_t sum = a + b; // Use a larger type to capture potential carry
	// Handle end-around carry
	while (sum > 0xFFFF) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return static_cast<uint16_t>(sum); // Convert back to 16 bits
}

uint16_t L4_UDP_Impl::calculate_checksum(pseudo_header& udp_pseudo_header, std::shared_ptr<std::vector<byte>>& m) {

	uint16_t checksum = 0;
	uint8_t* byte_ptr = reinterpret_cast<uint8_t*>(&udp_pseudo_header);

	for (size_t i = 0; i < sizeof(udp_pseudo_header); i += 2) {

		uint16_t word = 0;
		word = (byte_ptr[i] << 8) + byte_ptr[i+1];

		checksum = ones_complement_add(checksum, word);
	}

	byte_ptr = reinterpret_cast<uint8_t*>(&(*(m->begin() + sizeof(L2::ether_header) + sizeof(L3::iphdr))));

	for (size_t i = 0; i < udp_pseudo_header.udp_length; i+=2) {
	
		uint16_t word = 0;
		word = (byte_ptr[i] << 8) + byte_ptr[i + 1];

		checksum = ones_complement_add(checksum, word);
	}

	return ~checksum;
}

int L4_UDP_Impl::udp_output(L4_UDP::udpcb& up) {

	socket *so = dynamic_cast<socket*>(up.udp_inpcb->inp_socket);

	long len(so->so_snd.size());

	uint16_t hdrlen(sizeof(udphdr) + sizeof(L3::iphdr)); 

	std::shared_ptr<std::vector<byte>> m(new std::vector<byte>(hdrlen + sizeof(struct L2::ether_header) + len));
	if (m == nullptr)
		return out(up, ENOBUFS);

	std::vector<byte>::iterator it(m->begin() + sizeof(struct L2::ether_header) + sizeof(L3::iphdr));
	
	if (len > 0) {

		// copy data
		std::copy(so->so_snd.begin(), so->so_snd.begin() + len, it + sizeof(udphdr));

		// create udp header
		struct udphdr* udp_header = reinterpret_cast<struct udphdr*>(&(*it));

		// update header
		udp_header->dst_port_number = so->so_pcb->inp_fport();
		udp_header->src_port_number = so->so_pcb->inp_lport();
		udp_header->udp_datagram_length = len + sizeof(udphdr);

		// Create atrophied IP header with only src and dst IP addresses

		struct L3::iphdr* ip_header = reinterpret_cast<struct L3::iphdr*> (&(*(it - sizeof(L3::iphdr))));

		ip_header->ip_src = so->so_pcb->inp_laddr();
		ip_header->ip_dst = so->so_pcb->inp_faddr();

		// calculate UDP pseudo header and checksum 

		struct pseudo_header udp_pseudo_header(ip_header->ip_src, ip_header->ip_dst, IPPROTO_UDP, udp_header->udp_datagram_length);

		udp_header->udp_checksum = calculate_checksum(udp_pseudo_header, m);

		// send encapsualted result with udp header to IP layer

		int error(
			inet.inetsw(protosw::SWPROTO_IP_RAW)->pr_output(*dynamic_cast<const struct pr_output_args*>(
					&L3_impl::ip_output_args(m, it, up.udp_inpcb->inp_options, &up.udp_inpcb->inp_route, so->so_options & SO_DONTROUTE, nullptr)
					)));
		if (error)
			return out(up, error);

	}
	return 0;
}

int L4_UDP_Impl::pr_output(const struct pr_output_args& args) { 
	return udp_output(reinterpret_cast<const struct udp_output_args*>(&args)->up);
};

int L4_UDP_Impl::pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
	struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) {

	class inpcb* inp(so->so_pcb);
	class L4_UDP::udpcb* up(nullptr);

	if (inp == nullptr && req != PRU_ATTACH)
		return (EINVAL);

	int error{ 0 };

	switch (req) {

	case PRU_ATTACH:
	{
		if (inp) {
			error = EISCONN;
			break;
		}
		class L4_UDP::udpcb* up = L4_UDP::udpcb::sotoudpcb(dynamic_cast<socket*>(so));
		break;
	}

	case PRU_DETACH:
	{
		break;
	}

	case PRU_BIND:
	{
		if (error = inp->in_pcbbind(reinterpret_cast<struct sockaddr_in*>(nam), nam_len))
			break;
		break;
	}

	case PRU_SEND:
	{
		dynamic_cast<socket*>(so)->so_snd.sbappend(m->begin(), m->end());
		error = udp_output(*up);
		break;
	}
		
	return error;
	}
}

void L4_UDP_Impl::drop(class inpcb_impl* inp, const int dropsocket) {

	/*
	* Drop space held by incoming segment and return.
	*
	* destroy temporarily created socket
	*/
	if (dropsocket && inp)
		(void)dynamic_cast<socket*>(inp->inp_socket)->soabort();
	return;
}

int L4_UDP_Impl::out(L4_UDP::udpcb& up, int error)
{
	return (error);
}
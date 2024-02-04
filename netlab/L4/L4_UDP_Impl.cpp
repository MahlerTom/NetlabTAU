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

	/*
	* Get IP and UDP headers in first mbuf
	* The argument iphlen is the length of the IP header, including possible IP options.
	* If the length is greater than 20 bytes, options are present, and ip_stripoptions discards
	* the options.
	*/
	struct L4_UDP_Impl::pseudo_header* udp_ip_pseudo_hdr(reinterpret_cast<struct L4_UDP_Impl::pseudo_header*>(&m->data()[it - m->begin()]));

	if (iphlen > sizeof(struct L3::iphdr))
		L3_impl::ip_stripoptions(m, it);

	if (m->end() - it < sizeof(struct L4_UDP_Impl::pseudo_header))
		return drop(nullptr, 0);

	int ulen(reinterpret_cast<struct L3::iphdr*>(udp_ip_pseudo_hdr)->ip_len),
		len(sizeof(struct L3::iphdr) + ulen);

	/*
	* Calculate checksum for UDP IP pseudo header.
	*/
	u_short checksum(udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_sum());
	if (((udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_sum() = 0) = checksum ^ inet.in_cksum(&m->data()[it - m->begin()], len)) != 0)
		return drop(nullptr, 0);

	int dropsocket(0);
	class inpcb_impl* inp(nullptr);

findpcb:
	inp = udp_last_inpcb;
	if ((inp->inp_lport() != udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_dport() ||
		inp->inp_fport() != udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_sport() ||
		inp->inp_faddr().s_addr != udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_src().s_addr ||
		inp->inp_laddr().s_addr != udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_dst().s_addr) &&
		(inp = ucb.in_pcblookup(udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_src(), udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_sport()
			, udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_dst(), udp_ip_pseudo_hdr->udp_ip_pseudo_hdr_dport(), inpcb::INPLOOKUP_WILDCARD)))
		udp_last_inpcb = inp;


	
}

int L4_UDP_Impl::udp_output(class L4_UDP::udpcb& up) {

	socket *so = dynamic_cast<socket*>(up.udp_inpcb->inp_socket);

	long len(so->so_snd.size());

	std::shared_ptr<std::vector<byte>>& m(args.m);
	std::vector<byte>::iterator& it(args.it);
	

	struct udphdr *udp(reinterpret_cast<struct udphdr*>(&m->data()[it - m->begin()]));
	

	return 0;
}

int L4_UDP_Impl::pr_output(const struct pr_output_args& args) { 
	return udp_output(reinterpret_cast<const struct udp_output_args*>(&args)->up);
};

int L4_UDP_Impl::pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
	struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) {

	switch (req) {
		int error{ 0 };
	case PRU_SEND:
		dynamic_cast<socket*>(so)->so_snd.sbappend(m->begin(), m->end());

		//error = udp_output();
		break;
	}
	
	return 0;
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
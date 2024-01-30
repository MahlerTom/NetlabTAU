#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

#include "L4_UDP_Impl.hpp"

L4_UDP::L4_UDP(class inet_os& inet) : protosw(inet, SOCK_DGRAM, NULL, IPPROTO_UDP) { }

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
/*                         udp_output_args                               */
/************************************************************************/

L4_UDP_Impl::udp_output_args::udp_output_args(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it)
	: m(m), it(it) { };


/************************************************************************/
/*                         L4_UDP_Impl::L4_UDP                          */
/************************************************************************/

void L4_UDP_Impl::pr_init() { }

void L4_UDP_Impl::pr_input(const struct pr_input_args& args) { }

int L4_UDP_Impl::udp_output(const struct udp_output_args& args) {

	std::shared_ptr<std::vector<byte>>& m(args.m);
	std::vector<byte>::iterator& it(args.it);

	struct udphdr* udp(reinterpret_cast<struct udphdr*>(&m->data()[it - m->begin()]));
	


}

int L4_UDP_Impl::pr_output(const struct pr_output_args& args) { return udp_output(*reinterpret_cast<const struct udp_output_args*>(&args)); };

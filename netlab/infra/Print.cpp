#include "Print.h"

namespace netlab 
{

	size_t RawData(const Tins::PDU &pdu, std::shared_ptr<std::vector<byte>> &buf) 
	{
		Tins::PDU::serialization_type ser(((Tins::PDU&)pdu).serialize());
		size_t ret(0),
			lSize(pdu.size());

		for (auto i = ser.begin(); i != ser.end(); ++i)	{
			buf->operator[](ret++) = *i;
			if (ret > lSize)
				break;
		}
		return ret;
	}

	std::string StrPort(uint16_t port_number) 
	{
		char str_port[6];
		sprintf(str_port, "%d", port_number);
		return str_port;
	}

	//uint8_t RNG8() { return rand() % 256; }
	//uint16_t RNG16() { return rand() % 65536; }
	//uint32_t RNG32() { return 2 * rand(); }
	//size_t RawData(const Tins::PDU &pdu, uint8_t* buf, size_t size) {
	//	size_t lSize(std::min<size_t>(pdu.size(), size));
	//	Tins::PDU::serialization_type ser(((Tins::PDU&)pdu).serialize());
	//	size_t ret(0);
	//	for (auto i = ser.begin(); i != ser.end(); ++i) {
	//		buf[ret++] = *i;
	//		if (ret > lSize)
	//			break;
	//	}
	//	return ret;
	//}
	//size_t RawData(const IP &pdu, uint8_t* buf, size_t size, uint16_t totlen)
	//{
	//	size_t lSize = std::min<size_t>(pdu.size(), size);
	//	PDU::serialization_type ser = ((PDU&)pdu).serialize();
	//	size_t ret = 0;
	//	for (auto i = ser.begin(); i != ser.end(); ++i)
	//	{
	//		buf[ret++] = *i;
	//		if (ret > lSize)
	//			break;
	//	}
	//	uint16_t htotlen = htons(totlen);
	//	memcpy(&buf[2], &htotlen, sizeof(uint16_t));
	//	uint32_t check = Utils::do_checksum(buf, &buf[size]);
	//	while (check >> 16)
	//		check = (check & 0xffff) + (check >> 16);
	//	check = htons(~check);
	//	memcpy(&buf[10], (uint16_t *)&check, sizeof(uint16_t));
	//	return ret;
	//}
	//void HexDump(Tins::PDU &pdu, std::ostream& str) {
	//	size_t lSize = pdu.size();
	//	uint8_t *pAddressIn = new uint8_t[lSize];
	//	RawData(pdu, pAddressIn, lSize);
	//	char szBuf[100];
	//	long lIndent = 1;
	//	long lOutLen, lIndex, lIndex2, lOutLen2;
	//	long lRelPos;
	//	struct { char *pData; unsigned long lSize; } buf;
	//	unsigned char *pTmp, ucTmp;
	//	unsigned char *pAddress = (unsigned char *)pAddressIn;
	//	buf.pData = (char *)pAddress;
	//	buf.lSize = lSize;
	//	while (buf.lSize > 0)
	//	{
	//		pTmp = (unsigned char *)buf.pData;
	//		lOutLen = (int)buf.lSize;
	//		if (lOutLen > 16)
	//			lOutLen = 16;
	//		// create a 64-character formatted output line:
	//		sprintf(szBuf, "                              "
	//			"                      "
	//			"    %08lX", (long unsigned int) (pTmp - pAddress));
	//		lOutLen2 = lOutLen;
	//		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0;
	//			lOutLen2;
	//			lOutLen2--, lIndex += 2, lIndex2++
	//			)
	//		{
	//			ucTmp = *pTmp++;
	//			sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
	//			if (!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
	//			szBuf[lIndex2] = ucTmp;
	//			if (!(++lRelPos & 3))     // extra blank after 4 bytes
	//			{
	//				lIndex++; szBuf[lIndex + 2] = ' ';
	//			}
	//		}
	//		if (!(lRelPos & 3)) lIndex--;
	//		szBuf[lIndex] = ' ';
	//		szBuf[lIndex + 1] = ' ';
	//		str << szBuf << std::endl;
	//		buf.pData += lOutLen;
	//		buf.lSize -= lOutLen;
	//	}
	//	delete[] pAddressIn;
	//}
	//void HexDump(const Tins::PDU &pdu, std::ostream& str)
	//{
	//	class Tins::PDU *clone = pdu.clone();
	//	HexDump(*clone);
	//	delete clone;
	//}
	//void printPDU(const EthernetII& eth, std::ostream& str)
	//{
	//	ios::fmtflags f(str.flags());
	//	str << "< Ethernet (" << eth.header_size() << 
	//		" bytes) :: DestinationMAC = " << eth.dst_addr().to_string() <<
	//		" , SourceMAC = " << eth.src_addr().to_string() << 
	//		" , Type = 0x" << setfill('0') << setw(4) << std::hex << eth.payload_type() <<
	//		" , >" << std::endl;
	//	str.flags(f);
	//}
	//void printPDU(const ARP& arp, std::ostream& str)
	//{
	//	ios::fmtflags f(str.flags());
	//	str << "< ARP (" << (uint32_t)arp.header_size() <<
	//		" bytes) :: HardwareType = 0x" << setfill('0') << setw(2) << std::hex << arp.hw_addr_format() <<
	//		" , ProtocolType = 0x" << arp.prot_addr_format() <<
	//		" , HardwareAddressLength  = " << std::dec << (uint16_t)arp.header_size() <<
	//		" , ProtocolAddressLength  = " << (uint16_t)arp.prot_addr_length() <<
	//		" , Operation  = " << arp.opcode() <<
	//		" , SenderHardwareAddress = " << arp.sender_hw_addr().to_string() <<
	//		" , SenderProtocol Address = " << arp.sender_ip_addr().to_string() <<
	//		" , TargetHardwareAddress = " << arp.target_hw_addr().to_string() <<
	//		" , TargetProtocol Address = " << arp.target_ip_addr().to_string() <<
	//		" , >" << std::endl;
	//	str.flags(f);
	//}
	//void printPDU(const IP& ip, std::ostream& str)
	//{
	//	ios::fmtflags f(str.flags());
	//	str << "< IP (" << (uint32_t)ip.header_size() <<
	//		" bytes) :: Version = 0x" << std::hex << (USHORT)ip.version() <<
	//		" , HeaderLength = 0x" << (USHORT)ip.head_len() <<
	//		" , DiffServicesCP = 0x" << setfill('0') << setw(2) << (((uint8_t)ip.tos() >> 2) << 2) <<
	//		" , ExpCongestionNot = 0x" << ((uint8_t)ip.tos() << 6) << " , TotalLength = " << std::dec << (uint16_t)ip.tot_len() <<
	//		" , Identification = 0x" << setfill('0') << setw(4) << std::hex << (uint16_t)ip.id() <<
	//		/*" , Flags = " << Internals::pdu_flag_to_ip_type(ip.pdu_type())*/
	//		" , FragmentOffset = " << std::dec << (uint16_t)ip.frag_off() << " , TTL = " << (uint16_t)ip.ttl() <<
	//		" , Protocol = 0x" << setfill('0') << setw(4) << std::hex << (uint16_t)ip.protocol() <<
	//		" , Checksum = 0x" << setfill('0') << setw(4) << std::hex << ip.checksum() <<
	//		" , SourceIP = " <<	ip.src_addr().to_string() <<
	//		" , DestinationIP = " << ip.dst_addr().to_string() <<			
	//		" , >" << std::endl;
	//	str.flags(f);
	//}
	//void printPDU(const ICMP& icmp, std::ostream& str)
	//{
	//	ios::fmtflags f(str.flags());
	//	str << "< ICMP (" << (uint32_t)icmp.header_size() <<
	//		" bytes) :: Type = " << icmp.type() <<
	//		" , Code = " << (uint16_t)icmp.code();
	//	
	//	if (icmp.code() == 0 && 
	//		(icmp.type() == ICMP::ECHO_REPLY || icmp.type() == ICMP::ECHO_REQUEST))
	//		str << " , ID = " << std::dec << icmp.id() << " , Seq = " << icmp.sequence();
	//	str <<
	//		" , Checksum = 0x" << setfill('0') << setw(4) << std::hex << icmp.checksum() <<
	//		" , >" << std::endl;
	//	str.flags(f);
	//}
	//void printPDU(const TCP& tcp, std::ostream& str)
	//{
	//	ios::fmtflags f(str.flags());
	//	str << "< TCP (" << (uint32_t)tcp.header_size() <<
	//		" bytes) :: SourcePort = " << std::dec << (uint16_t)tcp.sport() <<
	//		" , DestinationPort = " << std::dec << (uint16_t)tcp.dport() <<
	//		" , Seq # = " << std::dec << (uint32_t)tcp.seq() <<
	//		" , ACK # = " << std::dec << (uint32_t)tcp.ack_seq() <<
	//		" , HeaderLength = 0x" << setfill('0') << setw(2) << std::hex << (uint16_t)tcp.data_offset() <<
	//		" , Flags = 0x" << setfill('0') << setw(2) << std::hex << (uint16_t)tcp.flags() <<
	//		" (";
	//	if (tcp.get_flag(TCP::URG))
	//		str << "URG, ";
	//	if (tcp.get_flag(TCP::ACK))
	//		str << "ACK, ";
	//	if (tcp.get_flag(TCP::PSH))
	//		str << "PSH, ";
	//	if (tcp.get_flag(TCP::RST))
	//		str << "RST, ";
	//	if (tcp.get_flag(TCP::SYN))
	//		str << "SYN, ";
	//	if (tcp.get_flag(TCP::FIN))
	//		str << "FIN, ";
	//	str << ")" <<
	//		" , WinSize = " << std::dec << (uint16_t)tcp.window() <<
	//		" , Checksum = 0x" << setfill('0') << setw(4) << std::hex << tcp.checksum() <<
	//		" , UrgentPointer = 0x" << setfill('0') << setw(4) << std::hex << tcp.urg_ptr() <<
	//		" , >" << std::endl;
	//	str.flags(f);
	//}

}

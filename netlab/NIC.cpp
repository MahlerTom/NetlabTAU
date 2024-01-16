/*!
    \file	NIC.cpp
	
	\author	Tom Mahler, contact at tommahler@gmail.com
    
	\brief	Implements the NIC class.
*/

#include "NIC.h"
#include "NIC_Cable.h"
#include "L2.h"
#include "utils.h"

struct netlab::NetworkInterface::Info 
{
	netlab::IPv4Address ip_addr;
	netlab::IPv4Address netmask;
	netlab::IPv4Address bcast_addr;
	address_type hw_addr;
};

NIC::NIC(inet_os &inet, struct in_addr *my_ip, mac_addr my_mac, struct in_addr *my_gw, 
	struct in_addr *my_netmask, bool promisc_mode, std::string filter)
	: inet(inet), _ifa_flags(IFF_UP), _etherbroadcastaddr(mac_addr::broadcast)
{
	inet.cable(new NIC_Cable(inet, promisc_mode, filter));
	inet.nic(this);
	
	_mac = 
		my_mac == "" ? 
		mac_addr(inet.cable()->iface.addresses().hw_addr.to_string()) : 
		my_mac;
	
	_ip_addr.s_addr = 
		my_ip ? 
		my_ip->s_addr : 
		inet_addr(inet.cable()->iface.addresses().ip_addr.to_string().c_str());
	
	_netmask_addr.s_addr = 
		my_netmask ?
		my_netmask->s_addr :
		inet_addr(inet.cable()->iface.addresses().netmask.to_string().c_str());
	
	if (my_gw)
		_dgw_addr.s_addr = my_gw->s_addr;
	else {
		netlab::IPv4Address gw;
		netlab::utils::gateway_from_ip(netlab::IPv4Address(_ip_addr.s_addr), gw);
		_dgw_addr.s_addr = inet_addr(gw.to_string().c_str());
	}
	
	_bcast_addr.s_addr =
		inet_addr(inet.cable()->iface.addresses().bcast_addr.to_string().c_str());
}

NIC::NIC(class inet_os &inet, netlab::IPv4Address my_ip, mac_addr my_mac, netlab::IPv4Address my_gw, 
	netlab::IPv4Address my_netmask, bool promisc_mode, std::string filter)
	: NIC(inet, nullptr, my_mac, nullptr, nullptr, promisc_mode, filter)
{
	_dgw_addr.s_addr = inet_addr(my_gw.to_string().c_str());
	_ip_addr.s_addr = inet_addr(my_ip.to_string().c_str());
}

bool NIC::in_localaddr(struct in_addr &addr) const { return ((addr.s_addr & _netmask_addr.s_addr) ^ (addr.s_addr & _netmask_addr.s_addr)) == 0; }

void NIC::HexDump(byte *m, const size_t &m_len, std::ostream& str) 
{
	char szBuf[100];
	long lIndent = 1, lOutLen, lIndex, lIndex2, lOutLen2, lRelPos;
	struct { char *pData; unsigned long lSize; } buf;
	unsigned char *pTmp, ucTmp, *pAddress = (unsigned char *)m;
	buf.pData = (char *)pAddress;
	buf.lSize = m_len;

	while (buf.lSize > 0)
	{
		pTmp = (unsigned char *)buf.pData;
		lOutLen = (int)buf.lSize;
		if (lOutLen > 16)
			lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, "                              "
			"                      "
			"    %08lX", (long unsigned int) (pTmp - pAddress));
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex += 2, lIndex2++)
		{
			ucTmp = *pTmp++;

			sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
			if (!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3))     // extra blank after 4 bytes
				lIndex++; szBuf[lIndex + 2] = ' ';
		}

		if (!(lRelPos & 3)) lIndex--;

		szBuf[lIndex] = ' ';
		szBuf[lIndex + 1] = ' ';

		str << szBuf << std::endl;

		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}

void NIC::HexDump(std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, std::ostream& str) 
{
	char szBuf[100];
	long lIndent = 1, lOutLen, lIndex, lIndex2, lOutLen2, lRelPos;
	struct { char *pData; unsigned long lSize; } buf;
	unsigned char *pTmp, ucTmp, *pAddress = (unsigned char *)m->data();
	buf.pData = (char *)pAddress;
	buf.lSize = m->end() - it;

	while (buf.lSize > 0)
	{
		pTmp = (unsigned char *)buf.pData;
		lOutLen = (int)buf.lSize;
		if (lOutLen > 16)
			lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, "                              "
			"                      "
			"    %08lX", (long unsigned int) (pTmp - pAddress));
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex += 2, lIndex2++)
		{
			ucTmp = *pTmp++;

			sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
			if (!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3))     // extra blank after 4 bytes
				lIndex++; szBuf[lIndex + 2] = ' ';
		}

		if (!(lRelPos & 3)) lIndex--;

		szBuf[lIndex] = ' ';
		szBuf[lIndex + 1] = ' ';

		str << szBuf << std::endl;

		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}

NIC::~NIC() 
{
	disconnect();
	
	if (inet.cable()) {
		delete inet.cable();
		inet.cable(nullptr);
	}
	inet.nic(nullptr);
}

void NIC::leread(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it) 
{
	struct L2::ether_header *et(reinterpret_cast<struct L2::ether_header *>(&m->data()[m->begin() - it]));
	et->ether_type = ntohs(static_cast<u_short>(et->ether_type));
	
	/* adjust input length to account for header and CRC */
	if ((it += sizeof(struct L2::ether_header)) > m->end())
		return;
	inet.datalink()->ether_input(m, it, et);
}

void NIC::lestart(std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it) {
	if (m == nullptr) 
	{
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "[!] lestart(nothing to send)" << std::endl;
		return;
	}

#ifdef NIC_DEBUG_OUT
	{
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "[#] HexDump of sent Packet:" << std::endl;
		HexDump(m, it);
	}
#endif

	try
	{
		inet.cable()->send_l2(m, it, inet.cable()->iface);
	}
	catch (const Tins::socket_write_error& socex)
	{
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "[!] Send failed with the error: " << socex.what() << std::endl;
	}
	return;
}

void NIC::connect(L2 &upperInterface, class L0_buffer *buf, const uint32_t count)
{
	ifa_flags(ifa_flags() | IFF_RUNNING);
	inet.cable()->connect(upperInterface, buf, count);
}

void NIC::disconnect(bool from_buf)
{ 
	ifa_flags(ifa_flags() & ~IFF_RUNNING);
	inet.cable()->disconnect(from_buf);
}

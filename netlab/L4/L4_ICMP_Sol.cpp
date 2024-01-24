//#include "L4.h"
//
//#include "tins.h"
//
//#include "L3.h"
//#include "NIC.h"
//#include "Print.h"
//#include <bitset>
//
///* Collapse namespaces */
//using namespace std;
//using namespace Tins;
//
//L4::L4(bool debug) : debug(debug), recvPacketLen(0), recvPacket(NULL)
//{
//	pthread_mutex_init(&recvPacket_mutex, NULL);
//	pthread_mutex_lock(&recvPacket_mutex);
//}
//
//void L4::setLowerInterface(L3 *lowerInterface){ this->lowerInterface = lowerInterface; }
//
//const NIC& L4::getLowestInterface(){ return lowerInterface->getLowestInterface(); }
//
//int L4::sendToL4(byte *sendData, size_t sendDataLen, std::string destIP, std::string srcIP)
//{
//	IP::address_type resolvedSrcIP;
//	try 
//	{
//		resolvedSrcIP = IP::address_type(srcIP);
//	}
//	catch (std::runtime_error &ex) 
//	{
//		if (srcIP != "")
//		{
//			pthread_mutex_lock(&NIC::print_mutex);
//			cout << "[@] Source IP resolving failed with the error: " << ex.what() << endl;
//			cout << "    Using myIP as a Source IP." << endl;
//			pthread_mutex_unlock(&NIC::print_mutex);
//		}
//		try {
//			resolvedSrcIP = IP::address_type(NIC::myIP);
//		}
//		catch (std::runtime_error &ex) 
//		{
//			pthread_mutex_lock(&NIC::print_mutex);
//			cout << "[!] Source IP resolving failed AGAIN with the error: " << ex.what() << endl;
//			pthread_mutex_unlock(&NIC::print_mutex);
//		}	
//	}
//
//	IP::address_type resolvedDestIP;
//	try 
//	{
//		resolvedDestIP = IP::address_type(destIP);
//	}
//	catch (std::runtime_error &ex) 
//	{
//		pthread_mutex_lock(&NIC::print_mutex);
//		cout << "[!] Destination IP resolving failed with the error: " << ex.what() << endl;
//		pthread_mutex_unlock(&NIC::print_mutex);
//		resolvedDestIP = "";
//	}
//
//	/* Create an ICMP header */
//	ICMP icmp_pdu;
//	icmp_pdu.id(RNG16());
//	icmp_pdu.code(0);
//	RawPDU raw_pdu(sendData, sendDataLen);
//	icmp_pdu.inner_pdu(raw_pdu);
//
//
//	byte* toSend = new byte[icmp_pdu.size()];
//	RawData(icmp_pdu, toSend, icmp_pdu.size());
//	
//	int ret = lowerInterface->sendToL3(toSend, icmp_pdu.size(), resolvedSrcIP.to_string(), resolvedDestIP.to_string());
//	delete[] toSend;
//
//
//	return ret;
//}
//
//int L4::readFromL4(byte *recvData, size_t recvDataLen)
//{
//	pthread_mutex_lock(&recvPacket_mutex);
//	size_t lSize = recvDataLen < recvPacketLen ? recvDataLen : recvPacketLen;
//	memcpy(recvData, recvPacket, lSize);
//	pthread_mutex_unlock(&recvPacket_mutex);
//	pthread_mutex_lock(&recvPacket_mutex);
//	return lSize;
//}
//
//
//int L4::recvFromL4(byte *recvData, size_t recvDataLen)
//{
//	ICMP icmp_pdu(recvData, recvDataLen);
//	int ret = 0;
//	if (icmp_pdu.code() == 0 && icmp_pdu.type() == ICMP::ECHO_REPLY)
//	{
//		if (debug)
//		{
//			pthread_mutex_lock(&NIC::print_mutex);
//			cout << "[#] ICMP packet receivied!" << endl;
//			printPDU(icmp_pdu);
//			pthread_mutex_unlock(&NIC::print_mutex);
//		}
//		RawPDU raw_pdu(icmp_pdu.rfind_pdu<RawPDU>());
//		recvPacketLen = raw_pdu.size();
//		ret = recvPacketLen;
//		if (recvPacket)
//			delete[] recvPacket;
//		recvPacket = new byte[recvPacketLen];
//		RawData(raw_pdu, recvPacket, recvPacketLen);
//		pthread_mutex_unlock(&recvPacket_mutex);	
//	}
//	else
//	{
//		pthread_mutex_lock(&NIC::print_mutex);
//		cout << "[!] ICMP type not supported, only ECHO_REPLY is currently supported, Droping Packet." << endl;
//		pthread_mutex_unlock(&NIC::print_mutex);
//		return ret;
//	}
//	return ret;
//}
//
//L4::~L4()
//{
//	pthread_mutex_destroy(&recvPacket_mutex);	/* Free up the_mutex */
//	if (recvPacket)
//		delete[] recvPacket;
//}
//

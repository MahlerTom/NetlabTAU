#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>

#include "pch.h"

class UDPTest : public testing::Test {

protected:

	/* Declaring the client and the server */
	inet_os inet_server;
	inet_os inet_client;

	/* Declaring the NIC of the client and the server */
	NIC nic_client;
	NIC nic_server;

	/* Declaring the Datalink of the client and the server using L2_impl*/
	L2_impl datalink_client;
	L2_impl datalink_server;

	/* Declaring the ARP of the client and the server using L2_impl*/
	L2_ARP_impl arp_server;
	L2_ARP_impl arp_client;

	// Create a SOCKET for listening for incoming connection requests.
	netlab::L5_socket_impl* ServerSocket;
	// Create a SOCKET for connecting to server.
	netlab::L5_socket_impl* ClientSocket;
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl* AcceptSocket;

	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound (SERVER)/and port of the server to be connected to (CLIENT).
	sockaddr_in service;
	sockaddr_in clientService;

	UDPTest()
		: inet_server(),
		inet_client(),
		nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "(arp and ether src bb:bb:bb:bb:bb:bb) or (udp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"),
		nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "(arp and ether src aa:aa:aa:aa:aa:aa) or (udp port 8888 and not ether src bb:bb:bb:bb:bb:bb)"),
		datalink_server(inet_server),
		datalink_client(inet_client),
		arp_server(inet_server, 10, 10000),
		arp_client(inet_client, 10, 10000)
	{

	}

	void SetUp() override {

		/* Declaring protocols is a bit different: */
		inet_server.inetsw(
			new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
			protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
		inet_server.inetsw(
			new L4_UDP_Impl(inet_server),		// Defining the UDP Layer using L4_UDP_Impl
			protosw::SWPROTO_UDP);				// Placing it in the appropriate place.
		inet_server.inetsw(
			new L3_impl(						// The actual IP layer we will use.
				inet_server,						// Binding this NIC to our server
				SOCK_RAW,							// The protocol type
				IPPROTO_RAW,						// The protocol
				protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
			protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.

		inet_server.domaininit();	// This calls each pr_init() for each defined protocol.

		arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address

		inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
		inet_client.inetsw(new L4_UDP_Impl(inet_client), protosw::SWPROTO_UDP);
		inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
		inet_client.domaininit();
		arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());

		/* Spawning both sniffers, 0U means continue forever */
		inet_server.connect(0U);
		inet_client.connect(0U);
	}

	void TearDown() override {

		std::this_thread::sleep_for(std::chrono::seconds(1));
		ServerSocket->shutdown(SD_RECEIVE);
	}
};


TEST_F(UDPTest, Test01) {

	// The socket address to be passed to bind

	//----------------------
	// Create a SOCKET for the server
	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	sockaddr_in sock_addr;
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	sock_addr.sin_port = htons(8888);

	////----------------------
	//// Bind the socket.
	ServerSocket->bind((SOCKADDR*)&sock_addr, sizeof(service));

	////----------------------
	//// Create a SOCKET for the client
	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	std::string send_msg;
	send_msg = "Client: Hi, I am Client!";

	ClientSocket->send(send_msg, send_msg.size());
	
}

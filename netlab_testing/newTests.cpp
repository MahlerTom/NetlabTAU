#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>

#include "pch.h"

#include "../netlab/inet_os.hpp"
#include "../netlab/NIC_Cable.h"
#include "../netlab/L0_buffer.h"
#include "../netlab/NIC.h"
#include "../netlab/L2.h"
#include "../netlab/L2_ARP.h"
#include "../netlab/L4.h"
#include "../netlab/L4_TCP.h"

using namespace std;

class newTests : public ::testing::Test {

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
    netlab::L5_socket_impl* ListenSocket;
	// Create a SOCKET for connecting to server.
    netlab::L5_socket_impl* ConnectSocket;
	// Create a SOCKET for accepting incoming requests.
    netlab::L5_socket_impl* AcceptSocket;

	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound (SERVER)/and port of the server to be connected to (CLIENT).
	sockaddr_in service;
	sockaddr_in clientService;

	newTests()
		: inet_server(),
		inet_client(),
		nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"),
		nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)"),
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
			new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
			protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
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
		inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
		inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
		inet_client.domaininit();
		arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); 

		/* Spawning both sniffers, 0U means continue forever */
		inet_server.connect(0U);
		inet_client.connect(0U);


		// The socket address to be passed to bind

		//----------------------
		// Create a SOCKET for listening for 
		// incoming connection requests
		ListenSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

		//----------------------
		// The sockaddr_in structure specifies the address family,
		// IP address, and port for the socket that is being bound.
		service.sin_family = AF_INET;
		service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		service.sin_port = htons(8888);

		////----------------------
		//// Bind the socket.
		//ListenSocket->bind((SOCKADDR*)&service, sizeof(service));

		////----------------------
		//// Listen for incoming connection requests 
		//// on the created socket
		//// 
		//ListenSocket->listen(5);

		////----------------------
		//// Create a SOCKET for connecting to server
		//ConnectSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

		//----------------------
		// The sockaddr_in structure specifies the address family,
		// IP address, and port of the server to be connected to.
		clientService.sin_family = AF_INET;
		clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		clientService.sin_port = htons(8888);

    }

    void TearDown() override {

		inet_client.stop_fasttimo();
		inet_client.stop_slowtimo();

		inet_server.stop_fasttimo();
		inet_server.stop_slowtimo();
		std::this_thread::sleep_for(std::chrono::seconds(1));

		ListenSocket->shutdown(SD_RECEIVE);
    }
};



TEST_F(newTests, arpTest) {


	/*std::shared_ptr<std::vector<byte>> m = std::make_shared<std::vector<byte>>(std::initializer_list<byte>{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 69, 0, 0, 60, 34, 107,
			0, 0, 64, 6, 68, 57, 10, 0, 0, 15,
			10, 0, 0, 10, 19, 136, 34, 184, 168, 13,
			160, 45, 0, 0, 0, 0, 160, 2, 255, 255,
			28, 215, 0, 0, 2, 4, 5, 180, 1, 3,
			3, 1, 1, 1, 8, 10, 205, 205, 205, 206,
			0, 0, 0, 0
	});

	std::vector<byte>::iterator it = std::find(m->begin(), m->end(), static_cast<byte>(69));

	

	datalink_client.ether_output(m, it, reinterpret_cast<struct sockaddr*>(ListenSocket), ro->ro_rt);*/



}


//TEST_F(newTests, arpTest2) {
//
//	size_t size = 32, num = 5;
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//
//	std::string send_msg(size, 'T');
//	std::thread([ConnectSocket, send_msg, num, size]()
//		{
//			typedef std::chrono::nanoseconds nanoseconds;
//			typedef std::chrono::duration<double> seconds;
//			typedef std::random_device generator;
//			generator gen;
//			std::exponential_distribution<> dist(3);
//
//			for (size_t i = 0; i < num; i++)
//			{
//				ConnectSocket->send(send_msg, size, size);
//				std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//			}
//
//		}).detach();
//
//		typedef std::chrono::nanoseconds nanoseconds;
//		typedef std::chrono::duration<double> seconds;
//		typedef std::random_device generator;
//		generator gen;
//		std::exponential_distribution<> dist(3);
//		std::string ret("");
//		for (size_t i = 0; i < num; i++)
//		{
//			AcceptSocket->recv(ret, size);
//			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//		}
//
//}


// Need to have 2 cases - one with 1 client and 1 server, 2 packets sent
// and one with 2 clients and 1 server, 2 total packets sent, 1 from each client
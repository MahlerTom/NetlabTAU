#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include <iostream>

#include "L2.h"
#include "L3.h"
#include "L4_TCP.h"
#include "NIC.h"
#include "L2_ARP.h"
#include "NIC_Cable.h"
#include "L0_buffer.h"


#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>
using namespace std;


void test1() 
{
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect(0U);
	inet_client.connect(0U);


	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();	
	std::this_thread::sleep_for(std::chrono::seconds(1));

	ListenSocket->shutdown(SD_RECEIVE);
}

void test2() 
{
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client


	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect(0U);
	inet_client.connect(0U);


	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	ListenSocket->shutdown(SD_RECEIVE);
}

void test3(size_t size = 32, size_t num = 5) 
{
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client

	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect();
	inet_client.connect();

	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	std::string send_msg(size, 'T');
	std::thread([ConnectSocket, send_msg, num, size]()
	{
		typedef std::chrono::nanoseconds nanoseconds;
		typedef std::chrono::duration<double> seconds;
		typedef std::random_device generator;
		generator gen;
		std::exponential_distribution<> dist(3);

		for (size_t i = 0; i < num; i++)
		{
			ConnectSocket->send(send_msg, size, size);
			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
		}

	}).detach();

	typedef std::chrono::nanoseconds nanoseconds;
	typedef std::chrono::duration<double> seconds;
	typedef std::random_device generator;
	generator gen;
	std::exponential_distribution<> dist(3);
	std::string ret("");
	for (size_t i = 0; i < num; i++)
	{
		AcceptSocket->recv(ret, size);
		std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
	}

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));
}

void test4(size_t size = 256) 
{
	size *= 1024;
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client

	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect();
	inet_client.connect();

	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);



	std::string send_msg(size, 'T');
	
	//std::thread([ConnectSocket, send_msg, size]() 
	//{
	//	ConnectSocket->send(send_msg, size);
	//}).detach();
	ConnectSocket->send(send_msg, size);
	std::string ret("");
	AcceptSocket->recv(ret, size);

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));

}

void test5() 
{
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client

	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect(0U);
	inet_client.connect(0U);


	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));
	
	delete AcceptSocket;
	delete ConnectSocket;
	
	std::this_thread::sleep_for(std::chrono::seconds(5));
	ListenSocket->shutdown(SD_RECEIVE);
}

void test6()
{
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client

	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect(0U);
	inet_client.connect(0U);


	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	AcceptSocket->shutdown(SD_BOTH);
	ConnectSocket->shutdown(SD_BOTH);
	ListenSocket->shutdown(SD_RECEIVE);

	delete ConnectSocket;
	delete AcceptSocket;
}

void test7() 
{
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client




	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect();
	inet_client.connect();
	
	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.5, L0_buffer::exponential_distribution_args(5)));
	//inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::exponential_distribution_args(0.5)));
	inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.5, L0_buffer::uniform_real_distribution_args(0.5, 5), L0_buffer::OUTGOING));
	inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::uniform_real_distribution_args(0.5, 5), L0_buffer::OUTGOING));

	std::string send_msg(512*32, 'T');
	ConnectSocket->send(send_msg);
	std::this_thread::sleep_for(std::chrono::seconds(30));
	std::string ret("");
	AcceptSocket->recv(ret, 512);


	std::thread([ConnectSocket, send_msg]()
	{ 
		typedef std::chrono::nanoseconds nanoseconds;
		typedef std::chrono::duration<double> seconds;
		typedef std::random_device generator;
		generator gen;
		std::exponential_distribution<> dist(3);

		for (size_t i = 0; i < 32; i++)
		{
			ConnectSocket->send(send_msg, 512, 512);
			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
		}
		
	}).detach();

	std::thread([AcceptSocket, send_msg]()
	{
		typedef std::chrono::nanoseconds nanoseconds;
		typedef std::chrono::duration<double> seconds;
		typedef std::random_device generator;
		generator gen;
		std::exponential_distribution<> dist(3);
		std::string ret("");
		for (size_t i = 0; i < 32; i++)
		{
			AcceptSocket->recv(ret, 512);
			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
		}
	}).join();

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	delete AcceptSocket;
	delete ConnectSocket;

	ListenSocket->shutdown(SD_RECEIVE);
}

void test8(bool drop = false) 
{
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (arp and ether src bb:bb:bb:bb:bb:bb) or (arp and ether src cc:cc:cc:cc:cc:cc) or (arp and ether src dd:dd:dd:dd:dd:dd) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address

	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // Inserting my address

	/* Client is declared similarly: */
	inet_os inet_client_2 = inet_os();
	NIC nic_client_2(
		inet_client_2,
		"10.0.0.22",
		"cc:cc:cc:cc:cc:cc",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src cc:cc:cc:cc:cc:cc)");

	L2_impl datalink_client_2(inet_client_2);
	L2_ARP_impl arp_client_2(inet_client_2, 10, 10000);
	inet_client_2.inetsw(new L3_impl(inet_client_2, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client_2.inetsw(new L4_TCP_impl(inet_client_2), protosw::SWPROTO_TCP);
	inet_client_2.inetsw(new L3_impl(inet_client_2, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client_2.domaininit();
	arp_client_2.insertPermanent(nic_client_2.ip_addr().s_addr, nic_client_2.mac()); // Inserting my address

	/* Client is declared similarly: */
	inet_os inet_client_3 = inet_os();
	NIC nic_client_3(
		inet_client_3,
		"10.0.0.33",
		"dd:dd:dd:dd:dd:dd",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src dd:dd:dd:dd:dd:dd)");

	L2_impl datalink_client_3(inet_client_3);
	L2_ARP_impl arp_client_3(inet_client_3, 10, 10000);
	inet_client_3.inetsw(new L3_impl(inet_client_3, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client_3.inetsw(new L4_TCP_impl(inet_client_3), protosw::SWPROTO_TCP);
	inet_client_3.inetsw(new L3_impl(inet_client_3, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client_3.domaininit();
	arp_client_3.insertPermanent(nic_client_3.ip_addr().s_addr, nic_client_3.mac()); // Inserting my address

	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect(0U);
	inet_client.connect(0U);
	inet_client_2.connect(0U);
	inet_client_3.connect(0U);

	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket_2(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client_2));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService_2;
	clientService_2.sin_family = AF_INET;
	clientService_2.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService_2.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket_2->connect((SOCKADDR *)& clientService_2, sizeof(clientService_2));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket_2 = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket_2 = ListenSocket->accept(nullptr, nullptr);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket_3(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client_3));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService_3;
	clientService_3.sin_family = AF_INET;
	clientService_3.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService_3.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket_3->connect((SOCKADDR *)& clientService_3, sizeof(clientService_3));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket_3 = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket_3 = ListenSocket->accept(nullptr, nullptr);

	if (drop)
	{
		//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.9, L0_buffer::exponential_distribution_args(1)));
		inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::exponential_distribution_args(1)));
		inet_client_2.cable()->set_buf(new L0_buffer(inet_client_2, 0.9, L0_buffer::exponential_distribution_args(1)));
		//inet_client_3.cable()->set_buf(new L0_buffer(inet_client_3, 0.9));
	}


	string recv_msg("");
	string send_msg;

	send_msg = "B: Hi, I am B!";
	ConnectSocket->send(send_msg, send_msg.size());
	AcceptSocket->recv(recv_msg, send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	string welcome_msg = string("A: Hi, I am a simple chat server. I currently hold: ")
		+ inet_client.nic()->mac().to_string() + ","
		+ inet_client_2.nic()->mac().to_string() + ", "
		+ inet_client_3.nic()->mac().to_string() + ". With whom would you like to speak ?";

	AcceptSocket->send(welcome_msg, welcome_msg.size());
	ConnectSocket->recv(recv_msg = "", welcome_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "B: C"; // C

	ConnectSocket->send(send_msg, send_msg.size());
	AcceptSocket->recv(recv_msg = "", send_msg.size());

	send_msg = "A: Please send the message dedicated for C.";

	AcceptSocket->send(send_msg, send_msg.size());
	ConnectSocket->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "B: Hi C, How are you ?"; //"Hi " + keep + ", How are you ?"

	ConnectSocket->send(send_msg, send_msg.size());
	AcceptSocket->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_2->send(send_msg, send_msg.size());
	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "C: fine, thank you. what about D? I'll check on him."; // fine, thank you. what about D? I'll check on him.

	ConnectSocket_2->send(send_msg, send_msg.size());
	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket->send(send_msg, send_msg.size());
	ConnectSocket->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "B: Ok I won't bug you anymore. Update me on D status."; // Ok I won't bug you anymore. Update me on D status.

	ConnectSocket->send(send_msg, send_msg.size());
	AcceptSocket->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_2->send(send_msg, send_msg.size());
	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "C: Hey D, Knock knock.";
	ConnectSocket_2->send(send_msg, send_msg.size());
	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_3->send(send_msg, send_msg.size());
	ConnectSocket_3->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "D: Who's there?"; // “Who’s there?”

	ConnectSocket_3->send(send_msg, send_msg.size());
	AcceptSocket_3->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_2->send(send_msg, send_msg.size());
	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "C: Little old lady."; // Little old lady.
	ConnectSocket_2->send(send_msg, send_msg.size());
	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_3->send(send_msg, send_msg.size());
	ConnectSocket_3->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "D: Little old lady who?"; // Little old lad who?

	ConnectSocket_3->send(send_msg, send_msg.size());
	AcceptSocket_3->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_2->send(send_msg, send_msg.size());
	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "C: I didn't know you could yodel..."; // I didn't know you could yodel...
	ConnectSocket_2->send(send_msg, send_msg.size());
	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_3->send(send_msg, send_msg.size());
	ConnectSocket_3->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "D: Ha Ha..."; // Ha Ha!

	ConnectSocket_3->send(send_msg, send_msg.size());
	AcceptSocket_3->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_2->send(send_msg, send_msg.size());
	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "C: Hey, D still got a sense of humor!"; // Hey, D still got a sence of humor!

	ConnectSocket_2->send(send_msg, send_msg.size());
	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket->send(send_msg, send_msg.size());
	ConnectSocket->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = "B: If you told him your yodel knock-knock joke, its not considered humor at all...";
	ConnectSocket->send(send_msg, send_msg.size());
	AcceptSocket->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();

	send_msg = string("A: Incoming message from ") + recv_msg;
	AcceptSocket_2->send(send_msg, send_msg.size());
	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
	inet_server.print_mutex.lock();
	cout << recv_msg << endl;
	inet_server.print_mutex.unlock();






	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();
	inet_client_2.stop_fasttimo();
	inet_client_2.stop_slowtimo();
	inet_client_3.stop_fasttimo();
	inet_client_3.stop_slowtimo();
	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	ConnectSocket->shutdown(SD_BOTH);
	AcceptSocket->shutdown(SD_BOTH);

	ConnectSocket_2->shutdown(SD_BOTH);
	AcceptSocket_2->shutdown(SD_BOTH);

	ConnectSocket_3->shutdown(SD_BOTH);
	AcceptSocket_3->shutdown(SD_BOTH);

	ListenSocket->shutdown(SD_RECEIVE);

	delete ConnectSocket;
	delete ConnectSocket_2;
	delete ConnectSocket_3;

	delete AcceptSocket;
	delete AcceptSocket_2;
	delete AcceptSocket_3;

}

void test9() { return test8(true); }

void test10() 
{
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client




	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect();
	inet_client.connect();

	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.5, L0_buffer::exponential_distribution_args(5)));
	//inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::exponential_distribution_args(0.5)));
	inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.5, L0_buffer::uniform_real_distribution_args(0.5, 5), L0_buffer::OUTGOING));
	inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::uniform_real_distribution_args(0.5, 5), L0_buffer::OUTGOING));

	std::string send_msg(512, 'T');
	std::thread([ConnectSocket, send_msg]()
	{
		typedef std::chrono::nanoseconds nanoseconds;
		typedef std::chrono::duration<double> seconds;
		typedef std::random_device generator;
		generator gen;
		std::exponential_distribution<> dist(3);

		for (size_t i = 0; i < 32; i++)
		{
			ConnectSocket->send(send_msg, 512, 512);
			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
		}

	}).detach();

	std::thread([AcceptSocket, send_msg]()
	{
		typedef std::chrono::nanoseconds nanoseconds;
		typedef std::chrono::duration<double> seconds;
		typedef std::random_device generator;
		generator gen;
		std::exponential_distribution<> dist(3);
		std::string ret("");
		for (size_t i = 0; i < 32; i++)
		{
			AcceptSocket->recv(ret, 512);
			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
		}
	}).join();

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	ListenSocket->shutdown(SD_RECEIVE);
}

void test11() {
	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);

	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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

	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client




	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect();
	inet_client.connect();

	// The socket address to be passed to bind
	sockaddr_in service;

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);

	std::string send_msg(250*1024, 'T');

	std::thread([ConnectSocket, send_msg]()
	{
		ConnectSocket->send(send_msg, send_msg.size(), 512);
	}).detach();
	
	std::this_thread::sleep_for(std::chrono::seconds(180));
	std::string ret("");
	AcceptSocket->recv(ret, send_msg.size());

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(1));

	ListenSocket->shutdown(SD_RECEIVE);
}

void handler(int request) 
{
	int packet_size(0), num(0);
	char remember('Y');
	switch (request)
	{
	case 1:
		return test1();
		break;
	case 2:
		return test2();
		break;
	case 3:
		std::cout << "Please insert the wanted packet size or 0 to use the default (32):" << std::endl;
		std::cin >> packet_size;
		if (packet_size == 0)
			packet_size = 32;
		std::cout << "Please insert the wanted number of times to send the packet or 0 to use the default (5):" << std::endl;
		std::cin >> num;
		if (num == 0)
			num = 5;
		return test3(packet_size, num);
		break;
	case 4:
		std::cout << "Did you remember to define the mac buffer size in L5.h [Y/N] ?" << std::endl;
		std::cin >> remember;
		if (remember == 'N')
		{
			std::cout << "Then change it and try again, closing program." << std::endl;
			std::this_thread::sleep_for(std::chrono::seconds(3));
			return;
		}
		std::cout << "Please insert the wanted packet size in MB, or 0 to use the default (256):" << std::endl;
		std::cin >> packet_size;
		if (packet_size > 256)
		{
			std::cout << "Max size is 256, using 256MB as packet size." << std::endl;
			packet_size = 256;
		}
		return test4(packet_size);
		break;
	case 5:
		return test5();
		break;
	case 6:
		return test6();
		break;
	case 7:
		return test7();
		break;
	case 8:
		return test8();
		break;
	case 9:
		return test9();
		break;
	case 10:
		return test10();
		break;
	default:
		return;
		break;
	}
}

void main() 
{
	std::cout << "Hello and Welcome to the test Unit!" << std::endl <<
		"Please insert the wanted test number:" << std::endl <<
		"[1] Resolving an IP address Using ARP" << std::endl <<
		"[2] Opening a TCP Connection Using the TCP 3-way Handshake" << std::endl <<
		"[3] Sending a Small Packet Using TCP" << std::endl <<
		"[4] Sending a Large Packet Using TCP" << std::endl <<
		"[5] Closing a TCP Connection" << std::endl <<
		"[6] Shutting Down a TCP Connection" << std::endl <<
		"[7] Combined Test: Unreliable and Delayed Channel" << std::endl <<
		"[8] Application Use Case" << std::endl <<
		"[9] Application Use Case (with drop)" << std::endl <<
		"[10] Cwnd Fall Test" << std::endl;

	int request(0);
	std::cin >> request;
	while (request)
	{

		handler(request);
		std::cout << "Please insert another test number, or 0 to terminate." << std::endl;
		std::cin >> request;
	}
	return;


	std::this_thread::sleep_for(std::chrono::seconds(5));

	/* Declaring the server */
	inet_os inet_server = inet_os();

	/* Declaring the server's NIC */
	NIC nic_server(
		inet_server,			// Binding this NIC to our server
		"10.0.0.10",			// Giving it an IP address
		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
		nullptr,				// Using my real machine default gateway address.
		nullptr,				// Using my real machine broadcast address.
		true,					// Setting the NIC to be in promisc mode
		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
	
	/* Declaring the server's datalink using my L2_impl */
	L2_impl datalink_server(inet_server);
	
	/* Declaring the server's arp using my L2_ARP_impl */
	L2_ARP_impl arp_server(
		inet_server,	// Binding this NIC to our server
		10,			// arp_maxtries parameter
		10000);		// arpt_down parameter

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
	
	/* Client is declared similarly: */
	inet_os inet_client = inet_os();
	NIC nic_client(
		inet_client,
		"10.0.0.15",
		"bb:bb:bb:bb:bb:bb",
		nullptr,
		nullptr,
		true,
		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
	
	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client

	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect(0U);
	inet_client.connect(0U);


	// The socket address to be passed to bind
	sockaddr_in service;
	
	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
	
	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	//----------------------
	// Bind the socket.
	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));

	//----------------------
	// Listen for incoming connection requests 
	// on the created socket
	// 
	ListenSocket->listen(5);

	//----------------------
	// Create a SOCKET for connecting to server
	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);

	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl *AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
	
	



	std::string re("");
	ConnectSocket->shutdown(SD_SEND);
	//std::this_thread::sleep_for(std::chrono::seconds(5));
	try 
	{
		ConnectSocket->send(string(1024, 'T'));
	}
	catch (runtime_error &e)
	{
		cout << e.what() << endl;
	}
	AcceptSocket->shutdown(SD_RECEIVE);
	//std::this_thread::sleep_for(std::chrono::seconds(5));
	
	try
	{
		AcceptSocket->recv(re, 1024);
	}
	catch (runtime_error &e)
	{
		cout << e.what() << endl;
	}
	
	AcceptSocket->shutdown(SD_SEND);
	//std::this_thread::sleep_for(std::chrono::seconds(5));
	try
	{
		AcceptSocket->send(string(1024, 'T'));
	}
	catch (runtime_error &e)
	{
		cout << e.what() << endl;
	}
	ConnectSocket->shutdown(SD_RECEIVE);
	//std::this_thread::sleep_for(std::chrono::seconds(5));
	try
	{
		ConnectSocket->recv(re, 1024);
	}
	catch (runtime_error &e)
	{
		cout << e.what() << endl;
	}

	std::this_thread::sleep_for(std::chrono::seconds(5));
	AcceptSocket->shutdown(SD_SEND);	
	std::this_thread::sleep_for(std::chrono::seconds(5));
	

	std::this_thread::sleep_for(std::chrono::seconds(5));
	ConnectSocket->shutdown(SD_RECEIVE);
	std::this_thread::sleep_for(std::chrono::seconds(5));
	//ConnectSocket->shutdown(SD_RECEIVE);
	delete AcceptSocket;
	
	std::this_thread::sleep_for(std::chrono::seconds(60));
	ConnectSocket->shutdown(SD_BOTH);
	AcceptSocket->shutdown(SD_BOTH);

	delete AcceptSocket;
	delete ConnectSocket;

	int str_size(256*1024);
	std::string send_str(str_size, 'T');
	std::string ret("");

	ConnectSocket->send(send_str);

	for (size_t i = 0; i < 30; i++)
	{
		std::this_thread::sleep_for(std::chrono::seconds(10));
		inet_client.print_mutex.lock();
		std::this_thread::sleep_for(std::chrono::seconds(1));
		inet_client.print_mutex.unlock();
		inet_server.print_mutex.lock();
		std::this_thread::sleep_for(std::chrono::seconds(1));
		inet_server.print_mutex.unlock();

	}

	AcceptSocket->recv(ret, str_size);
	
	std::this_thread::sleep_for(std::chrono::seconds(60));

	int iResult = 0;            // used to return function results
	
	//int server;
	//std::cin >> server;
	//if (server)
	//{

		







	/*}
	else
	{*/



	//}
	
	
	//send_syn(IPv4Address("172.16.65.131"), 8888, datalink);
	//Sleep(2000);
	//send_ack(IPv4Address("172.16.65.131"), 8888, datalink);



	int retFlag(0);
	
//	int stop;
	//Sleep(3000);
	
	std::thread([ConnectSocket, send_str]() { ConnectSocket->send(send_str, 1024); }).detach();
	std::this_thread::sleep_for(std::chrono::seconds(20));

	std::thread([AcceptSocket, str_size]()
	{ 
		std::string ret("");
		AcceptSocket->recv(ret, str_size, 1);
		std::cout << "received buffer of size: " << std::to_string(ret.size()) << std::endl;
	}).detach();
	std::this_thread::sleep_for(std::chrono::seconds(150));
	AcceptSocket->recv(ret, str_size);
	std::cout << "received buffer of size: " << std::to_string(ret.size()) << std::endl;
	
	//ConnectSocket->sosend(send_str);
	Sleep(5000);
	Sleep(15000);
	ConnectSocket->shutdown(SD_SEND);
	Sleep(5000);
	AcceptSocket->shutdown(SD_RECEIVE);
	Sleep(15000);
	pthread_mutex_t _mutex;
	pthread_mutex_init(&_mutex, NULL);
	pthread_mutex_lock(&_mutex);
	pthread_mutex_lock(&_mutex);
	delete AcceptSocket;
	Sleep(5000);
	delete ListenSocket;
	//ListenSocket->shutdown(SD_RECEIVE);
	
	//AcceptSocket->shutdown(SD_RECEIVE);

	// shutdown the connection since no more data will be sent
	//ConnectSocket->shutdown(2);
	//delete ConnectSocket;
	int f(0);
	// Receive until the peer closes the connection
	do {
		ret = "";
		ConnectSocket->recv(ret, 1024, f, 1024);
		if (ret != "")
			std::cout << "Bytes received: " << ret.size() << " = " << ret << endl;

	} while (ret != "");


	// close the socket
	delete ConnectSocket;
	
	Sleep(1000);
	//ConnectSocket->soreceive_stream(ret, send_str.size(), retFlag);
	//std::cin >> stop;
	//AcceptSocket->sosend(nullptr, send_str, nullptr, 0);
	//std::cin >> stop;
	////Sleep(5000);
	//ConnectSocket->soreceive_stream(ret, send_str.size(), retFlag);
	//std::cin >> stop;

	return;

	ConnectSocket->shutdown(2);
	Sleep(5000);
	delete ConnectSocket;
	Sleep(5000);
	delete AcceptSocket;
	Sleep(5000);

	//pthread_mutex_t _mutex;
	//pthread_mutex_init(&_mutex, NULL);
	//pthread_mutex_lock(&_mutex);
	//pthread_mutex_lock(&_mutex);
	
	/* L4 tries to resolves destination IP address, if it can't it passes NULL string to L3.*/
	//sendToL3(toSend, icmp_pdu.size(), resolvedSrcIP.to_string(), resolvedDestIP.to_string());
	//Transport->sendToL4((byte *)test, testLen, dstIP, "");
	byte* readData = new byte[1500];
	

	//Transport->readFromL4(readData, 1500);
	//inet.print_lock();
	//cout << string((char*)readData, testLen) << endl;
	//inet.print_unlock();


	int argc = 4;
	//char *argv[3] = { "", "172.16.65.131", "8888"};
	char *argv[4] = { "", "10.0.0.11", "9998", "9999" };
	//if (argc < 3 && cout << "Usage: " << *argv << " <IPADDR> <port1> [port2] [port3]\n")
	//	return 1;
	try {
		//scan(argc, argv, datalink);
	}
	catch (std::runtime_error &ex) {
		cout << "Error - " << ex.what() << endl;
	}

	delete ListenSocket;
	return;
}




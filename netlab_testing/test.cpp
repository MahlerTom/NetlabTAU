#include "pch.h"
#include "../netlab/inet_os.hpp"

#include "../netlab/NIC.h"
#include "../netlab/L2.h"
#include "../netlab/L2_ARP.h"
#include "../netlab/L4.h"
#include "../netlab/L4_TCP.h"

#include <iostream>

#include "../netlab/NIC_Cable.h"
#include "../netlab/L0_buffer.h"


#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>

using namespace std;

TEST(test1, TestName) {
    /* Declaring the server */
    inet_os inet_server = inet_os();

    /* Declaring the server's NIC */
    NIC nic_server(
    inet_server,         // Binding this NIC to our server
    "10.0.0.10",         // Giving it an IP address
    "aa:aa:aa:aa:aa:aa", // Givinig it a MAC address
    nullptr,             // Using my real machine default gateway address.
    nullptr,             // Using my real machine broadcast address.
    true,                // Setting the NIC to be in promisc mode
    "(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether "
    "src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.

    /* Declaring the server's datalink using my L2_impl */
    L2_impl datalink_server(inet_server);

    /* Declaring the server's arp using my L2_ARP_impl */
    L2_ARP_impl arp_server(inet_server, // Binding this NIC to our server
                            10,          // arp_maxtries parameter
                            10000);      // arpt_down parameter

    /* Declaring protocols is a bit different: */
    inet_server.inetsw(
    new L3_impl(inet_server, 0, 0, 0), // A default IP layer is defined, using
                                        // my L3_impl, as in a real BSD system
    protosw::SWPROTO_IP); // I place the layer in the appropriate place, though
                            // any place should do.
    inet_server.inetsw(
    new L4_TCP_impl(
        inet_server),        // Defining the TCP Layer using my L4_TCP_impl
    protosw::SWPROTO_TCP); // Placing it in the appropriate place.
    inet_server.inetsw(
    new L3_impl(   // The actual IP layer we will use.
        inet_server, // Binding this NIC to our server
        SOCK_RAW,    // The protocol type
        IPPROTO_RAW, // The protocol
        protosw::PR_ATOMIC | protosw::PR_ADDR), // Protocol flags
    protosw::SWPROTO_IP_RAW); // Placing it in the appropriate place.

    inet_server
    .domaininit(); // This calls each pr_init() for each defined protocol.

    arp_server.insertPermanent(nic_server.ip_addr().s_addr,
                                nic_server.mac()); // Inserting my address

    /* Client is declared similarly: */
    inet_os inet_client = inet_os();
    NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr,
                    nullptr, true,
                    "(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and "
                    "not ether src bb:bb:bb:bb:bb:bb)");

    L2_impl datalink_client(inet_client);
    L2_ARP_impl arp_client(inet_client, 10, 10000);
    inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
    inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
    inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW,
                                    protosw::PR_ATOMIC | protosw::PR_ADDR),
                        protosw::SWPROTO_IP_RAW);
    inet_client.domaininit();
    arp_client.insertPermanent(nic_client.ip_addr().s_addr,
                                nic_client.mac()); // My

    /* Spawning both sniffers, 0U means continue forever */
    inet_server.connect(0U);
    inet_client.connect(0U);

    // The socket address to be passed to bind
    sockaddr_in service;

    //----------------------
    // Create a SOCKET for listening for
    // incoming connection requests
    netlab::L5_socket_impl* ListenSocket(new netlab::L5_socket_impl(
    AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound.
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
    service.sin_port = htons(8888);

    //----------------------
    // Bind the socket.
    ListenSocket->bind((SOCKADDR*)&service, sizeof(service));

    //----------------------
    // Listen for incoming connection requests
    // on the created socket
    //
    ListenSocket->listen(5);

    //----------------------
    // Create a SOCKET for connecting to server
    netlab::L5_socket_impl* ConnectSocket(new netlab::L5_socket_impl(
    AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port of the server to be connected to.
    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
    clientService.sin_port = htons(8888);

    //----------------------
    // Connect to server.
    ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));

    //----------------------
    // Create a SOCKET for accepting incoming requests.
    netlab::L5_socket_impl* AcceptSocket = nullptr;

    //----------------------
    // Accept the connection.
    AcceptSocket = ListenSocket->accept(nullptr, nullptr);

    inet_client.stop_fasttimo();
    inet_client.stop_slowtimo();

    inet_server.stop_fasttimo();
    inet_server.stop_slowtimo();
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ListenSocket->shutdown(SD_RECEIVE);
    EXPECT_EQ(1, 1);
    EXPECT_TRUE(true);
}

//TEST(test2, TestName)
//{
//  /* Declaring the server */
//  inet_os inet_server = inet_os();
//
//  /* Declaring the server's NIC */
//  NIC nic_server(
//    inet_server,         // Binding this NIC to our server
//    "10.0.0.10",         // Giving it an IP address
//    "aa:aa:aa:aa:aa:aa", // Givinig it a MAC address
//    nullptr,             // Using my real machine default gateway address.
//    nullptr,             // Using my real machine broadcast address.
//    true,                // Setting the NIC to be in promisc mode
//    "(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether "
//    "src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//  /* Declaring the server's datalink using my L2_impl */
//  L2_impl datalink_server(inet_server);
//
//  /* Declaring the server's arp using my L2_ARP_impl */
//  L2_ARP_impl arp_server(inet_server, // Binding this NIC to our server
//                         10,          // arp_maxtries parameter
//                         10000);      // arpt_down parameter
//
//  /* Declaring protocols is a bit different: */
//  inet_server.inetsw(
//    new L3_impl(inet_server, 0, 0, 0), // A default IP layer is defined, using
//                                       // my L3_impl, as in a real BSD system
//    protosw::SWPROTO_IP); // I place the layer in the appropriate place, though
//                          // any place should do.
//  inet_server.inetsw(
//    new L4_TCP_impl(
//      inet_server),        // Defining the TCP Layer using my L4_TCP_impl
//    protosw::SWPROTO_TCP); // Placing it in the appropriate place.
//  inet_server.inetsw(
//    new L3_impl(   // The actual IP layer we will use.
//      inet_server, // Binding this NIC to our server
//      SOCK_RAW,    // The protocol type
//      IPPROTO_RAW, // The protocol
//      protosw::PR_ATOMIC | protosw::PR_ADDR), // Protocol flags
//    protosw::SWPROTO_IP_RAW); // Placing it in the appropriate place.
//
//  inet_server
//    .domaininit(); // This calls each pr_init() for each defined protocol.
//
//  arp_server.insertPermanent(nic_server.ip_addr().s_addr,
//                             nic_server.mac()); // Inserting my address
//
//  /* Client is declared similarly: */
//  inet_os inet_client = inet_os();
//  NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr,
//                 nullptr, true,
//                 "(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and "
//                 "not ether src bb:bb:bb:bb:bb:bb)");
//
//  L2_impl datalink_client(inet_client);
//  L2_ARP_impl arp_client(inet_client, 10, 10000);
//  inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//  inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//  inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW,
//                                 protosw::PR_ATOMIC | protosw::PR_ADDR),
//                     protosw::SWPROTO_IP_RAW);
//  inet_client.domaininit();
//  arp_client.insertPermanent(nic_client.ip_addr().s_addr,
//                             nic_client.mac()); // My
//
//  arp_client.insertPermanent(nic_server.ip_addr().s_addr,
//                             nic_server.mac()); // server
//  arp_server.insertPermanent(nic_client.ip_addr().s_addr,
//                             nic_client.mac()); // client
//
//  /* Spawning both sniffers, 0U means continue forever */
//  inet_server.connect(0U);
//  inet_client.connect(0U);
//
//  // The socket address to be passed to bind
//  sockaddr_in service;
//
//  //----------------------
//  // Create a SOCKET for listening for
//  // incoming connection requests
//  netlab::L5_socket_impl* ListenSocket(new netlab::L5_socket_impl(
//    AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//  //----------------------
//  // The sockaddr_in structure specifies the address family,
//  // IP address, and port for the socket that is being bound.
//  service.sin_family = AF_INET;
//  service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//  service.sin_port = htons(8888);
//
//  //----------------------
//  // Bind the socket.
//  ListenSocket->bind((SOCKADDR*)&service, sizeof(service));
//
//  //----------------------
//  // Listen for incoming connection requests
//  // on the created socket
//  //
//  ListenSocket->listen(5);
//
//  //----------------------
//  // Create a SOCKET for connecting to server
//  netlab::L5_socket_impl* ConnectSocket(new netlab::L5_socket_impl(
//    AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//  //----------------------
//  // The sockaddr_in structure specifies the address family,
//  // IP address, and port of the server to be connected to.
//  sockaddr_in clientService;
//  clientService.sin_family = AF_INET;
//  clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//  clientService.sin_port = htons(8888);
//
//  //----------------------
//  // Connect to server.
//  ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//
//  //----------------------
//  // Create a SOCKET for accepting incoming requests.
//  netlab::L5_socket_impl* AcceptSocket = nullptr;
//
//  //----------------------
//  // Accept the connection.
//  AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//  inet_client.stop_fasttimo();
//  inet_client.stop_slowtimo();
//
//  inet_server.stop_fasttimo();
//  inet_server.stop_slowtimo();
//  std::this_thread::sleep_for(std::chrono::seconds(1));
//
//  ListenSocket->shutdown(SD_RECEIVE);
//}
//
//TEST(test3, TestName)
//{
//  size_t size = 32;
//  size_t num = 5;
//  /* Declaring the server */
//  inet_os inet_server = inet_os();
//
//  /* Declaring the server's NIC */
//  NIC nic_server(
//    inet_server,         // Binding this NIC to our server
//    "10.0.0.10",         // Giving it an IP address
//    "aa:aa:aa:aa:aa:aa", // Givinig it a MAC address
//    nullptr,             // Using my real machine default gateway address.
//    nullptr,             // Using my real machine broadcast address.
//    true,                // Setting the NIC to be in promisc mode
//    "(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether "
//    "src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//  /* Declaring the server's datalink using my L2_impl */
//  L2_impl datalink_server(inet_server);
//
//  /* Declaring the server's arp using my L2_ARP_impl */
//  L2_ARP_impl arp_server(inet_server, // Binding this NIC to our server
//                         10,          // arp_maxtries parameter
//                         10000);      // arpt_down parameter
//
//  /* Declaring protocols is a bit different: */
//  inet_server.inetsw(
//    new L3_impl(inet_server, 0, 0, 0), // A default IP layer is defined, using
//                                       // my L3_impl, as in a real BSD system
//    protosw::SWPROTO_IP); // I place the layer in the appropriate place, though
//                          // any place should do.
//  inet_server.inetsw(
//    new L4_TCP_impl(
//      inet_server),        // Defining the TCP Layer using my L4_TCP_impl
//    protosw::SWPROTO_TCP); // Placing it in the appropriate place.
//  inet_server.inetsw(
//    new L3_impl(   // The actual IP layer we will use.
//      inet_server, // Binding this NIC to our server
//      SOCK_RAW,    // The protocol type
//      IPPROTO_RAW, // The protocol
//      protosw::PR_ATOMIC | protosw::PR_ADDR), // Protocol flags
//    protosw::SWPROTO_IP_RAW); // Placing it in the appropriate place.
//
//  inet_server
//    .domaininit(); // This calls each pr_init() for each defined protocol.
//
//  arp_server.insertPermanent(nic_server.ip_addr().s_addr,
//                             nic_server.mac()); // Inserting my address
//
//  /* Client is declared similarly: */
//  inet_os inet_client = inet_os();
//  NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr,
//                 nullptr, true,
//                 "(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and "
//                 "not ether src bb:bb:bb:bb:bb:bb)");
//
//  L2_impl datalink_client(inet_client);
//  L2_ARP_impl arp_client(inet_client, 10, 10000);
//  inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//  inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//  inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW,
//                                 protosw::PR_ATOMIC | protosw::PR_ADDR),
//                     protosw::SWPROTO_IP_RAW);
//  inet_client.domaininit();
//  arp_client.insertPermanent(nic_client.ip_addr().s_addr,
//                             nic_client.mac()); // My
//
//  arp_client.insertPermanent(nic_server.ip_addr().s_addr,
//                             nic_server.mac()); // server
//  arp_server.insertPermanent(nic_client.ip_addr().s_addr,
//                             nic_client.mac()); // client
//
//  /* Spawning both sniffers, 0U means continue forever */
//  inet_server.connect();
//  inet_client.connect();
//
//  // The socket address to be passed to bind
//  sockaddr_in service;
//
//  //----------------------
//  // Create a SOCKET for listening for
//  // incoming connection requests
//  netlab::L5_socket_impl* ListenSocket(new netlab::L5_socket_impl(
//    AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//  //----------------------
//  // The sockaddr_in structure specifies the address family,
//  // IP address, and port for the socket that is being bound.
//  service.sin_family = AF_INET;
//  service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//  service.sin_port = htons(8888);
//
//  //----------------------
//  // Bind the socket.
//  ListenSocket->bind((SOCKADDR*)&service, sizeof(service));
//
//  //----------------------
//  // Listen for incoming connection requests
//  // on the created socket
//  //
//  ListenSocket->listen(5);
//
//  //----------------------
//  // Create a SOCKET for connecting to server
//  netlab::L5_socket_impl* ConnectSocket(new netlab::L5_socket_impl(
//    AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//  //----------------------
//  // The sockaddr_in structure specifies the address family,
//  // IP address, and port of the server to be connected to.
//  sockaddr_in clientService;
//  clientService.sin_family = AF_INET;
//  clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//  clientService.sin_port = htons(8888);
//
//  //----------------------
//  // Connect to server.
//  ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//
//  //----------------------
//  // Create a SOCKET for accepting incoming requests.
//  netlab::L5_socket_impl* AcceptSocket = nullptr;
//
//  //----------------------
//  // Accept the connection.
//  AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//  std::string send_msg(size, 'T');
//  std::thread([ConnectSocket, send_msg, num, size]() {
//    typedef std::chrono::nanoseconds nanoseconds;
//    typedef std::chrono::duration<double> seconds;
//    typedef std::random_device generator;
//    generator gen;
//    std::exponential_distribution<> dist(3);
//
//    for (size_t i = 0; i < num; i++) {
//      ConnectSocket->send(send_msg, size, size);
//      std::this_thread::sleep_for(
//        std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//    }
//  }).detach();
//
//  typedef std::chrono::nanoseconds nanoseconds;
//  typedef std::chrono::duration<double> seconds;
//  typedef std::random_device generator;
//  generator gen;
//  std::exponential_distribution<> dist(3);
//  std::string ret("");
//  for (size_t i = 0; i < num; i++) {
//    AcceptSocket->recv(ret, size);
//    std::this_thread::sleep_for(
//      std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//  }
//
//  inet_client.stop_fasttimo();
//  inet_client.stop_slowtimo();
//
//  inet_server.stop_fasttimo();
//  inet_server.stop_slowtimo();
//  std::this_thread::sleep_for(std::chrono::seconds(1));
//}

//TEST(test4, TestName)
//{
//  size_t size = 256;
//  size *= 1024;
//  /* Declaring the server */
//  inet_os inet_server = inet_os();
//
//  /* Declaring the server's NIC */
//  NIC nic_server(
//    inet_server,         // Binding this NIC to our server
//    "10.0.0.10",         // Giving it an IP address
//    "aa:aa:aa:aa:aa:aa", // Givinig it a MAC address
//    nullptr,             // Using my real machine default gateway address.
//    nullptr,             // Using my real machine broadcast address.
//    true,                // Setting the NIC to be in promisc mode
//    "(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether "
//    "src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//  /* Declaring the server's datalink using my L2_impl */
//  L2_impl datalink_server(inet_server);
//
//  /* Declaring the server's arp using my L2_ARP_impl */
//  L2_ARP_impl arp_server(inet_server, // Binding this NIC to our server
//                         10,          // arp_maxtries parameter
//                         10000);      // arpt_down parameter
//
//  /* Declaring protocols is a bit different: */
//  inet_server.inetsw(
//    new L3_impl(inet_server, 0, 0, 0), // A default IP layer is defined, using
//                                       // my L3_impl, as in a real BSD system
//    protosw::SWPROTO_IP); // I place the layer in the appropriate place, though
//                          // any place should do.
//  inet_server.inetsw(
//    new L4_TCP_impl(
//      inet_server),        // Defining the TCP Layer using my L4_TCP_impl
//    protosw::SWPROTO_TCP); // Placing it in the appropriate place.
//  inet_server.inetsw(
//    new L3_impl(   // The actual IP layer we will use.
//      inet_server, // Binding this NIC to our server
//      SOCK_RAW,    // The protocol type
//      IPPROTO_RAW, // The protocol
//      protosw::PR_ATOMIC | protosw::PR_ADDR), // Protocol flags
//    protosw::SWPROTO_IP_RAW); // Placing it in the appropriate place.
//
//  inet_server
//    .domaininit(); // This calls each pr_init() for each defined protocol.
//
//  arp_server.insertPermanent(nic_server.ip_addr().s_addr,
//                             nic_server.mac()); // Inserting my address
//
//  /* Client is declared similarly: */
//  inet_os inet_client = inet_os();
//  NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr,
//                 nullptr, true,
//                 "(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and "
//                 "not ether src bb:bb:bb:bb:bb:bb)");
//
//  L2_impl datalink_client(inet_client);
//  L2_ARP_impl arp_client(inet_client, 10, 10000);
//  inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//  inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//  inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW,
//                                 protosw::PR_ATOMIC | protosw::PR_ADDR),
//                     protosw::SWPROTO_IP_RAW);
//  inet_client.domaininit();
//  arp_client.insertPermanent(nic_client.ip_addr().s_addr,
//                             nic_client.mac()); // My
//
//  arp_client.insertPermanent(nic_server.ip_addr().s_addr,
//                             nic_server.mac()); // server
//  arp_server.insertPermanent(nic_client.ip_addr().s_addr,
//                             nic_client.mac()); // client
//
//  /* Spawning both sniffers, 0U means continue forever */
//  inet_server.connect();
//  inet_client.connect();
//
//  // The socket address to be passed to bind
//  sockaddr_in service;
//
//  //----------------------
//  // Create a SOCKET for listening for
//  // incoming connection requests
//  netlab::L5_socket_impl* ListenSocket(new netlab::L5_socket_impl(
//    AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//  //----------------------
//  // The sockaddr_in structure specifies the address family,
//  // IP address, and port for the socket that is being bound.
//  service.sin_family = AF_INET;
//  service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//  service.sin_port = htons(8888);
//
//  //----------------------
//  // Bind the socket.
//  ListenSocket->bind((SOCKADDR*)&service, sizeof(service));
//
//  //----------------------
//  // Listen for incoming connection requests
//  // on the created socket
//  //
//  ListenSocket->listen(5);
//
//  //----------------------
//  // Create a SOCKET for connecting to server
//  netlab::L5_socket_impl* ConnectSocket(new netlab::L5_socket_impl(
//    AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//  //----------------------
//  // The sockaddr_in structure specifies the address family,
//  // IP address, and port of the server to be connected to.
//  sockaddr_in clientService;
//  clientService.sin_family = AF_INET;
//  clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//  clientService.sin_port = htons(8888);
//
//  //----------------------
//  // Connect to server.
//  ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//
//  //----------------------
//  // Create a SOCKET for accepting incoming requests.
//  netlab::L5_socket_impl* AcceptSocket = nullptr;
//
//  //----------------------
//  // Accept the connection.
//  AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//  std::string send_msg(size, 'T');
//
//  // std::thread([ConnectSocket, send_msg, size]()
//  //{
//  //	ConnectSocket->send(send_msg, size);
//  // }).detach();
//  ConnectSocket->send(send_msg, size);
//  std::string ret("");
//  AcceptSocket->recv(ret, size);
//
//  inet_client.stop_fasttimo();
//  inet_client.stop_slowtimo();
//
//  inet_server.stop_fasttimo();
//  inet_server.stop_slowtimo();
//  std::this_thread::sleep_for(std::chrono::seconds(1));
//}

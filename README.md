# Netlab TAU

The purpose of this project is to create a full networking stack for an operating system that I call "inet_os", consisting of a C++ implementation of a full TCP/IP stack for educational purposes. 

The network stack includes OSI model layers: 
1. Layer 1, Physical layer (NIC)
2. Layer 2, Ethernet and ARP (L2, L2_ARP_impl)
3. Layer 3, IP (L3)
4. Layer 4, TCP (L4_TCP)
5. Layer 5, sockets (L5_socket)

The implementation is based on the [4.4BSD-Lite2](https://github.com/sergev/4.4BSD-Lite2) distribution, a UNIX based operating system, which is implemented in C. Using C++ instead of C was a huge step, however necessary in order to better implement the code, and provide a cleaner implementation. 

![alt text](https://github.com/tommahler/NetlabTAU/blob/master/documentation/readme/inet_os.jpg "inet_os, top view")

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Project was built using Visual Studio 2013, so its best to use it during the build process.



### Installing

1. Install [Visual Studio 2013](https://msdn.microsoft.com/en-us/library/dd831853(v=vs.120).aspx).
2. Download the NetlabTAU project.
3. Install latest version of [Boost](http://www.boost.org/users/download/).
4. Go to [pthreads-win32](http://sourceware.org/pthreads-win32/) and install latest version of pthread (For example, [pthreads-w32-2-9-1-release](ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.zip)).
5. Install latest version of [WinPcap Developer's Pack](https://www.winpcap.org/devel.htm) (`WpdPack`).


Configure Sniffer project build (debug and release):

For both debug and release configurations:
1. Go to `Sniffer -> Project properties -> VC++ Directories -> General -> Include Directories` and add path to:
	1. `WpdPack` library root (in my case `C:\Projects\WpdPack_4_1_2\Include`).
2. Go to `Sniffer -> Project properties -> C/C++ -> Preprocessor Definitions` and make sure that you have defined: `_SCL_SECURE_NO_WARNINGS`, `_CRT_SECURE_NO_WARNINGS`, `WIN32`, `_LIB`, and `_DEBUG` (for debug build) or `NDEBUG` (for release build).
3. Build Sniffer project in debug and release and make sure it works (don't run it, just build).

Configure NetlabTAU project build (debug and release):
1. Go to `NetlabTAU -> Project properties -> VC++ Directories -> General -> Include Directories` and add path to:
	1. `WpdPack` library root (in my case `C:\Projects\WpdPack_4_1_2\Include`).
	2. `boost` library root (in my case `C:\Projects\Boost_1_66_0`).
	3. `pthreads-win32` library root (in my case `C:\Projects\pthreads-w32-2-9-1-release\Pre-built.2\include`).
2. Go to `NetlabTAU -> Project properties -> C/C++ -> Preprocessor Definitions` and make sure that you have defined:
	1. For release: `_SCL_SECURE_NO_WARNINGS`, `_CRT_SECURE_NO_WARNINGS`, `WIN32`, `_LIB`, `_CONSOLE`, `BOOST_CB_DISABLE_DEBUG` and `_WINSOCK_DEPRECATED_NO_WARNINGS`.
	2. For debug, add the release definitions and add: `HAVE_REMOTE`, `_DEBUG`, `_WINDOWS`, `NOMINMAX` and `CMAKE_INTDIR="Debug"`.
3. Go to `NetlabTAU -> Project properties -> Linker -> Input -> Additional Dependencies` and add:
	1. The `Sniffer.lib` from `Debug\Sniffer.lib` (for debug) or from `Release\Sniffer.lib` (for release).
	2. The `wpcap.lib` from your `WpdPack` library (in my case `C:\Projects\WpdPack_4_1_2\Lib\wpcap.lib`). 
	3. The `pthreadVC2.lib` from your `pthreads-win32` library (in my case `C:\Projects\pthreads-w32-2-9-1-release\Pre-built.2\lib\x86\pthreadVC2.lib`).
	4. `Iphlpapi.lib`
	5. `ws2_32.lib`
4. Copy and paste `pthreadVC2.dll` from the `pthreads-win32` library (in my case `C:\Projects\pthreads-w32-2-9-1-release\Pre-built.2\dll\x86`) into the `NetlabTAU\Debug` and `NetlabTAU\Release` folders.
5. Build Netlab project in debug and release and make sure it works.

## Running the tests

The main program includes several tests:
1. Resolving an IP address Using ARP
2. Opening a TCP Connection Using the TCP 3-way Handshake
3. Sending a Small Packet Using TCP
4. Sending a Large Packet Using TCP
5. Closing a TCP Connection
6. Shutting Down a TCP Connection
7. Combined Test: Unreliable and Delayed Channel
8. Application Use Case
9. Application Use Case (with drop)
10. Cwnd Fall Test

More information will be added later

## Contributing

If you want to contribute, please ask email the author. Further instructions will be posted, if needed.


## Authors

* **Tom Mahler** - tommahler email address from Gmail.com.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

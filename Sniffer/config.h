#ifndef TINS_CONFIG_H
#define TINS_CONFIG_H

/* Define if the compiler supports basic C++11 syntax */
/* #undef HAVE_CXX11 */

/* Have IEEE 802.11 support */
#define HAVE_DOT11

/* Have WPA2 decryption library */
/* #undef HAVE_WPA2_DECRYPTION */

/* Use pcap_sendpacket to send l2 packets */
#define HAVE_PACKET_SENDER_PCAP_SENDPACKET

#endif // TINS_CONFIG_H

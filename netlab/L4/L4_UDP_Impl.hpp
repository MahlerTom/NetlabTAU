#pragma once

#include <iostream>
#include <fstream>
#include "L4_UDP.hpp"

class L4_UDP_Impl : public L4_UDP {
public:

/************************************************************************/
/*                         L4_UDP_Impl::udphdr                          */
/************************************************************************/

	struct udphdr {

		/*!

		\brief Definition of the UDP's header parts.

		\param	src_port_number	 	Two bytes used to represent the source port number.
		\param	dst_port_number   	Two bytes used to represent the destination port number.
		\param	udp_datagram_length   	Two bytes used to represent the length of the UDP datagram (header + data).
		\param	udp_checksum   	Two bytes used to represent the checksum of the UDP datagram.
		*/

		u_short src_port_number;
		u_short dst_port_number;
		u_short udp_datagram_length;
		u_short udp_checksum;

		udphdr()
			: src_port_number(0), dst_port_number(0), udp_datagram_length(0), udp_checksum(0) {}

		/*!
			\fn	friend std::ostream& operator<<(std::ostream &out, const struct udphdr &udp);

			\brief	Stream insertion operator.

			\param [in,out]	out	The output stream (usually std::cout).
			\param	tcp		   	The udphdr to printout.

			\return	The output stream, when #udp was inserted and printed.
		*/
		friend std::ostream& operator<<(std::ostream& out, const struct udphdr& udp);

	};

/************************************************************************/
/*                         L4_UDP_Impl::pseudo_header                   */
/************************************************************************/

	struct pseudo_header {

		struct ipovly
		{
			/*!
				\fn	ipovly()

				\brief	Default constructor.
			*/
			ipovly();

			/*!
				\fn
				ipovly(const u_char& ih_pr, const short &ih_len, const in_addr &ih_src, const in_addr &ih_dst)

				\brief	Constructor.

			\param	ih_pr	 	The ip header protocol.
			\param	ip_len   	The ip header parameter ip_len (total length).
			\param	ip_src   	The IP source address.
			\param	ip_dst   	The IP destination address.
			*/
			ipovly(const u_char& ih_pr, const short& ih_len, const in_addr& ih_src, const in_addr& ih_dst);

			/*!
				\fn
				friend std::ostream& operator<<(std::ostream &out, const struct tcpiphdr::ipovly &ip);

				\brief	Stream insertion operator.

				\param [in,out]	out	The output stream (usually std::cout).
				\param	ip		   	The ipovly to printout.

				\return	The output stream, when #ip was inserted and printed.
			*/

			friend std::ostream& operator<<(std::ostream& out, const struct pseudo_header::ipovly& ip);

			struct L4_UDP::pseudo_header* ih_next, * ih_prev;			/*!< for protocol sequence q's */
			u_char	ih_x1 = 0x00;		/*!< (unused) */
			u_char	ih_pr;				/*!< protocol */
			short	ih_len;				/*!< protocol length */
			struct	in_addr ih_src;		/*!< source internet address */
			struct	in_addr ih_dst;		/*!< destination internet address */
		};

		/*!
			\fn	pseudo_header()

			\brief	Default constructor.
		*/

		pseudo_header();

		/*!
			\fn
			udpiphdr(byte *m, const u_char& ih_pr, const short &ip_len, const in_addr &ip_src, const in_addr &ip_dst)

			\brief	Constructor from received packet, does the casting.

			\param [in,out]	m	If non-null, the byte to process.
			\param	ih_pr	 	The ip header protocol.
			\param	ip_len   	The ip header parameter ip_len (total length).
			\param	ip_src   	The IP source address.
			\param	ip_dst   	The IP destination address.
		*/

		pseudo_header(byte* m, const u_char& ih_pr, const short& ip_len, const in_addr& ip_src, const in_addr& ip_dst);

		/*!
			\fn	friend std::ostream& operator<<(std::ostream &out, const struct udpiphdr &ti)

			\brief	Stream insertion operator.

			\param [in,out]	out	The output stream (usually std::cout).
			\param	ti		   	The udphdr to printout.

			\return	The output stream, when #udp was inserted and printed.
		*/
		friend std::ostream& operator<<(std::ostream& out, const struct pseudo_header& ti);

		/*!
			\fn
			void udp_template(const struct in_addr &inp_faddr, const u_short &inp_fport, const struct in_addr &inp_laddr, const u_short &inp_lport)

			\brief
			Create template to be used to send UDP packets on a connection. Call after host entry
			created, allocates an mbuf and fills in a skeletal UDP/IP header, minimizing the amount
			of work necessary when the connection is used.

			\param	inp_faddr	The foreign host table entry
			\param	inp_fport	The foreign port.
			\param	inp_laddr	The local host table entry.
			\param	inp_lport	The local port.
		*/
		void udp_template(const struct in_addr& inp_faddr, const u_short& inp_fport, const struct in_addr& inp_laddr, const u_short& inp_lport);

	};

	/*!
		\pure	virtual void L4_UDP::pr_init() override;

		\brief	UDP initialization.
	*/
	virtual void pr_init() override;

	/*!
		\pure	virtual void L4_UDP::pr_input(const struct pr_input_args& args) override;

		\brief	UDP input routine: figure out what should be sent and send it.
	*/
	virtual void pr_input(const struct pr_input_args& args) override;

	/*!
		\pure	virtual int L4_UDP::pr_output(const struct pr_output_args &args) override;

		\brief
		UDP output routine: figure out what should be sent and send it.
	*/

	virtual int pr_output(const struct pr_output_args& args) override;

	/*!
		\pure virtual int L4_TCP::pr_usrreq(class netlab::socket *so, int req, std::shared_ptr<std::vector<byte>> &m, struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) override;

		\brief
		TCP's user-request function is called for sending data over UDP.

		\param [in,out]	so	   	If non-null, the socket that request something.
		\param	req			   	The request to perform (always send data in the case of UDP).
		\param [in,out]	m	   	The std::shared_ptr<std::vector<byte>> to process, generally the input data.
		\param [in,out]	nam	   	If non-null, the nam additional parameter, usually sockaddr.
		\param	nam_len		   	Length of the nam.
		\param [in,out]	control	The control (unused).

		\return	An int.
	*/

	virtual int pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) override;

/************************************************************************/
/*                         L4_UDP_Impl::udp_output_args                 */
/************************************************************************/

	struct udp_output_args
		: public pr_output_args
	{
		/*!
			\fn	udp_output_args(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, std::shared_ptr<std::vector<byte>> &opt, struct L3::route *ro, int flags, struct L3::ip_moptions *imo);

			\brief	Constructor.

			\param [in,out]	m  	The std::shared_ptr<std::vector<byte>> to process.
			\param [in,out]	it 	The iterator, maintaining the current offset in the vector.
			\param [in,out]
			\param [in,out]
			\param [in,out]
			\param [in,out]
		*/
		udp_output_args(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it);

		std::shared_ptr<std::vector<byte>>& m;		/*!< The std::shared_ptr<std::vector<byte>> to process. */
		std::vector<byte>::iterator& it;			/*!< The iterator, maintaining the current offset in the vector. */
	};

	int udp_output(const struct udp_output_args& args);

};



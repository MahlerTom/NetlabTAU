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
			
		in_addr ip_src_addr;
		in_addr ip_dst_addr;
		u_char	reserved = 0x00;		/*!< (unused) */
		u_char	protocol;				/*!< protocol */
		short	udp_length;				/*!< protocol length */

		/*!
			\fn
			udpiphdr(byte *m, const u_char& ih_pr, const short &ip_len, const in_addr &ip_src, const in_addr &ip_dst)

			\brief	Constructor from received packet, does the casting.

			\param [in,out]	m		If non-null, the byte to process.
			\param	protocol	 	The ip header protocol.
			\param	udp_length   	The udp header parameter udp_length (total length).
			\param	ip_src_addr   	The IP source address.
			\param	ip_dst_addr   	The IP destination address.
		*/

		pseudo_header(const in_addr& ip_src_addr, const in_addr& ip_dst_addr, const u_char& protocol, const short& udp_length);
	};

/************************************************************************/
/*                         L4_UDP_Impl									*/
/************************************************************************/

	typedef class netlab::L5_socket_impl socket;

	/*!
		\fn	L4_UDP_Impl::L4_UDP_Impl(class inet_os &inet)

		\brief	Constructor.

		\param [in,out]	inet	The inet.
	*/

	L4_UDP_Impl(class inet_os &inet);

	/*!
		\fn	L4_UDP_Impl::~L4_UDP_Impl()

		\brief	Deletes the UDP object.
	*/

	~L4_UDP_Impl();

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
		\fn	void L4_UDP_Impl::drop(class inpcb_impl *inp, const int dropsocket);

		\brief
		Drop UDP socket.

		\param [in,out]	inp	If non-null, the inp holding the socket to abort.
		\param	dropsocket 	The dropsocket.
	*/

	inline void drop(class inpcb_impl* inp, const int dropsocket);

	static inline int out(udpcb& up, int error);

	/*!
		\pure	virtual int L4_UDP::pr_output(const struct pr_output_args &args) override;

		\brief
		UDP output routine: figure out what should be sent and send it.
	*/

	virtual int pr_output(const struct pr_output_args& args) override;

	/*!
		\fn	int L4_UDP_Impl::udp_output(udpcb &up);

		\brief	The actual function, with the desired arguments.

		\note
		Most of the work is done by again, this separation was in order to avoid gotos.

		\param [in,out]	up	The udpcb of this connection.

		\return	An int, for error handling.
	*/

	inline int udp_output(udpcb &up);

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
		*/
		udp_output_args(udpcb &up);

		udpcb& up;
	};

	

private:

		uint16_t calculate_checksum(pseudo_header& udp_pseaudo_header, std::shared_ptr<std::vector<byte>>& m);
		class L4_UDP::udpcb ucb;
		class inpcb_impl* udp_last_inpcb;

		u_long	udp_sendspace;   /*!< The UDP send space */
		u_long	udp_recvspace;   /*!< The UDP recv space */

};



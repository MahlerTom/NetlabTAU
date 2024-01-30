//#ifndef NETLAB_L4_UDP_H
//#define NETLAB_L4_UDP_H

#pragma once

#include "L3.h"

class L4_UDP : public protosw {
public:

	/*!
		\struct	udphdr

		\brief	UDP header.

		\sa	Per RFC 768, August, 1980.
	*/
	struct udphdr; 

	/*!
		\struct	pseudo_header

		\brief	UDP pseudo header: UDP + IP header, after ip options removed.
	*/

	struct pseudo_header;

	/*!
		\fn	L4_UDP::L4_UDP(class inet_os &inet)

		\brief	Constructor.

		\param [in,out]	inet	The inet.
	*/

	L4_UDP(class inet_os& inet);

		//protosw(inet, SOCK_DGRAM, NULL, IPPROTO_UDP) { } 

	/*!
		\pure	virtual void L4_UDP::pr_init() = 0;

		\brief	UDP initialization.
	*/

	virtual void pr_init() = 0;

	/*!
		\pure	virtual void L4_UDP::pr_input(const struct pr_input_args& args) override;

		\brief	UDP input routine: figure out what should be sent and send it.
	*/

	virtual void pr_input(const struct pr_input_args& args) = 0;

	/*!
		\pure	virtual int L4_UDP::pr_output(const struct pr_output_args &args) = 0;

		\brief
		UDP output routine: figure out what should be sent and send it.
	*/

	virtual int pr_output(const struct pr_output_args& args) = 0;

	/*!
		\pure virtual int L4_TCP::pr_usrreq(class netlab::socket *so, int req, std::shared_ptr<std::vector<byte>> &m, struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) = 0;

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
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) = 0;
};

//#endif
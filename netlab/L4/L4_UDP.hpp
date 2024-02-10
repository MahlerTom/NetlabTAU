//#ifndef NETLAB_L4_UDP_H
//#define NETLAB_L4_UDP_H

#pragma once

#include "../L2/L2.h"
#include "../L3/L3.h"
#include "../infra/pcb.h"

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

	/*!
		\class	udpcb

		\brief	UDP control block, one per UDP.
	*/
	class udpcb;

	L4_UDP(class inet_os& inet);

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


private:

	/* Unused - protosw virtual functions */
	virtual void pr_drain() { }
	virtual void pr_fasttimo() { }
	virtual void pr_slowtimo() { }
	virtual int pr_sysctl() { return 0; }
	virtual void pr_ctlinput() { }
	virtual int pr_ctloutput() { return 0; }

};

class L4_UDP::udpcb : public inpcb_impl {

	friend class L4_UDP_Impl;

private:

	/*!
		\fn	explicit L4_UDP::udpcb::udpcb(inet_os &inet)

		\brief	Constructor.

		\param [in,out]	inet	The inet.
	*/

	explicit udpcb(inet_os& inet);

	/*!
		\fn	L4_UDP::udpcb::udpcb(socket &so, inpcb_impl &head);

		\brief
		Create a new UDP control block, making an empty reassembly queue and hooking it to the
		argument protocol control block.

		\param [in,out]	so  	The so.
		\param [in,out]	head	The head.
	*/

	udpcb(socket& so, inpcb_impl& head);

	~udpcb() {};

	/*!
		\fn	static inline udpcb* L4_UDP::udpcb::intoudpcb(inpcb_impl *ip)

		\brief	A udpcb* caster from inpcb_impl.

		\param [in,out]	ip	If non-null, the inpcb_impl to cast.

		\return	null if it fails, else a udpcb* casted version of #ip.
	*/
	static inline class L4_UDP::udpcb* intoudpcb(class inpcb_impl* ip) { return dynamic_cast<class L4_UDP::udpcb*>(ip); };
	static inline class L4_UDP::udpcb* intoudpcb(class inpcb* ip) { return dynamic_cast<class L4_UDP::udpcb*>(ip); } ;

	/*!
		\fn	static inline udpcb* L4_UDP::udpcb::sotoudpcb(socket *so)

		\brief	A udpcb* caster from socket.

		\param [in,out]	so	If non-null, the socket to cast.

		\return	null if it fails, else a udpcb* casted version of the #so pcb.
	*/

	static inline class L4_UDP::udpcb* sotoudpcb(socket* so) { return dynamic_cast<L4_UDP::udpcb*>(so->so_pcb); } // TODO

	/*!
		\fn virtual udpcb * in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags)

		\brief	Calls inpcb_impl::in_pcblookup();

		\param	faddr	 	The foreign host table entry.
		\param	fport_arg	The foreign port.
		\param	laddr	 	The local host table entry.
		\param	lport_arg	The local port.
		\param	flags	 	The flags \ref INPLOOKUP_.

		\return	null if it fails, else the matching inpcb.
	*/
	virtual class L4_UDP::udpcb* in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags) { return nullptr; } // TODO;

	/*!
		\fn	void L4_UDP::udpcb::udp_template()

		\brief
		Create template to be used to send UDP packets on a connection. Call after host entry
		created, allocates an mbuf and fills in a skeletal UDP/IP header, minimizing the amount
		of work necessary when the connection is used.
	*/
	void udp_template();


	struct	pseudo_header *udp_ip_template;	/*!< skeletal packet for transmit */
	class	inpcb_impl *udp_inpcb;	/*!< back pointer to internet pcb */

	class udpcb_logger {
		friend class L4_UDP::udpcb;
	public:
		~udpcb_logger() { log.close(); }
	private:
		typedef std::chrono::duration<double> seconds;
		udpcb_logger() {};
		udpcb_logger(const udpcb_logger&)
		{
			//udpcb_logger();
		}

		void update(u_long snd_cwnd);

		std::ofstream log;
		std::chrono::time_point<std::chrono::high_resolution_clock> start;
		static int log_number;
	};

	udpcb_logger log;
};

//#endif
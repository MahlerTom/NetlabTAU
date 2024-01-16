/*!
    \file	protosw.hpp
    
    \author	Tom Mahler

    \brief	Declares the protosw class.
*/

#ifndef NETLAB_PROTOSW_H
#define NETLAB_PROTOSW_H

#include "L5.h"


struct u_char_pack {
	typedef unsigned char   u_char;
	u_char_pack(const u_char& lb, const u_char& hb) 
		: lb(lb & 0x0f), hb(hb & 0xf0) { }
	
	void hton() {
		struct u_char_pack tmp(lb, hb);
		lb = hb;
		hb = tmp.lb;
	}
	u_char lb : 4;		/* low 4 bits */
	u_char hb : 4;		/* high 4 bits */
};

/*!
    \class	protosw

    \brief
    Protocol switch table.
    
    Base class for each protocol, which is used for protocol-protocol and system-protocol
    communication.
    
    A protocol is called through the pr_init entry before any other. Thereafter it is called
    every 200ms through the pr_fasttimo() entry and every 500ms through the pr_slowtimo() for
    timer based actions.
    
    Protocols pass data between themselves as structs using	the pr_input() and the pr_output().
    pr_input() passes data up (towards application) and pr_output() passes it down (towards the
    \ref NIC);
    control	information passes up and down on pr_ctlinput() and pr_ctloutput(). The protocol is
    responsible for the space occupied by any the arguments to these entries and must dispose it.
    
    The userreq() routine interfaces protocols to the system and is described below.
*/
class protosw {
public:

	friend class inet_os;

	/*!
	    \enum	SWPROTO_
	
	    \brief	Values that represent the index of the protocol in the inet_os::inetsw array.
	*/
	enum SWPROTO_ 
	{
		SWPROTO_IP = 0,			/*!< IP Protocol  */
		SWPROTO_UDP = 1,		/*!< UDP Protocol */
		SWPROTO_TCP = 2,		/*!< TCP Protocol */
		SWPROTO_IP_RAW = 3,		/*!< IP raw Protocol */
		SWPROTO_ICMP = 4,		/*!< ICMP Protocol */
		SWPROTO_IGMP = 5,		/*!< IGMP Protocol */
		SWPROTO_IP_RAW_2 = 6,   /*!< IP raw 2 Protocol */
		SWPROTO_LEN = 7			/*!< The SWPROTO_ length */
	};

	/*!
	    \enum	PR_
	
	    \brief
	    Flags for pr_flags.
	    
	    \note
	    	*	PR_ADDR requires PR_ATOMIC;
	    	*	PR_ADDR and PR_CONNREQUIRED are mutually exclusive.
	*/
	enum PR_ 
	{
		PR_ATOMIC = 0x01,		/*!< exchange atomic messages only flag */
		PR_ADDR = 0x02,			/*!< addresses given with messages flag */
		PR_CONNREQUIRED = 0x04, /*!< connection required by protocol flag */
		PR_WANTRCVD = 0x08,		/*!< want PRU_RCVD calls flag */
		PR_RIGHTS = 0x10		/*!< passes capabilities flag */
	};

	/*!
	    \enum	PRU_
	
	    \brief
	    A single pr_usrreq() function is invoked with an operation number indicating what
	    operation was desired. We now provide individual function pointers which protocols can
	    implement, which offers a number of benefits (such as type checking for arguments). These
	    older constants are still present in order to support TCP debugging.
	*/
	enum PRU_ 
	{
		PRU_ATTACH = 0,		/*!< The attach protocol to up option */
		PRU_DETACH = 1,		/*!< The detach protocol from up option */
		PRU_BIND = 2,		/*!< The bind socket to address option */
		PRU_LISTEN = 3,		/*!< The listen for connection option */
		PRU_CONNECT = 4,	/*!< The establish connection to peer option */
		PRU_ACCEPT = 5,		/*!< The accept connection from peer option */
		PRU_DISCONNECT = 6, /*!< The disconnect from peer option */
		PRU_SHUTDOWN = 7,   /*!< The won't send any more data option */
		PRU_RCVD = 8,		/*!< The have taken data; more room now option */
		PRU_SEND = 9,		/*!< The send this data option */
		PRU_ABORT = 10,		/*!< The abort (fast DISCONNECT, DETATCH) option */
		PRU_CONTROL = 11,   /*!< The control operations on protocol option */
		PRU_SENSE = 12,		/*!< The return status into m option */
		PRU_RCVOOB = 13,	/*!< The retrieve out of band data option */
		PRU_SENDOOB = 14,   /*!< The send out of band data option */
		PRU_SOCKADDR = 15,  /*!< The fetch socket's address option */
		PRU_PEERADDR = 16,  /*!< The fetch peer's address option */
		PRU_CONNECT2 = 17,  /*!< The connect two sockets option */	
		/* begin for protocols internal use */
		PRU_FASTTIMO = 18,  /*!< The 200ms timeout option */
		PRU_SLOWTIMO = 19,  /*!< The 500ms timeout option */
		PRU_PROTORCV = 20,  /*!< The receive from below option */
		PRU_PROTOSEND = 21, /*!< The send to below option */
		PRU_NREQ = 21		/*!< The PRU_ length */
	};

	/*!
	    \enum	
	
	    \brief	Values that represent the number of times the timer invokes.
	*/
	enum  PR_HZ
	{
		PR_SLOWHZ = 2,  /*!< The 2 slow timeouts per second option */
		PR_FASTHZ = 5   /*!< The 5 slow timeouts per second option */
	};

	/*!
	    \fn
	    protosw::protosw(const short &pr_type = 0, class domain *pr_domain = nullptr, const short &pr_protocol = 0, const short &pr_flags = 0)
	
	    \brief	Constructor.
	
	    \param	pr_type
	    Type of the protocol, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW for TCP, UDP and ICMP/rawIP
	    respectively.
	    \param	pr_domain	(Optional) If non-null, the protocol domain.
	    \param	pr_protocol		 	The protocol number based on IPPROTO_ enum of winsock2.h.
	    \param	pr_flags		 	The protocol flags from the PRU_ enum.
	*/
	protosw::protosw(class inet_os &inet, const short &pr_type = 0, class domain *pr_domain = nullptr, const short &pr_protocol = 0, const short &pr_flags = 0)
		: _pr_type(pr_type), _pr_domain(pr_domain), _pr_protocol(pr_protocol), _pr_flags(pr_flags), inet(inet){ }

	/*!
	    \fn	void protosw::pr_domain(class domain *pr_domain)
	
	    \brief	Sets the domain of the protocol.
	
	    \param pr_domain	the domain.
	*/
	inline void pr_domain(class domain *pr_domain) { _pr_domain = pr_domain; }

	/*!
	    \struct	pr_input_args
	
	    \brief	Arguments for pr_input() function.
	    
		\note
		User can inherit from this struct in order to add additional variables. In such case, use:
		
		\code
		//	Inheriting fro pr_output_args
		struct new_pr_input_args : public pr_input_args	{
			int newVar;		// The new variable
		};

		//	Defining a new_pr_input function that accepts the new struct,
		// 	in addition to the pr_input that we must define:
		void pr_input(const struct pr_input_args &args) { return new_pr_input(*reinterpret_cast<const struct new_pr_input_args*>(&args)); }

		//	Calls to pr_input
		void someOtherFunction(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, const int &iphlen, int newVar) { 
			return pr_input(*dynamic_cast<const struct pr_input_args*>(&new_pr_input_args(m, it, iphlen, newVar))); 
		}
		\endcode
	*/
	struct pr_input_args { 
		pr_input_args(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, const int &iphlen)
			: m(m), it(it), iphlen(iphlen) { }
		std::shared_ptr<std::vector<byte>> &m;
		std::vector<byte>::iterator &it;
		const int &iphlen;
	};

	/*!
	    \pure	virtual void protosw::pr_input(const struct pr_input_args &args) = 0;
	
	    \brief
	    The protocol's input function, process incoming data (from the NIC towards the
	    application).
	
	    \param	args	the input arguments.
	*/

	virtual void pr_input(const struct pr_input_args &args) = 0;		

	/*!
	    \struct	pr_output_args
	
	    \brief
	    Arguments for pr_output() function.
	    
	    \note User can inherit from this struct in order to add additional variables. In such
	    case, use:
	    
	    \code	    
	    //	Inheriting fro pr_output_args
	    struct new_pr_output_args : public pr_output_args	{
			int newVar;		// The new variable
	    };
	    
	    //	Defining a new_pr_output function that accepts the new struct,
	    // 	in addition to the pr_output that we must define:
	    int pr_output(const struct pr_output_args &args) { return new_pr_output(*reinterpret_cast<const struct new_pr_output_args*>(&args)); }
	    
	    //	Calls to pr_output
	    int someOtherFunction(int newVar) { return pr_output(*dynamic_cast<const struct pr_output_args*>(&new_pr_output_args(newVar))); }	    
	    \endcode.
	*/
	struct pr_output_args { };

	/*!
	    \pure	virtual int protosw::pr_output(const struct pr_output_args &args) = 0;
	
	    \brief
	    The protocol's output function, process outgoing data (from the application towards the
	    NIC).
	
	    \param	args	the input arguments.
	
	    \return
	    An int, for error handling.
	    
	    \note Users are encouraged to throw exception rather than use the return value for error
	    handling.
	*/

	virtual int pr_output(const struct pr_output_args &args) = 0;

	/*!
		\pure	virtual int protosw::pr_usrreq(class netlab::socket *so, int req, std::shared_ptr<std::vector<byte>> &m, struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) = 0;
	
	    \brief	process user requests from process, mostly implemented by L4 protocols.
	
	    \param	so	   		The socket that request something.
	    \param	req		   	The request, see \ref PRU_.
	    \param	m	   		Data parameter.
	    \param	nam			Address parameter, may be casted into other types such as int.
	    \param	nam_len	   	Length of the nam, in case nam was casted.
	    \param	control		Control parameter, unused.
	
		\return	An int, for error handling.

		\note
		Users are encouraged to throw exception rather than use the return value for error handling.
	*/
	virtual int pr_usrreq(class netlab::L5_socket *so, int req, std::shared_ptr<std::vector<byte>> &m,
	struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) = 0;

	/*!
	    \pure	virtual void protosw::pr_init() = 0;
	
	    \brief	Initialization hook, called once by inet_os::domaininit(const bool start_timer).
	    
		\note
		Should contain static or global parameters of the entire protocol.
	*/
	virtual void pr_init() = 0;													

	/*!
	    \pure	virtual void protosw::pr_fasttimo() = 0;
	
	    \brief	fast timeout (200ms), mostly for TCP timers.
	*/
	virtual void pr_fasttimo() = 0;												

	/*!
		\pure	virtual void protosw::pr_fasttimo() = 0;

		\brief	slow timeout (500ms), mostly for TCP timers.
	*/
	virtual void pr_slowtimo() = 0;												

	/*!
	    \fn	inline const short protosw::pr_type() const
	
	    \brief	Getter for the #pr_type.
	
	    \return	A copy of #pr_type.
	*/
	inline const short pr_type() const { return _pr_type; }

	/*!
	    \fn	inline const short protosw::pr_protocol() const
	
	    \brief	Getter for the #pr_protocol.
	
	    \return	A copy of #pr_protocol.
	*/
	inline const short pr_protocol() const { return _pr_protocol; }

	/*!
	    \fn	inline const short protosw::pr_flags() const
	
	    \brief	Getter for the #pr_flags.
	
	    \return	A copy of #pr_flags.
	*/
	inline const short pr_flags() const { return _pr_flags; }

	/*!
	    \fn	const int protosw::dom_family() const;
	
	    \brief	Getter for the #dom_family inside #pr_domain.
	
	    \return	A copy of the #dom_family inside #pr_domain.
	*/
	const int dom_family() const;

	/*!
	    \fn	SWPROTO_ protosw::to_swproto()
	
	    \brief	Converts this object's #pr_protocol to a \ref SWPROTO_.
	
	    \return	The #pr_protocol as a \ref SWPROTO_.
	*/
	SWPROTO_ to_swproto() {
		switch (_pr_protocol) {
		case 0:
			return _pr_type ? SWPROTO_::SWPROTO_IP_RAW_2 : SWPROTO_::SWPROTO_IP;
			break;
		case IPPROTO_UDP:
			return SWPROTO_::SWPROTO_UDP;
			break;
		case IPPROTO_TCP:
			return SWPROTO_::SWPROTO_TCP;
			break;
		case IPPROTO_RAW:
			return SWPROTO_::SWPROTO_IP_RAW;
			break;
		case IPPROTO_ICMP:
			return SWPROTO_::SWPROTO_ICMP;
			break;
		case IPPROTO_IGMP:
			return SWPROTO_::SWPROTO_IGMP;
			break;
		default:
			break;
		}
		return SWPROTO_::SWPROTO_IP;
	}

	/*!
		\pure	virtual void protosw::pr_ctlinput() = 0;

		\brief	control input (from below).

		\note
		Shouldn't be used
	*/
	virtual void pr_ctlinput() = 0;

	/*!
		\pure	virtual int protosw::pr_ctloutput() = 0;

		\brief	control output (from above)

		\return	An int.

		\note
		Shouldn't be used
	*/
	virtual int pr_ctloutput() = 0;

	/*!
	    \pure	virtual void protosw::pr_drain() = 0;
	
	    \brief	Flush any excess space possible.
	    
		\note
		Shouldn't be used
	*/
	virtual void pr_drain() = 0;

	/*!
	    \pure	virtual int protosw::pr_sysctl() = 0;
	
	    \brief	System control for protocol.
	
	    \return	An int.
	    
		\note
		Shouldn't be used
	*/
	virtual int pr_sysctl() = 0;											

protected:
	class inet_os &inet; /*!< The inet_os owning this protocol. */

private:
	short	_pr_type;			/*!< Type of the protocol, used by the socket */
	class	domain *_pr_domain;	/*!< The domain protocol */
	short	_pr_protocol;		/*!< The protocol number */
	short	_pr_flags;			/*!< The protocol flags, \ref PR_ */
};

#endif /* NETLAB_PROTOSW_H */
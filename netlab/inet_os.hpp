/*!
    \file	inet_os.hpp

	\author	Tom Mahler, contact at tommahler@gmail.com
	
    \brief	Declares the inet operating system class.
*/
#ifndef NETLAB_INET_OS_H
#define NETLAB_INET_OS_H

#include <mutex>
#include <chrono>		
#include <thread>		

#include "Types.h"
#include "domain.hpp"

/*!
    \class	inet_os

    \brief
    An inet operating system.
    
    The inet_os is a networking operating system that manages the network interface card. It
    binds together the 5 OSI layers, allowing the user to switch layers on the fly, as well as
    add new implementation for the layers.
*/
class inet_os {
public:

	/*!
	    \fn	inet_os::inet_os(const int slowtimo = 500, const int fasttimo = 200)
	
	    \brief	Constructor.
	
	    \param	slowtimo	The slow timer mostly for the TCP.
	    \param	fasttimo	The fast timer mostly for the TCP.
	*/
	inet_os(const int slowtimo = 500, const int fasttimo = 200)
		: slowtimo(slowtimo), fasttimo(fasttimo), _fasttimo_on(false), _slowtimo_on(false),
		_cable(nullptr), _nic(nullptr), _datalink(nullptr), _arp(nullptr), _inetdomain(nullptr),
		_router(nullptr)
	{
		for (size_t i = 0; i < protosw::SWPROTO_LEN; i++)
			_inetsw[i] = nullptr;
	}

	// remove
	inet_os(const inet_os&)
	{
		
	}

	/*!
	    \fn	inline inet_os::~inet_os()
	
	    \brief	Destructor.
	*/
	inline ~inet_os() {
		if (_inetdomain)
			delete _inetdomain;
	}

	/*!
	    \fn	inline void inet_os::domaininit(const bool start_timer = true)
	
	    \brief
	    Initiates the inetdomain given start timer bool to indicate whether to spawn the timer
	    threads immediately or not.
	
	    \param	start_timer
	    The start timer bool.
	    
	    \pre	All the desired protocols were initiated using the inetsw(class protosw *proto, protosw::SWPROTO_ place) function.
	    
	    \post	#_inetdomain != nullptr
	    
	    \post	All the initiated protocols in the #_inetsw hold the #_inetdomain inside #pr_domain.
	    
	    \post	All the initiated protocols in the #_inetsw called pr_init().
	    
	    \post	If #start_timer == true then the timer threads were spawned.
	*/
	inline void domaininit(const bool start_timer = true) {
		_inetdomain = new domain(AF_INET, "internet", _inetsw, &_inetsw[sizeof(_inetsw) / sizeof(_inetsw[0])], 32, sizeof(struct sockaddr_in));

		const class domain *dp(nullptr);
		for (dp = _inetdomain; dp; dp = dp->dom_next)
			for (class protosw **pr = reinterpret_cast<class protosw **>(const_cast<class domain *>(dp)->dom_protosw); pr < dp->dom_protoswNPROTOSW; pr++)
				if (*pr)
					(*pr)->pr_domain(_inetdomain);
		
		for (dp = _inetdomain; dp; dp = dp->dom_next)
			for (class protosw **pr = reinterpret_cast<class protosw **>(const_cast<class domain *>(dp)->dom_protosw); pr < dp->dom_protoswNPROTOSW; pr++)
				if (*pr)
					(*pr)->pr_init();

		if (start_timer) {
			if (slowtimo.count())
				start_slowtimo(this->slowtimo);
			if (fasttimo.count())
				start_fasttimo(this->slowtimo);
		}
	}

	/*!
	    \fn	inline class protosw** inet_os::pffindtype(const int family, const int type) const
	
	    \brief
	    Look up a protocol by type (e.g., SOCK_STREAM). This function is called to locate the
	    appropriate protosw entry when a process creates a socket. pffindtype() performs a linear
	    search of domains for the specified family and then searches the protocols within the
	    domain for the first one of the specified type.
	    
	    \par Example:
			*	When an application calls:
			*	\code socket(AF_INET, SOCK_STREAM, 0); \endcode
			*	pffindtype() gets called as:
			*	\code pffindtype(AF_INET, SOCK_STREAM);		//TCP socket	\endcode
			*	pffindtype() will return a pointer to #inetsw[2], since TCP is
			*	the first SOCK_STREAM protocol in the array.
	
	    \param	family	The family (should be AF_INET).
	    \param	type  	The type (e.g. SOCK_STREAM).
	
	    \return	null if it fails, else a \ref protosw**.
	*/
	inline class protosw** pffindtype(const int family, const int type) const {
		bool found(false);
		const class domain *dp(nullptr);
		for (dp = _inetdomain; dp; dp = dp->dom_next)
			if (dp->dom_family() == family) {
				found = true;
				break;
			}

		if (found)
			for (class protosw **pr = reinterpret_cast<class protosw **>(const_cast<class domain *>(dp)->dom_protosw); pr < dp->dom_protoswNPROTOSW; pr++)
				if ((*pr)->pr_type() && (*pr)->pr_type() == type)
					return pr;
		return nullptr;
	}

	/*!
	    \fn	inline class protosw** inet_os::pffindproto(const int family, const int protocol, const int type) const
	
	    \brief
	    Look up a protocol by number (e.g.,	IPPROTO_TCP). This function is called to locate the
	    appropriate protosw entry when a process creates a socket. pffindproto() searches domains
	    exactly as pffindtype() does but looks for the family, type, and protocol specified by
	    the caller. If pffindproto() does not find a (protocol, type) match within the specified
	    protocol family, and type is SOCK_RAW, and the domain has a default raw protocol
	    (#_pr_protocol equals 0), then pffindproto() selects the default raw protocol instead of
	    failing completely.
	    
	    \par For Example:
			*	A call such as
			*	\code pffindproto(PF_INET, 27, SOCK_RAW);	\endcode
			*	returns a pointer to inetsw [6], the default raw IP protocol, since Net/3 does not
			*	include support for protocol 27. With access to raw IP, a process could implement
			*	protocol 27 services on its own using the kernel to manage the sending and receiving of
			*	the IP packets.
			*	\note
			*	Protocol 27 is reserved for the Reliable Datagram Protocol (RFC 1151).
	    
	    \par Another Example:
			*	Similar to the pffindtype() example:
			*	\code socket(PF_INET, SOCK_DGRAM, 0); \endcode
			*	Leads to:
			*	\code pffindtype(PF_INET, SOCK_OGRAM);	// UDP socket	\endcode
			*	which returns a pointer to UDP in #inetsw[1].
	
	    \param	family  	The family (should be AF_INET).
	    \param	protocol	The protocol.
	    \param	type		The type (e.g. SOCK_STREAM).
	
	    \return	null if it fails, else a \ref protosw**.
	*/
	inline class protosw** pffindproto(const int family, const int protocol, const int type) const {
		bool found(false);
		const class domain *dp(nullptr);
		for (dp = _inetdomain; dp; dp = dp->dom_next)
			if (dp->dom_family() == family) {
				found = true;
				break;
			}

		class protosw **maybe = nullptr;
		if (found)
			for (class protosw **pr = reinterpret_cast<class protosw **>(const_cast<class domain *>(dp)->dom_protosw); pr < dp->dom_protoswNPROTOSW; pr++) 
				if (*pr)
					if (((*pr)->pr_protocol() == protocol) && ((*pr)->pr_type() == type))
						return (pr);
					else if (type == SOCK_RAW && (*pr)->pr_type() == SOCK_RAW && (*pr)->pr_protocol() == 0 && maybe == nullptr)
						maybe = pr;

		return (maybe);
	}

	/*!
	    \fn	inline void inet_os::pfslowtimo()
	
	    \brief
	    Use two for loops to call the pr_slowtimo() function for each protocol, if it is
	    defined. The functions schedule themselves to be called #slowtimo (500 ms) later by
	    calling std::this_thread::sleep_for(slowtimo).
	    
		\pre	Some protocol (usually TCP) should implement such function, or this thread is redundant
	    \post	A thread is spawned which calls pr_slowtimo for each defined protocol every
	    #slowtimo (500 ms).
	*/
	inline void pfslowtimo() {
		const class domain *dp(nullptr);
		while (_slowtimo_on) {
			for (dp = _inetdomain; dp; dp = dp->dom_next)
				for (class protosw **pr = reinterpret_cast<class protosw **>(const_cast<class domain *>(dp)->dom_protosw); pr < dp->dom_protoswNPROTOSW; pr++)
					if (*pr)
						(*pr)->pr_slowtimo();
			std::this_thread::sleep_for(slowtimo);
		}
	}

	/*!
	    \fn	inline void inet_os::pffasttimo()
	
	    \brief
	    Use two for loops to call the pr_fasttimo() function for each protocol, if it is defined.
	    The functions schedule themselves to be called #fasttimo (200 ms) later by calling
	    std::this_thread::sleep_for(fasttimo).
	    
	    \pre	Some protocol (usually TCP) should implement such function, or this thread is redundant
	    \post
	    A thread is spawned which calls pr_fasttimo for each defined protocol every
	    #fasttimo (200 ms).
	*/
	inline void pffasttimo() {
		const class domain *dp(nullptr);
		_fasttimo_on = true;
		while (_fasttimo_on) {
			for (dp = _inetdomain; dp; dp = dp->dom_next)
				for (class protosw **pr = reinterpret_cast<class protosw **>(const_cast<class domain *>(dp)->dom_protosw); pr < dp->dom_protoswNPROTOSW; pr++)
					if (*pr)
						(*pr)->pr_fasttimo();
			std::this_thread::sleep_for(fasttimo);
		}
	}

	/*!
	    \fn	inline void inet_os::start_slowtimo(const std::chrono::milliseconds new_slowtimo)
	
	    \brief
	    If user initiated inet_os with false, or if the user stopped pfslowtimo(), this function
	    calls pfslowtimo() with #new_slowtimo.
	
	    \param	new_slowtimo
	    The new slowtimo as a const std::chrono::milliseconds type.
	    
	    \post #slowtimo is set to the #new_slowtimo
	    
	    \post A thread is spawned which calls pr_fasttimo for each defined protocol every
	    #new_slowtimo (500 ms).
	*/
	inline void start_slowtimo(const std::chrono::milliseconds new_slowtimo) {
		slowtimo = std::chrono::milliseconds(new_slowtimo);
		_slowtimo_on = true;
		std::thread(&inet_os::pfslowtimo, this).detach();
	}

	/*!
	    \fn	inline void inet_os::start_fasttimo(const std::chrono::milliseconds new_fasttimo)
	
	    \brief
	    If user initiated inet_os with false, or if the user stopped pffasttimo(), this function
	    calls pffasttimo() with #new_fasttimo.
	
	    \param	new_fasttimo
	    The new fasttimo as a const std::chrono::milliseconds type.
	    
	    \post #fasttimo is set to the #new_fasttimo
	    
	    \post A thread is spawned which calls pr_fasttimo for each defined protocol every
	    #new_fasttimo (200 ms).
	*/
	inline void start_fasttimo(const std::chrono::milliseconds new_fasttimo) {
		fasttimo = std::chrono::milliseconds(new_fasttimo);
		_fasttimo_on = true;
		std::thread(&inet_os::pffasttimo, this).detach();
	}

	/*!
	    \fn	inline void inet_os::start_slowtimo(const int new_slowtimo = 500)
	
	    \brief
	    If user initiated inet_os with false, or if the user stopped pfslowtimo(), this function
	    calls pfslowtimo() with #new_slowtimo.
	
	    \param	new_slowtimo
	    The new slowtimo as a const int type.
	    
	    \post #slowtimo is set to the #new_slowtimo
	    
	    \post A thread is spawned which calls pr_fasttimo for each defined protocol every
	    #new_slowtimo (500 ms).
	*/
	inline void start_slowtimo(const int new_slowtimo = 500) { start_slowtimo(std::chrono::milliseconds(new_slowtimo)); }

	/*!
	    \fn	inline void inet_os::start_fasttimo(const int new_fasttimo = 200)
	
	    \brief
	    If user initiated inet_os with false, or if the user stopped pffasttimo(), this function
	    calls pffasttimo() with #new_fasttimo.
	
	    \param	new_fasttimo
	    The new fasttimo as a const int type.
	    
	    \post #fasttimo is set to the #new_fasttimo
	    
	    \post A thread is spawned which calls pr_fasttimo for each defined protocol every
	    #new_fasttimo (200 ms).
	*/
	inline void start_fasttimo(const int new_fasttimo = 200) { start_fasttimo(std::chrono::milliseconds(new_fasttimo)); }

	/*!
	    \fn	inline void inet_os::stop_slowtimo()
	
	    \brief	Stops a slowtimo by setting #slowtimo_on to be false, which will make the while loop in pfslowtimo() to stop.
	    
		\post after at most #slowtimo (500 ms), the pfslowtimo() thread will exit
	*/
	inline std::chrono::milliseconds stop_slowtimo()
	{ 
		_slowtimo_on = false; 
		return slowtimo;
	}

	/*!
	    \fn	inline void inet_os::stop_fasttimo()
	
	    \brief
	    Stops a fasttimo by setting #fasttimo_on to be false, which will make the while loop in
	    pffasttimo() to stop.
	    
	    \post after at most #fasttimo (200 ms), the pffasttimo() thread will exit.
	*/
	inline std::chrono::milliseconds stop_fasttimo() 
	{ 
		_fasttimo_on = false; 
		return fasttimo;
	}

	/*!
	    \fn	inline NIC_Cable* inet_os::cable() const
	
	    \brief	Gets the #_cable.
	
	    \return	null if it fails, else #_cable.
	*/
	inline class NIC_Cable* cable() const { return _cable; }

	/*!
	    \fn	inline NIC* inet_os::nic() const
	
	    \brief	Gets the #_nic.

		\return	null if it fails, else #_nic.
	*/
	inline class NIC* nic() const { return _nic; }

	/*!
	    \fn	inline L2* inet_os::datalink() const
	
	    \brief	Gets the #_datalink.
	
	    \return	null if it fails, else #_datalink.
	*/
	inline class L2* datalink() const { return _datalink; }

	class L0_buffer* buf() const;

	/*!
	    \fn	inline L2_ARP* inet_os::arp() const
	
	    \brief	Gets the #_arp.
	
	    \return	null if it fails, else a #_arp.
	*/
	inline class L2_ARP* arp() const { return _arp; }

	/*!
	    \fn	inline void inet_os::cable(class NIC_Cable *cable)
	
	    \brief	Sets #_cable to the given cable.
	
	    \param cable	The NIC_Cable to insert into #_cable.
	*/
	inline void cable(class NIC_Cable *cable) { _cable = cable; }

	/*!
	    \fn	inline void inet_os::nic(class NIC *nic)
	
	    \brief	Sets #_nic to the given #nic.
	
	    \param	nic	If non-null, the #nic to insert into #_nic.
	*/
	inline void nic(class NIC *nic) { _nic = nic; }

	/*!
	    \fn	inline void inet_os::datalink(class L2 *datalink)
	
	    \brief	Sets #_datalink to the given #datalink.
	
	    \param datalink	If non-null, the #datalink to insert into #_datalink.
	*/
	inline void datalink(class L2 *datalink) { _datalink = datalink; }

	/*!
	    \fn	inline void inet_os::arp(class L2_ARP *arp)
	
	    \brief	Sets #_arp to the given #arp.
	
	    \param arp	If non-null, the #arp to insert into #_arp.
	*/
	inline void arp(class L2_ARP *arp) { _arp = arp; }

	/*!
	    \fn	inline void inetsw(class protosw *proto, protosw::SWPROTO_ place)
	
	    \brief	Sets the #place protocol in the #inetsw array to be #proto.
	
	    \param	proto	If non-null, the protocol to insert into #inetsw[#place].
	    \param	place	The place.
	*/
	inline void inetsw(class protosw *proto, protosw::SWPROTO_ place) {
		if (place < protosw::SWPROTO_LEN)
			_inetsw[place] = proto;
	}

	/*!
	    \fn	inline protosw* inet_os::inetsw(protosw::SWPROTO_ place)
	
	    \brief	Gets the the #place protocol in #inetsw.
	
	    \param	place	The place.
	
	    \return	null if it fails, else a protosw*.
	*/
	inline class protosw* inetsw(protosw::SWPROTO_ place) {
		if (place < protosw::SWPROTO_LEN)
			return _inetsw[place];
		return nullptr;
	}

	/*!
	    \fn	inline domain* inet_os::inetdomain()
	
	    \brief	Gets the #_inetdomain.
	
	    \return	null if it fails, else #_inetdomain.
	*/
	inline class domain* inetdomain() { return _inetdomain; }

	/*!
	    \fn	void inet_os::connect(const uint32_t count = 0U);
	
	    \brief	Connects the cable with the given #count.
	
	    \param	count	Number of packets to accept, 0 = infinity.
	*/
	void connect(class L0_buffer *buf = nullptr, const uint32_t &count = 0U);

	/*!
	    \fn	void inet_os::disconnect();
	
	    \brief
	    Virtually disconnects the cable from the NIC.
	    
	    In other wards, turns the NIC off.
	*/
	void disconnect(bool from_buf = false);

	/*!
	    \fn	uint16_t inet_os::in_cksum(const byte* buff, size_t len) const;
	
	    \brief	Calculates the 16-bit checksum of the #buff of length #len.
	
		\note
		This routine is very heavily used in the network code and should be modified for each CPU
		to be as fast as possible.

		\note
		This implementation is 386 version.

	    \param	buff	The buffer to checksum.
	    \param	len 	The length.
	
	    \return	An uint16_t checksum result.
	*/
	uint16_t in_cksum(const byte* buff, size_t len) const;
	
	std::mutex _splnet; /*!< The splnet mutex */
	
	static	std::mutex print_mutex; /*!< \static The print mutex. Must be locked before printing and unlocked afterwards. */

	const bool slowtimo_on() const { return _slowtimo_on; }

	const bool fasttimo_on() const { return _fasttimo_on; }

	inline void set_router(class router *r) { _router = r; }

	inline class router* get_router() const { return _router; }

private:

	class NIC_Cable *_cable;	/*!< \private The actual cable (L0) */
	class NIC *_nic;			/*!< \private The NIC (L1) */
	class L2 *_datalink;		/*!< \private The datalink (L2) */
	class L2_ARP *_arp;			/*!< \private The arp module */
	
	class router *_router;

	class protosw *_inetsw[protosw::SWPROTO_LEN]; /*!< \private array of protosw classes for the Internet protocols */
	class domain *_inetdomain;   /*!< \private The domain class for the Internet protocols */

	bool _slowtimo_on;   /*!< \private true to enable, false to disable the slowtimo */
	bool _fasttimo_on;   /*!< \private true to enable, false to disable the fasttimo */
	std::chrono::milliseconds slowtimo; /*!< \private The slowtimo duration */
	std::chrono::milliseconds fasttimo; /*!< \private The fasttimo duration */
	
};

#endif /* NETLAB_INET_OS_H */
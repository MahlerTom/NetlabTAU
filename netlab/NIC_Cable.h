#ifndef NIC_CABLE_H_
#define NIC_CABLE_H_

#include "NIC.h"
#ifdef NIC_DEBUG
#define NIC_CABLE_DEBUG
#endif

#include <pthread.h>

#include "NetworkInterface.h"
#include "Sniffer/tins.h"

class NIC_Cable 
{
public:
	void set_buf(class L0_buffer* new_buf) { buf = new_buf; }
private:
	friend class L0_buffer;
	friend class inet_os;
	/*!
	    \typedef	std::map<class netlab::NetworkInterface, pcap_t*> PcapHandleMap
	
	    \brief	Defines an alias representing the pcap handle map.
	*/
	typedef std::map<class netlab::NetworkInterface, pcap_t*> PcapHandleMap;

	friend class NIC;

	/*!
	    \fn NIC_Cable::NIC_Cable(class inet_os &inet, const bool &promisc_mode = true, const std::string &filter = "");
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet_os using this nic.
	    \param	promisc_mode
	    Decides the whether the NIC is in promiscuous mode (which opens the NIC to read any
	    packet that comes in) or not (in which the NIC drops any packet which is not destined for
	    the NIC's MAC address and not a broadcast)
	    Default value is true.
	    \param	filter
	    Enables the use of explicit filters, following the syntax of of pcap filter found in
	    <a href="https://www.winpcap.org/docs/docs_40_2/html/group__language.html">Winpcap
	    filtering expression syntax</a>. Default value is "" which means no filters. \note this
	    is given to you \b ONLY for debugging purposes. Final submission must Support default
	    values.
	*/
	NIC_Cable(class inet_os &inet, const bool &promisc_mode = true, const std::string &filter = "");

	/*!
	    \fn	NIC_Cable::~NIC_Cable();
	
	    \brief	Destructor, disconnects the cable and deletes the sniffer.
	*/
	~NIC_Cable();

	/*!
	    \fn void NIC_Cable::send_l2(byte *buffer, const size_t &bufferSize, const class netlab::NetworkInterface &iface);
	
	    \brief
	    Sends a level 2 packet.
	    This method is used internally.	    
	    This method sends a layer 2 packet, using a wire injection.
	
	    \param [in,out]	buffer	The buffer to send.
	    \param	bufferSize	  	The buffer size.
	    \param	iface		  	The interface to inject.
	*/
	void send_l2(byte *buffer, const size_t &bufferSize, const class netlab::NetworkInterface &iface);

	/*!
	    \fn
	    void NIC_Cable::send_l2(const std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, const class netlab::NetworkInterface &iface);
	
	    \brief
	    Sends a level 2 packet. This method is used internally. This method sends a layer 2
	    packet, using a wire injection.
	
	    \param	m	 	The smart pointer to a buffer to send.
	    \param	it   	The buffer size.
	    \param	iface	The iterator, as the current offset in the vector.
	*/
	void send_l2(const std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, const class netlab::NetworkInterface &iface);
	void send_l2_helper(const std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, const class netlab::NetworkInterface &iface);

	/*!
	    \fn	void NIC_Cable::open_l2_socket(const class netlab::NetworkInterface &iface);
	
	    \brief
	    Opens a layer 2 socket.
	    
	    If this operation fails, then a socket_open_error will be thrown.
	
	    \param	iface	The interface.
	*/
	void open_l2_socket(const class netlab::NetworkInterface &iface);

	/*!
	    \fn	pcap_t* NIC_Cable::make_pcap_handle(const class netlab::NetworkInterface &iface) const;
	
	    \brief	Makes pcap handle for the nic.
	
	    \param	iface	The interface.
	
	    \return	null if it fails, else a pcap_t*.
	*/
	pcap_t* make_pcap_handle(const class netlab::NetworkInterface &iface) const;

	/*!
	    \fn	void NIC_Cable::connect(class L2 &upperInterface, const uint32_t &count = 0U);
	
	    \brief	Connects.
	
	    \param [in,out]	upperInterface	The upper interface.
	    \param	count				  	Number of.
	*/
	void connect(class L2 &upperInterface, class L0_buffer *buf = nullptr, const uint32_t &count = 0U);


	/*!
	    \fn	void NIC_Cable::disconnect();
	
	    \brief
	    Virtually disconnects the cable from the NIC.
	    
	    In other wards, turns the NIC off.
	*/
	void disconnect(bool from_buf = false);

	/*!
	    \fn	static void* NIC_Cable::SpawnThread(void *thread_arg);
	
	    \brief	Spawn a sniffer thread.
	
	    \param [in,out]	thread_arg	If non-null, the thread argument.
	
	    \return	null if it fails, else a void*.
	*/
	static void* SpawnThread(void *thread_arg);

	/*!
	    \fn	bool NIC_Cable::callback(const Tins::PDU &pdu);
	
	    \brief	Callback from the sniffer thread, passes data to leread().
	
	    \param	pdu	The Tins::PDU packet (can't change that).
	
	    \return	true if it succeeds, false if it fails.
	*/
	bool callback(const Tins::PDU &pdu);
	
	/*!
		\struct	SpawnData

		\brief	Data for spawning a sniffer thread.
	*/
	struct SpawnData;

	pthread_t sniffer_id;			/*!< Identifier for the sniffer thread */
	class Tins::Sniffer *sniffer;	/*!< The sniffer */
	bool status;					/*!< true to if sniffer is live */
	
	class netlab::NetworkInterface iface;	/*!< The interface on which we sniff/inject */
	PcapHandleMap pcap_handles;				/*!< The pcap handles for the interface */

	class inet_os &inet;	/*!< The inet_os owning this protocol. */

	class L0_buffer *buf;
};


#endif /* NIC_CABLE_H_ */
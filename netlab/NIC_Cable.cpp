#include "NIC_Cable.h"

#include <functional>

#include "Print.h"
#include "packet_sender_adapter.h"
#include "inet_os.hpp"
#include "L0_buffer.h"


struct NIC_Cable::SpawnData 
{
	/*!
	    \fn
	    SpawnData(uint32_t count = 0, class Tins::Sniffer *sniff_ptr = nullptr, class NIC_Cable *cable = nullptr)
	
	    \brief	Constructor.
	
	    \param	count			 	Number of packets to count.
	    \param [in,out]	sniff_ptr	The sniffer.
	    \param [in,out]	cable	 	The cable.
	*/
	SpawnData(uint32_t count = 0, class Tins::Sniffer *sniff_ptr = nullptr, class NIC_Cable *cable = nullptr)
		: count(count), sniff_ptr(sniff_ptr), cable(cable) { }

	uint32_t count;					/*!< Packet count, for Capture argument  */
	class Tins::Sniffer *sniff_ptr;	/*!< Pointer to the sniffer  */
	class NIC_Cable *cable;			/*!< Pointer to the cable  */
};

NIC_Cable::NIC_Cable(class inet_os &inet, const bool &promisc_mode, const std::string &filter)
	: iface(netlab::NetworkInterface(netlab::NetworkInterface::default_interface())),
	inet(inet), status(false) 
{
	inet.cable(this);
	Tins::SnifferConfiguration config;
	config.set_promisc_mode(promisc_mode);
	config.set_filter(filter);

	/* 
	 * Sniff on the provided interface in promiscuous mode
	 */
	try 
	{
		sniffer = new Tins::Sniffer(iface.name(), config);
	}
	catch (std::runtime_error &ex)
	{
		{
			std::lock_guard<std::mutex> lock(inet.print_mutex);
			std::cout << "[!] NIC failed with the error: " << ex.what() << std::endl
				<< "Using NULL filter" << std::endl;
		}
		config.set_filter("");
		sniffer = new Tins::Sniffer(iface.name(), config);
	}
}

NIC_Cable::~NIC_Cable() 
{
	disconnect(true);
	if (sniffer)
		delete sniffer;
}

bool NIC_Cable::callback(const Tins::PDU &pdu) 
{
	std::shared_ptr<std::vector<byte>> m(new std::vector<byte>(pdu.size()));
	netlab::RawData(pdu, m);


#ifdef NIC_CABLE_DEBUG
	{
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "[#] New Packet arrived:" << std::endl;
		inet.nic()->HexDump(m, m->begin());
	}
#endif
	if (buf)
		buf->leread(m, m->begin());
	else
		inet.nic()->leread(m, m->begin());
	return true;
}

void* NIC_Cable::SpawnThread(void* thread_arg) 
{
	/* Cast back the argument */
	SpawnData* spawn_data(static_cast<SpawnData*>(thread_arg));
	spawn_data->sniff_ptr->sniff_loop(std::bind(&NIC_Cable::callback, spawn_data->cable, std::placeholders::_1), spawn_data->count);
	delete spawn_data;
	
	/* Exit the function */
	pthread_exit(nullptr);
	return nullptr;
}

void NIC_Cable::connect(class L2& upperInterface, class L0_buffer *buf, const uint32_t &count)
{
	if (buf)
		this->buf = buf;

	/* First, get the data for spawning a thread, Cast the spawn data and spawn a thread */
	int rc(pthread_create(&sniffer_id, nullptr, SpawnThread, static_cast<void*>(new struct SpawnData(count, sniffer, this))));
	if (rc)
		throw std::runtime_error("Sniffer::Spawn() : Creating thread. Returning code = " + netlab::StrPort(rc));
	status = true;
}

void NIC_Cable::disconnect(bool from_buf) 
{
	if (from_buf && buf)
		delete buf;

	if (status)	{
		sniffer->stop_sniff();
		status = false;
	}
}

void NIC_Cable::send_l2(const std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, const class netlab::NetworkInterface &iface) 
{
	if (buf)
		buf->send_l2_helper(m, it, iface);
	else
		send_l2_helper(m, it, iface);
}

void NIC_Cable::send_l2_helper(const std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, const class netlab::NetworkInterface &iface)
{
	open_l2_socket(iface);
	pcap_t* handle(pcap_handles[iface]);
	if (pcap_sendpacket(handle, m->data(), m->end() - it) != 0)
		throw std::runtime_error("Failed to send packet: " + std::string(pcap_geterr(handle)));
}
void NIC_Cable::send_l2(byte* buffer, const size_t &bufferSize, const netlab::NetworkInterface &iface) 
{
	open_l2_socket(iface);
	pcap_t* handle(pcap_handles[iface]);
	if (pcap_sendpacket(handle, buffer, bufferSize) != 0)
		throw std::runtime_error("Failed to send packet: " + std::string(pcap_geterr(handle)));
}

void NIC_Cable::open_l2_socket(const netlab::NetworkInterface &iface) 
{
	if (pcap_handles.count(iface) == 0)
		pcap_handles.insert(std::make_pair(iface, make_pcap_handle(iface)));
}

pcap_t* NIC_Cable::make_pcap_handle(const netlab::NetworkInterface& iface) const 
{
	char error[PCAP_ERRBUF_SIZE];
	pcap_t* handle(pcap_create(("\\Device\\NPF_" + iface.name()).c_str(), error));
	if (!handle)
		throw std::runtime_error("Error opening pcap handle: " + std::string(error));
	if (pcap_set_promisc(handle, 1) < 0)
		throw std::runtime_error("Failed to set pcap handle promisc mode: " + std::string(pcap_geterr(handle)));
	if (pcap_activate(handle) < 0)
		throw std::runtime_error("Failed to activate pcap handle: " + std::string(pcap_geterr(handle)));
	return handle;
}
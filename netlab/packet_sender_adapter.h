#ifndef TINS_PACKET_SENDER_ADAPTER_H
#define TINS_PACKET_SENDER_ADAPTER_H
#include "sniffer/packet_sender.h"

class L2;

namespace netlab 
{
	class NetworkInterface;

	/*!
	    \class	PacketSenderAdapter
	
	    \brief
	    An adapter class for the Tins::PacketSender. Sends packets through a network interface.
	
	    \sa	Tins::PacketSender
	*/
	class PacketSenderAdapter 
		: public Tins::PacketSender 
	{
	public:

		/*!
		    \fn PacketSenderAdapter::PacketSenderAdapter(L2 & Datalink, const NetworkInterface &iface = NetworkInterface(), uint32_t recv_timeout = PacketSender::DEFAULT_TIMEOUT, uint32_t usec = 0);
		
		    \brief	Constructor for PacketSenderAdapter objects.
		
		    \param [in,out]	datalink	The datalink.
		    \param	iface				The default interface in which to send the packets.
		    \param	recv_timeout		The timeout which will be used when receiving responses.
		    \param	usec				The usec.
		*/
		PacketSenderAdapter(L2 &datalink, const netlab::NetworkInterface &iface, uint32_t recv_timeout = PacketSender::DEFAULT_TIMEOUT, uint32_t usec = 0);

		/*!
		    \fn	PacketSenderAdapter::~PacketSenderAdapter();
		
		    \brief
		    PacketSender destructor, that does not destroy #datalink.
		    
		    This gracefully closes all open sockets.
		*/
		~PacketSenderAdapter();

	private:

		class L2 &datalink;  /*!< The datalink to pass incoming packets */
	};
}

#endif // TINS_PACKET_SENDER_H

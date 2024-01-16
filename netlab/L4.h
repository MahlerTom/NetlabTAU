#ifndef L4_H_
#define L4_H_
#include "Types.h"
#include <string>
#include <pthread.h>

/**
* \class L4
* \brief Represents a Layer 4 interface (ICMP in this case).
*/
class L4{
public:

	/**
	* \brief Constructs an L4 interface.
	*
	* May use it to initiate variables and data structure that you wish to use.
	* Should remain empty by default (if no global class variables are beeing used).
	*
	* \param debug \a (bool)
	* \parblock
	* Decide the mode of the interface, when true the interface will print messages for debuf purposes.
	* Default value is false.
	* \endparblock
	*/
	L4(bool debug);

	/**
	* \brief L4 destructor.
	*
	* Deletes the interface, the held recv packet (if one exsists) and destroy the
	* recv Packetmutex. lowerInterface os \b not destroyed. That means after calling this function,
	* \b you are responsible to delete it.
	*/
	~L4();

	/**
	* \brief L4 output routine.
	*
	* This method wrap data with an ICMP ECHO header specifically for an ICMP request
	* packet and sends the data to sendToL3.
	*
	* \param sendData \a (byte*) The data to be sent.
	* \param sendDataLen \a (size_t) The length of the data to be sent.
	* \param destIP \a (string) The destination IP address (from the main).
	* \param srcIP \a (string) The source IP address (from NIC::myIP).
	* \retval int the number of bytes that were sent (from sendToL2).
	*/
	int sendToL4(byte *sendData, size_t sendDataLen, std::string destIP, std::string srcIP = "");

	/**
	* \brief L4 input routine.
	*
	* This method was called by the recvFromL3 (member function of the L3 class).
	* It unwraps the ICMP header of the received data, drops invalid packets
	* (only ICMP ECHO packets are supported) and possibly prints relevant information.
	* In addition, the method copy the payload data to a local buf and releases
	* The mutex, so that a blocked readFromL4 can take the content of the buf
	* and return it to the main. After unlocking the mutex it locks the mutex again
	* so that it will be ready for another packet. If another packet arrives,
	* before readFromL4 could read the buf, recvFromL4 ovewrites the buf with
	* the new data.
	*
	* \param recvData \a (byte*) The received data.
	* \param recvDataLen \a (size_t) The length of the received data.
	* \retval int the number of bytes that were received.
	*/
	virtual int recvFromL4(byte *recvData, size_t recvDataLen);

	/**
	* \brief L4 read routine.
	*
	* This method enables the passing of relevant arriving packets back to the
	* main routine, which calles it.
	* When beeing called, the function tries to lock the recv packet mutex and
	* if it is already locked then the packet did not yet arrive and the function
	* is blocked. When the mutex is released, the function copies the content of
	* the buf containing the received packet into recvData (which pre-allocated
	* enough memory), frees the buf, and unlock the mutex (to unblock recvFromL4)
	* We expect that the recvData will look exactly like the sent data that the
	* main initialized.
	*
	* \param recvData \a (byte*) The received data.
	* \param recvDataLen \a (size_t) The length of the received data.
	* \retval int the number of bytes that were received.
	*/
	int readFromL4(byte *recvData, size_t recvDataLen);

	/**
	* \brief Setter for the pointer to the L3 to be used by this layer.
	*
	* \param lowerInterface \a (L3*) the L3 to be used by this layer.
	*/
	void setLowerInterface(class L3 *lowerInterface);

	/**
	* \brief Getter for the name of the lowest interface.
	*
	* \retval string the name of the lowest interface.
	*/
	const class NIC& getLowestInterface();

private:
	pthread_mutex_t recvPacket_mutex;
	byte *recvPacket;
	size_t recvPacketLen;
	bool debug;
	class L3* lowerInterface;
};

#endif /* L4_H_ */
/*
* Author: Tom Mahler
* Date: June 2015
*/
#include "L4.h"

#include "L3.h"
#include "NIC.h"

using namespace std;

/*
L4 constructor, use it to initiate variables and data structure that you wish to use.
By default, initiates the recvPacket mutex and locks it (in order to block upcoming readFromL4 call)
and sets the recvPacket buff to NULL.
*/
L4::L4(bool debug) : debug(debug), recvPacketLen(0), recvPacket(NULL)
{
	pthread_mutex_init(&recvPacket_mutex, NULL);
	pthread_mutex_lock(&recvPacket_mutex);
}

/*
Implemented for you
*/
void L4::setLowerInterface(L3* lowerInterface){ this->lowerInterface = lowerInterface; }

/*
Implemented for you
*/
string L4::getLowestInterface(){ return lowerInterface->getLowestInterface(); }

/*
sendToL4 is called by the application (main) directly.
sendData is the pointer to the data that the main wish to send.
sendDataLen is the length of that data.
destIP is the destination IP address that the main supplied.

### // NOT TO BE USED // ###
srcIP is the machines IP address that the main supplied.
take the srcIP from the NIC instead and pass it to L3.
*/
int L4::sendToL4(byte *sendData, size_t sendDataLen, std::string destIP, std::string srcIP)
{
	/* ADD YOUR IMPLEMENTATION HERE*/


	return 0;
}


/*
recvFromL3 is called by the upper layer via the upper layer's L3 pointer.
recvData is the pointer to the data L4 wish to receive.
recvDataLen is the length of that data.
*/
int L4::recvFromL4(byte *recvData, size_t recvDataLen)
{
	/* ADD YOUR IMPLEMENTATION HERE*/


	return 0;
}

/*
Implemented for you
*/
int L4::readFromL4(byte *recvData, size_t recvDataLen)
{
	pthread_mutex_lock(&recvPacket_mutex);
	size_t lSize = recvDataLen<recvPacketLen ? recvDataLen : recvPacketLen;
	memcpy(recvData, recvPacket, lSize);
	pthread_mutex_unlock(&recvPacket_mutex);
	pthread_mutex_lock(&recvPacket_mutex);
	return lSize;
}

L4::~L4()
{
	pthread_mutex_destroy(&recvPacket_mutex);	/* Free up the_mutex */
	if (recvPacket)
		delete[] recvPacket;
}


#include "L3.h"
#include "L2.h"

using namespace std;


/*
L3 constructor, use it to initiate variables and data structure that you wish to use.
Should remain empty by default (if no global class variables are beeing used).
*/
L3::L3(bool debug){ this->debug = debug; }

/*
sendToL3 is called by the upper layer via the upper layer's L3 pointer.
sendData is the pointer to the data L4 wish to send.
sendDataLen is the length of that data.
srcIP is the machines IP address that L4 supplied.
destIP is the destination IP address that L4 supplied.
debug is to enable print (use true)
*/
int L3::sendToL3(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP){

	/* ADD YOUR IMPLEMENTATION HERE*/


	return 0;
}

/*
recvFromL3 is called by the upper layer via the upper layer's L3 pointer.
recvData is the pointer to the data L4 wish to receive.
recvDataLen is the length of that data.
debug is to enable print (use true)
*/
int L3::recvFromL3(byte *recvData, size_t recvDataLen){

	/* ADD YOUR IMPLEMENTATION HERE*/


	return 0;
}

/*
Implemented for you
*/
void L3::setLowerInterface(L2* lowerInterface){ this->lowerInterface = lowerInterface; }

/*
Implemented for you
*/
void L3::setUpperInterface(L4* upperInterface){ this->upperInterface = upperInterface; }

/*
Implemented for you
*/
std::string L3::getLowestInterface(){ return lowerInterface->getLowestInterface(); }
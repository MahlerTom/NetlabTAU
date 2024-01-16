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
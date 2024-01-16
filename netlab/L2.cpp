#include "L2.h"
#include "NIC.h"
using namespace std;

/**
* Implemented for you
*/
L2::L2(bool debug) : debug(debug){ }

/**
* Implemented for you
*/
void L2::setUpperInterface(L3* upperInterface){ this->upperInterface = upperInterface; }

/**
* Implemented for you
*/
void L2::setNIC(NIC* nic){ this->nic = nic; }

/**
* Implemented for you
*/
NIC* L2::getNIC(){ return nic; }

/**
* Implemented for you
*/
std::string L2::getLowestInterface(){ return nic->getLowestInterface(); }

int L2::recvFromL2(byte *recvData, size_t recvDataLen)
{
	/* ADD YOUR IMPLEMENTATION HERE*/
	return 0;
}

int L2::sendToL2(byte *sendData, size_t sendDataLen, uint16_t family, string spec_mac, uint16_t spec_type, string dst_addr)
{
	/* ADD YOUR IMPLEMENTATION HERE*/
	return 0;
}

/**
* Implemented for you
*/
L2::~L2() {}
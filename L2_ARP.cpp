#include "L2_ARP.h"	
#include "NIC.h"
using namespace std;

/**
* Implemented for you
*/
L2_ARP::L2_ARP(bool debug) : debug(debug){ }

L2_ARP::~L2_ARP()
{
	/* ADD YOUR IMPLEMENTATION HERE, DONT FORGET TO FREE THE ARP TABLE! */
}

/**
* Implemented for you
*/
void L2_ARP::setNIC(NIC* nic){ this->nic = nic; }

int L2_ARP::arprequest(string ip_addr)
{
	/* ADD YOUR IMPLEMENTATION HERE */
	return 0;
}

string L2_ARP::arpresolve(string ip_addr, byte *sendData, size_t sendDataLen)
{
	/* ADD YOUR IMPLEMENTATION HERE */
	return "";
}


void* L2_ARP::arplookup(string ip_addr, bool create)
{
	/* ADD YOUR IMPLEMENTATION HERE */
	return NULL;
}

int L2_ARP::in_arpinput(byte *recvData, size_t recvDataLen)
{
	/* ADD YOUR IMPLEMENTATION HERE */
	return 0;
}

void* L2_ARP::SendArpReply(string itaddr, string isaddr, string hw_tgt, string hw_snd)
{
	/* ADD YOUR IMPLEMENTATION HERE */
	return NULL;
}




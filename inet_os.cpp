/*!
    \file	inet_os.cpp
    
	\author	Tom Mahler, contact at tommahler@gmail.com

    \brief	Implements the inet operating system class.
*/

#include "inet_os.hpp"
#include "NIC.h"
#include "NIC_Cable.h"
#include "L0_buffer.h"

//std::mutex inet_os::splnet;
std::mutex inet_os::print_mutex;

/*!
    \fn	void inet_os::connect(const uint32_t count)

    \brief	Connects the given count.

    \param	count	The count to connect.
*/

void  inet_os::connect(class L0_buffer *buf, const uint32_t &count) { return _nic->connect(*_datalink, buf, count); }

void inet_os::disconnect(bool from_buf) { return _nic->disconnect(from_buf); }

uint16_t inet_os::in_cksum(const byte* buff, size_t len) const 
{
	uint32_t sum(0); /* assume 32 bit long, 16 bit short */
	const uint16_t *buff_ptr((uint16_t*)buff);
	while (len > 1) {
		sum += *buff_ptr++;
		if (sum & 0x80000000) /* if high - order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if (len) /* take care of left over byte */
		sum += (uint16_t)*(byte *)buff_ptr;
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return ~sum;
}

class L0_buffer* inet_os::buf() const { return _cable->buf; }



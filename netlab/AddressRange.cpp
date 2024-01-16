#include "AddressRange.h"
#include "NIC.h"
#include "utils.h"
#include "Sniffer/endianness.h"

namespace netlab {

	template<typename Address>
	struct AddressRangeIterator<Address>::end_iterator { };

	template<typename Address>
	AddressRangeIterator<Address>::AddressRangeIterator(const value_type &addr)
		: addr(addr), reached_end(false) { }

	template<typename Address>
	AddressRangeIterator<Address>::AddressRangeIterator(const value_type &address, end_iterator) 
		: addr(address) 
	{ 
		reached_end = Internals::increment(addr); 
	}

	template<typename Address>
	const typename AddressRangeIterator<Address>::value_type& AddressRangeIterator<Address>::operator*() const { return addr; }

	template<typename Address>
	const typename AddressRangeIterator<Address>::value_type* AddressRangeIterator<Address>::operator->() const { return &addr; }

	template<typename Address>
	bool AddressRangeIterator<Address>::operator==(const AddressRangeIterator &rhs) const { return reached_end == rhs.reached_end && addr == rhs.addr; }

	template<typename Address>
	bool AddressRangeIterator<Address>::operator!=(const AddressRangeIterator &rhs) const { return !(*this == rhs); }

	template<typename Address>
	AddressRangeIterator<Address>& AddressRangeIterator<Address>::operator++() {
		reached_end = Internals::increment(addr);
		return *this;
	}

	template<typename Address>
	AddressRangeIterator<Address> AddressRangeIterator<Address>::operator++(int) {
		AddressRangeIterator copy(*this);
		(*this)++;
		return copy;
	}




	template<typename Address>
	AddressRange<Address>::AddressRange(const address_type &first, const address_type &last, bool only_hosts = false)
		: first(first), last(last), only_hosts(only_hosts) {
		if (last < first)
			throw std::runtime_error("Invalid address range");
	}

	template<typename Address>
	AddressRange<Address> AddressRange<Address>::from_mask(const address_type &first, const address_type &mask) {
		return AddressRange<address_type>(first, internals::last_address_from_mask(first, mask), true);
	}

	template<typename Address>
	typename AddressRange<Address>::const_iterator AddressRange<Address>::begin() const {
		address_type addr = first;
		if (only_hosts)
			Internals::increment(addr);
		return const_iterator(addr);
	}

	template<typename Address>
	typename AddressRange<Address>::const_iterator AddressRange<Address>::end() const {
		address_type addr = last;
		if (only_hosts)
			Internals::decrement(addr);
		return const_iterator(addr, typename const_iterator::end_iterator());
	}

	template<typename Address>
	bool AddressRange<Address>::is_iterable() const {
		// Since first < last, it's iterable
		if (!only_hosts)
			return true;
		// We need that distance(first, last) >= 4
		address_type addr(first);
		for (int i = 0; i < 3; ++i) {
			// If there's overflow before the last iteration, we're done
			if (Internals::increment(addr) && i != 2)
				return false;
		}
		// If addr <= last, it's OK.
		return addr < last || addr == last;
	}


	IPv4Range operator/(const IPv4Address &addr, int mask) {
		if (mask > 32)
			throw std::logic_error("Prefix length cannot exceed 32");
		return IPv4Range::from_mask(addr, IPv4Address(Tins::Endian::host_to_be(0xffffffff << (32 - mask))));
	}



}
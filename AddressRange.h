#ifndef ADDRESSRANGE_H_
#define ADDRESSRANGE_H_
#include <iterator>

namespace netlab {
	class IPv4Address;
	/**
	* \brief AddressRange iterator class.
	*/
	template<typename Address>
	class AddressRangeIterator 
		: public std::iterator<std::forward_iterator_tag, const Address> {
	public:
		typedef typename std::iterator<std::forward_iterator_tag, const Address>::value_type value_type;

		struct end_iterator;

		/**
		* Constructs an iterator.
		*
		* \param first The address held by this iterator.
		*/
		AddressRangeIterator(const value_type &addr);

		/**
		* Constructs an iterator.
		*
		* \param first The address held by this iterator.
		*/
		AddressRangeIterator(const value_type &address, end_iterator);

		/**
		* Retrieves the current address pointed by this iterator.
		*/
		const value_type& operator*() const;

		/**
		* Retrieves a pointer to the current address pointed by this iterator.
		*/
		const value_type* operator->() const;

		/**
		* Compares two iterators for equality.
		*
		* \param rhs The iterator with which to compare.
		*/
		bool operator==(const AddressRangeIterator &rhs) const;

		/**
		* Compares two iterators for inequality.
		*
		* \param rhs The iterator with which to compare.
		*/
		bool operator!=(const AddressRangeIterator &rhs) const;

		/**
		* Increments this iterator.
		*/
		AddressRangeIterator& operator++();

		/**
		* Increments this iterator.
		*/
		AddressRangeIterator operator++(int);

	private:
		Address addr;
		bool reached_end;
	};

	/**
	* \brief Represents a range of addresses.
	*
	* This class provides a begin()/end() interface which allows
	* iterating through every address stored in it.
	*
	* Note that when iterating a range that was created using
	* operator/(IPv4Address, int) and the analog for IPv6, the
	* network and broadcast addresses are discarded:
	*
	* \code
	* auto range = IPv4Address("192.168.5.0") / 24;
	* for(const auto &addr : range) {
	*     // process 192.168.5.1-254, .0 and .255 are discarded
	*     process(addr);
	* }
	*
	* // That's only valid for iteration, not for AddressRange<>::contains
	*
	* assert(range.contains("192.168.5.0")); // works
	* assert(range.contains("192.168.5.255")); // works
	* \endcode
	*
	* Ranges created using AddressRange(address_type, address_type)
	* will allow the iteration over the entire range:
	*
	* \code
	* AddressRange<IPv4Address> range("192.168.5.0", "192.168.5.255");
	* for(const auto &addr : range) {
	*     // process 192.168.5.0-255, no addresses are discarded
	*     process(addr);
	* }
	*
	* assert(range.contains("192.168.5.0")); // still valid
	* assert(range.contains("192.168.5.255")); // still valid
	* \endcode
	*
	*/
	template<typename Address>
	class AddressRange {
	public:
		/**
		* The type of addresses stored in the range.
		*/
		typedef Address address_type;

		/**
		* The iterator type.
		*/
		typedef AddressRangeIterator<address_type> const_iterator;

		/**
		* \brief The iterator type.
		*
		* This is the same type as const_iterator, since the
		* addresses stored in this range are read only.
		*/
		typedef const_iterator iterator;

		/**
		* \brief Constructs an address range from two addresses.
		*
		* The range will consist of the addresses [first, last].
		*
		* If only_hosts is true, then the network and broadcast addresses
		* will not be available when iterating the range.
		*
		* If last < first, an std::runtime_error exception is thrown.
		*
		* \param first The first address in the range.
		* \param last The last address(inclusive) in the range.
		* \param only_hosts Indicates whether only host addresses
		* should be accessed when using iterators.
		*/
		AddressRange(const address_type &first, const address_type &last, bool only_hosts = false);

		/**
		* \brief Creates an address range from a base address
		* and a network mask.
		*
		* \param first The base address.
		* \param mask The network mask to be used.
		*/
		static AddressRange from_mask(const address_type &first, const address_type &mask);

		/**
		* \brief Indicates whether an address is included in this range.
		* \param addr The address to test.
		* \return a bool indicating whether the address is in the range.
		*/
		bool contains(const address_type &addr) const { return (first < addr && addr < last) || addr == first || addr == last; }

		/**
		* \brief Returns an interator to the beginning of this range.
		* \brief const_iterator pointing to the beginning of this range.
		*/
		const_iterator begin() const;

		/**
		* \brief Returns an interator to the end of this range.
		* \brief const_iterator pointing to the end of this range.
		*/
		const_iterator end() const;

		/**
		* \brief Indicates whether this range is iterable.
		*
		* Iterable ranges are those for which there is at least one
		* address that could represent a host. For IPv4 ranges, a /31 or
		* /32 ranges does not contain any, therefore it's not iterable.
		* The same is true for /127 and /128 IPv6 ranges.
		*
		* If is_iterable returns false for a range, then iterating it
		* through the iterators returned by begin() and end() is
		* undefined.
		*
		* \return bool indicating whether this range is iterable.
		*/
		bool is_iterable() const;

	private:
		address_type first, last;
		bool only_hosts;
	};

	/**
	* An IPv4 address range.
	*/
	typedef AddressRange<class IPv4Address> IPv4Range;

	/**
	* \brief Constructs an IPv4Range from a base IPv4Address and a mask.
	* \param addr The range's first address.
	* \param mask The bit-length of the prefix.
	*/
	IPv4Range operator/(const class IPv4Address &addr, int mask);

} // namespace Netlab


#endif /* ADDRESSRANGE_H_ */
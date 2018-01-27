#ifndef HWADDRESS_H_
#define HWADDRESS_H_

#include <stdint.h>
#include <sstream>

struct in_addr;

namespace netlab 
{

	/**
	* \class HWAddress
	* \brief Represents a hardware address.
	*
	* This class represents a hardware (MAC) address. It can
	* be constructed from it's string representation and you can
	* iterate over the bytes that compose it.
	*
	* For example:
	*
	* \code
	* // Construct it from a string.
	* HWAddress<6> address("00:01:fa:9e:1a:cd");
	*
	* // Iterate over its bytes.
	* for(auto element : address) {
	*     // element will be each of the bytes(\x00, \x01, \xfa, etc)
	* }
	* \endcode
	*/
	template<size_t n = 6, typename Storage = uint8_t>
	class HWAddress 
	{
	public:
		/**
		* \brief The type of the elements stored in the hardware address.
		*
		* This is the same as the template parameter Storage.
		*/
		typedef Storage storage_type;

		/**
		* \brief The random access iterator type.
		*/
		typedef storage_type* iterator;

		/**
		* \brief Const iterator type.
		*/
		typedef const storage_type* const_iterator;

		/**
		* \brief Non-member constant indicating the amount of storage_type
		* elements in this address.
		*/
		static const size_t address_size;

		/**
		* \brief The broadcast address.
		*/
		static const HWAddress<n, Storage> broadcast;

		/**
		* \brief Constructor from a const storage_type*.
		*
		* If no pointer or a null pointer is provided, the address is
		* initialized to 00:00:00:00:00:00.
		*
		* This constructor is very usefull when passing zero initialized
		* addresses as arguments to other functions. You can use a
		* literal 0, which will be implicitly converted to the empty address.
		*
		* If a pointer is provided, address_size storage_type elements
		* are copied from the pointer, into the internal address representation.
		*
		* \param ptr The pointer from which to construct this address.
		*/
		HWAddress(const storage_type* ptr = nullptr);
		
		/**
		* \brief Constructs an address from a hex-notation address.
		*
		* This constructor will parse strings in the form:
		*
		* "00:01:da:fa:..."
		*
		* And initialize the internal representation accordingly.
		*
		* \param address The hex-notation address to be parsed.
		*/
		HWAddress(const std::string &address);

		/**
		* \brief Overload provided basically for string literals.
		*
		* This constructor takes a const char array of i elements in
		* hex-notation. \sa HWAddress::HWAddress(const std::string &address)
		*
		* This is mostly used when providing string literals. If this where
		* a const char*, then there would be an ambiguity when providing
		* a null pointer.
		*
		* \param address The array of chars containing the hex-notation
		* cstring to be parsed.
		*/
		template<size_t i>
		HWAddress(const char(&address)[i]);

		/**
		* \brief Overload provided basically for string literals.
		*
		* This constructor takes a const char array of i elements in
		* hex-notation. \sa HWAddress::HWAddress(const std::string &address)
		*
		* This is mostly used when providing string literals. If this where
		* a const uint8_t*, then there would be an ambiguity when providing
		* a null pointer.
		*
		* \param address The array of chars containing the hex-notation
		* cstring to be parsed.
		*/
		template<size_t i>
		HWAddress(const uint8_t(&address)[i]);

		/**
		* \brief Copy construct from a HWAddress of length i.
		*
		* If i is lower or equal than address_size, then i storage_type
		* elements are copied, and the last (n - i) are initialized to
		* the default storage_type value(0 most of the times).
		*
		* If i is larger than address_size, then only the first address_size
		* elements are copied.
		*
		* \param rhs The HWAddress to be constructed from.
		*/
		template<size_t i>
		HWAddress(const HWAddress<i> &rhs);

		/**
		* \brief Retrieves an iterator pointing to the beginning of the
		* address.
		*
		* \return iterator.
		*/
		iterator begin();

		/**
		* \brief Retrieves a const iterator pointing to the beginning of
		* the address.
		*
		* \return const_iterator.
		*/
		const_iterator begin() const;

		/**
		* \brief Retrieves an iterator pointing one-past-the-end of the
		* address.
		*
		* \return iterator.
		*/
		iterator end();

		/**
		* \brief Retrieves a const iterator pointing one-past-the-end of
		* the address.
		*
		* \return const_iterator.
		*/
		const_iterator end() const;

		/**
		* \brief Compares this HWAddress for equality.
		*
		* \param rhs The HWAddress to be compared to.
		*
		* \return bool indicating whether addresses are equal.
		*/
		bool operator==(const HWAddress &rhs) const;

		/**
		* \brief Compares this HWAddress for in-equality.
		*
		* \param rhs The HWAddress to be compared to.
		*
		* \return bool indicating whether addresses are distinct.
		*/
		bool operator!=(const HWAddress &rhs) const;

		/**
		* \brief Compares this HWAddress for less-than inequality.
		*
		* \param rhs The HWAddress to be compared to.
		*
		* \return bool indicating whether this address is less-than rhs.
		*/
		bool operator<(const HWAddress &rhs) const;

		/**
		* \brief Retrieves the size of this address.
		*
		* This effectively returns the address_size constant.
		*/
		const size_t size() const;

		/**
		* \brief Indicates whether this is a broadcast address.
		*/
		bool is_broadcast() const;

		/**
		* \brief Indicates whether this is a multicast address.
		*/
		bool is_multicast() const;

		/**
		* \brief Indicates whether this is an unicast address.
		*/
		bool is_unicast() const;

		/**
		* \brief Convert this address to a hex-notation std::string address.
		*
		* \return std::string containing the hex-notation address.
		*/
		std::string to_string() const;

		/**
		* \brief Retrieves the i-th storage_type in this address.
		*
		* \param i The element to retrieve.
		*/
		storage_type operator[](size_t i) const;

		/**
		* \brief Retrieves the i-th storage_type in this address.
		*
		* \param i The element to retrieve.
		*/
		storage_type& operator[](size_t i);

		/**
		* \brief Writes this HWAddress in hex-notation to a std::ostream.
		*
		* \param os The stream in which to write the address.
		* \param addr The parameter to be written.
		* \return std::ostream& pointing to the os parameter.
		*/
		friend std::ostream& operator<<(std::ostream &os, const HWAddress &addr) {
			std::transform(addr.begin(), addr.end() - 1, std::ostream_iterator<std::string>(os, ":"), &HWAddress::storage_to_string);
			return os << HWAddress::storage_to_string(addr.buffer[address_size - 1]);
		}
		/**
		* \brief Helper function which copies the address into an output
		* iterator.
		*
		* This is the same as:
		*
		* std::copy(begin(), end(), iter);
		*
		* But since some PDUs return a HWAddress<> by value, this function
		* can be used to avoid temporaries.
		*
		* \param output The output iterator in which to store this address.
		* \return OutputIterator pointing to one-past the last position
		* written.
		*/
		template<typename OutputIterator>
		OutputIterator copy(OutputIterator output) const;

		static inline HWAddress<6, Storage> ETHER_MAP_IP_MULTICAST(struct in_addr *ipaddr);

	private:
		template<typename OutputIterator>
		static void convert(const std::string &hw_addr, OutputIterator output);
		
		static std::string storage_to_string(storage_type element);

		storage_type buffer[n];
	};



} // namespace netlab

namespace netlab {
	template<size_t n, typename Storage>
	const size_t HWAddress<n, Storage>::address_size(n);

	template<size_t n, typename Storage>
	const HWAddress<n, Storage> HWAddress<n, Storage>::broadcast = "ff:ff:ff:ff:ff:ff";

	template<size_t n, typename Storage>
	HWAddress<n, Storage>::HWAddress(const storage_type* ptr) { ptr ? std::copy(ptr, ptr + address_size, buffer) : std::fill(begin(), end(), storage_type()); }

	template<size_t n, typename Storage>
	HWAddress<n, Storage>::HWAddress(const std::string &address) { convert(address, buffer); }

	template<size_t n, typename Storage>
	template<size_t i>
	HWAddress<n, Storage>::HWAddress(const char(&address)[i]) { convert(address, buffer); }


	template<size_t n, typename Storage>
	template<size_t i>
	HWAddress<n, Storage>::HWAddress(const uint8_t(&address)[i]) { convert(address, buffer); }

	template<size_t n, typename Storage>
	template<size_t i>
	HWAddress<n, Storage>::HWAddress(const HWAddress<i> &rhs) {
		// Fill extra bytes
		std::fill(
			// Copy as most as we can
			std::copy(rhs.begin(), rhs.begin() + std::min(i, n), begin()),
			end(),
			0);
	}

	template<size_t n, typename Storage>
	typename HWAddress<n, Storage>::iterator HWAddress<n, Storage>::begin() { return buffer; }

	template<size_t n, typename Storage>
	typename HWAddress<n, Storage>::const_iterator HWAddress<n, Storage>::begin() const { return buffer; }

	template<size_t n, typename Storage>
	typename HWAddress<n, Storage>::iterator HWAddress<n, Storage>::end() { return buffer + address_size; }

	template<size_t n, typename Storage>
	typename HWAddress<n, Storage>::const_iterator HWAddress<n, Storage>::end() const { return buffer + address_size; }

	template<size_t n, typename Storage>
	bool HWAddress<n, Storage>::operator==(const HWAddress &rhs) const { return std::equal(begin(), end(), rhs.buffer); }

	template<size_t n, typename Storage>
	bool HWAddress<n, Storage>::operator!=(const HWAddress &rhs) const { return !(*this == rhs); }

	template<size_t n, typename Storage>
	bool HWAddress<n, Storage>::operator<(const HWAddress &rhs) const { return std::lexicographical_compare(begin(), end(), rhs.begin(), rhs.end()); }

	template<size_t n, typename Storage>
	const size_t HWAddress<n, Storage>::size() const { return address_size; }

	template<size_t n, typename Storage>
	bool HWAddress<n, Storage>::is_broadcast() const { return *this == broadcast; }

	template<size_t n, typename Storage>
	bool HWAddress<n, Storage>::is_multicast() const { return (buffer[0] & 0x01); }

	template<size_t n, typename Storage>
	bool HWAddress<n, Storage>::is_unicast() const { return !is_broadcast() && !is_multicast(); }

	template<size_t n, typename Storage>
	std::string HWAddress<n, Storage>::to_string() const {
		std::ostringstream oss;
		oss << *this;
		return oss.str();
	}

	template<size_t n, typename Storage>
	typename HWAddress<n, Storage>::storage_type HWAddress<n, Storage>::operator[](size_t i) const { return buffer[i]; }

	template<size_t n, typename Storage>
	typename HWAddress<n, Storage>::storage_type& HWAddress<n, Storage>::operator[](size_t i) { return buffer[i]; }

	template<size_t n, typename Storage>
	std::ostream& operator<<(std::ostream &os, const HWAddress<n, Storage> &addr) {
		std::transform(addr.begin(), addr.end() - 1, std::ostream_iterator<std::string>(os, ":"), &HWAddress<n, Storage>::storage_to_string);
		return os << HWAddress<n, Storage>::storage_to_string(addr.buffer[HWAddress<n, Storage>::address_size - 1]);
	}

	template<size_t n, typename Storage>
	template<typename OutputIterator>
	OutputIterator HWAddress<n, Storage>::copy(OutputIterator output) const {
		for (const_iterator iter = begin(); iter != end(); ++iter)
			*output++ = *iter;
		return output;
	}

	template<size_t n, typename Storage>
	HWAddress<6, Storage> HWAddress<n, Storage>::ETHER_MAP_IP_MULTICAST(struct in_addr *ipaddr) {
		Storage enaddr[6];
		(enaddr)[0] = 0x01;
		(enaddr)[1] = 0x00;
		(enaddr)[2] = 0x5e;
		(enaddr)[3] = (reinterpret_cast<Storage *>(ipaddr))[1] & 0x7f;
		(enaddr)[4] = (reinterpret_cast<Storage *>(ipaddr))[2];
		(enaddr)[5] = (reinterpret_cast<Storage *>(ipaddr))[3];

		return HWAddress<6, Storage>(enaddr);
	}


	template<size_t n, typename Storage>
	template<typename OutputIterator>
	void HWAddress<n, Storage>::convert(const std::string &hw_addr, OutputIterator output) {
		unsigned i(0);
		size_t count(0);
		storage_type tmp;
		while (i < hw_addr.size() && count < n) {
			const unsigned end = i + 2;
			tmp = storage_type();
			while (i < end) {
				if (hw_addr[i] >= 'a' && hw_addr[i] <= 'f')
					tmp = (tmp << 4) | (hw_addr[i] - 'a' + 10);
				else if (hw_addr[i] >= 'A' && hw_addr[i] <= 'F')
					tmp = (tmp << 4) | (hw_addr[i] - 'A' + 10);
				else if (hw_addr[i] >= '0' && hw_addr[i] <= '9')
					tmp = (tmp << 4) | (hw_addr[i] - '0');
				else if (hw_addr[i] == ':')
					break;
				else
					throw std::runtime_error("Invalid byte found");
				i++;
			}
			*(output++) = tmp;
			count++;
			if (i < hw_addr.size())
				if (hw_addr[i] == ':')
					i++;
				else
					throw std::runtime_error("Invalid separator");
		}
		while (count++ < n)
			*(output++) = storage_type();
	}

	template<size_t n, typename Storage>
	std::string HWAddress<n, Storage>::storage_to_string(storage_type element) {
		std::ostringstream oss;
		oss << std::hex;
		if (element < 0x10)
			oss << '0';
		oss << static_cast<unsigned>(element);
		return oss.str();
	}
}

#endif /* HWADDRESS_H_ */

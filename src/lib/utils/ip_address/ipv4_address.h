/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_IPV4_ADDRESS_H_
#define BOTAN_IPV4_ADDRESS_H_

#include <botan/types.h>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

/**
* IPv4 Address
*/
class BOTAN_PUBLIC_API(3, 12) IPv4Address final {
   public:
      explicit IPv4Address(uint32_t ip) : m_ip(ip) {}

      static std::optional<IPv4Address> from_string(std::string_view str);

      /**
      * Return an address with the leading @p bits set to one and the remainder
      * zero. Throws Invalid_Argument if @p bits > 32.
      */
      static IPv4Address netmask(size_t bits);

      static IPv4Address host_mask() { return netmask(32); }

      IPv4Address operator&(const IPv4Address& other) const { return IPv4Address(m_ip & other.m_ip); }

      auto operator<=>(const IPv4Address&) const = default;

      /// The address as a 32-bit big-endian integer
      BOTAN_DEPRECATED("Use IPv4Address::address") uint32_t value() const { return m_ip; }

      /// The address as a 32-bit big-endian integer
      uint32_t address() const { return m_ip; }

      /// The address as four bytes, network-byte-order.
      std::array<uint8_t, 4> to_bytes() const;

      /// Dotted-decimal form, e.g. "10.0.0.1".
      std::string to_string() const;

      /**
      * If this value is a netmask consisting of a run of one bits followed by
      * a run of zero bits, return the number of one bits.
      *
      * Otherwise return nullopt.
      */
      std::optional<size_t> prefix_length() const;

   private:
      uint32_t m_ip;
};

/**
* An IPv4 subnet in CIDR form: a network address paired with a prefix length
*/
class BOTAN_PUBLIC_API(3, 12) IPv4Subnet final {
   public:
      /**
      * Construct from a network address and a prefix length in [0, 32].
      * Host bits of @p address are cleared.
      *
      * Throws Invalid_Argument if @p prefix_length > 32.
      */
      IPv4Subnet(IPv4Address address, size_t prefix_length);

      /**
      * Construct from a network address and a netmask (4 bytes each)
      * Returns nullopt if netmask is not a valid contiguous CIDR prefix.
      */
      static std::optional<IPv4Subnet> from_address_and_mask(std::span<const uint8_t, 8> addr_and_mask);

      /**
      * Construct from a network address and a netmask (4 bytes each)
      * Returns nullopt if netmask is not a valid contiguous CIDR prefix.
      */
      static std::optional<IPv4Subnet> from_address_and_mask(uint32_t addr, uint32_t mask);

      /**
      * Parse CIDR-style form "10.0.0.0/8".
      *
      * The "/N" suffix is required: bare addresses should be parsed via
      * IPv4Address::from_string and wrapped with IPv4Subnet::host if needed.
      *
      * Returns nullopt on parse failure or out-of-range prefix length.
      */
      static std::optional<IPv4Subnet> from_string(std::string_view str);

      /**
      * A single-host subnet (prefix length 32) covering exactly @p address.
      */
      static IPv4Subnet host(IPv4Address address) { return IPv4Subnet(address, 32); }

      /// The network address (host bits already zeroed).
      const IPv4Address& address() const { return m_address; }

      /// Prefix length in [0, 32].
      size_t prefix_length() const { return m_prefix_length; }

      /// True iff prefix_length() == 32.
      bool is_host() const { return m_prefix_length == 32; }

      /// True iff @p ip falls within this subnet.
      bool contains(const IPv4Address& ip) const;

      /// CIDR-style "10.0.0.0/8".
      std::string to_string() const;

      /**
      * Bytes for use in a DER-encoded GeneralName iPAddress field.
      *
      * If this is an address (is_host returns true) the output is 4 bytes (the address in network order)
      * Otherwise it is a subnet and the output is 4 bytes (address || netmask)
      */
      std::vector<uint8_t> serialize() const;

      friend bool operator==(const IPv4Subnet&, const IPv4Subnet&) = default;

   private:
      IPv4Address m_address;
      uint8_t m_prefix_length;
};

}  // namespace Botan

#endif

/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_IPV6_ADDRESS_H_
#define BOTAN_IPV6_ADDRESS_H_

#include <botan/types.h>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class IPv4Address;

/**
* IPv6 Address
*/
class BOTAN_PUBLIC_API(3, 12) IPv6Address final {
   public:
      explicit IPv6Address(std::span<const uint8_t, 16> ip);

      explicit IPv6Address(std::array<uint8_t, 16> ip) : m_ip(ip) {}

      /**
      * Convert a string representation of an IPv6 address to IPv6Address.
      *
      * Accepts the full form (eight colon-separated hex groups), the
      * "::"-compressed form (exactly one run of zero groups elided), and
      * combinations such as "2001:db8::1". The final 32 bits may be given
      * in IPv4 dotted-decimal form (e.g. "::ffff:192.0.2.1"). Surrounding
      * brackets and zone identifiers are not accepted.
      */
      static std::optional<IPv6Address> from_string(std::string_view str);

      /**
      * Return an address with the leading @p bits set to one and the remainder
      * zero. Throws Invalid_Argument if @p bits > 128.
      */
      static IPv6Address netmask(size_t bits);

      static IPv6Address host_mask() { return netmask(128); }

      IPv6Address operator&(const IPv6Address& other) const;

      auto operator<=>(const IPv6Address&) const = default;

      std::array<uint8_t, 16> address() const { return m_ip; }

      /**
      * Convert an IPv6 address to the RFC 5952 canonical text form:
      * lowercase hex, leading zeros within a group suppressed, and the
      * longest run of two or more zero groups compressed to "::". The
      * mixed hex/dotted notation is never produced, even for IPv4-mapped
      * addresses.
      */
      std::string to_string() const;

      /**
      * If this value is a netmask consisting of a run of one bits followed by
      * a run of zero bits, return the number of one bits.
      *
      * Otherwise return nullopt.
      */
      std::optional<size_t> prefix_length() const;

      /**
      * If this IPv6 address is an IPv4-compatible IPv6 address (RFC 4291 2.5.5.1)
      * or an IPv4-mapped IPv6 address (RFC 4291 2.5.5.2), return the embedded
      * IPv4 address.
      */
      std::optional<IPv4Address> as_ipv4() const;

   private:
      std::array<uint8_t, 16> m_ip;
};

/**
* An IPv6 subnet in CIDR form: a network address paired with a prefix length
*/
class BOTAN_PUBLIC_API(3, 12) IPv6Subnet final {
   public:
      /**
      * Construct from a network address and a prefix length in [0, 128].
      * Host bits of @p address are cleared.
      *
      * Throws Invalid_Argument if @p prefix_length > 128.
      */
      IPv6Subnet(IPv6Address address, size_t prefix_length);

      /**
      * Construct from a network address and a 16-byte CIDR netmask.
      * Returns nullopt if netmask is not a valid contiguous CIDR prefix.
      */
      static std::optional<IPv6Subnet> from_address_and_mask(std::span<const uint8_t, 32> addr_and_mask);

      /**
      * Parse the CIDR-style form "2001:db8::/32".
      *
      * The "/N" suffix is required: bare addresses should be parsed via
      * IPv6Address::from_string and wrapped with IPv6Subnet::host if needed.
      * The input must already be canonical, such that from_string and
      * to_string are exact inverses: the address is RFC 5952 form with host
      * bits clear ("2001:db8::/32") and the prefix length is canonical
      * decimal ("/32", not "/032"). In particular the IPv4-mapped dotted form
      * ("::ffff:1.2.3.4/120") is rejected even though IPv6Address::from_string
      * would accept the address.
      *
      * Returns nullopt on parse failure or out-of-range prefix length.
      */
      static std::optional<IPv6Subnet> from_string(std::string_view str);

      /**
      * A single-host subnet (prefix length 128) covering exactly @p address.
      */
      static IPv6Subnet host(IPv6Address address) { return IPv6Subnet(address, 128); }

      /// The network address (host bits already zeroed).
      const IPv6Address& address() const { return m_address; }

      /// Prefix length in [0, 128].
      size_t prefix_length() const { return m_prefix_length; }

      /// True iff prefix_length() == 128.
      bool is_host() const { return m_prefix_length == 128; }

      /// True iff @p ip falls within this subnet.
      bool contains(const IPv6Address& ip) const;

      /// CIDR-style "2001:db8::/32".
      std::string to_string() const;

      /**
      * Bytes for use in a DER-encoded GeneralName iPAddress field:
      *  - 16 bytes (the address) if is_host(); the SAN form per RFC 5280 4.2.1.6.
      *  - 32 bytes (address || netmask) otherwise; the name constraint form
      *    per RFC 5280 4.2.1.10.
      */
      std::vector<uint8_t> serialize() const;

      friend bool operator==(const IPv6Subnet&, const IPv6Subnet&) = default;

   private:
      IPv6Address m_address;
      uint8_t m_prefix_length;
};

}  // namespace Botan

#endif

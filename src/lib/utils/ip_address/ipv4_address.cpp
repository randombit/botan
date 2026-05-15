/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ipv4_address.h>

#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <bit>

namespace Botan {

namespace {

/*
* Convert a decimal-dotted string to binary IP
*/
std::optional<uint32_t> string_to_ipv4(std::string_view str) {
   // At least 3 dots + 4 1-digit integers
   // At most 3 dots + 4 3-digit integers
   if(str.size() < 3 + 4 * 1 || str.size() > 3 + 4 * 3) {
      return {};
   }

   // the final result
   uint32_t ip = 0;
   // the number of '.' seen so far
   size_t dots = 0;
   // accumulates one quad (range 0-255)
   uint32_t accum = 0;
   // # of digits pushed to accum since last dot
   size_t cur_digits = 0;

   for(const char c : str) {
      if(c == '.') {
         // . without preceding digit is invalid
         if(cur_digits == 0) {
            return {};
         }
         dots += 1;
         // too many dots
         if(dots > 3) {
            return {};
         }

         cur_digits = 0;
         ip = (ip << 8) | accum;
         accum = 0;
      } else if(c >= '0' && c <= '9') {
         const auto d = static_cast<uint8_t>(c - '0');

         // prohibit leading zero in quad (used for octal)
         if(cur_digits > 0 && accum == 0) {
            return {};
         }
         accum = (accum * 10) + d;

         if(accum > 255) {
            return {};
         }

         cur_digits++;
         BOTAN_ASSERT_NOMSG(cur_digits <= 3);
      } else {
         return {};
      }
   }

   // no trailing digits?
   if(cur_digits == 0) {
      return {};
   }

   // insufficient # of dots
   if(dots != 3) {
      return {};
   }

   ip = (ip << 8) | accum;

   return ip;
}

}  // namespace

//static
std::optional<IPv4Address> IPv4Address::from_string(std::string_view str) {
   if(auto ipv4 = string_to_ipv4(str)) {
      return IPv4Address(*ipv4);
   } else {
      return {};
   }
}

//static
IPv4Address IPv4Address::netmask(size_t bits) {
   BOTAN_ARG_CHECK(bits <= 32, "IPv4 netmask prefix length must be at most 32");
   if(bits == 0) {
      return IPv4Address(0);
   }
   return IPv4Address(0xFFFFFFFF << (32 - bits));
}

std::array<uint8_t, 4> IPv4Address::to_bytes() const {
   std::array<uint8_t, 4> out{};
   store_be(m_ip, out);
   return out;
}

std::string IPv4Address::to_string() const {
   const auto addr = this->to_bytes();

   std::string str;
   str.reserve(15);  // maximum possible size

   for(size_t i = 0; i != 4; ++i) {
      if(i > 0) {
         str += ".";
      }
      str += std::to_string(addr[i]);
   }

   return str;
}

std::optional<size_t> IPv4Address::prefix_length() const {
   // A 32-bit mask m is a CIDR prefix iff (~m) + 1 is a power of two or zero,
   // i.e. (~m) & (~m + 1) == 0. If so, the prefix length is the leading-one count.
   const uint32_t inv = ~m_ip;
   if((inv & (inv + 1)) != 0) {
      return std::nullopt;
   }
   return std::countl_one(m_ip);
}

IPv4Subnet::IPv4Subnet(IPv4Address address, size_t prefix_length) :
      m_address(address & IPv4Address::netmask(prefix_length)), m_prefix_length(static_cast<uint8_t>(prefix_length)) {
   // IPv4Address::netmask validates prefix_length <= 32, so by this point
   // the static_cast is in range.
}

//static
std::optional<IPv4Subnet> IPv4Subnet::from_address_and_mask(uint32_t addr, uint32_t mask) {
   std::array<uint8_t, 8> addr_and_mask{};
   store_be(&addr_and_mask[0], addr);  // NOLINT(*-container-data-pointer)
   store_be(&addr_and_mask[4], mask);
   return IPv4Subnet::from_address_and_mask(addr_and_mask);
}

//static
std::optional<IPv4Subnet> IPv4Subnet::from_address_and_mask(std::span<const uint8_t, 8> addr_and_mask) {
   const IPv4Address addr(load_be<uint32_t>(addr_and_mask.data(), 0));
   const IPv4Address mask(load_be<uint32_t>(addr_and_mask.data(), 1));

   if(const auto plen = mask.prefix_length()) {
      return IPv4Subnet(addr, *plen);
   } else {
      return {};
   }
}

//static
std::optional<IPv4Subnet> IPv4Subnet::from_string(std::string_view str) {
   const auto slash = str.find('/');
   if(slash == std::string_view::npos) {
      return std::nullopt;
   }

   auto addr = IPv4Address::from_string(str.substr(0, slash));
   if(!addr.has_value()) {
      return std::nullopt;
   }

   const auto plen_str = str.substr(slash + 1);
   if(plen_str.empty() || plen_str.size() > 2) {
      return std::nullopt;
   }
   size_t plen = 0;
   for(const char c : plen_str) {
      if(c < '0' || c > '9') {
         return std::nullopt;
      }
      plen = plen * 10 + static_cast<size_t>(c - '0');
   }
   if(plen > 32) {
      return std::nullopt;
   }

   return IPv4Subnet(*addr, plen);
}

bool IPv4Subnet::contains(const IPv4Address& ip) const {
   return (ip & IPv4Address::netmask(m_prefix_length)) == m_address;
}

std::string IPv4Subnet::to_string() const {
   return fmt("{}/{}", m_address.to_string(), static_cast<size_t>(m_prefix_length));
}

std::vector<uint8_t> IPv4Subnet::serialize() const {
   std::vector<uint8_t> out;
   if(is_host()) {
      out.resize(4);
      store_be(m_address.address(), out.data());
      return out;
   }
   out.resize(8);
   store_be(m_address.address(), out.data());
   store_be(IPv4Address::netmask(m_prefix_length).address(), out.data() + 4);
   return out;
}

}  // namespace Botan

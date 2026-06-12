/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ipv6_address.h>

#include <botan/ipv4_address.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <bit>

namespace Botan {

IPv6Address::IPv6Address(std::span<const uint8_t, 16> ip) : m_ip{} {
   for(size_t i = 0; i != 16; ++i) {
      m_ip[i] = ip[i];
   }
}

//static
std::optional<IPv6Address> IPv6Address::from_string(std::string_view str) {
   if(str.empty()) {
      return {};
   }

   // Parsed hex groups, split by whether they appeared before or after a "::".
   // If no "::" appears, only `pre` is populated and must reach exactly 8 groups.
   std::array<uint16_t, 8> pre{};
   std::array<uint16_t, 8> post{};
   size_t pre_count = 0;
   size_t post_count = 0;
   bool seen_double_colon = false;

   auto hex_value = [](char c) -> std::optional<uint8_t> {
      if(c >= '0' && c <= '9') {
         return c - '0';
      } else if(c >= 'a' && c <= 'f') {
         return 10 + (c - 'a');
      } else if(c >= 'A' && c <= 'F') {
         return 10 + (c - 'A');
      } else {
         return {};
      }
   };

   size_t idx = 0;
   bool expect_group = true;  // set after any separator, cleared after a group

   while(idx < str.size()) {
      if(str[idx] == ':') {
         if(idx + 1 < str.size() && str[idx + 1] == ':') {
            if(seen_double_colon) {
               return {};  // at most one "::"
            }
            seen_double_colon = true;
            idx += 2;
            expect_group = (idx < str.size());
            continue;
         }
         // single ':' separator between groups, only valid after a group
         if(expect_group) {
            return {};
         }
         expect_group = true;
         idx += 1;
         continue;
      }

      // Parse a hex group of 1..4 digits
      const size_t group_start = idx;
      uint32_t group = 0;
      size_t hex_chars = 0;
      while(idx < str.size() && hex_chars < 4) {
         const auto digit = hex_value(str[idx]);
         if(digit.has_value() == false) {
            break;
         }
         group = (group << 4) | static_cast<uint32_t>(digit.value());
         idx += 1;
         hex_chars += 1;
      }
      if(hex_chars == 0) {
         return {};
      }
      // If a 5th hex digit follows, the group is oversized.
      if(hex_chars == 4 && idx < str.size() && hex_value(str[idx]).has_value()) {
         return {};
      }

      /*
      RFC 4291 2.2 allows the final 32 bits in dotted decimal, eg
      "::ffff:1.2.3.4". The dotted quad must consume the remainder of the
      input, and accounts for two 16-bit groups.
      */
      if(idx < str.size() && str[idx] == '.') {
         const auto ipv4 = IPv4Address::from_string(str.substr(group_start));
         if(!ipv4.has_value()) {
            return {};
         }
         const uint32_t v4 = ipv4->address();
         const std::array<uint16_t, 2> v4_groups{static_cast<uint16_t>(v4 >> 16), static_cast<uint16_t>(v4 & 0xFFFF)};
         for(const auto g : v4_groups) {
            if(seen_double_colon) {
               if(post_count >= 8) {
                  return {};
               }
               post[post_count++] = g;
            } else {
               if(pre_count >= 8) {
                  return {};
               }
               pre[pre_count++] = g;
            }
         }
         idx = str.size();
         expect_group = false;
         continue;
      }

      if(seen_double_colon) {
         if(post_count >= 8) {
            return {};
         }
         post[post_count++] = static_cast<uint16_t>(group);
      } else {
         if(pre_count >= 8) {
            return {};
         }
         pre[pre_count++] = static_cast<uint16_t>(group);
      }
      expect_group = false;
   }

   // Trailing single ':' is invalid
   if(expect_group) {
      return {};
   }

   const size_t total_groups = pre_count + post_count;
   if(seen_double_colon) {
      // "::" has to cover at least one zero group
      if(total_groups > 7) {
         return {};
      }
   } else {
      if(total_groups != 8) {
         return {};
      }
   }

   std::array<uint8_t, 16> out{};
   for(size_t i = 0; i != pre_count; ++i) {
      out[2 * i] = get_byte<0>(pre[i]);
      out[2 * i + 1] = get_byte<1>(pre[i]);
   }
   const size_t gap = 8 - total_groups;
   for(size_t i = 0; i != post_count; ++i) {
      const size_t target = pre_count + gap + i;
      out[2 * target] = get_byte<0>(post[i]);
      out[2 * target + 1] = get_byte<1>(post[i]);
   }
   return IPv6Address(out);
}

//static
IPv6Address IPv6Address::netmask(size_t bits) {
   BOTAN_ARG_CHECK(bits <= 128, "IPv6 netmask prefix length must be at most 128");

   const size_t full_bytes = bits / 8;
   const size_t leftover = bits % 8;

   std::array<uint8_t, 16> m{};
   for(size_t i = 0; i != full_bytes; ++i) {
      m[i] = 0xFF;
   }

   if(leftover > 0) {
      m[full_bytes] = static_cast<uint8_t>(0xFF << (8 - leftover));
   }

   return IPv6Address(m);
}

std::string IPv6Address::to_string() const {
   static const char* hex = "0123456789abcdef";

   std::array<uint16_t, 8> groups{};
   for(size_t i = 0; i != 8; ++i) {
      groups[i] = make_uint16(m_ip[2 * i], m_ip[2 * i + 1]);
   }

   /*
   Find the run of zero groups to elide with "::", per RFC 5952 4.2:
   "The use of the symbol '::' MUST be used to its maximum capability",
   "The symbol '::' MUST NOT be used to shorten just one 16-bit 0 field",
   and on ties "the first sequence of zero bits MUST be shortened".
   */
   size_t best_start = 0;
   size_t best_len = 0;
   size_t run_len = 0;
   for(size_t i = 0; i != 8; ++i) {
      if(groups[i] == 0) {
         run_len += 1;
         if(run_len > best_len) {
            best_len = run_len;
            best_start = i + 1 - run_len;
         }
      } else {
         run_len = 0;
      }
   }

   std::string out;
   out.reserve(39);

   auto append_group = [&](uint16_t group) {
      bool started = false;
      // Write each nibble omitting leading 0s
      for(int s = 12; s >= 0; s -= 4) {
         const auto nibble = (group >> s) & 0xF;
         if(nibble != 0 || started || s == 0) {
            out.push_back(hex[nibble]);
            started = true;
         }
      }
   };

   if(best_len < 2) {
      // No run of two or more zero groups; write the full form
      for(size_t i = 0; i != 8; ++i) {
         if(i > 0) {
            out.push_back(':');
         }
         append_group(groups[i]);
      }
   } else {
      for(size_t i = 0; i != best_start; ++i) {
         if(i > 0) {
            out.push_back(':');
         }
         append_group(groups[i]);
      }
      out += "::";
      for(size_t i = best_start + best_len; i != 8; ++i) {
         if(i > best_start + best_len) {
            out.push_back(':');
         }
         append_group(groups[i]);
      }
   }
   return out;
}

IPv6Address IPv6Address::operator&(const IPv6Address& other) const {
   std::array<uint8_t, 16> masked{};
   for(size_t i = 0; i != 16; ++i) {
      masked[i] = m_ip[i] & other.m_ip[i];
   }
   return IPv6Address(masked);
}

std::optional<size_t> IPv6Address::prefix_length() const {
   // Count leading one bits, stopping at the first byte that isn't fully set.
   size_t leading = 0;
   for(size_t i = 0; i != 16; ++i) {
      const size_t hw = (m_ip[i] == 0xFF) ? 8 : std::countl_one(m_ip[i]);
      leading += hw;
      if(hw != 8) {
         break;
      }
   }

   // Verify this is exactly equal to a netmask of that size
   if(*this != netmask(leading)) {
      return std::nullopt;
   }
   return leading;
}

std::optional<IPv4Address> IPv6Address::as_ipv4() const {
   const uint32_t ip0 = load_be<uint32_t>(m_ip.data(), 0);
   const uint32_t ip1 = load_be<uint32_t>(m_ip.data(), 1);
   const uint32_t ip2 = load_be<uint32_t>(m_ip.data(), 2);
   const uint32_t ip3 = load_be<uint32_t>(m_ip.data(), 3);

   if(ip0 == 0x00000000 && ip1 == 0x00000000 && (ip2 == 0x00000000 || ip2 == 0x0000FFFF)) {
      return IPv4Address(ip3);
   } else {
      return {};
   }
}

IPv6Subnet::IPv6Subnet(IPv6Address address, size_t prefix_length) :
      m_address(address & IPv6Address::netmask(prefix_length)), m_prefix_length(static_cast<uint8_t>(prefix_length)) {
   // IPv6Address::netmask validates prefix_length <= 128, so by this point
   // the static_cast is in range.
}

//static
std::optional<IPv6Subnet> IPv6Subnet::from_address_and_mask(std::span<const uint8_t, 32> addr_and_mask) {
   const auto addr = IPv6Address(addr_and_mask.first<16>());
   const auto mask = IPv6Address(addr_and_mask.last<16>());

   if(const auto plen = mask.prefix_length()) {
      return IPv6Subnet(addr, *plen);
   } else {
      return {};
   }
}

//static
std::optional<IPv6Subnet> IPv6Subnet::from_string(std::string_view str) {
   const auto slash = str.find('/');
   if(slash == std::string_view::npos) {
      return std::nullopt;
   }

   auto addr = IPv6Address::from_string(str.substr(0, slash));
   if(!addr.has_value()) {
      return std::nullopt;
   }

   // Parse the prefix length as a canonical decimal integer in [0, 128]
   const auto plen_str = str.substr(slash + 1);

   const auto plen = parse_sz(plen_str, /*require_canonical=*/true);

   if(!plen.has_value() || plen.value() > 128) {
      return std::nullopt;
   }

   return IPv6Subnet(*addr, plen.value());
}

bool IPv6Subnet::contains(const IPv6Address& ip) const {
   return (ip & IPv6Address::netmask(m_prefix_length)) == m_address;
}

std::string IPv6Subnet::to_string() const {
   return fmt("{}/{}", m_address.to_string(), static_cast<size_t>(m_prefix_length));
}

std::vector<uint8_t> IPv6Subnet::serialize() const {
   const auto addr = m_address.address();
   if(is_host()) {
      return std::vector<uint8_t>(addr.begin(), addr.end());
   }
   const auto mask = IPv6Address::netmask(m_prefix_length).address();
   std::vector<uint8_t> out;
   out.reserve(32);
   out.insert(out.end(), addr.begin(), addr.end());
   out.insert(out.end(), mask.begin(), mask.end());
   return out;
}

}  // namespace Botan

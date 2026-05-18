/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dns_name.h>

#include <botan/exceptn.h>
#include <botan/internal/parsing.h>

namespace Botan {

namespace {

/*
* Validate @p name as an RFC 1035 / 1123 DNS name and return its
* lowercased canonical form. Throws Decoding_Error if @p name is not
* a valid DNS name. A "*" label is accepted so SAN wildcard entries
* round-trip through this validator unchanged.
*/
std::optional<std::string> check_and_canonicalize_dns_name(std::string_view name) {
   // Purported name is longer than what DNS allows
   if(name.size() > 255) {
      return {};
   }

   // DNS names are not empty
   if(name.empty()) {
      return {};
   }

   // DNS names do not start with or end with a dot
   if(name.starts_with(".") || name.ends_with(".")) {
      return {};
   }

   /*
   * Table mapping uppercase to lowercase and only including values valid for
   * DNS names: A-Z, a-z, 0-9, '-', '.', plus '*' for wildcarding (RFC 1035)
   */
   // clang-format off
   constexpr uint8_t DNS_CHAR_MAPPING[128] = {
      '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
      '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
      '\0', '\0', '\0', '\0',  '*', '\0', '\0',  '-',  '.', '\0',  '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',
       '9', '\0', '\0', '\0', '\0', '\0', '\0', '\0',  'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',
       'l',  'm',  'n',  'o',  'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z', '\0', '\0', '\0', '\0',
       '\0', '\0',  'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',  'p',  'q',
       'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z', '\0', '\0', '\0', '\0', '\0',
   };
   // clang-format on

   std::string canon;
   canon.reserve(name.size());

   // RFC 1035: DNS labels must not exceed 63 characters
   size_t current_label_length = 0;

   for(size_t i = 0; i != name.size(); ++i) {
      const char c = name[i];

      if(c == '.') {
         // Sequential dot (.) characters are not allowed
         if(i > 0 && name[i - 1] == '.') {
            return {};
         }

         // Empty labels are not allowed
         if(current_label_length == 0) {
            return {};
         }
         current_label_length = 0;  // Reset for next label
      } else {
         current_label_length++;

         // Labels cannot exceed maximum DNS label length
         if(current_label_length > 63) {
            return {};
         }
      }

      const uint8_t cu = static_cast<uint8_t>(c);
      // DNS names are not allowed to include any high-bit set characters
      if(cu >= 128) {
         return {};
      }
      const uint8_t mapped = DNS_CHAR_MAPPING[cu];
      // DNS names are from a restricted character set
      if(mapped == 0) {
         return {};
      }

      if(mapped == '-') {
         // DNS labels are not allowed to include a leading or trailing hyphen
         if(i == 0 || (i > 0 && name[i - 1] == '.')) {
            return {};  // leading hyphen
         }

         if(i == name.size() - 1 || (i < name.size() - 1 && name[i + 1] == '.')) {
            return {};  // trailing hyphen
         }
      }
      canon.push_back(static_cast<char>(mapped));
   }

   // This should never be hit, due to earlier validation steps
   if(current_label_length == 0) {
      return {};
   }

   return canon;
}

}  // namespace

//static
std::optional<DNSName> DNSName::from_string(std::string_view name) {
   if(auto canon = check_and_canonicalize_dns_name(name)) {
      // TODO(C++23) std::string::contains
      if(canon->find('*') != std::string::npos) {
         return {};
      }
      return DNSName(std::move(*canon));
   } else {
      return {};
   }
}

//static
std::optional<DNSName> DNSName::from_san_string(std::string_view name) {
   if(auto canon = check_and_canonicalize_dns_name(name)) {
      /*
      Validate the wildcard shape: at most one "*", and if present it must be in
      the leftmost label (no "." before it). This matches the RFC 6125 6.4.3
      form that host_wildcard_match accepts and rejects eg "*.*.example.com" or
      "foo.*.example.com"
      */
      const auto first_star = canon->find('*');
      if(first_star != std::string::npos) {
         if(canon->find('*', first_star + 1) != std::string::npos) {
            return std::nullopt;
         }
         const auto first_dot = canon->find('.');
         if(first_dot != std::string::npos && first_dot < first_star) {
            return std::nullopt;
         }
      }
      return DNSName(std::move(*canon));
   } else {
      return {};
   }
}

bool DNSName::matches_wildcard(std::string_view wildcard) const {
   return host_wildcard_match(wildcard, m_name);
}

}  // namespace Botan

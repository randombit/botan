/*
* Various string utils and parsing functions
* (C) 1999-2007,2013,2014,2015,2018 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/parsing.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>

namespace Botan {

uint16_t to_uint16(std::string_view str) {
   const uint32_t x = to_u32bit(str);

   if(x >> 16) {
      throw Invalid_Argument("Integer value exceeds 16 bit range");
   }

   return static_cast<uint16_t>(x);
}

uint32_t to_u32bit(std::string_view str_view) {
   const std::string str(str_view);

   // std::stoul is not strict enough. Ensure that str is digit only [0-9]*
   for(const char chr : str) {
      if(chr < '0' || chr > '9') {
         throw Invalid_Argument("to_u32bit invalid decimal string '" + str + "'");
      }
   }

   const unsigned long int x = std::stoul(str);

   if constexpr(sizeof(unsigned long int) > 4) {
      // x might be uint64
      if(x > std::numeric_limits<uint32_t>::max()) {
         throw Invalid_Argument("Integer value of " + str + " exceeds 32 bit range");
      }
   }

   return static_cast<uint32_t>(x);
}

/*
* Parse a SCAN-style algorithm name
*/
std::vector<std::string> parse_algorithm_name(std::string_view namex) {
   if(namex.find('(') == std::string::npos && namex.find(')') == std::string::npos) {
      return {std::string(namex)};
   }

   std::string name(namex);
   std::string substring;
   std::vector<std::string> elems;
   size_t level = 0;

   elems.push_back(name.substr(0, name.find('(')));
   name = name.substr(name.find('('));

   for(auto i = name.begin(); i != name.end(); ++i) {
      char c = *i;

      if(c == '(') {
         ++level;
      }
      if(c == ')') {
         if(level == 1 && i == name.end() - 1) {
            if(elems.size() == 1) {
               elems.push_back(substring.substr(1));
            } else {
               elems.push_back(substring);
            }
            return elems;
         }

         if(level == 0 || (level == 1 && i != name.end() - 1)) {
            throw Invalid_Algorithm_Name(namex);
         }
         --level;
      }

      if(c == ',' && level == 1) {
         if(elems.size() == 1) {
            elems.push_back(substring.substr(1));
         } else {
            elems.push_back(substring);
         }
         substring.clear();
      } else {
         substring += c;
      }
   }

   if(!substring.empty()) {
      throw Invalid_Algorithm_Name(namex);
   }

   return elems;
}

std::vector<std::string> split_on(std::string_view str, char delim) {
   std::vector<std::string> elems;
   if(str.empty()) {
      return elems;
   }

   std::string substr;
   for(auto i = str.begin(); i != str.end(); ++i) {
      if(*i == delim) {
         if(!substr.empty()) {
            elems.push_back(substr);
         }
         substr.clear();
      } else {
         substr += *i;
      }
   }

   if(substr.empty()) {
      throw Invalid_Argument(fmt("Unable to split string '{}", str));
   }
   elems.push_back(substr);

   return elems;
}

/*
* Join a string
*/
std::string string_join(const std::vector<std::string>& strs, char delim) {
   std::ostringstream out;

   for(size_t i = 0; i != strs.size(); ++i) {
      if(i != 0) {
         out << delim;
      }
      out << strs[i];
   }

   return out.str();
}

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

   for(char c : str) {
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

/*
* Convert an IP address to decimal-dotted string
*/
std::string ipv4_to_string(uint32_t ip) {
   uint8_t bits[4];
   store_be(ip, bits);

   std::string str;

   for(size_t i = 0; i != 4; ++i) {
      if(i > 0) {
         str += ".";
      }
      str += std::to_string(bits[i]);
   }

   return str;
}

std::string tolower_string(std::string_view in) {
   std::string s(in);
   for(size_t i = 0; i != s.size(); ++i) {
      const int cu = static_cast<unsigned char>(s[i]);
      if(std::isalpha(cu)) {
         s[i] = static_cast<char>(std::tolower(cu));
      }
   }
   return s;
}

bool host_wildcard_match(std::string_view issued_, std::string_view host_) {
   const std::string issued = tolower_string(issued_);
   const std::string host = tolower_string(host_);

   if(host.empty() || issued.empty()) {
      return false;
   }

   /*
   If there are embedded nulls in your issued name
   Well I feel bad for you son
   */
   if(std::count(issued.begin(), issued.end(), char(0)) > 0) {
      return false;
   }

   // If more than one wildcard, then issued name is invalid
   const size_t stars = std::count(issued.begin(), issued.end(), '*');
   if(stars > 1) {
      return false;
   }

   // '*' is not a valid character in DNS names so should not appear on the host side
   if(std::count(host.begin(), host.end(), '*') != 0) {
      return false;
   }

   // Similarly a DNS name can't end in .
   if(host[host.size() - 1] == '.') {
      return false;
   }

   // And a host can't have an empty name component, so reject that
   if(host.find("..") != std::string::npos) {
      return false;
   }

   // Exact match: accept
   if(issued == host) {
      return true;
   }

   /*
   Otherwise it might be a wildcard

   If the issued size is strictly longer than the hostname size it
   couldn't possibly be a match, even if the issued value is a
   wildcard. The only exception is when the wildcard ends up empty
   (eg www.example.com matches www*.example.com)
   */
   if(issued.size() > host.size() + 1) {
      return false;
   }

   // If no * at all then not a wildcard, and so not a match
   if(stars != 1) {
      return false;
   }

   /*
   Now walk through the issued string, making sure every character
   matches. When we come to the (singular) '*', jump forward in the
   hostname by the corresponding amount. We know exactly how much
   space the wildcard takes because it must be exactly `len(host) -
   len(issued) + 1 chars`.

   We also verify that the '*' comes in the leftmost component, and
   doesn't skip over any '.' in the hostname.
   */
   size_t dots_seen = 0;
   size_t host_idx = 0;

   for(size_t i = 0; i != issued.size(); ++i) {
      dots_seen += (issued[i] == '.');

      if(issued[i] == '*') {
         // Fail: wildcard can only come in leftmost component
         if(dots_seen > 0) {
            return false;
         }

         /*
         Since there is only one * we know the tail of the issued and
         hostname must be an exact match. In this case advance host_idx
         to match.
         */
         const size_t advance = (host.size() - issued.size() + 1);

         if(host_idx + advance > host.size()) {  // shouldn't happen
            return false;
         }

         // Can't be any intervening .s that we would have skipped
         if(std::count(host.begin() + host_idx, host.begin() + host_idx + advance, '.') != 0) {
            return false;
         }

         host_idx += advance;
      } else {
         if(issued[i] != host[host_idx]) {
            return false;
         }

         host_idx += 1;
      }
   }

   // Wildcard issued name must have at least 3 components
   if(dots_seen < 2) {
      return false;
   }

   return true;
}

std::string check_and_canonicalize_dns_name(std::string_view name) {
   if(name.size() > 255) {
      throw Decoding_Error("DNS name exceeds maximum allowed length");
   }

   if(name.empty()) {
      throw Decoding_Error("DNS name cannot be empty");
   }

   if(name.starts_with(".")) {
      throw Decoding_Error("DNS name cannot start with a dot");
   }

   /*
   * Table mapping uppercase to lowercase and only including values for valid DNS names
   * namely A-Z, a-z, 0-9, hypen, and dot, plus '*' for wildcarding.
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

   for(size_t i = 0; i != name.size(); ++i) {
      char c = name[i];

      if(c == '.') {
         if(name[i - 1] == '.') {
            throw Decoding_Error("DNS name contains sequential period chars");
         }
         if(i == name.size() - 1) {
            throw Decoding_Error("DNS name cannot end in a period");
         }
      }

      const uint8_t cu = static_cast<uint8_t>(c);
      if(cu >= 128) {
         throw Decoding_Error("DNS name must not contain any extended ASCII code points");
      }
      const uint8_t mapped = DNS_CHAR_MAPPING[cu];
      if(mapped == 0) {
         throw Decoding_Error("DNS name includes invalid character");
      }
      // TODO check label lengths
      canon.push_back(static_cast<char>(mapped));
   }

   return canon;
}

}  // namespace Botan

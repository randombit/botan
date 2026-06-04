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
#include <concepts>
#include <limits>
#include <sstream>

namespace Botan {

namespace {

std::optional<size_t> digit_from_ascii(char c) {
   if(c >= '0' && c <= '9') {
      return c - '0';
   } else {
      return {};
   }
}

template <std::unsigned_integral T>
std::optional<T> parse_decimal_integer(std::string_view input) {
   if(input.empty() || input.size() > (std::numeric_limits<T>::digits10 + 1)) {
      return {};
   }

   T accum = 0;

   for(const char c : input) {
      if(const auto digit = digit_from_ascii(c)) {
         if(accum > (std::numeric_limits<T>::max() - static_cast<T>(*digit)) / 10) {
            return {};
         }
         accum = accum * 10 + static_cast<T>(*digit);
      } else {
         return {};
      }
   }

   return accum;
}

}  // namespace

std::optional<uint16_t> parse_u16(std::string_view input) {
   return parse_decimal_integer<uint16_t>(input);
}

std::optional<uint32_t> parse_u32(std::string_view input) {
   return parse_decimal_integer<uint32_t>(input);
}

std::optional<uint64_t> parse_u64(std::string_view input) {
   return parse_decimal_integer<uint64_t>(input);
}

std::optional<size_t> parse_sz(std::string_view input) {
   return parse_decimal_integer<size_t>(input);
}

uint32_t to_u32bit(std::string_view input) {
   if(const auto parsed = parse_u32(input)) {
      return *parsed;
   } else {
      throw Invalid_Argument(fmt("Failed to parse input '{}' as a 32-bit integer", input));
   }
}

/*
* Parse a SCAN-style algorithm name
*/
std::vector<std::string> parse_algorithm_name(std::string_view scan_name) {
   if(scan_name.find('(') == std::string::npos && scan_name.find(')') == std::string::npos) {
      return {std::string(scan_name)};
   }

   std::string name(scan_name);
   std::string substring;
   std::vector<std::string> elems;
   size_t level = 0;

   elems.push_back(name.substr(0, name.find('(')));
   name = name.substr(name.find('('));

   for(auto i = name.begin(); i != name.end(); ++i) {
      const char c = *i;

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
            throw Invalid_Algorithm_Name(scan_name);
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
      throw Invalid_Algorithm_Name(scan_name);
   }

   return elems;
}

std::vector<std::string> split_on(std::string_view str, char delim) {
   std::vector<std::string> elems;
   if(str.empty()) {
      return elems;
   }

   std::string substr;
   for(const char c : str) {
      if(c == delim) {
         if(!substr.empty()) {
            elems.push_back(substr);
         }
         substr.clear();
      } else {
         substr += c;
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

std::string tolower_string(std::string_view str) {
   // Locale-independent ASCII fold; the only callers (DNS name canonicalization
   // for SAN/name-constraints) work on ASCII strings per RFC 1035.
   std::string lower(str);
   for(char& c : lower) {
      if(c >= 'A' && c <= 'Z') {
         c = static_cast<char>(c + ('a' - 'A'));
      }
   }
   return lower;
}

}  // namespace Botan

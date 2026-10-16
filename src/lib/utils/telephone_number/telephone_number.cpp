/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/telephone_number.h>

#include <botan/assert.h>

namespace Botan {

std::optional<TelephoneNumber> TelephoneNumber::from_string(std::string_view tn) {
   // TelephoneNumber ::= IA5String (SIZE (1..15)) (FROM ("0123456789#*"))
   if(tn.empty() || tn.size() > 15 || tn.find_first_not_of("0123456789#*") != std::string_view::npos) {
      return std::nullopt;
   }
   return TelephoneNumber(std::string(tn));
}

bool TelephoneNumber::is_wildcard() const {
   return m_number.find_first_of("*#") != std::string::npos;
}

std::optional<uint64_t> TelephoneNumber::numeric_value() const {
   if(is_wildcard()) {
      return std::nullopt;
   }
   uint64_t value = 0;
   for(const char c : m_number) {
      value = (value * 10) + static_cast<uint64_t>(c - '0');
   }
   return value;
}

/*
* RFC 8226 Section 9:
* "The count field is only applicable to start fields whose values do not
*  include "*" or "#" (i.e., a TelephoneNumber that does not include "*" or
*  "#").  count MUST NOT make the number increase in length (i.e., a
*  TelephoneNumberRange with TelephoneNumber=10 and count=91 is invalid);
*  formally, given the inputs count and TelephoneNumber of length D,
*  TelephoneNumber + count MUST be less than 10^D."
*
* The formal statement is off by one relative to its own example, so this
* checks that the last number in the range (start + count - 1) has D digits.
*/
std::optional<TelephoneNumberRange> TelephoneNumberRange::from(const TelephoneNumber& start, uint64_t count) {
   const auto pow10 = [](size_t n) -> uint64_t {
      // Always in range since the input length is at most 15
      uint64_t v = 1;
      for(size_t i = 0; i != n; ++i) {
         v *= 10;
      }
      return v;
   };

   const auto first = start.numeric_value();
   if(!first.has_value() || count <= 1) {
      return std::nullopt;
   }
   if(count > pow10(start.length()) - *first) {
      return std::nullopt;
   }
   return TelephoneNumberRange(start, count);
}

TelephoneNumber TelephoneNumberRange::last() const {
   uint64_t value = m_start.numeric_value().value() + m_count - 1;
   std::string digits(m_start.length(), '0');
   for(size_t i = digits.size(); i > 0; --i) {
      digits[i - 1] = static_cast<char>('0' + (value % 10));
      value /= 10;
   }
   auto tn = TelephoneNumber::from_string(digits);
   BOTAN_ASSERT_NOMSG(tn.has_value());
   return *tn;
}

bool TelephoneNumberRange::contains(const TelephoneNumber& tn) const {
   const auto value = tn.numeric_value();
   if(!value.has_value() || tn.length() != m_start.length()) {
      return false;
   }
   const uint64_t first = m_start.numeric_value().value();
   return *value >= first && (*value - first) < m_count;
}

bool TelephoneNumberRange::contains(const TelephoneNumberRange& other) const {
   if(other.m_start.length() != m_start.length()) {
      return false;
   }
   const uint64_t first = m_start.numeric_value().value();
   const uint64_t other_first = other.m_start.numeric_value().value();
   return other_first >= first && (other_first - first) + other.m_count <= m_count;
}

}  // namespace Botan

/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TELEPHONE_NUMBER_H_
#define BOTAN_TELEPHONE_NUMBER_H_

#include <botan/types.h>
#include <optional>
#include <string>
#include <string_view>

namespace Botan {

/**
* A telephone number as used in RFC 8226 STIR certificates
*
* TelephoneNumber ::= IA5String (SIZE (1..15)) (FROM ("0123456789#*"))
*
* This is the dialed form rather than E.164: '*' and '#' may appear, and
* leading zeros are significant, so "0123" and "123" are distinct numbers.
*/
class BOTAN_PUBLIC_API(3, 14) TelephoneNumber final {
   public:
      /**
      * Parse a telephone number
      * @return the number, or nullopt unless @p tn is 1 to 15 characters from "0123456789#*"
      */
      static std::optional<TelephoneNumber> from_string(std::string_view tn);

      /**
      * @return the number as it was given
      */
      const std::string& to_string() const { return m_number; }

      /**
      * @return true if the number contains '*' or '#'
      */
      bool is_wildcard() const;

      /**
      * @return the length of the number in characters
      */
      size_t length() const { return m_number.size(); }

      /**
      * @return the number as an integer, or nullopt if is_wildcard()
      */
      std::optional<uint64_t> numeric_value() const;

      /**
      * Numbers are ordered by their string form
      */
      auto operator<=>(const TelephoneNumber&) const = default;

   private:
      explicit TelephoneNumber(std::string number) : m_number(std::move(number)) {}

      std::string m_number;
};

/**
* A block of consecutive telephone numbers, all of the same length
*/
class BOTAN_PUBLIC_API(3, 14) TelephoneNumberRange final {
   public:
      /**
      * Create the range of @p count numbers beginning at @p start
      *
      * @return the range, or nullopt if @p start is a wildcard, @p count is
      * less than 2, or the range would run past the last number of the same length
      * as @p start
      */
      static std::optional<TelephoneNumberRange> from(const TelephoneNumber& start, uint64_t count);

      /**
      * @return the first number in the range
      */
      const TelephoneNumber& start() const { return m_start; }

      /**
      * @return the number of numbers in the range
      */
      uint64_t count() const { return m_count; }

      /**
      * @return the final number in the range
      */
      TelephoneNumber last() const;

      /**
      * @return true if @p tn has the same length as this range and lies within it
      */
      bool contains(const TelephoneNumber& tn) const;

      /**
      * @return true if every number of @p other lies within this range
      */
      bool contains(const TelephoneNumberRange& other) const;

      /**
      * Ranges are ordered by start and then by count
      */
      auto operator<=>(const TelephoneNumberRange&) const = default;

   private:
      TelephoneNumberRange(TelephoneNumber start, uint64_t count) : m_start(std::move(start)), m_count(count) {}

      TelephoneNumber m_start;
      uint64_t m_count;
};

}  // namespace Botan

#endif

/*
* (C) 1999-2007,2018,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASN1_TIME_TYPE_H_
#define BOTAN_ASN1_TIME_TYPE_H_

#include <botan/asn1_obj.h>
#include <chrono>

namespace Botan {

/**
* Time (GeneralizedTime/UniversalTime)
*/
class BOTAN_PUBLIC_API(2, 0) ASN1_Time final : public ASN1_Object {
   public:
      /// DER encode a ASN1_Time
      void encode_into(DER_Encoder& to) const override;

      // Decode a BER encoded ASN1_Time
      void decode_from(BER_Decoder& from) override;

      /// Return an internal string representation of the time
      std::string to_string() const;

      /// Returns a human friendly string representation of no particular formatting
      std::string readable_string() const;

      /// Return if the time has been set somehow
      bool time_is_set() const;

      /// Return the tag (UtcTime or GeneralizedTime) this time was encoded with
      ASN1_Type tagging() const { return m_tag; }

      ///  Compare this time against another
      int32_t cmp(const ASN1_Time& other) const;

      /// Create an invalid ASN1_Time
      ASN1_Time() = default;

      /// Create an ASN1_Time from seconds since epoch
      static ASN1_Time from_seconds_since_epoch(uint64_t seconds);

      /// Create a ASN1_Time from a time point
      static ASN1_Time from_time_point(const std::chrono::system_clock::time_point& time);

      /// Create a ASN1_Time from a string
      ///
      /// Only the fixed 13 or 15 char RFC 5280 format (eg [YY]YYMMDDHHMMSSZ) is accepted,
      /// tag is set based on the use of 2 or 4 digit year, 2-digit years use the
      /// 1950 breakeven point (see RFC 5280 Section 4.1.2.5.1)
      static ASN1_Time from_string(std::string_view t_spec);

      /// Create a ASN1_Time from a string
      ///
      /// Only the fixed 13 or 15 char RFC 5280 format (eg [YY]YYMMDDHHMMSSZ) is accepted,
      /// based on the provided tag (which must be UtcTime or GeneralizedTime)
      static ASN1_Time from_string(std::string_view t_spec, ASN1_Type tag);

      /// Create a ASN1_Time from a time point
      explicit ASN1_Time(const std::chrono::system_clock::time_point& time) {
         *this = ASN1_Time::from_time_point(time);
      }

      /// Create an ASN1_Time from string
      BOTAN_FUTURE_EXPLICIT ASN1_Time(std::string_view t_spec) { *this = ASN1_Time::from_string(t_spec); }

      /// Create an ASN1_Time from string and a specified tagging (Utc or Generalized)
      ASN1_Time(std::string_view t_spec, ASN1_Type tag) { *this = ASN1_Time::from_string(t_spec, tag); }

      /// Returns a STL timepoint object
      std::chrono::system_clock::time_point to_std_timepoint() const;

      /// Return time since epoch
      uint64_t time_since_epoch() const;

   private:
      ASN1_Time(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second, ASN1_Type tag);

      uint16_t m_year = 0;   // range 0-9999
      uint8_t m_month = 0;   // range 1-12
      uint8_t m_day = 0;     // range 1-31
      uint8_t m_hour = 0;    // range 0-23
      uint8_t m_minute = 0;  // range 0-59
      uint8_t m_second = 0;  // range 0-59 (leap seconds not supported)
      ASN1_Type m_tag = ASN1_Type::NoObject;
};

/*
* Comparison Operations
*/
BOTAN_PUBLIC_API(2, 0) bool operator==(const ASN1_Time& x, const ASN1_Time& y);
BOTAN_PUBLIC_API(2, 0) bool operator!=(const ASN1_Time& x, const ASN1_Time& y);
BOTAN_PUBLIC_API(2, 0) bool operator<=(const ASN1_Time& x, const ASN1_Time& y);
BOTAN_PUBLIC_API(2, 0) bool operator>=(const ASN1_Time& x, const ASN1_Time& y);
BOTAN_PUBLIC_API(2, 0) bool operator<(const ASN1_Time& x, const ASN1_Time& y);
BOTAN_PUBLIC_API(2, 0) bool operator>(const ASN1_Time& x, const ASN1_Time& y);

}  // namespace Botan

#endif

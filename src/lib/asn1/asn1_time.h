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

      ///  Compare this time against another
      int32_t cmp(const ASN1_Time& other) const;

      /// Create an invalid ASN1_Time
      ASN1_Time() = default;

      /// Create a ASN1_Time from a time point
      explicit ASN1_Time(const std::chrono::system_clock::time_point& time);

      /// Create an ASN1_Time from seconds since epoch
      static ASN1_Time from_seconds_since_epoch(uint64_t seconds);

      /// Create an ASN1_Time from string
      BOTAN_FUTURE_EXPLICIT ASN1_Time(std::string_view t_spec);

      /// Create an ASN1_Time from string and a specified tagging (Utc or Generalized)
      ASN1_Time(std::string_view t_spec, ASN1_Type tag);

      /// Returns a STL timepoint object
      std::chrono::system_clock::time_point to_std_timepoint() const;

      /// Return time since epoch
      uint64_t time_since_epoch() const;

   private:
      void set_to(std::string_view t_spec, ASN1_Type type);
      bool passes_sanity_check() const;

      uint32_t m_year = 0;
      uint32_t m_month = 0;
      uint32_t m_day = 0;
      uint32_t m_hour = 0;
      uint32_t m_minute = 0;
      uint32_t m_second = 0;
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

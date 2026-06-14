/*
* X.509 Time Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_time.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/internal/calendar.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <sstream>

namespace Botan {

namespace {

// Format an integer as exactly `digits` zero-padded decimal digits
std::string zero_pad(uint32_t value, size_t digits) {
   std::string s = std::to_string(value);
   BOTAN_ASSERT_NOMSG(s.size() <= digits);
   const size_t padding = digits - s.size();
   if(padding == 0) {
      return s;
   } else {
      return std::string(padding, '0') + s;
   }
}

}  // namespace

ASN1_Time ASN1_Time::from_seconds_since_epoch(uint64_t time_since_epoch) {
   return ASN1_Time::from_time_point(std::chrono::system_clock::time_point(std::chrono::seconds(time_since_epoch)));
}

ASN1_Time::ASN1_Time(
   uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second, ASN1_Type tag) :
      m_year(year), m_month(month), m_day(day), m_hour(hour), m_minute(minute), m_second(second), m_tag(tag) {
   if(tag != ASN1_Type::UtcTime && tag != ASN1_Type::GeneralizedTime) {
      throw Invalid_Argument("ASN1_Time tag must be UtcTime or GeneralizedTime");
   }

   /*
   * RFC 5280 Section 4.1.2.5:
   *    To indicate that a certificate has no well-defined expiration date,
   *    the notAfter SHOULD be assigned the GeneralizedTime value of
   *    99991231235959Z.
   */
   const uint16_t min_year = 1950;
   const uint16_t max_year = (tag == ASN1_Type::UtcTime) ? 2049 : 9999;

   if(m_year < min_year || m_year > max_year) {
      throw Invalid_Argument(fmt("ASN1_Time year {} is out of range ({} to {})", m_year, min_year, max_year));
   }

   if(m_month < 1 || m_month > 12) {
      throw Invalid_Argument(fmt("ASN1_Time month {} is out of range", static_cast<uint32_t>(m_month)));
   }

   constexpr uint8_t days_in_month[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

   const bool is_leap_year = (m_year % 4 == 0) && (m_year % 100 != 0 || m_year % 400 == 0);
   const uint8_t max_day = (m_month == 2 && is_leap_year) ? 29 : days_in_month[m_month - 1];

   if(m_day < 1 || m_day > max_day) {
      throw Invalid_Argument(fmt("ASN1_Time day {} is out of range for month {}",
                                 static_cast<uint32_t>(m_day),
                                 static_cast<uint32_t>(m_month)));
   }

   if(m_hour > 23) {
      throw Invalid_Argument(fmt("ASN1_Time hour {} is out of range", static_cast<uint32_t>(m_hour)));
   }

   if(m_minute > 59) {
      throw Invalid_Argument(fmt("ASN1_Time minute {} is out of range", static_cast<uint32_t>(m_minute)));
   }

   /*
   * RFC 5280 is silent on the issue of leap seconds in certificate fields, but both
   * OpenSSL and Go reject which suggests they are rarely if ever used in practice.
   */
   if(m_second > 59) {
      throw Invalid_Argument(fmt("ASN1_Time second {} is out of range", static_cast<uint32_t>(m_second)));
   }
}

//static
ASN1_Time ASN1_Time::from_time_point(const std::chrono::system_clock::time_point& time) {
   const calendar_point cal(time);

   const ASN1_Type tag = (cal.year() >= 2050) ? ASN1_Type::GeneralizedTime : ASN1_Type::UtcTime;

   return ASN1_Time(static_cast<uint16_t>(cal.year()),
                    static_cast<uint8_t>(cal.month()),
                    static_cast<uint8_t>(cal.day()),
                    static_cast<uint8_t>(cal.hour()),
                    static_cast<uint8_t>(cal.minutes()),
                    static_cast<uint8_t>(cal.seconds()),
                    tag);
}

//static
ASN1_Time ASN1_Time::from_string(std::string_view t_spec, ASN1_Type tag) {
   BOTAN_ARG_CHECK(tag == ASN1_Type::UtcTime || tag == ASN1_Type::GeneralizedTime, "Invalid tag for ASN1_Time");

   if(tag == ASN1_Type::GeneralizedTime) {
      BOTAN_ARG_CHECK(t_spec.size() == 15, "Invalid GeneralizedTime input string");
   } else {
      BOTAN_ARG_CHECK(t_spec.size() == 13, "Invalid UTCTime input string");
   }

   BOTAN_ARG_CHECK(t_spec.back() == 'Z', "Botan does not support ASN1 times with timezones other than Z");

   const size_t field_len = 2;
   const size_t year_len = (tag == ASN1_Type::UtcTime) ? 2 : 4;

   const size_t year_start = 0;
   const size_t month_start = year_start + year_len;
   const size_t day_start = month_start + field_len;
   const size_t hour_start = day_start + field_len;
   const size_t min_start = hour_start + field_len;
   const size_t sec_start = min_start + field_len;

   uint32_t year = to_u32bit(t_spec.substr(year_start, year_len));
   const uint32_t month = to_u32bit(t_spec.substr(month_start, field_len));
   const uint32_t day = to_u32bit(t_spec.substr(day_start, field_len));
   const uint32_t hour = to_u32bit(t_spec.substr(hour_start, field_len));
   const uint32_t minute = to_u32bit(t_spec.substr(min_start, field_len));
   const uint32_t second = to_u32bit(t_spec.substr(sec_start, field_len));

   if(tag == ASN1_Type::UtcTime) {
      // Interpret the two digit year by the 1950/2050 split (RFC 5280 Section 4.1.2.5.1)
      year += (year >= 50) ? 1900 : 2000;
   }

   return ASN1_Time(static_cast<uint16_t>(year),
                    static_cast<uint8_t>(month),
                    static_cast<uint8_t>(day),
                    static_cast<uint8_t>(hour),
                    static_cast<uint8_t>(minute),
                    static_cast<uint8_t>(second),
                    tag);
}

//static
ASN1_Time ASN1_Time::from_string(std::string_view t_spec) {
   if(t_spec.size() == 13) {
      return ASN1_Time::from_string(t_spec, ASN1_Type::UtcTime);
   } else if(t_spec.size() == 15) {
      return ASN1_Time::from_string(t_spec, ASN1_Type::GeneralizedTime);
   } else {
      throw Invalid_Argument("Time string could not be parsed as GeneralizedTime or UTCTime.");
   }
}

void ASN1_Time::encode_into(DER_Encoder& der) const {
   BOTAN_ARG_CHECK(m_tag == ASN1_Type::UtcTime || m_tag == ASN1_Type::GeneralizedTime, "ASN1_Time: Bad encoding tag");

   der.add_object(m_tag, ASN1_Class::Universal, to_string());
}

void ASN1_Time::decode_from(BER_Decoder& source) {
   const BER_Object ber_time = source.get_next_object();

   if(ber_time.get_class() != ASN1_Class::Universal ||
      (ber_time.type() != ASN1_Type::UtcTime && ber_time.type() != ASN1_Type::GeneralizedTime)) {
      throw Decoding_Error(fmt("ASN1_Time: Unexpected tag {}/{}",
                               static_cast<uint32_t>(ber_time.type()),
                               static_cast<uint32_t>(ber_time.get_class())));
   }

   try {
      // Assigning only after a successful parse means that a decoding error
      // cannot leave this object in a partially written state
      *this = ASN1_Time::from_string(ASN1::to_string(ber_time), ber_time.type());
   } catch(Invalid_Argument& e) {
      throw Decoding_Error(fmt("Invalid ASN1_Time encoding: {}", e.what()));
   }
}

std::string ASN1_Time::to_string() const {
   if(!time_is_set()) {
      throw Invalid_State("ASN1_Time::to_string: No time set");
   }

   BOTAN_ASSERT_NOMSG(m_year <= 9999);

   std::ostringstream out;

   // UTCTime uses a 2 digit year, GeneralizedTime a 4 digit year
   if(m_tag == ASN1_Type::UtcTime) {
      if(m_year < 1950 || m_year >= 2050) {
         throw Encoding_Error(fmt("ASN_Time: The time {} cannot be encoded as UTCTime", readable_string()));
      }

      out << (zero_pad((m_year >= 2000) ? (m_year - 2000) : (m_year - 1900), 2));
   } else {
      out << zero_pad(m_year, 4);
   }

   // clang-format off
   out << zero_pad(m_month, 2)
       << zero_pad(m_day, 2)
       << zero_pad(m_hour, 2)
       << zero_pad(m_minute, 2)
       << zero_pad(m_second, 2) << "Z";
   // clang-format on

   return out.str();
}

std::string ASN1_Time::readable_string() const {
   if(!time_is_set()) {
      throw Invalid_State("ASN1_Time::readable_string: No time set");
   }

   // desired format: "YYYY/MM/DD HH:MM:SS UTC"

   std::ostringstream out;

   out << zero_pad(m_year, 4) << "/" << zero_pad(m_month, 2) << "/" << zero_pad(m_day, 2) << " ";
   out << zero_pad(m_hour, 2) << ":" << zero_pad(m_minute, 2) << ":" << zero_pad(m_second, 2) << " UTC";

   return out.str();
}

bool ASN1_Time::time_is_set() const {
   return (m_year != 0);
}

int32_t ASN1_Time::cmp(const ASN1_Time& other) const {
   if(!time_is_set() || !other.time_is_set()) {
      throw Invalid_State("ASN1_Time::cmp: Cannot compare empty times");
   }

   constexpr int32_t EARLIER = -1;
   constexpr int32_t LATER = 1;
   constexpr int32_t SAME_TIME = 0;

   if(m_year < other.m_year) {
      return EARLIER;
   }
   if(m_year > other.m_year) {
      return LATER;
   }
   if(m_month < other.m_month) {
      return EARLIER;
   }
   if(m_month > other.m_month) {
      return LATER;
   }
   if(m_day < other.m_day) {
      return EARLIER;
   }
   if(m_day > other.m_day) {
      return LATER;
   }
   if(m_hour < other.m_hour) {
      return EARLIER;
   }
   if(m_hour > other.m_hour) {
      return LATER;
   }
   if(m_minute < other.m_minute) {
      return EARLIER;
   }
   if(m_minute > other.m_minute) {
      return LATER;
   }
   if(m_second < other.m_second) {
      return EARLIER;
   }
   if(m_second > other.m_second) {
      return LATER;
   }

   return SAME_TIME;
}

std::chrono::system_clock::time_point ASN1_Time::to_std_timepoint() const {
   return calendar_point(m_year, m_month, m_day, m_hour, m_minute, m_second).to_std_timepoint();
}

uint64_t ASN1_Time::time_since_epoch() const {
   return calendar_point(m_year, m_month, m_day, m_hour, m_minute, m_second).seconds_since_epoch();
}

/*
* Compare two ASN1_Times for in various ways
*/
bool operator==(const ASN1_Time& t1, const ASN1_Time& t2) {
   return (t1.cmp(t2) == 0);
}

bool operator!=(const ASN1_Time& t1, const ASN1_Time& t2) {
   return (t1.cmp(t2) != 0);
}

bool operator<=(const ASN1_Time& t1, const ASN1_Time& t2) {
   return (t1.cmp(t2) <= 0);
}

bool operator>=(const ASN1_Time& t1, const ASN1_Time& t2) {
   return (t1.cmp(t2) >= 0);
}

bool operator<(const ASN1_Time& t1, const ASN1_Time& t2) {
   return (t1.cmp(t2) < 0);
}

bool operator>(const ASN1_Time& t1, const ASN1_Time& t2) {
   return (t1.cmp(t2) > 0);
}

}  // namespace Botan

/*
* X.509 Time Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/internal/calendar.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <iomanip>

namespace Botan {

ASN1_Time::ASN1_Time(const std::chrono::system_clock::time_point& time) {
   calendar_point cal(time);

   m_year = cal.year();
   m_month = cal.month();
   m_day = cal.day();
   m_hour = cal.hour();
   m_minute = cal.minutes();
   m_second = cal.seconds();

   m_tag = (m_year >= 2050) ? ASN1_Type::GeneralizedTime : ASN1_Type::UtcTime;
}

ASN1_Time::ASN1_Time(std::string_view t_spec, ASN1_Type tag) {
   set_to(t_spec, tag);
}

ASN1_Time::ASN1_Time(std::string_view t_spec) {
   if(t_spec.size() == 13) {
      set_to(t_spec, ASN1_Type::UtcTime);
   } else if(t_spec.size() == 15) {
      set_to(t_spec, ASN1_Type::GeneralizedTime);
   } else {
      throw Invalid_Argument("Time string could not be parsed as GeneralizedTime or UTCTime.");
   }
}

void ASN1_Time::encode_into(DER_Encoder& der) const {
   BOTAN_ARG_CHECK(m_tag == ASN1_Type::UtcTime || m_tag == ASN1_Type::GeneralizedTime, "ASN1_Time: Bad encoding tag");

   der.add_object(m_tag, ASN1_Class::Universal, to_string());
}

void ASN1_Time::decode_from(BER_Decoder& source) {
   BER_Object ber_time = source.get_next_object();

   set_to(ASN1::to_string(ber_time), ber_time.type());
}

std::string ASN1_Time::to_string() const {
   if(time_is_set() == false) {
      throw Invalid_State("ASN1_Time::to_string: No time set");
   }

   uint32_t full_year = m_year;

   if(m_tag == ASN1_Type::UtcTime) {
      if(m_year < 1950 || m_year >= 2050) {
         throw Encoding_Error(fmt("ASN_Time: The time {} cannot be encoded as UTCTime", readable_string()));
      }

      full_year = (m_year >= 2000) ? (m_year - 2000) : (m_year - 1900);
   }

   const uint64_t year_factor = 10000000000;
   const uint64_t mon_factor = 100000000;
   const uint64_t day_factor = 1000000;
   const uint64_t hour_factor = 10000;
   const uint64_t min_factor = 100;

   const uint64_t int_repr = year_factor * full_year + mon_factor * m_month + day_factor * m_day +
                             hour_factor * m_hour + min_factor * m_minute + m_second;

   std::string repr = std::to_string(int_repr) + "Z";

   const size_t desired_size = (m_tag == ASN1_Type::UtcTime) ? 13 : 15;

   const std::string zero_padding(desired_size - repr.size(), '0');

   return zero_padding + repr;
}

std::string ASN1_Time::readable_string() const {
   if(time_is_set() == false) {
      throw Invalid_State("ASN1_Time::readable_string: No time set");
   }

   // desired format: "%04d/%02d/%02d %02d:%02d:%02d UTC"
   std::stringstream output;
   output << std::setfill('0') << std::setw(4) << m_year << "/" << std::setw(2) << m_month << "/" << std::setw(2)
          << m_day << " " << std::setw(2) << m_hour << ":" << std::setw(2) << m_minute << ":" << std::setw(2)
          << m_second << " UTC";

   return output.str();
}

bool ASN1_Time::time_is_set() const {
   return (m_year != 0);
}

int32_t ASN1_Time::cmp(const ASN1_Time& other) const {
   if(!time_is_set() || !other.time_is_set()) {
      throw Invalid_State("ASN1_Time::cmp: Cannot compare empty times");
   }

   const int32_t EARLIER = -1, LATER = 1, SAME_TIME = 0;

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

void ASN1_Time::set_to(std::string_view t_spec, ASN1_Type spec_tag) {
   BOTAN_ARG_CHECK(spec_tag == ASN1_Type::UtcTime || spec_tag == ASN1_Type::GeneralizedTime,
                   "Invalid tag for ASN1_Time");

   if(spec_tag == ASN1_Type::GeneralizedTime) {
      BOTAN_ARG_CHECK(t_spec.size() == 15, "Invalid GeneralizedTime input string");
   } else if(spec_tag == ASN1_Type::UtcTime) {
      BOTAN_ARG_CHECK(t_spec.size() == 13, "Invalid UTCTime input string");
   }

   BOTAN_ARG_CHECK(t_spec.back() == 'Z', "Botan does not support ASN1 times with timezones other than Z");

   const size_t field_len = 2;

   const size_t year_start = 0;
   const size_t year_len = (spec_tag == ASN1_Type::UtcTime) ? 2 : 4;
   const size_t month_start = year_start + year_len;
   const size_t day_start = month_start + field_len;
   const size_t hour_start = day_start + field_len;
   const size_t min_start = hour_start + field_len;
   const size_t sec_start = min_start + field_len;

   m_year = to_u32bit(t_spec.substr(year_start, year_len));
   m_month = to_u32bit(t_spec.substr(month_start, field_len));
   m_day = to_u32bit(t_spec.substr(day_start, field_len));
   m_hour = to_u32bit(t_spec.substr(hour_start, field_len));
   m_minute = to_u32bit(t_spec.substr(min_start, field_len));
   m_second = to_u32bit(t_spec.substr(sec_start, field_len));
   m_tag = spec_tag;

   if(spec_tag == ASN1_Type::UtcTime) {
      if(m_year >= 50) {
         m_year += 1900;
      } else {
         m_year += 2000;
      }
   }

   if(!passes_sanity_check()) {
      throw Invalid_Argument(fmt("ASN1_Time string '{}' does not seem to be valid", t_spec));
   }
}

/*
* Do a general sanity check on the time
*/
bool ASN1_Time::passes_sanity_check() const {
   // AppVeyor's trust store includes a cert with expiration date in 3016 ...
   if(m_year < 1950 || m_year > 3100) {
      return false;
   }
   if(m_month == 0 || m_month > 12) {
      return false;
   }

   const uint32_t days_in_month[12] = {31, 28 + 1, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

   if(m_day == 0 || m_day > days_in_month[m_month - 1]) {
      return false;
   }

   if(m_month == 2 && m_day == 29) {
      if(m_year % 4 != 0) {
         return false;  // not a leap year
      }

      if(m_year % 100 == 0 && m_year % 400 != 0) {
         return false;
      }
   }

   if(m_hour >= 24 || m_minute >= 60 || m_second > 60) {
      return false;
   }

   if(m_tag == ASN1_Type::UtcTime) {
      /*
      UTCTime limits the value of components such that leap seconds
      are not covered. See "UNIVERSAL 23" in "Information technology
      Abstract Syntax Notation One (ASN.1): Specification of basic notation"

      http://www.itu.int/ITU-T/studygroups/com17/languages/
      */
      if(m_second > 59) {
         return false;
      }
   }

   return true;
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

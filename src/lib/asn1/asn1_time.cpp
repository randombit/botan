/*
* X.509 Time Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/exceptn.h>
#include <botan/parsing.h>
#include <botan/calendar.h>
#include <sstream>
#include <iomanip>

namespace Botan {

ASN1_Time::ASN1_Time(const std::chrono::system_clock::time_point& time)
   {
   calendar_point cal = calendar_value(time);

   m_year   = cal.get_year();
   m_month  = cal.get_month();
   m_day    = cal.get_day();
   m_hour   = cal.get_hour();
   m_minute = cal.get_minutes();
   m_second = cal.get_seconds();

   m_tag = (m_year >= 2050) ? GENERALIZED_TIME : UTC_TIME;
   }

ASN1_Time::ASN1_Time(const std::string& t_spec, ASN1_Tag tag)
   {
   set_to(t_spec, tag);
   }

void ASN1_Time::encode_into(DER_Encoder& der) const
   {
   BOTAN_ARG_CHECK(m_tag == UTC_TIME || m_tag == GENERALIZED_TIME,
                   "ASN1_Time: Bad encoding tag");

   der.add_object(m_tag, UNIVERSAL, to_string());
   }

void ASN1_Time::decode_from(BER_Decoder& source)
   {
   BER_Object ber_time = source.get_next_object();

   set_to(ASN1::to_string(ber_time), ber_time.type());
   }

std::string ASN1_Time::to_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("ASN1_Time::to_string: No time set");

   uint32_t full_year = m_year;

   if(m_tag == UTC_TIME)
      {
      if(m_year < 1950 || m_year >= 2050)
         throw Encoding_Error("ASN1_Time: The time " + readable_string() +
                              " cannot be encoded as a UTCTime");

      full_year = (m_year >= 2000) ? (m_year - 2000) : (m_year - 1900);
      }

   const uint64_t YEAR_FACTOR = 10000000000ULL;
   const uint64_t MON_FACTOR  = 100000000;
   const uint64_t DAY_FACTOR  = 1000000;
   const uint64_t HOUR_FACTOR = 10000;
   const uint64_t MIN_FACTOR  = 100;

   const uint64_t int_repr =
      YEAR_FACTOR * full_year +
      MON_FACTOR * m_month +
      DAY_FACTOR * m_day +
      HOUR_FACTOR * m_hour +
      MIN_FACTOR * m_minute +
      m_second;

   std::string repr = std::to_string(int_repr) + "Z";

   uint32_t desired_size = (m_tag == UTC_TIME) ? 13 : 15;

   while(repr.size() < desired_size)
      repr = "0" + repr;

   return repr;
   }

std::string ASN1_Time::readable_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("ASN1_Time::readable_string: No time set");

   // desired format: "%04d/%02d/%02d %02d:%02d:%02d UTC"
   std::stringstream output;
   output << std::setfill('0')
          << std::setw(4) << m_year << "/"
          << std::setw(2) << m_month << "/"
          << std::setw(2) << m_day
          << " "
          << std::setw(2) << m_hour << ":"
          << std::setw(2) << m_minute << ":"
          << std::setw(2) << m_second
          << " UTC";

   return output.str();
   }

bool ASN1_Time::time_is_set() const
   {
   return (m_year != 0);
   }

int32_t ASN1_Time::cmp(const ASN1_Time& other) const
   {
   if(time_is_set() == false)
      throw Invalid_State("ASN1_Time::cmp: No time set");

   const int32_t EARLIER = -1, LATER = 1, SAME_TIME = 0;

   if(m_year < other.m_year)     return EARLIER;
   if(m_year > other.m_year)     return LATER;
   if(m_month < other.m_month)   return EARLIER;
   if(m_month > other.m_month)   return LATER;
   if(m_day < other.m_day)       return EARLIER;
   if(m_day > other.m_day)       return LATER;
   if(m_hour < other.m_hour)     return EARLIER;
   if(m_hour > other.m_hour)     return LATER;
   if(m_minute < other.m_minute) return EARLIER;
   if(m_minute > other.m_minute) return LATER;
   if(m_second < other.m_second) return EARLIER;
   if(m_second > other.m_second) return LATER;

   return SAME_TIME;
   }

void ASN1_Time::set_to(const std::string& t_spec, ASN1_Tag spec_tag)
   {
   if(spec_tag == UTC_OR_GENERALIZED_TIME)
      {
      try
         {
         set_to(t_spec, GENERALIZED_TIME);
         return;
         }
      catch(Invalid_Argument&) {} // Not a generalized time. Continue

      try
         {
         set_to(t_spec, UTC_TIME);
         return;
         }
      catch(Invalid_Argument&) {} // Not a UTC time. Continue

      throw Invalid_Argument("Time string could not be parsed as GeneralizedTime or UTCTime.");
      }

   BOTAN_ASSERT(spec_tag == UTC_TIME || spec_tag == GENERALIZED_TIME, "Invalid tag.");

   BOTAN_ARG_CHECK(t_spec.size() > 0, "Time string must not be empty.");

   BOTAN_ARG_CHECK(t_spec.back() == 'Z', "Botan does not support times with timezones other than Z");

   if(spec_tag == GENERALIZED_TIME)
      {
      BOTAN_ARG_CHECK(t_spec.size() == 15, "Invalid GeneralizedTime string");
      }
   else if(spec_tag == UTC_TIME)
      {
      BOTAN_ARG_CHECK(t_spec.size() == 13, "Invalid UTCTime string");
      }

   const size_t YEAR_SIZE = (spec_tag == UTC_TIME) ? 2 : 4;

   std::vector<std::string> params;
   std::string current;

   for(size_t j = 0; j != YEAR_SIZE; ++j)
      current += t_spec[j];
   params.push_back(current);
   current.clear();

   for(size_t j = YEAR_SIZE; j != t_spec.size() - 1; ++j)
      {
      current += t_spec[j];
      if(current.size() == 2)
         {
         params.push_back(current);
         current.clear();
         }
      }

   m_year   = to_u32bit(params[0]);
   m_month  = to_u32bit(params[1]);
   m_day    = to_u32bit(params[2]);
   m_hour   = to_u32bit(params[3]);
   m_minute = to_u32bit(params[4]);
   m_second = (params.size() == 6) ? to_u32bit(params[5]) : 0;
   m_tag    = spec_tag;

   if(spec_tag == UTC_TIME)
      {
      if(m_year >= 50) m_year += 1900;
      else             m_year += 2000;
      }

   if(!passes_sanity_check())
      throw Invalid_Argument("Time " + t_spec + " does not seem to be valid");
   }

/*
* Do a general sanity check on the time
*/
bool ASN1_Time::passes_sanity_check() const
   {
   // AppVeyor's trust store includes a cert with expiration date in 3016 ...
   if(m_year < 1950 || m_year > 3100)
      return false;
   if(m_month == 0 || m_month > 12)
      return false;

   const uint32_t days_in_month[12] = { 31, 28+1, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

   if(m_day == 0 || m_day > days_in_month[m_month-1])
      return false;

   if(m_month == 2 && m_day == 29)
      {
      if(m_year % 4 != 0)
         return false; // not a leap year

      if(m_year % 100 == 0 && m_year % 400 != 0)
         return false;
      }

   if(m_hour >= 24 || m_minute >= 60 || m_second > 60)
      return false;

   if (m_tag == UTC_TIME)
      {
      /*
      UTCTime limits the value of components such that leap seconds
      are not covered. See "UNIVERSAL 23" in "Information technology
      Abstract Syntax Notation One (ASN.1): Specification of basic notation"

      http://www.itu.int/ITU-T/studygroups/com17/languages/
      */
      if(m_second > 59)
         {
         return false;
         }
      }

   return true;
   }

std::chrono::system_clock::time_point ASN1_Time::to_std_timepoint() const
   {
   return calendar_point(m_year, m_month, m_day, m_hour, m_minute, m_second).to_std_timepoint();
   }

uint64_t ASN1_Time::time_since_epoch() const
   {
   auto tp = this->to_std_timepoint();
   return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
   }

/*
* Compare two ASN1_Times for in various ways
*/
bool operator==(const ASN1_Time& t1, const ASN1_Time& t2)
   { return (t1.cmp(t2) == 0); }
bool operator!=(const ASN1_Time& t1, const ASN1_Time& t2)
   { return (t1.cmp(t2) != 0); }

bool operator<=(const ASN1_Time& t1, const ASN1_Time& t2)
   { return (t1.cmp(t2) <= 0); }
bool operator>=(const ASN1_Time& t1, const ASN1_Time& t2)
   { return (t1.cmp(t2) >= 0); }

bool operator<(const ASN1_Time& t1, const ASN1_Time& t2)
   { return (t1.cmp(t2) < 0); }
bool operator>(const ASN1_Time& t1, const ASN1_Time& t2)
   { return (t1.cmp(t2) > 0); }

}

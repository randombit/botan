/*
* X.509 Time Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_time.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/charset.h>
#include <botan/exceptn.h>
#include <botan/parsing.h>
#include <botan/calendar.h>
#include <sstream>
#include <iomanip>

namespace Botan {

X509_Time::X509_Time(const std::chrono::system_clock::time_point& time)
   {
   calendar_point cal = calendar_value(time);

   m_year   = cal.year;
   m_month  = cal.month;
   m_day    = cal.day;
   m_hour   = cal.hour;
   m_minute = cal.minutes;
   m_second = cal.seconds;

   m_tag = (m_year >= 2050) ? GENERALIZED_TIME : UTC_TIME;
   }

X509_Time::X509_Time(const std::string& t_spec, ASN1_Tag tag)
   {
   set_to(t_spec, tag);
   }

void X509_Time::encode_into(DER_Encoder& der) const
   {
   if(m_tag != GENERALIZED_TIME && m_tag != UTC_TIME)
      throw Invalid_Argument("X509_Time: Bad encoding tag");

   der.add_object(m_tag, UNIVERSAL,
                  Charset::transcode(to_string(),
                                     LOCAL_CHARSET,
                                     LATIN1_CHARSET));
   }

void X509_Time::decode_from(BER_Decoder& source)
   {
   BER_Object ber_time = source.get_next_object();

   set_to(Charset::transcode(ASN1::to_string(ber_time),
                             LATIN1_CHARSET,
                             LOCAL_CHARSET),
          ber_time.type_tag);
   }

std::string X509_Time::to_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("X509_Time::as_string: No time set");

   uint32_t full_year = m_year;

   if(m_tag == UTC_TIME)
      {
      if(m_year < 1950 || m_year >= 2050)
         throw Encoding_Error("X509_Time: The time " + readable_string() +
                              " cannot be encoded as a UTCTime");

      full_year = (m_year >= 2000) ? (m_year - 2000) : (m_year - 1900);
      }

   const auto factor_y = uint64_t{10000000000ull}; // literal exceeds 32bit int range
   const auto factor_m = uint64_t{100000000ull};
   const auto factor_d = uint64_t{1000000ull};
   const auto factor_h = uint64_t{10000ull};
   const auto factor_i = uint64_t{100ull};

   std::string repr = std::to_string(factor_y * full_year +
                                     factor_m * m_month +
                                     factor_d * m_day +
                                     factor_h * m_hour +
                                     factor_i * m_minute +
                                     m_second) + "Z";

   uint32_t desired_size = (m_tag == UTC_TIME) ? 13 : 15;

   while(repr.size() < desired_size)
      repr = "0" + repr;

   return repr;
   }

std::string X509_Time::readable_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("X509_Time::readable_string: No time set");

   // desired format: "%04d/%02d/%02d %02d:%02d:%02d UTC"
   std::stringstream output;
      {
      using namespace std;
      output << setfill('0')
             << setw(4) << m_year << "/" << setw(2) << m_month << "/" << setw(2) << m_day
             << " "
             << setw(2) << m_hour << ":" << setw(2) << m_minute << ":" << setw(2) << m_second
             << " UTC";
      }
   return output.str();
   }

bool X509_Time::time_is_set() const
   {
   return (m_year != 0);
   }

int32_t X509_Time::cmp(const X509_Time& other) const
   {
   if(time_is_set() == false)
      throw Invalid_State("X509_Time::cmp: No time set");

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

void X509_Time::set_to(const std::string& t_spec, ASN1_Tag spec_tag)
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

   if(t_spec.empty())
      throw Invalid_Argument("Time string must not be empty.");

   if(t_spec.back() != 'Z')
      throw Unsupported_Argument("Botan does not support times with timezones other than Z: " + t_spec);

   if(spec_tag == GENERALIZED_TIME)
      {
      if(t_spec.size() != 13 && t_spec.size() != 15)
         throw Invalid_Argument("Invalid GeneralizedTime string: '" + t_spec + "'");
      }
   else if(spec_tag == UTC_TIME)
      {
      if(t_spec.size() != 11 && t_spec.size() != 13)
         throw Invalid_Argument("Invalid UTCTime string: '" + t_spec + "'");
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
      throw Invalid_Argument("Time did not pass sanity check: " + t_spec);
   }

/*
* Do a general sanity check on the time
*/
bool X509_Time::passes_sanity_check() const
   {
   if(m_year < 1950 || m_year > 2100)
      return false;
   if(m_month == 0 || m_month > 12)
      return false;
   if(m_day == 0 || m_day > 31)
      return false;
   if(m_hour >= 24 || m_minute > 60 || m_second > 60)
      return false;

   if (m_tag == UTC_TIME)
      {
      /*
      UTCTime limits the value of components such that leap seconds
      are not covered. See "UNIVERSAL 23" in "Information technology
      Abstract Syntax Notation One (ASN.1): Specification of basic notation"

      http://www.itu.int/ITU-T/studygroups/com17/languages/
      */
      if (m_hour > 23 || m_minute > 59 || m_second > 59)
         {
         return false;
         }
      }

   return true;
   }

std::chrono::system_clock::time_point X509_Time::to_std_timepoint() const
   {
   return calendar_point(m_year, m_month, m_day, m_hour, m_minute, m_second).to_std_timepoint();
   }

/*
* Compare two X509_Times for in various ways
*/
bool operator==(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) == 0); }
bool operator!=(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) != 0); }

bool operator<=(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) <= 0); }
bool operator>=(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) >= 0); }

bool operator<(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) < 0); }
bool operator>(const X509_Time& t1, const X509_Time& t2)
   { return (t1.cmp(t2) > 0); }

}

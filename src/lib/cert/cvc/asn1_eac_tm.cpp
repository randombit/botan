/*
* EAC Time Types
* (C) 2007 FlexSecure GmbH
*     2008-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eac_asn_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/charset.h>
#include <botan/parsing.h>
#include <botan/internal/rounding.h>
#include <botan/calendar.h>
#include <sstream>
#include <iomanip>

namespace Botan {

namespace {

std::vector<byte> enc_two_digit(u32bit in)
   {
   std::vector<byte> result;
   in %= 100;
   if(in < 10)
      result.push_back(0x00);
   else
      {
      u32bit y_first_pos = round_down<u32bit>(in, 10) / 10;
      result.push_back(static_cast<byte>(y_first_pos));
      }

   u32bit y_sec_pos = in % 10;
   result.push_back(static_cast<byte>(y_sec_pos));
   return result;
   }

u32bit dec_two_digit(byte b1, byte b2)
   {
   u32bit upper = b1;
   u32bit lower = b2;

   if(upper > 9 || lower > 9)
      throw Invalid_Argument("CVC dec_two_digit value too large");

   return upper*10 + lower;
   }

}

/*
* Create an EAC_Time
*/
EAC_Time::EAC_Time(const std::chrono::system_clock::time_point& time,
                   ASN1_Tag t) : m_tag(t)
   {
   calendar_point cal = calendar_value(time);

   m_year   = cal.year;
   m_month  = cal.month;
   m_day    = cal.day;
   }

/*
* Create an EAC_Time
*/
EAC_Time::EAC_Time(const std::string& t_spec, ASN1_Tag t) : m_tag(t)
   {
   set_to(t_spec);
   }

/*
* Create an EAC_Time
*/
EAC_Time::EAC_Time(u32bit y, u32bit m, u32bit d, ASN1_Tag t) :
   m_year(y), m_month(m), m_day(d), m_tag(t)
   {
   }

/*
* Set the time with a human readable string
*/
void EAC_Time::set_to(const std::string& time_str)
   {
   if(time_str == "")
      {
      m_year = m_month = m_day = 0;
      return;
      }

   std::vector<std::string> params;
   std::string current;

   for(u32bit j = 0; j != time_str.size(); ++j)
      {
      if(Charset::is_digit(time_str[j]))
         current += time_str[j];
      else
         {
         if(current != "")
            params.push_back(current);
         current.clear();
         }
      }
   if(current != "")
      params.push_back(current);

   if(params.size() != 3)
      throw Invalid_Argument("Invalid time specification " + time_str);

   m_year   = to_u32bit(params[0]);
   m_month  = to_u32bit(params[1]);
   m_day    = to_u32bit(params[2]);

   if(!passes_sanity_check())
      throw Invalid_Argument("Invalid time specification " + time_str);
   }


/*
* DER encode a EAC_Time
*/
void EAC_Time::encode_into(DER_Encoder& der) const
   {
   der.add_object(m_tag, APPLICATION,
                  encoded_eac_time());
   }

/*
* Return a string representation of the time
*/
std::string EAC_Time::as_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("EAC_Time::as_string: No time set");

   return std::to_string(m_year * 10000 + m_month * 100 + m_day);
   }

/*
* Return if the time has been set somehow
*/
bool EAC_Time::time_is_set() const
   {
   return (m_year != 0);
   }

/*
* Return a human readable string representation
*/
std::string EAC_Time::readable_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("EAC_Time::readable_string: No time set");

   // desired format: "%04d/%02d/%02d"
   std::stringstream output;
   output << std::setfill('0')
          << std::setw(4) << m_year << "/"
          << std::setw(2) << m_month << "/"
          << std::setw(2) << m_day;
   return output.str();
   }

/*
* Do a general sanity check on the time
*/
bool EAC_Time::passes_sanity_check() const
   {
   if(m_year < 2000 || m_year > 2099)
      return false;
   if(m_month == 0 || m_month > 12)
      return false;
   if(m_day == 0 || m_day > 31)
      return false;

   return true;
   }

/*
* modification functions
*/
void EAC_Time::add_years(u32bit years)
   {
   m_year += years;
   }

void EAC_Time::add_months(u32bit months)
   {
   m_year += months/12;
   m_month += months % 12;
   if(m_month > 12)
      {
      m_year += 1;
      m_month -= 12;
      }
   }

/*
* Compare this time against another
*/
s32bit EAC_Time::cmp(const EAC_Time& other) const
   {
   if(time_is_set() == false)
      throw Invalid_State("EAC_Time::cmp: No time set");

   const s32bit EARLIER = -1, LATER = 1, SAME_TIME = 0;

   if(m_year < other.m_year)     return EARLIER;
   if(m_year > other.m_year)     return LATER;
   if(m_month < other.m_month)   return EARLIER;
   if(m_month > other.m_month)   return LATER;
   if(m_day < other.m_day)       return EARLIER;
   if(m_day > other.m_day)       return LATER;

   return SAME_TIME;
   }

/*
* Compare two EAC_Times for in various ways
*/
bool operator==(const EAC_Time& t1, const EAC_Time& t2)
   {
   return (t1.cmp(t2) == 0);
   }

bool operator!=(const EAC_Time& t1, const EAC_Time& t2)
   {
   return (t1.cmp(t2) != 0);
   }

bool operator<=(const EAC_Time& t1, const EAC_Time& t2)
   {
   return (t1.cmp(t2) <= 0);
   }

bool operator>=(const EAC_Time& t1, const EAC_Time& t2)
   {
   return (t1.cmp(t2) >= 0);
   }

bool operator>(const EAC_Time& t1, const EAC_Time& t2)
   {
   return (t1.cmp(t2) > 0);
   }

bool operator<(const EAC_Time& t1, const EAC_Time& t2)
   {
   return (t1.cmp(t2) < 0);
   }

/*
* Decode a BER encoded EAC_Time
*/
void EAC_Time::decode_from(BER_Decoder& source)
   {
   BER_Object obj = source.get_next_object();

   if(obj.type_tag != m_tag)
      throw BER_Decoding_Error("Tag mismatch when decoding");

   if(obj.value.size() != 6)
      {
      throw Decoding_Error("EAC_Time decoding failed");
      }

   try
      {
      u32bit tmp_year = dec_two_digit(obj.value[0], obj.value[1]);
      u32bit tmp_mon = dec_two_digit(obj.value[2], obj.value[3]);
      u32bit tmp_day = dec_two_digit(obj.value[4], obj.value[5]);
      m_year = tmp_year + 2000;
      m_month = tmp_mon;
      m_day = tmp_day;
      }
   catch (Invalid_Argument)
      {
      throw Decoding_Error("EAC_Time decoding failed");
      }

   }

/*
* make the value an octet string for encoding
*/
std::vector<byte> EAC_Time::encoded_eac_time() const
   {
   std::vector<byte> result;
   result += enc_two_digit(m_year);
   result += enc_two_digit(m_month);
   result += enc_two_digit(m_day);
   return result;
   }

}

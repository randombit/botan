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
                   ASN1_Tag t) : tag(t)
   {
   calendar_point cal = calendar_value(time);

   year   = cal.year;
   month  = cal.month;
   day    = cal.day;
   }

/*
* Create an EAC_Time
*/
EAC_Time::EAC_Time(const std::string& t_spec, ASN1_Tag t) : tag(t)
   {
   set_to(t_spec);
   }

/*
* Create an EAC_Time
*/
EAC_Time::EAC_Time(u32bit y, u32bit m, u32bit d, ASN1_Tag t) :
   year(y), month(m), day(d), tag(t)
   {
   }

/*
* Set the time with a human readable string
*/
void EAC_Time::set_to(const std::string& time_str)
   {
   if(time_str == "")
      {
      year = month = day = 0;
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

   year   = to_u32bit(params[0]);
   month  = to_u32bit(params[1]);
   day    = to_u32bit(params[2]);

   if(!passes_sanity_check())
      throw Invalid_Argument("Invalid time specification " + time_str);
   }


/*
* DER encode a EAC_Time
*/
void EAC_Time::encode_into(DER_Encoder& der) const
   {
   der.add_object(tag, APPLICATION,
                  encoded_eac_time());
   }

/*
* Return a string representation of the time
*/
std::string EAC_Time::as_string() const
   {
   if(time_is_set() == false)
      throw Invalid_State("EAC_Time::as_string: No time set");

   return std::to_string(year * 10000 + month * 100 + day);
   }

/*
* Return if the time has been set somehow
*/
bool EAC_Time::time_is_set() const
   {
   return (year != 0);
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
          << std::setw(4) << year << "/"
          << std::setw(2) << month << "/"
          << std::setw(2) << day;
   return output.str();
   }

/*
* Do a general sanity check on the time
*/
bool EAC_Time::passes_sanity_check() const
   {
   if(year < 2000 || year > 2099)
      return false;
   if(month == 0 || month > 12)
      return false;
   if(day == 0 || day > 31)
      return false;

   return true;
   }

/*
* modification functions
*/
void EAC_Time::add_years(u32bit years)
   {
   year += years;
   }

void EAC_Time::add_months(u32bit months)
   {
   year += months/12;
   month += months % 12;
   if(month > 12)
      {
      year += 1;
      month -= 12;
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

   if(year < other.year)     return EARLIER;
   if(year > other.year)     return LATER;
   if(month < other.month)   return EARLIER;
   if(month > other.month)   return LATER;
   if(day < other.day)       return EARLIER;
   if(day > other.day)       return LATER;

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

   if(obj.type_tag != this->tag)
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
      year = tmp_year + 2000;
      month = tmp_mon;
      day = tmp_day;
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
   result += enc_two_digit(year);
   result += enc_two_digit(month);
   result += enc_two_digit(day);
   return result;
   }

}

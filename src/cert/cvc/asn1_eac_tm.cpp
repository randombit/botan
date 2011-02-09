/*
* EAC Time Types
* (C) 2007 FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eac_asn_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/charset.h>
#include <botan/parsing.h>
#include <ctime>
#include <sstream>
#include <ios>

namespace Botan {

namespace {

/*
* Convert a time_t to a struct tm
*/
std::tm get_tm(u64bit timer)
   {
   std::time_t time_val = static_cast<std::time_t>(timer);

   std::tm* tm_p = std::gmtime(&time_val);
   if (tm_p == 0)
      throw Encoding_Error("EAC_Time: gmtime could not encode " +
                           to_string(timer));
   return (*tm_p);
   }
SecureVector<byte> enc_two_digit(u32bit in)
   {
   SecureVector<byte> result;
   in %= 100;
   if (in < 10)
      {
      result.append(0x00);
      }
   else
      {
      u32bit y_first_pos = (in - (in%10))/10;
      result.append(static_cast<byte>(y_first_pos));
      }
   u32bit y_sec_pos = in%10;
   result.append(static_cast<byte>(y_sec_pos));
   return result;
   }
u32bit dec_two_digit(byte b1, byte b2)
   {
   u32bit upper = (u32bit)b1;
   u32bit lower = (u32bit)b2;
   if (upper > 9 || lower > 9)
      {
      throw Invalid_Argument("u32bit dec_two_digit(byte b1, byte b2): value too large");
      }
   return upper*10 + lower;

   }
}

/*
* Create an EAC_Time
*/
EAC_Time::EAC_Time(u64bit timer, ASN1_Tag t)
   :tag(t)
   {
   std::tm time_info = get_tm(timer);

   year   = time_info.tm_year + 1900;
   month  = time_info.tm_mon + 1;
   day    = time_info.tm_mday;

   }

/*
* Create an EAC_Time
*/
EAC_Time::EAC_Time(const std::string& t_spec, ASN1_Tag t)
   :tag(t)
   {
   set_to(t_spec);
   }
/*
* Create an EAC_Time
*/
EAC_Time::EAC_Time(u32bit y, u32bit m, u32bit d, ASN1_Tag t)
   : year(y),
     month(m),
     day(d),
     tag(t)
   {
   }

/*
* Set the time with a human readable string
*/
void EAC_Time::set_to(const std::string& time_str)
   {
   if (time_str == "")
      {
      year = month = day = 0;
      return;
      }

   std::vector<std::string> params;
   std::string current;

   for (u32bit j = 0; j != time_str.size(); ++j)
      {
      if (Charset::is_digit(time_str[j]))
         current += time_str[j];
      else
         {
         if (current != "")
            params.push_back(current);
         current.clear();
         }
      }
   if (current != "")
      params.push_back(current);

   if (params.size() != 3)
      throw Invalid_Argument("Invalid time specification " + time_str);

   year   = to_u32bit(params[0]);
   month  = to_u32bit(params[1]);
   day    = to_u32bit(params[2]);

   if (!passes_sanity_check())
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
   if (time_is_set() == false)
      throw Invalid_State("EAC_Time::as_string: No time set");

   std::string asn1rep;
   asn1rep = to_string(year, 2);

   asn1rep += to_string(month, 2) + to_string(day, 2);

   return asn1rep;
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
   if (time_is_set() == false)
      throw Invalid_State("EAC_Time::readable_string: No time set");

   std::string readable;
   readable += to_string(year,     2) + "/";
   readable += to_string(month,    2) + "/";
   readable += to_string(day,      2) + " ";

   return readable;
   }

/*
* Do a general sanity check on the time
*/
bool EAC_Time::passes_sanity_check() const
   {
   if (year < 2000 || year > 2099)
      return false;
   if (month == 0 || month > 12)
      return false;
   if (day == 0 || day > 31)
      return false;

   return true;
   }

/******************************************
* modification functions
******************************************/

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
   if (time_is_set() == false)
      throw Invalid_State("EAC_Time::cmp: No time set");

   const s32bit EARLIER = -1, LATER = 1, SAME_TIME = 0;

   if (year < other.year)     return EARLIER;
   if (year > other.year)     return LATER;
   if (month < other.month)   return EARLIER;
   if (month > other.month)   return LATER;
   if (day < other.day)       return EARLIER;
   if (day > other.day)       return LATER;

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
   if (obj.type_tag != this->tag)
      {
      std::string message("decoding type mismatch for EAC_Time, tag is ");
      std::stringstream ss;
      std::string str_is;
      ss << std::hex << obj.type_tag;
      ss >> str_is;
      message.append(str_is);
      message.append(", while it should be ");
      std::stringstream ss2;
      std::string str_should;
      ss2 << std::hex << this->tag;
      ss2 >> str_should;
      message.append(str_should);
      throw Decoding_Error(message);

      }
   if (obj.value.size() != 6)
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

u32bit EAC_Time::get_year() const
   {
   return year;
   }
u32bit EAC_Time::get_month() const
   {
   return month;
   }
u32bit EAC_Time::get_day() const
   {
   return day;
   }

/*
* make the value an octet string for encoding
*/
SecureVector<byte> EAC_Time::encoded_eac_time() const
   {
   SecureVector<byte> result;
   result.append(enc_two_digit(year));
   result.append(enc_two_digit(month));
   result.append(enc_two_digit(day));
   return result;
   }

ASN1_Ced::ASN1_Ced(std::string const& str)
   : EAC_Time(str, ASN1_Tag(37))
   {}

ASN1_Ced::ASN1_Ced(u64bit val)
   : EAC_Time(val, ASN1_Tag(37))
   {}

ASN1_Ced::ASN1_Ced(EAC_Time const& other)
   : EAC_Time(other.get_year(), other.get_month(), other.get_day(), ASN1_Tag(37))
   {}

ASN1_Cex::ASN1_Cex(std::string const& str)
   : EAC_Time(str, ASN1_Tag(36))
   {}

ASN1_Cex::ASN1_Cex(u64bit val)
   : EAC_Time(val, ASN1_Tag(36))
   {}

ASN1_Cex::ASN1_Cex(EAC_Time const& other)
   : EAC_Time(other.get_year(), other.get_month(), other.get_day(), ASN1_Tag(36))
   {}

}

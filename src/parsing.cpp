/*************************************************
* Parser Functions Source File                   *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <botan/charset.h>

namespace Botan {

/*************************************************
* Convert a string into an integer               *
*************************************************/
u32bit to_u32bit(const std::string& number)
   {
   u32bit n = 0;

   for(std::string::const_iterator j = number.begin(); j != number.end(); ++j)
      {
      const u32bit OVERFLOW_MARK = 0xFFFFFFFF / 10;

      byte digit = char2digit(*j);

      if((n > OVERFLOW_MARK) || (n == OVERFLOW_MARK && digit > 5))
         throw Decoding_Error("to_u32bit: Integer overflow");
      n *= 10;
      n += digit;
      }
   return n;
   }


/*************************************************
* Convert an integer into a string               *
*************************************************/
std::string to_string(u64bit n, u32bit min_len)
   {
   std::string lenstr;
   if(n)
      {
      while(n > 0)
         {
         lenstr = digit2char(n % 10) + lenstr;
         n /= 10;
         }
      }
   else
      lenstr = "0";

   while(lenstr.size() < min_len)
      lenstr = "0" + lenstr;

   return lenstr;
   }

/*************************************************
* Parse a SCAN-style algorithm name              *
*************************************************/
std::vector<std::string> parse_algorithm_name(const std::string& namex)
   {
   if(namex.find('(') == std::string::npos &&
      namex.find(')') == std::string::npos)
      return std::vector<std::string>(1, namex);

   std::string name = namex, substring;
   std::vector<std::string> elems;
   u32bit level = 0;

   elems.push_back(name.substr(0, name.find('(')));
   name = name.substr(name.find('('));

   for(std::string::const_iterator j = name.begin(); j != name.end(); ++j)
      {
      char c = *j;

      if(c == '(')
         ++level;
      if(c == ')')
         {
         if(level == 1 && j == name.end() - 1)
            {
            if(elems.size() == 1)
               elems.push_back(substring.substr(1));
            else
               elems.push_back(substring);
            return elems;
            }

         if(level == 0 || (level == 1 && j != name.end() - 1))
            throw Invalid_Algorithm_Name(namex);
         --level;
         }

      if(c == ',' && level == 1)
         {
         if(elems.size() == 1)
            elems.push_back(substring.substr(1));
         else
            elems.push_back(substring);
         substring = "";
         }
      else
         substring += c;
      }

   if(substring != "")
      throw Invalid_Algorithm_Name(namex);

   return elems;
   }

/*************************************************
* Split the string on slashes                    *
*************************************************/
std::vector<std::string> split_on(const std::string& str, char delim)
   {
   std::vector<std::string> elems;
   if(str == "") return elems;

   std::string substr;
   for(std::string::const_iterator j = str.begin(); j != str.end(); ++j)
      {
      if(*j == delim)
         {
         if(substr != "")
            elems.push_back(substr);
         substr = "";
         }
      else
         substr += *j;
      }

   if(substr == "")
      throw Format_Error("Unable to split string: " + str);
   elems.push_back(substr);

   return elems;
   }

/*************************************************
* Parse an ASN.1 OID string                      *
*************************************************/
std::vector<u32bit> parse_asn1_oid(const std::string& oid)
   {
   std::string substring;
   std::vector<u32bit> oid_elems;

   for(std::string::const_iterator j = oid.begin(); j != oid.end(); ++j)
      {
      char c = *j;

      if(c == '.')
         {
         if(substring == "")
            throw Invalid_OID(oid);
         oid_elems.push_back(to_u32bit(substring));
         substring = "";
         }
      else
         substring += c;
      }

   if(substring == "")
      throw Invalid_OID(oid);
   oid_elems.push_back(to_u32bit(substring));

   if(oid_elems.size() < 2)
      throw Invalid_OID(oid);

   return oid_elems;
   }

/*************************************************
* X.500 String Comparison                        *
*************************************************/
bool x500_name_cmp(const std::string& name1, const std::string& name2)
   {
   std::string::const_iterator p1 = name1.begin();
   std::string::const_iterator p2 = name2.begin();

   while((p1 != name1.end()) && is_space(*p1)) ++p1;
   while((p2 != name2.end()) && is_space(*p2)) ++p2;

   while(p1 != name1.end() && p2 != name2.end())
      {
      if(is_space(*p1))
         {
         if(!is_space(*p2))
            return false;

         while((p1 != name1.end()) && is_space(*p1)) ++p1;
         while((p2 != name2.end()) && is_space(*p2)) ++p2;

         if(p1 == name1.end() && p2 == name2.end())
            return true;
         }

      if(to_lower(*p1) != to_lower(*p2))
         return false;
      ++p1;
      ++p2;
      }

   while((p1 != name1.end()) && is_space(*p1)) ++p1;
   while((p2 != name2.end()) && is_space(*p2)) ++p2;

   if((p1 != name1.end()) || (p2 != name2.end()))
      return false;
   return true;
   }

/*************************************************
* Convert from UTF-8 to ISO 8859-1               *
*************************************************/
std::string utf2iso(const std::string& utf8)
   {
   std::string iso8859;

   u32bit position = 0;
   while(position != utf8.size())
      {
      const byte c1 = (byte)utf8[position++];

      if(c1 <= 0x7F)
         iso8859 += (char)c1;
      else if(c1 >= 0xC0 && c1 <= 0xC7)
         {
         if(position == utf8.size())
            throw Decoding_Error("UTF-8: sequence truncated");

         const byte c2 = (byte)utf8[position++];
         const byte iso_char = ((c1 & 0x07) << 6) | (c2 & 0x3F);

         if(iso_char <= 0x7F)
            throw Decoding_Error("UTF-8: sequence longer than needed");

         iso8859 += (char)iso_char;
         }
      else
         throw Decoding_Error("UTF-8: Unicode chars not in Latin1 used");
      }

   return iso8859;
   }

/*************************************************
* Convert from ISO 8859-1 to UTF-8               *
*************************************************/
std::string iso2utf(const std::string& iso8859)
   {
   std::string utf8;
   for(u32bit j = 0; j != iso8859.size(); ++j)
      {
      const byte c = (byte)iso8859[j];

      if(c <= 0x7F)
         utf8 += (char)c;
      else
         {
         utf8 += (char)(0xC0 | (c >> 6));
         utf8 += (char)(0x80 | (c & 0x3F));
         }
      }
   return utf8;
   }

/*************************************************
* Parse and compute an arithmetic expression     *
*************************************************/
u32bit parse_expr(const std::string& expr)
   {
   const bool have_add = (expr.find('+') != std::string::npos);
   const bool have_mul = (expr.find('*') != std::string::npos);

   if(have_add)
      {
      std::vector<std::string> sub_expr = split_on(expr, '+');
      u32bit result = 0;
      for(u32bit j = 0; j != sub_expr.size(); ++j)
         result += parse_expr(sub_expr[j]);
      return result;
      }
   else if(have_mul)
      {
      std::vector<std::string> sub_expr = split_on(expr, '*');
      u32bit result = 1;
      for(u32bit j = 0; j != sub_expr.size(); ++j)
         result *= parse_expr(sub_expr[j]);
      return result;
      }
   else
      return to_u32bit(expr);
   }

}

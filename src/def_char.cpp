/*************************************************
* Default Character Set Handling Source File     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/def_char.h>
#include <botan/exceptn.h>
#include <botan/parsing.h>

namespace Botan {

namespace {

/*************************************************
* Convert from UCS-2 to ISO 8859-1               *
*************************************************/
std::string ucs2_to_latin1(const std::string& ucs2)
   {
   if(ucs2.size() % 2 == 1)
      throw Decoding_Error("UCS-2 string has an odd number of bytes");

   std::string latin1;

   for(u32bit j = 0; j != ucs2.size(); j += 2)
      {
      const byte c1 = ucs2[j];
      const byte c2 = ucs2[j+1];

      if(c1 != 0)
         throw Decoding_Error("UCS-2 has non-Latin1 characters");

      latin1 += (char)c2;
      }

   return latin1;
   }

/*************************************************
* Convert from UTF-8 to ISO 8859-1               *
*************************************************/
std::string utf8_to_latin1(const std::string& utf8)
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
std::string latin1_to_utf8(const std::string& iso8859)
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

}

/*************************************************
* Transcode between character sets               *
*************************************************/
std::string Default_Charset_Transcoder::transcode(const std::string& str,
                                                  Character_Set to,
                                                  Character_Set from) const
   {
   if(to == LOCAL_CHARSET)
      to = LATIN1_CHARSET;
   if(from == LOCAL_CHARSET)
      from = LATIN1_CHARSET;

   if(to == from)
      return str;

   if(from == LATIN1_CHARSET && to == UTF8_CHARSET)
      return latin1_to_utf8(str);
   if(from == UTF8_CHARSET && to == LATIN1_CHARSET)
      return utf8_to_latin1(str);
   if(from == UCS2_CHARSET && to == LATIN1_CHARSET)
      return ucs2_to_latin1(str);

   throw Invalid_Argument("Unknown transcoding operation from " +
                          to_string(from) + " to " + to_string(to));
   }

}

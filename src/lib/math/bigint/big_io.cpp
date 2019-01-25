/*
* BigInt Input/Output
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>
#include <istream>
#include <ostream>

namespace Botan {

/*
* Write the BigInt into a stream
*/
std::ostream& operator<<(std::ostream& stream, const BigInt& n)
   {
   size_t base = 10;
   if(stream.flags() & std::ios::hex)
      base = 16;
   if(stream.flags() & std::ios::oct)
      throw Invalid_Argument("Octal output of BigInt not supported");

   if(n == 0)
      stream.write("0", 1);
   else
      {
      if(n < 0)
         stream.write("-", 1);

      std::string enc;

      if(base == 10)
         enc = n.to_dec_string();
      else
         enc = n.to_hex_string();

      size_t skip = 0;
      while(skip < enc.size() && enc[skip] == '0')
         ++skip;
      stream.write(&enc[skip], enc.size() - skip);
      }
   if(!stream.good())
      throw Stream_IO_Error("BigInt output operator has failed");
   return stream;
   }

/*
* Read the BigInt from a stream
*/
std::istream& operator>>(std::istream& stream, BigInt& n)
   {
   std::string str;
   std::getline(stream, str);
   if(stream.bad() || (stream.fail() && !stream.eof()))
      throw Stream_IO_Error("BigInt input operator has failed");
   n = BigInt(str);
   return stream;
   }

}

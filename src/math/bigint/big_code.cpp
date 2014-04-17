/*
* BigInt Encoding/Decoding
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/bigint.h>
#include <botan/divide.h>
#include <botan/charset.h>
#include <botan/hex.h>

namespace Botan {

/*
* Encode a BigInt
*/
void BigInt::encode(byte output[], const BigInt& n, Base base)
   {
   if(base == Binary)
      n.binary_encode(output);
   else if(base == Hexadecimal)
      {
      SecureVector<byte> binary(n.encoded_size(Binary));
      n.binary_encode(&binary[0]);

      hex_encode(reinterpret_cast<char*>(output),
                 &binary[0], binary.size());
      }
   else if(base == Octal)
      {
      BigInt copy = n;
      const size_t output_size = n.encoded_size(Octal);
      for(size_t j = 0; j != output_size; ++j)
         {
         output[output_size - 1 - j] =
            Charset::digit2char(static_cast<byte>(copy % 8));

         copy /= 8;
         }
      }
   else if(base == Decimal)
      {
      BigInt copy = n;
      BigInt remainder;
      copy.set_sign(Positive);
      const size_t output_size = n.encoded_size(Decimal);
      for(size_t j = 0; j != output_size; ++j)
         {
         divide(copy, 10, copy, remainder);
         output[output_size - 1 - j] =
            Charset::digit2char(static_cast<byte>(remainder.word_at(0)));
         if(copy.is_zero())
            break;
         }
      }
   else
      throw Invalid_Argument("Unknown BigInt encoding method");
   }

/*
* Encode a BigInt
*/
SecureVector<byte> BigInt::encode(const BigInt& n, Base base)
   {
   SecureVector<byte> output(n.encoded_size(base));
   encode(&output[0], n, base);
   if(base != Binary)
      for(size_t j = 0; j != output.size(); ++j)
         if(output[j] == 0)
            output[j] = '0';
   return output;
   }

/*
* Encode a BigInt, with leading 0s if needed
*/
SecureVector<byte> BigInt::encode_1363(const BigInt& n, size_t bytes)
   {
   const size_t n_bytes = n.bytes();
   if(n_bytes > bytes)
      throw Encoding_Error("encode_1363: n is too large to encode properly");

   const size_t leading_0s = bytes - n_bytes;

   SecureVector<byte> output(bytes);
   encode(&output[leading_0s], n, Binary);
   return output;
   }

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const MemoryRegion<byte>& buf, Base base)
   {
   return BigInt::decode(&buf[0], buf.size(), base);
   }

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const byte buf[], size_t length, Base base)
   {
   BigInt r;
   if(base == Binary)
      r.binary_decode(buf, length);
   else if(base == Hexadecimal)
      {
      SecureVector<byte> binary;

      if(length % 2)
         {
         // Handle lack of leading 0
         const char buf0_with_leading_0[2] = { '0', static_cast<char>(buf[0]) };
         binary = hex_decode(buf0_with_leading_0, 2);

         binary += hex_decode(reinterpret_cast<const char*>(&buf[1]),
                              length - 1,
                              false);
         }
      else
         binary = hex_decode(reinterpret_cast<const char*>(buf),
                             length, false);

      r.binary_decode(&binary[0], binary.size());
      }
   else if(base == Decimal || base == Octal)
      {
      const size_t RADIX = ((base == Decimal) ? 10 : 8);
      for(size_t j = 0; j != length; ++j)
         {
         if(Charset::is_space(buf[j]))
            continue;

         if(!Charset::is_digit(buf[j]))
            throw Invalid_Argument("BigInt::decode: "
                                   "Invalid character in decimal input");

         byte x = Charset::char2digit(buf[j]);
         if(x >= RADIX)
            {
            if(RADIX == 10)
               throw Invalid_Argument("BigInt: Invalid decimal string");
            else
               throw Invalid_Argument("BigInt: Invalid octal string");
            }

         r *= RADIX;
         r += x;
         }
      }
   else
      throw Invalid_Argument("Unknown BigInt decoding method");
   return r;
   }

}

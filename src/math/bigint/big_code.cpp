/*
* BigInt Encoding/Decoding
* (C) 1999-2007 Jack Lloyd
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
      n.binary_encode(binary);
      for(u32bit j = 0; j != binary.size(); ++j)
         Hex_Encoder::encode(binary[j], output + 2*j);
      }
   else if(base == Octal)
      {
      BigInt copy = n;
      const u32bit output_size = n.encoded_size(Octal);
      for(u32bit j = 0; j != output_size; ++j)
         {
         output[output_size - 1 - j] = Charset::digit2char(copy % 8);
         copy /= 8;
         }
      }
   else if(base == Decimal)
      {
      BigInt copy = n;
      BigInt remainder;
      copy.set_sign(Positive);
      const u32bit output_size = n.encoded_size(Decimal);
      for(u32bit j = 0; j != output_size; ++j)
         {
         divide(copy, 10, copy, remainder);
         output[output_size - 1 - j] =
            Charset::digit2char(remainder.word_at(0));
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
   encode(output, n, base);
   if(base != Binary)
      for(u32bit j = 0; j != output.size(); ++j)
         if(output[j] == 0)
            output[j] = '0';
   return output;
   }

/*
* Encode a BigInt, with leading 0s if needed
*/
SecureVector<byte> BigInt::encode_1363(const BigInt& n, u32bit bytes)
   {
   const u32bit n_bytes = n.bytes();
   if(n_bytes > bytes)
      throw Encoding_Error("encode_1363: n is too large to encode properly");

   const u32bit leading_0s = bytes - n_bytes;

   SecureVector<byte> output(bytes);
   encode(output + leading_0s, n, Binary);
   return output;
   }

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const MemoryRegion<byte>& buf, Base base)
   {
   return BigInt::decode(buf, buf.size(), base);
   }

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const byte buf[], u32bit length, Base base)
   {
   BigInt r;
   if(base == Binary)
      r.binary_decode(buf, length);
   else if(base == Hexadecimal)
      {
      SecureVector<byte> hex;
      for(u32bit j = 0; j != length; ++j)
         if(Hex_Decoder::is_valid(buf[j]))
            hex.append(buf[j]);

      u32bit offset = (hex.size() % 2);
      SecureVector<byte> binary(hex.size() / 2 + offset);

      if(offset)
         {
         byte temp[2] = { '0', hex[0] };
         binary[0] = Hex_Decoder::decode(temp);
         }

      for(u32bit j = offset; j != binary.size(); ++j)
         binary[j] = Hex_Decoder::decode(hex+2*j-offset);
      r.binary_decode(binary, binary.size());
      }
   else if(base == Decimal || base == Octal)
      {
      const u32bit RADIX = ((base == Decimal) ? 10 : 8);
      for(u32bit j = 0; j != length; ++j)
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

/*
* BigInt Encoding/Decoding
* (C) 1999-2010,2012,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>
#include <botan/internal/divide.h>
#include <botan/hex.h>

namespace Botan {

std::string BigInt::to_dec_string() const
   {
   BigInt copy = *this;
   copy.set_sign(Positive);

   uint8_t remainder;
   std::vector<uint8_t> digits;

   while(copy > 0)
      {
      ct_divide_u8(copy, 100, copy, remainder);

      const uint8_t ld = remainder % 10;
      const uint8_t td = (remainder - ld) / 10;
      digits.push_back(ld);

      if(copy > 0 || td > 0)
         digits.push_back(td);
      }

   std::string s;

   for(auto i = digits.rbegin(); i != digits.rend(); ++i)
      {
      s.push_back(*i + '0');
      }

   if(s.empty())
      s += "0";

   return s;
   }

std::string BigInt::to_hex_string() const
   {
   const std::vector<uint8_t> bits = BigInt::encode(*this);
   if(bits.empty())
      return "00";
   else
      return hex_encode(bits);
   }

/*
* Encode a BigInt, with leading 0s if needed
*/
secure_vector<uint8_t> BigInt::encode_1363(const BigInt& n, size_t bytes)
   {
   if(n.bytes() > bytes)
      throw Encoding_Error("encode_1363: n is too large to encode properly");

   secure_vector<uint8_t> output(bytes);
   n.binary_encode(output.data(), output.size());
   return output;
   }

//static
void BigInt::encode_1363(uint8_t output[], size_t bytes, const BigInt& n)
   {
   if(n.bytes() > bytes)
      throw Encoding_Error("encode_1363: n is too large to encode properly");

   n.binary_encode(output, bytes);
   }

/*
* Encode two BigInt, with leading 0s if needed, and concatenate
*/
secure_vector<uint8_t> BigInt::encode_fixed_length_int_pair(const BigInt& n1, const BigInt& n2, size_t bytes)
   {
   if(n1.bytes() > bytes || n2.bytes() > bytes)
      throw Encoding_Error("encode_fixed_length_int_pair: values too large to encode properly");
   secure_vector<uint8_t> output(2 * bytes);
   n1.binary_encode(output.data()        , bytes);
   n2.binary_encode(output.data() + bytes, bytes);
   return output;
   }

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const uint8_t buf[], size_t length, Base base)
   {
   BigInt r;
   if(base == Binary)
      {
      r.binary_decode(buf, length);
      }
   else if(base == Hexadecimal)
      {
      secure_vector<uint8_t> binary;

      if(length % 2)
         {
         // Handle lack of leading 0
         const char buf0_with_leading_0[2] =
            { '0', static_cast<char>(buf[0]) };

         binary = hex_decode_locked(buf0_with_leading_0, 2);

         binary += hex_decode_locked(cast_uint8_ptr_to_char(&buf[1]),
                                     length - 1,
                                     false);
         }
      else
         binary = hex_decode_locked(cast_uint8_ptr_to_char(buf),
                                    length, false);

      r.binary_decode(binary.data(), binary.size());
      }
   else if(base == Decimal)
      {
      for(size_t i = 0; i != length; ++i)
         {
         const char c = buf[i];

         if(c < '0' || c > '9')
            throw Invalid_Argument("BigInt::decode: invalid decimal char");

         const uint8_t x = c - '0';
         BOTAN_ASSERT_NOMSG(x < 10);

         r *= 10;
         r += x;
         }
      }
   else
      throw Invalid_Argument("Unknown BigInt decoding method");
   return r;
   }

}

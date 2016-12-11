/*
* EMSA1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa1.h>

namespace Botan {

namespace {

secure_vector<uint8_t> emsa1_encoding(const secure_vector<uint8_t>& msg,
                                  size_t output_bits)
   {
   if(8*msg.size() <= output_bits)
      return msg;

   size_t shift = 8*msg.size() - output_bits;

   size_t byte_shift = shift / 8, bit_shift = shift % 8;
   secure_vector<uint8_t> digest(msg.size() - byte_shift);

   for(size_t j = 0; j != msg.size() - byte_shift; ++j)
      digest[j] = msg[j];

   if(bit_shift)
      {
      uint8_t carry = 0;
      for(size_t j = 0; j != digest.size(); ++j)
         {
         uint8_t temp = digest[j];
         digest[j] = (temp >> bit_shift) | carry;
         carry = (temp << (8 - bit_shift));
         }
      }
   return digest;
   }

}

EMSA* EMSA1::clone()
   {
   return new EMSA1(m_hash->clone());
   }

void EMSA1::update(const uint8_t input[], size_t length)
   {
   m_hash->update(input, length);
   }

secure_vector<uint8_t> EMSA1::raw_data()
   {
   return m_hash->final();
   }

secure_vector<uint8_t> EMSA1::encoding_of(const secure_vector<uint8_t>& msg,
                                       size_t output_bits,
                                       RandomNumberGenerator&)
   {
   if(msg.size() != hash_output_length())
      throw Encoding_Error("EMSA1::encoding_of: Invalid size for input");
   return emsa1_encoding(msg, output_bits);
   }

bool EMSA1::verify(const secure_vector<uint8_t>& input,
                   const secure_vector<uint8_t>& raw,
                   size_t key_bits)
   {
   try {
      if(raw.size() != m_hash->output_length())
         throw Encoding_Error("EMSA1::encoding_of: Invalid size for input");

      // Call emsa1_encoding to handle any required bit shifting
      const secure_vector<uint8_t> our_coding = emsa1_encoding(raw, key_bits);

      if(our_coding.size() < input.size())
         return false;

      const size_t offset = our_coding.size() - input.size(); // must be >= 0 per check above

      // If our encoding is longer, all the bytes in it must be zero
      for(size_t i = 0; i != offset; ++i)
         if(our_coding[i] != 0)
            return false;

      return same_mem(input.data(), &our_coding[offset], input.size());
      }
   catch(Invalid_Argument)
      {
      return false;
      }
   }

}

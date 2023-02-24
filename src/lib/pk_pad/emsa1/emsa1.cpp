/*
* EMSA1
* (C) 1999-2007,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/emsa1.h>
#include <botan/exceptn.h>
#include <botan/pk_keys.h>

namespace Botan {

namespace {

secure_vector<uint8_t> emsa1_encoding(const secure_vector<uint8_t>& msg,
                                  size_t output_bits)
   {
   const size_t msg_bits = 8*msg.size();
   if(msg_bits <= output_bits)
      return msg;

   const size_t shift = msg_bits - output_bits;
   const size_t byte_shift = shift / 8;
   const size_t bit_shift = shift % 8;

   secure_vector<uint8_t> digest(msg.size() - byte_shift);

   for(size_t i = 0; i != msg.size() - byte_shift; ++i)
      digest[i] = msg[i];

   if(bit_shift)
      {
      uint8_t carry = 0;
      for(size_t i = 0; i != digest.size(); ++i)
         {
         uint8_t temp = digest[i];
         digest[i] = (temp >> bit_shift) | carry;
         carry = (temp << (8 - bit_shift));
         }
      }
   return digest;
   }

}

std::string EMSA1::name() const
   {
   return "EMSA1(" + m_hash->name() + ")";
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
                                       RandomNumberGenerator& /*rng*/)
   {
   if(msg.size() != hash_output_length())
      throw Encoding_Error("EMSA1::encoding_of: Invalid size for input");
   return emsa1_encoding(msg, output_bits);
   }

bool EMSA1::verify(const secure_vector<uint8_t>& input,
                   const secure_vector<uint8_t>& raw,
                   size_t key_bits)
   {
   if(raw.size() != m_hash->output_length())
      return false;

   // Call emsa1_encoding to handle any required bit shifting
   const secure_vector<uint8_t> our_coding = emsa1_encoding(raw, key_bits);

   if(our_coding.size() < input.size())
      return false;

   const size_t offset = our_coding.size() - input.size(); // must be >= 0 per check above

   // If our encoding is longer, all the bytes in it must be zero
   for(size_t i = 0; i != offset; ++i)
      if(our_coding[i] != 0)
         return false;

   return constant_time_compare(input.data(), &our_coding[offset], input.size());
   }

}

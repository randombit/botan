/*
* EMSA1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa1.h>

namespace Botan {

namespace {

secure_vector<byte> emsa1_encoding(const secure_vector<byte>& msg,
                                  size_t output_bits)
   {
   if(8*msg.size() <= output_bits)
      return msg;

   size_t shift = 8*msg.size() - output_bits;

   size_t byte_shift = shift / 8, bit_shift = shift % 8;
   secure_vector<byte> digest(msg.size() - byte_shift);

   for(size_t j = 0; j != msg.size() - byte_shift; ++j)
      digest[j] = msg[j];

   if(bit_shift)
      {
      byte carry = 0;
      for(size_t j = 0; j != digest.size(); ++j)
         {
         byte temp = digest[j];
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

void EMSA1::update(const byte input[], size_t length)
   {
   m_hash->update(input, length);
   }

secure_vector<byte> EMSA1::raw_data()
   {
   return m_hash->final();
   }

secure_vector<byte> EMSA1::encoding_of(const secure_vector<byte>& msg,
                                       size_t output_bits,
                                       RandomNumberGenerator&)
   {
   if(msg.size() != hash_output_length())
      throw Encoding_Error("EMSA1::encoding_of: Invalid size for input");
   return emsa1_encoding(msg, output_bits);
   }

bool EMSA1::verify(const secure_vector<byte>& coded,
                   const secure_vector<byte>& raw, size_t key_bits)
   {
   try {
      if(raw.size() != m_hash->output_length())
         throw Encoding_Error("EMSA1::encoding_of: Invalid size for input");

      secure_vector<byte> our_coding = emsa1_encoding(raw, key_bits);

      if(our_coding == coded) return true;
      if(our_coding.empty() || our_coding[0] != 0) return false;
      if(our_coding.size() <= coded.size()) return false;

      size_t offset = 0;
      while(offset < our_coding.size() && our_coding[offset] == 0)
         ++offset;
      if(our_coding.size() - offset != coded.size())
         return false;

      for(size_t j = 0; j != coded.size(); ++j)
         if(coded[j] != our_coding[j+offset])
            return false;

      return true;
      }
   catch(Invalid_Argument)
      {
      return false;
      }
   }

}

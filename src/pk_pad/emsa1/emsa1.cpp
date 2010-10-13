/*
* EMSA1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa1.h>

namespace Botan {

namespace {

SecureVector<byte> emsa1_encoding(const MemoryRegion<byte>& msg,
                                  size_t output_bits)
   {
   if(8*msg.size() <= output_bits)
      return msg;

   size_t shift = 8*msg.size() - output_bits;

   size_t byte_shift = shift / 8, bit_shift = shift % 8;
   SecureVector<byte> digest(msg.size() - byte_shift);

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

/*
* EMSA1 Update Operation
*/
void EMSA1::update(const byte input[], size_t length)
   {
   hash->update(input, length);
   }

/*
* Return the raw (unencoded) data
*/
SecureVector<byte> EMSA1::raw_data()
   {
   return hash->final();
   }

/*
* EMSA1 Encode Operation
*/
SecureVector<byte> EMSA1::encoding_of(const MemoryRegion<byte>& msg,
                                      size_t output_bits,
                                      RandomNumberGenerator&)
   {
   if(msg.size() != hash->output_length())
      throw Encoding_Error("EMSA1::encoding_of: Invalid size for input");
   return emsa1_encoding(msg, output_bits);
   }

/*
* EMSA1 Decode/Verify Operation
*/
bool EMSA1::verify(const MemoryRegion<byte>& coded,
                   const MemoryRegion<byte>& raw, size_t key_bits)
   {
   try {
      if(raw.size() != hash->output_length())
         throw Encoding_Error("EMSA1::encoding_of: Invalid size for input");

      SecureVector<byte> our_coding = emsa1_encoding(raw, key_bits);

      if(our_coding == coded) return true;
      if(our_coding[0] != 0) return false;
      if(our_coding.size() <= coded.size()) return false;

      size_t offset = 0;
      while(our_coding[offset] == 0 && offset < our_coding.size())
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

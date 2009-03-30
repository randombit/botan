/*
* EMSA4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa4.h>
#include <botan/mgf1.h>
#include <botan/bit_ops.h>

namespace Botan {

/*
* EMSA4 Update Operation
*/
void EMSA4::update(const byte input[], u32bit length)
   {
   hash->update(input, length);
   }

/*
* Return the raw (unencoded) data
*/
SecureVector<byte> EMSA4::raw_data()
   {
   return hash->final();
   }

/*
* EMSA4 Encode Operation
*/
SecureVector<byte> EMSA4::encoding_of(const MemoryRegion<byte>& msg,
                                      u32bit output_bits,
                                      RandomNumberGenerator& rng)
   {
   const u32bit HASH_SIZE = hash->OUTPUT_LENGTH;

   if(msg.size() != HASH_SIZE)
      throw Encoding_Error("EMSA4::encoding_of: Bad input length");
   if(output_bits < 8*HASH_SIZE + 8*SALT_SIZE + 9)
      throw Encoding_Error("EMSA4::encoding_of: Output length is too small");

   const u32bit output_length = (output_bits + 7) / 8;

   SecureVector<byte> salt(SALT_SIZE);
   rng.randomize(salt, SALT_SIZE);

   for(u32bit j = 0; j != 8; ++j)
      hash->update(0);
   hash->update(msg);
   hash->update(salt, SALT_SIZE);
   SecureVector<byte> H = hash->final();

   SecureVector<byte> EM(output_length);

   EM[output_length - HASH_SIZE - SALT_SIZE - 2] = 0x01;
   EM.copy(output_length - 1 - HASH_SIZE - SALT_SIZE, salt, SALT_SIZE);
   mgf->mask(H, HASH_SIZE, EM, output_length - HASH_SIZE - 1);
   EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
   EM.copy(output_length - 1 - HASH_SIZE, H, HASH_SIZE);
   EM[output_length-1] = 0xBC;

   return EM;
   }

/*
* EMSA4 Decode/Verify Operation
*/
bool EMSA4::verify(const MemoryRegion<byte>& const_coded,
                   const MemoryRegion<byte>& raw, u32bit key_bits) throw()
   {
   const u32bit HASH_SIZE = hash->OUTPUT_LENGTH;
   const u32bit KEY_BYTES = (key_bits + 7) / 8;

   if(key_bits < 8*HASH_SIZE + 9)
      return false;
   if(raw.size() != HASH_SIZE)
      return false;
   if(const_coded.size() > KEY_BYTES)
      return false;
   if(const_coded[const_coded.size()-1] != 0xBC)
      return false;

   SecureVector<byte> coded = const_coded;
   if(coded.size() < KEY_BYTES)
      {
      SecureVector<byte> temp(KEY_BYTES);
      temp.copy(KEY_BYTES - coded.size(), coded, coded.size());
      coded = temp;
      }

   const u32bit TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
   if(TOP_BITS > 8 - high_bit(coded[0]))
      return false;

   SecureVector<byte> DB(coded.begin(), coded.size() - HASH_SIZE - 1);
   SecureVector<byte> H(coded + coded.size() - HASH_SIZE - 1, HASH_SIZE);

   mgf->mask(H, H.size(), DB, coded.size() - H.size() - 1);
   DB[0] &= 0xFF >> TOP_BITS;

   u32bit salt_offset = 0;
   for(u32bit j = 0; j != DB.size(); ++j)
      {
      if(DB[j] == 0x01)
         { salt_offset = j + 1; break; }
      if(DB[j])
         return false;
      }
   if(salt_offset == 0)
      return false;

   SecureVector<byte> salt(DB + salt_offset, DB.size() - salt_offset);

   for(u32bit j = 0; j != 8; ++j)
      hash->update(0);
   hash->update(raw);
   hash->update(salt);
   SecureVector<byte> H2 = hash->final();

   return (H == H2);
   }

/*
* EMSA4 Constructor
*/
EMSA4::EMSA4(HashFunction* h) :
   SALT_SIZE(h->OUTPUT_LENGTH), hash(h)
   {
   mgf = new MGF1(hash->clone());
   }

/*
* EMSA4 Constructor
*/
EMSA4::EMSA4(HashFunction* h, u32bit salt_size) :
   SALT_SIZE(salt_size), hash(h)
   {
   mgf = new MGF1(hash->clone());
   }

}

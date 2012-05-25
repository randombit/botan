/*
* EMSA4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa4.h>
#include <botan/mgf1.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

/*
* EMSA4 Update Operation
*/
void EMSA4::update(const byte input[], size_t length)
   {
   hash->update(input, length);
   }

/*
* Return the raw (unencoded) data
*/
secure_vector<byte> EMSA4::raw_data()
   {
   return hash->final();
   }

/*
* EMSA4 Encode Operation
*/
secure_vector<byte> EMSA4::encoding_of(const secure_vector<byte>& msg,
                                      size_t output_bits,
                                      RandomNumberGenerator& rng)
   {
   const size_t HASH_SIZE = hash->output_length();

   if(msg.size() != HASH_SIZE)
      throw Encoding_Error("EMSA4::encoding_of: Bad input length");
   if(output_bits < 8*HASH_SIZE + 8*SALT_SIZE + 9)
      throw Encoding_Error("EMSA4::encoding_of: Output length is too small");

   const size_t output_length = (output_bits + 7) / 8;

   secure_vector<byte> salt = rng.random_vec(SALT_SIZE);

   for(size_t j = 0; j != 8; ++j)
      hash->update(0);
   hash->update(msg);
   hash->update(salt);
   secure_vector<byte> H = hash->final();

   secure_vector<byte> EM(output_length);

   EM[output_length - HASH_SIZE - SALT_SIZE - 2] = 0x01;
   buffer_insert(EM, output_length - 1 - HASH_SIZE - SALT_SIZE, salt);
   mgf->mask(&H[0], HASH_SIZE, &EM[0], output_length - HASH_SIZE - 1);
   EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
   buffer_insert(EM, output_length - 1 - HASH_SIZE, H);
   EM[output_length-1] = 0xBC;

   return EM;
   }

/*
* EMSA4 Decode/Verify Operation
*/
bool EMSA4::verify(const secure_vector<byte>& const_coded,
                   const secure_vector<byte>& raw, size_t key_bits)
   {
   const size_t HASH_SIZE = hash->output_length();
   const size_t KEY_BYTES = (key_bits + 7) / 8;

   if(key_bits < 8*HASH_SIZE + 9)
      return false;

   if(raw.size() != HASH_SIZE)
      return false;

   if(const_coded.size() > KEY_BYTES || const_coded.size() <= 1)
      return false;

   if(const_coded[const_coded.size()-1] != 0xBC)
      return false;

   secure_vector<byte> coded = const_coded;
   if(coded.size() < KEY_BYTES)
      {
      secure_vector<byte> temp(KEY_BYTES);
      buffer_insert(temp, KEY_BYTES - coded.size(), coded);
      coded = temp;
      }

   const size_t TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
   if(TOP_BITS > 8 - high_bit(coded[0]))
      return false;

   byte* DB = &coded[0];
   const size_t DB_size = coded.size() - HASH_SIZE - 1;

   const byte* H = &coded[DB_size];
   const size_t H_size = HASH_SIZE;

   mgf->mask(&H[0], H_size, &DB[0], DB_size);
   DB[0] &= 0xFF >> TOP_BITS;

   size_t salt_offset = 0;
   for(size_t j = 0; j != DB_size; ++j)
      {
      if(DB[j] == 0x01)
         { salt_offset = j + 1; break; }
      if(DB[j])
         return false;
      }
   if(salt_offset == 0)
      return false;

   for(size_t j = 0; j != 8; ++j)
      hash->update(0);
   hash->update(raw);
   hash->update(&DB[salt_offset], DB_size - salt_offset);
   secure_vector<byte> H2 = hash->final();

   return same_mem(&H[0], &H2[0], HASH_SIZE);
   }

/*
* EMSA4 Constructor
*/
EMSA4::EMSA4(HashFunction* h) :
   SALT_SIZE(h->output_length()), hash(h)
   {
   mgf = new MGF1(hash->clone());
   }

/*
* EMSA4 Constructor
*/
EMSA4::EMSA4(HashFunction* h, size_t salt_size) :
   SALT_SIZE(salt_size), hash(h)
   {
   mgf = new MGF1(hash->clone());
   }

}

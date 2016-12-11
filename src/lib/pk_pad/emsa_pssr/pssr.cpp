/*
* PSSR
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pssr.h>
#include <botan/mgf1.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

/*
* PSSR Update Operation
*/
void PSSR::update(const uint8_t input[], size_t length)
   {
   m_hash->update(input, length);
   }

/*
* Return the raw (unencoded) data
*/
secure_vector<uint8_t> PSSR::raw_data()
   {
   return m_hash->final();
   }

/*
* PSSR Encode Operation
*/
secure_vector<uint8_t> PSSR::encoding_of(const secure_vector<uint8_t>& msg,
                                      size_t output_bits,
                                      RandomNumberGenerator& rng)
   {
   const size_t HASH_SIZE = m_hash->output_length();

   if(msg.size() != HASH_SIZE)
      throw Encoding_Error("PSSR::encoding_of: Bad input length");
   if(output_bits < 8*HASH_SIZE + 8*m_SALT_SIZE + 9)
      throw Encoding_Error("PSSR::encoding_of: Output length is too small");

   const size_t output_length = (output_bits + 7) / 8;

   secure_vector<uint8_t> salt = rng.random_vec(m_SALT_SIZE);

   for(size_t j = 0; j != 8; ++j)
      m_hash->update(0);
   m_hash->update(msg);
   m_hash->update(salt);
   secure_vector<uint8_t> H = m_hash->final();

   secure_vector<uint8_t> EM(output_length);

   EM[output_length - HASH_SIZE - m_SALT_SIZE - 2] = 0x01;
   buffer_insert(EM, output_length - 1 - HASH_SIZE - m_SALT_SIZE, salt);
   mgf1_mask(*m_hash, H.data(), HASH_SIZE, EM.data(), output_length - HASH_SIZE - 1);
   EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
   buffer_insert(EM, output_length - 1 - HASH_SIZE, H);
   EM[output_length-1] = 0xBC;

   return EM;
   }

/*
* PSSR Decode/Verify Operation
*/
bool PSSR::verify(const secure_vector<uint8_t>& const_coded,
                   const secure_vector<uint8_t>& raw, size_t key_bits)
   {
   const size_t HASH_SIZE = m_hash->output_length();
   const size_t KEY_BYTES = (key_bits + 7) / 8;

   if(key_bits < 8*HASH_SIZE + 9)
      return false;

   if(raw.size() != HASH_SIZE)
      return false;

   if(const_coded.size() > KEY_BYTES || const_coded.size() <= 1)
      return false;

   if(const_coded[const_coded.size()-1] != 0xBC)
      return false;

   secure_vector<uint8_t> coded = const_coded;
   if(coded.size() < KEY_BYTES)
      {
      secure_vector<uint8_t> temp(KEY_BYTES);
      buffer_insert(temp, KEY_BYTES - coded.size(), coded);
      coded = temp;
      }

   const size_t TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
   if(TOP_BITS > 8 - high_bit(coded[0]))
      return false;

   uint8_t* DB = coded.data();
   const size_t DB_size = coded.size() - HASH_SIZE - 1;

   const uint8_t* H = &coded[DB_size];
   const size_t H_size = HASH_SIZE;

   mgf1_mask(*m_hash, H, H_size, DB, DB_size);
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
      m_hash->update(0);
   m_hash->update(raw);
   m_hash->update(&DB[salt_offset], DB_size - salt_offset);
   secure_vector<uint8_t> H2 = m_hash->final();

   return same_mem(H, H2.data(), HASH_SIZE);
   }

PSSR::PSSR(HashFunction* h) :
   m_SALT_SIZE(h->output_length()), m_hash(h)
   {
   }

PSSR::PSSR(HashFunction* h, size_t salt_size) :
   m_SALT_SIZE(salt_size), m_hash(h)
   {
   }

}

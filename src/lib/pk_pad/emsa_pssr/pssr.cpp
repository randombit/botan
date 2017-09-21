/*
* PSSR
* (C) 1999-2007,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pssr.h>
#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/mgf1.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

namespace {

/*
* PSSR Encode Operation
*/
secure_vector<uint8_t> pss_encode(HashFunction& hash,
                                  const secure_vector<uint8_t>& msg,
                                  const secure_vector<uint8_t>& salt,
                                  size_t output_bits)
   {
   const size_t HASH_SIZE = hash.output_length();
   const size_t SALT_SIZE = salt.size();

   if(msg.size() != HASH_SIZE)
      throw Encoding_Error("Cannot encode PSS string, input length invalid for hash");
   if(output_bits < 8*HASH_SIZE + 8*SALT_SIZE + 9)
      throw Encoding_Error("Cannot encode PSS string, output length too small");

   const size_t output_length = (output_bits + 7) / 8;

   for(size_t i = 0; i != 8; ++i)
      hash.update(0);
   hash.update(msg);
   hash.update(salt);
   secure_vector<uint8_t> H = hash.final();

   secure_vector<uint8_t> EM(output_length);

   EM[output_length - HASH_SIZE - SALT_SIZE - 2] = 0x01;
   buffer_insert(EM, output_length - 1 - HASH_SIZE - SALT_SIZE, salt);
   mgf1_mask(hash, H.data(), HASH_SIZE, EM.data(), output_length - HASH_SIZE - 1);
   EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
   buffer_insert(EM, output_length - 1 - HASH_SIZE, H);
   EM[output_length-1] = 0xBC;
   return EM;
   }

bool pss_verify(HashFunction& hash,
                const secure_vector<uint8_t>& const_coded,
                const secure_vector<uint8_t>& raw,
                size_t key_bits)
   {
   const size_t HASH_SIZE = hash.output_length();
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

   mgf1_mask(hash, H, H_size, DB, DB_size);
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

   const size_t salt_size = DB_size - salt_offset;

   for(size_t j = 0; j != 8; ++j)
      hash.update(0);
   hash.update(raw);
   hash.update(&DB[salt_offset], salt_size);

   secure_vector<uint8_t> H2 = hash.final();

   return constant_time_compare(H, H2.data(), HASH_SIZE);
   }

}

PSSR::PSSR(HashFunction* h) :
   m_hash(h), m_SALT_SIZE(m_hash->output_length())
   {
   }

PSSR::PSSR(HashFunction* h, size_t salt_size) :
   m_hash(h), m_SALT_SIZE(salt_size)
   {
   }

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

secure_vector<uint8_t> PSSR::encoding_of(const secure_vector<uint8_t>& msg,
                                         size_t output_bits,
                                         RandomNumberGenerator& rng)
   {
   secure_vector<uint8_t> salt = rng.random_vec(m_SALT_SIZE);
   return pss_encode(*m_hash, msg, salt, output_bits);
   }

/*
* PSSR Decode/Verify Operation
*/
bool PSSR::verify(const secure_vector<uint8_t>& coded,
                  const secure_vector<uint8_t>& raw,
                  size_t key_bits)
   {
   return pss_verify(*m_hash, coded, raw, key_bits);
   }

PSSR_Raw::PSSR_Raw(HashFunction* h) :
   m_hash(h), m_SALT_SIZE(m_hash->output_length())
   {
   }

PSSR_Raw::PSSR_Raw(HashFunction* h, size_t salt_size) :
   m_hash(h), m_SALT_SIZE(salt_size)
   {
   }

/*
* PSSR_Raw Update Operation
*/
void PSSR_Raw::update(const uint8_t input[], size_t length)
   {
   m_msg.insert(m_msg.end(), input, input + length);
   }

/*
* Return the raw (unencoded) data
*/
secure_vector<uint8_t> PSSR_Raw::raw_data()
   {
   secure_vector<uint8_t> ret;
   std::swap(ret, m_msg);

   if(ret.size() != m_hash->output_length())
      throw Encoding_Error("PSSR_Raw Bad input length, did not match hash");

   return ret;
   }

secure_vector<uint8_t> PSSR_Raw::encoding_of(const secure_vector<uint8_t>& msg,
                                             size_t output_bits,
                                             RandomNumberGenerator& rng)
   {
   secure_vector<uint8_t> salt = rng.random_vec(m_SALT_SIZE);
   return pss_encode(*m_hash, msg, salt, output_bits);
   }

/*
* PSSR_Raw Decode/Verify Operation
*/
bool PSSR_Raw::verify(const secure_vector<uint8_t>& coded,
                      const secure_vector<uint8_t>& raw,
                      size_t key_bits)
   {
   return pss_verify(*m_hash, coded, raw, key_bits);
   }

}

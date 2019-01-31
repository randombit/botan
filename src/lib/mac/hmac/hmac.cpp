/*
* HMAC
* (C) 1999-2007,2014 Jack Lloyd
*     2007 Yves Jerschow
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hmac.h>

namespace Botan {

/*
* Update a HMAC Calculation
*/
void HMAC::add_data(const uint8_t input[], size_t length)
   {
   verify_key_set(m_ikey.empty() == false);
   m_hash->update(input, length);
   }

/*
* Finalize a HMAC Calculation
*/
void HMAC::final_result(uint8_t mac[])
   {
   verify_key_set(m_okey.empty() == false);
   m_hash->final(mac);
   m_hash->update(m_okey);
   m_hash->update(mac, m_hash_output_length);
   m_hash->final(mac);
   m_hash->update(m_ikey);
   }

Key_Length_Specification HMAC::key_spec() const
   {
   // Support very long lengths for things like PBKDF2 and the TLS PRF
   return Key_Length_Specification(0, 4096);
   }

size_t HMAC::output_length() const
   {
   return m_hash_output_length;
   }

/*
* HMAC Key Schedule
*/
void HMAC::key_schedule(const uint8_t key[], size_t length)
   {
   const uint8_t ipad = 0x36;
   const uint8_t opad = 0x5C;

   m_hash->clear();

   m_ikey.resize(m_hash_block_size);
   set_mem(m_ikey.data(), m_hash_block_size, ipad);

   m_okey.resize(m_hash_block_size);
   set_mem(m_okey.data(), m_hash_block_size, opad);

   if(length > m_hash_block_size)
      {
      m_hash->update(key, length);
      m_hash->final(m_ikey.data());

      xor_buf(m_okey.data(), m_ikey.data(), m_hash_output_length);

      for(size_t i = 0; i != m_hash_output_length; ++i)
         {
         m_ikey[i] ^= ipad;
         }
      }
   else
      {
      xor_buf(m_ikey, key, length);
      xor_buf(m_okey, key, length);
      }

   m_hash->update(m_ikey);
   }

/*
* Clear memory of sensitive data
*/
void HMAC::clear()
   {
   m_hash->clear();
   zap(m_ikey);
   zap(m_okey);
   }

/*
* Return the name of this type
*/
std::string HMAC::name() const
   {
   return "HMAC(" + m_hash->name() + ")";
   }

/*
* Return a clone of this object
*/
MessageAuthenticationCode* HMAC::clone() const
   {
   return new HMAC(m_hash->clone());
   }

/*
* HMAC Constructor
*/
HMAC::HMAC(HashFunction* hash) :
   m_hash(hash),
   m_hash_output_length(m_hash->output_length()),
   m_hash_block_size(m_hash->hash_block_size())
   {
   BOTAN_ARG_CHECK(m_hash_block_size >= m_hash_output_length,
                   "HMAC is not compatible with this hash function");
   }

}

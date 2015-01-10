/*
* SSL3-MAC
* (C) 1999-2004 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ssl3_mac.h>

namespace Botan {

/*
* Update a SSL3-MAC Calculation
*/
void SSL3_MAC::add_data(const byte input[], size_t length)
   {
   m_hash->update(input, length);
   }

/*
* Finalize a SSL3-MAC Calculation
*/
void SSL3_MAC::final_result(byte mac[])
   {
   m_hash->final(mac);
   m_hash->update(m_okey);
   m_hash->update(mac, output_length());
   m_hash->final(mac);
   m_hash->update(m_ikey);
   }

/*
* SSL3-MAC Key Schedule
*/
void SSL3_MAC::key_schedule(const byte key[], size_t length)
   {
   m_hash->clear();

   // Quirk to deal with specification bug
   const size_t inner_hash_length =
      (m_hash->name() == "SHA-160") ? 60 : m_hash->hash_block_size();

   m_ikey.resize(inner_hash_length);
   m_okey.resize(inner_hash_length);

   std::fill(m_ikey.begin(), m_ikey.end(), 0x36);
   std::fill(m_okey.begin(), m_okey.end(), 0x5C);

   copy_mem(&m_ikey[0], key, length);
   copy_mem(&m_okey[0], key, length);

   m_hash->update(m_ikey);
   }

/*
* Clear memory of sensitive data
*/
void SSL3_MAC::clear()
   {
   m_hash->clear();
   zap(m_ikey);
   zap(m_okey);
   }

/*
* Return the name of this type
*/
std::string SSL3_MAC::name() const
   {
   return "SSL3-MAC(" + m_hash->name() + ")";
   }

/*
* Return a clone of this object
*/
MessageAuthenticationCode* SSL3_MAC::clone() const
   {
   return new SSL3_MAC(m_hash->clone());
   }

/*
* SSL3-MAC Constructor
*/
SSL3_MAC::SSL3_MAC(HashFunction* hash) : m_hash(hash)
   {
   if(m_hash->hash_block_size() == 0)
      throw Invalid_Argument("SSL3-MAC cannot be used with " + m_hash->name());
   }

}

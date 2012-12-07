/*
* SSL3-MAC
* (C) 1999-2004 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ssl3_mac.h>

namespace Botan {

/*
* Update a SSL3-MAC Calculation
*/
void SSL3_MAC::add_data(const byte input[], size_t length)
   {
   hash->update(input, length);
   }

/*
* Finalize a SSL3-MAC Calculation
*/
void SSL3_MAC::final_result(byte mac[])
   {
   hash->final(mac);
   hash->update(o_key);
   hash->update(mac, output_length());
   hash->final(mac);
   hash->update(i_key);
   }

/*
* SSL3-MAC Key Schedule
*/
void SSL3_MAC::key_schedule(const byte key[], size_t length)
   {
   hash->clear();

   // Quirk to deal with specification bug
   const size_t inner_hash_length =
      (hash->name() == "SHA-160") ? 60 : hash->hash_block_size();

   i_key.resize(inner_hash_length);
   o_key.resize(inner_hash_length);

   std::fill(i_key.begin(), i_key.end(), 0x36);
   std::fill(o_key.begin(), o_key.end(), 0x5C);

   copy_mem(&i_key[0], key, length);
   copy_mem(&o_key[0], key, length);

   hash->update(i_key);
   }

/*
* Clear memory of sensitive data
*/
void SSL3_MAC::clear()
   {
   hash->clear();
   zap(i_key);
   zap(o_key);
   }

/*
* Return the name of this type
*/
std::string SSL3_MAC::name() const
   {
   return "SSL3-MAC(" + hash->name() + ")";
   }

/*
* Return a clone of this object
*/
MessageAuthenticationCode* SSL3_MAC::clone() const
   {
   return new SSL3_MAC(hash->clone());
   }

/*
* SSL3-MAC Constructor
*/
SSL3_MAC::SSL3_MAC(HashFunction* hash_in) : hash(hash_in)
   {
   if(hash->hash_block_size() == 0)
      throw Invalid_Argument("SSL3-MAC cannot be used with " + hash->name());
   }

}

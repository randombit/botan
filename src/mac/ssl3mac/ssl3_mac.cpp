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
void SSL3_MAC::add_data(const byte input[], u32bit length)
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
   hash->update(mac, OUTPUT_LENGTH);
   hash->final(mac);
   hash->update(i_key);
   }

/*
* SSL3-MAC Key Schedule
*/
void SSL3_MAC::key_schedule(const byte key[], u32bit length)
   {
   hash->clear();
   std::fill(i_key.begin(), i_key.end(), 0x36);
   std::fill(o_key.begin(), o_key.end(), 0x5C);

   i_key.copy(key, length);
   o_key.copy(key, length);
   hash->update(i_key);
   }

/*
* Clear memory of sensitive data
*/
void SSL3_MAC::clear() throw()
   {
   hash->clear();
   i_key.clear();
   o_key.clear();
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
SSL3_MAC::SSL3_MAC(HashFunction* hash_in) :
   MessageAuthenticationCode(hash_in->OUTPUT_LENGTH,
                             hash_in->OUTPUT_LENGTH),
   hash(hash_in)
   {
   if(hash->HASH_BLOCK_SIZE == 0)
      throw Invalid_Argument("SSL3-MAC cannot be used with " + hash->name());

   u32bit INNER_HASH_LENGTH =
      (hash->name() == "SHA-160") ? 60 : hash->HASH_BLOCK_SIZE;

   i_key.create(INNER_HASH_LENGTH);
   o_key.create(INNER_HASH_LENGTH);
   }

}

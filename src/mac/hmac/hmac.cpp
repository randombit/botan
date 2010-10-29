/*
* HMAC
* (C) 1999-2007 Jack Lloyd
*     2007 Yves Jerschow
*
* Distributed under the terms of the Botan license
*/

#include <botan/hmac.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* Update a HMAC Calculation
*/
void HMAC::add_data(const byte input[], size_t length)
   {
   hash->update(input, length);
   }

/*
* Finalize a HMAC Calculation
*/
void HMAC::final_result(byte mac[])
   {
   hash->final(mac);
   hash->update(o_key);
   hash->update(mac, output_length());
   hash->final(mac);
   hash->update(i_key);
   }

/*
* HMAC Key Schedule
*/
void HMAC::key_schedule(const byte key[], size_t length)
   {
   hash->clear();
   std::fill(i_key.begin(), i_key.end(), 0x36);
   std::fill(o_key.begin(), o_key.end(), 0x5C);

   if(length > hash->hash_block_size())
      {
      SecureVector<byte> hmac_key = hash->process(key, length);
      xor_buf(i_key, hmac_key, hmac_key.size());
      xor_buf(o_key, hmac_key, hmac_key.size());
      }
   else
      {
      xor_buf(i_key, key, length);
      xor_buf(o_key, key, length);
      }

   hash->update(i_key);
   }

/*
* Clear memory of sensitive data
*/
void HMAC::clear()
   {
   hash->clear();
   zeroise(i_key);
   zeroise(o_key);
   }

/*
* Return the name of this type
*/
std::string HMAC::name() const
   {
   return "HMAC(" + hash->name() + ")";
   }

/*
* Return a clone of this object
*/
MessageAuthenticationCode* HMAC::clone() const
   {
   return new HMAC(hash->clone());
   }

/*
* HMAC Constructor
*/
HMAC::HMAC(HashFunction* hash_in) : hash(hash_in)
   {
   if(hash->hash_block_size() == 0)
      throw Invalid_Argument("HMAC cannot be used with " + hash->name());

   i_key.resize(hash->hash_block_size());
   o_key.resize(hash->hash_block_size());
   }

}

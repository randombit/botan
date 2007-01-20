/*************************************************
* HMAC Source File                               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/hmac.h>
#include <botan/lookup.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* Update a HMAC Calculation                      *
*************************************************/
void HMAC::add_data(const byte input[], u32bit length)
   {
   hash->update(input, length);
   }

/*************************************************
* Finalize a HMAC Calculation                    *
*************************************************/
void HMAC::final_result(byte mac[])
   {
   hash->final(mac);
   hash->update(o_key);
   hash->update(mac, OUTPUT_LENGTH);
   hash->final(mac);
   hash->update(i_key);
   }

/*************************************************
* HMAC Key Schedule                              *
*************************************************/
void HMAC::key(const byte key[], u32bit length)
   {
   hash->clear();
   std::fill(i_key.begin(), i_key.end(), 0x36);
   std::fill(o_key.begin(), o_key.end(), 0x5C);

   SecureVector<byte> hmac_key(key, length);
   if(hmac_key.size() > hash->HASH_BLOCK_SIZE)
      hmac_key = hash->process(hmac_key);

   xor_buf(i_key, hmac_key, hmac_key.size());
   xor_buf(o_key, hmac_key, hmac_key.size());
   hash->update(i_key);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void HMAC::clear() throw()
   {
   hash->clear();
   i_key.clear();
   o_key.clear();
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string HMAC::name() const
   {
   return "HMAC(" + hash->name() + ")";
   }

/*************************************************
* Return a clone of this object                  *
*************************************************/
MessageAuthenticationCode* HMAC::clone() const
   {
   return new HMAC(hash->name());
   }

/*************************************************
* HMAC Constructor                               *
*************************************************/
HMAC::HMAC(const std::string& hash_name) :
   MessageAuthenticationCode(output_length_of(hash_name),
                             1, 2*block_size_of(hash_name)),
   hash(get_hash(hash_name))
   {
   if(hash->HASH_BLOCK_SIZE == 0)
      throw Invalid_Argument("HMAC cannot be used with " + hash->name());
   i_key.create(hash->HASH_BLOCK_SIZE);
   o_key.create(hash->HASH_BLOCK_SIZE);
   }

}

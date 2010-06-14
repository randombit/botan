/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pk_keys.h>
#include <botan/der_enc.h>
#include <botan/oids.h>

namespace Botan {

/*
* Default OID access
*/
OID Public_Key::get_oid() const
   {
   try {
      return OIDS::lookup(algo_name());
      }
   catch(Lookup_Error)
      {
      throw Lookup_Error("PK algo " + algo_name() + " has no defined OIDs");
      }
   }

SecureVector<byte> Private_Key::PKCS8_BER_encode() const
   {
   const u32bit PKCS8_VERSION = 0;

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(PKCS8_VERSION)
            .encode(this->pkcs8_algorithm_identifier())
            .encode(this->pkcs8_private_key(), OCTET_STRING)
         .end_cons()
      .get_contents();
   }

/*
* Run checks on a loaded public key
*/
void Public_Key::load_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD))
      throw Invalid_Argument(algo_name() + ": Invalid public key");
   }

/*
* Run checks on a loaded private key
*/
void Private_Key::load_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD))
      throw Invalid_Argument(algo_name() + ": Invalid private key");
   }

/*
* Run checks on a generated private key
*/
void Private_Key::gen_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE))
      throw Self_Test_Failure(algo_name() + " private key generation failed");
   }

}

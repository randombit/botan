/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_keys.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/hash.h>
#include <botan/hex.h>

namespace Botan {

/*
* Default OID access
*/
OID Public_Key::get_oid() const
   {
   try {
      return OIDS::lookup(algo_name());
      }
   catch(Lookup_Error&)
      {
      throw Lookup_Error("PK algo " + algo_name() + " has no defined OIDs");
      }
   }

/*
* Run checks on a loaded public key
*/
void Public_Key::load_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD))
      throw Invalid_Argument("Invalid public key");
   }

/*
* Run checks on a loaded private key
*/
void Private_Key::load_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD))
      throw Invalid_Argument("Invalid private key");
   }

/*
* Run checks on a generated private key
*/
void Private_Key::gen_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE))
      throw Self_Test_Failure("Private key generation failed");
   }

/*
* Hash of the PKCS #8 encoding for this key object
*/
std::string Private_Key::fingerprint(const std::string& alg) const
   {
   secure_vector<byte> buf = pkcs8_private_key();
   std::unique_ptr<HashFunction> hash(HashFunction::create(alg));
   hash->update(buf);
   const auto hex_print = hex_encode(hash->final());

   std::string formatted_print;

   for(size_t i = 0; i != hex_print.size(); i += 2)
      {
      formatted_print.push_back(hex_print[i]);
      formatted_print.push_back(hex_print[i+1]);

      if(i != hex_print.size() - 2)
         formatted_print.push_back(':');
      }

   return formatted_print;
   }

}

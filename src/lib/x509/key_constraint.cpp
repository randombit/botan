/*
* KeyUsage
* (C) 1999-2007,2016 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>
#include <botan/pk_keys.h>
#include <vector>

namespace Botan {

std::string key_constraints_to_string(Key_Constraints constraints)
   {
   std::vector<std::string> str;

   if(constraints == NO_CONSTRAINTS)
      return "no_constraints";

   if(constraints & DIGITAL_SIGNATURE)
      str.push_back("digital_signature");

   if(constraints & NON_REPUDIATION)
      str.push_back("non_repudiation");

   if(constraints & KEY_ENCIPHERMENT)
      str.push_back("key_encipherment");

   if(constraints & DATA_ENCIPHERMENT)
      str.push_back("data_encipherment");

   if(constraints & KEY_AGREEMENT)
      str.push_back("key_agreement");

   if(constraints & KEY_CERT_SIGN)
      str.push_back("key_cert_sign");

   if(constraints & CRL_SIGN)
      str.push_back("crl_sign");

   if(constraints & ENCIPHER_ONLY)
      str.push_back("encipher_only");

   if(constraints & DECIPHER_ONLY)
      str.push_back("decipher_only");

   // Not 0 (checked at start) but nothing matched above!
   if(str.empty())
      return "other_unknown_constraints";

   if(str.size() == 1)
      return str[0];

   std::string out;
   for(size_t i = 0; i < str.size() - 1; ++i)
      {
      out += str[i];
      out += ',';
      }
   out += str[str.size() - 1];

   return out;
   }

/*
* Make sure the given key constraints are permitted for the given key type
*/
void verify_cert_constraints_valid_for_key_type(const Public_Key& pub_key,
                                                Key_Constraints constraints)
   {
   const std::string name = pub_key.algo_name();

   size_t permitted = 0;

   const bool can_agree = (name == "DH" || name == "ECDH");
   const bool can_encrypt = (name == "RSA" || name == "ElGamal");

   const bool can_sign =
      (name == "RSA" || name == "DSA" ||
       name == "ECDSA" || name == "ECGDSA" || name == "ECKCDSA" || name == "Ed25519" ||
       name == "GOST-34.10" || name == "GOST-34.10-2012-256" || name == "GOST-34.10-2012-512");

   if(can_agree)
      {
      permitted |= KEY_AGREEMENT | ENCIPHER_ONLY | DECIPHER_ONLY;
      }

   if(can_encrypt)
      {
      permitted |= KEY_ENCIPHERMENT | DATA_ENCIPHERMENT;
      }

   if(can_sign)
      {
      permitted |= DIGITAL_SIGNATURE | NON_REPUDIATION | KEY_CERT_SIGN | CRL_SIGN;
      }

   if(Key_Constraints(constraints & permitted) != constraints)
      {
      throw Invalid_Argument("Invalid " + name + " constraints " + key_constraints_to_string(constraints));
      }
   }

}

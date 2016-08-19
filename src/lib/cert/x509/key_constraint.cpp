/*
* KeyUsage
* (C) 1999-2007 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/key_constraint.h>
#include <botan/x509_key.h>

namespace Botan {

/*
* Make sure the given key constraints are permitted for the given key type
*/
void verify_cert_constraints_valid_for_key_type(const Public_Key& pub_key,
                                                      Key_Constraints constraints)
   {
   const std::string name = pub_key.algo_name();

   size_t permitted = 0;

   if(name == "DH" || name == "ECDH")
      {
      permitted |= KEY_AGREEMENT | ENCIPHER_ONLY | DECIPHER_ONLY;
      }

   if(name == "RSA" || name == "ElGamal")
      {
      permitted |= KEY_ENCIPHERMENT | DATA_ENCIPHERMENT;
      }

   if(name == "RSA" || name == "RW" || name == "NR" ||
      name == "DSA" || name == "ECDSA" || name == "ECGDSA" || name == "ECKCDSA")
      {
      permitted |= DIGITAL_SIGNATURE | NON_REPUDIATION | KEY_CERT_SIGN | CRL_SIGN;
      }

   if ( ( constraints & permitted ) != constraints )
      {
      throw Exception("Constraint not permitted for key type " + name);
      }
   }

}

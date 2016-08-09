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
* Find the allowable key constraints
*/
Key_Constraints find_constraints(const Public_Key& pub_key,
                                 Key_Constraints limits)
   {
   const std::string name = pub_key.algo_name();

   size_t constraints = 0;

   if(name == "DH" || name == "ECDH")
      constraints |= KEY_AGREEMENT;

   if(name == "RSA" || name == "ElGamal")
      constraints |= KEY_ENCIPHERMENT | DATA_ENCIPHERMENT | ENCIPHER_ONLY | DECIPHER_ONLY;

   if(name == "RSA" || name == "RW" || name == "NR" ||
      name == "DSA" || name == "ECDSA" || name == "ECGDSA" || name == "ECKCDSA")
      constraints |= DIGITAL_SIGNATURE | NON_REPUDIATION | KEY_CERT_SIGN | CRL_SIGN;

   if(limits)
      constraints &= limits;

   return Key_Constraints(constraints);
   }

}

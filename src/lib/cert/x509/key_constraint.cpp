/*
* KeyUsage
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/key_constraint.h>
#include <botan/x509_key.h>
#include <botan/ber_dec.h>

namespace Botan {

namespace BER {

/*
* Decode a BER encoded KeyUsage
*/
void decode(BER_Decoder& source, Key_Constraints& key_usage)
   {
   BER_Object obj = source.get_next_object();

   if(obj.type_tag != BIT_STRING || obj.class_tag != UNIVERSAL)
      throw BER_Bad_Tag("Bad tag for usage constraint",
                        obj.type_tag, obj.class_tag);
   if(obj.value.size() != 2 && obj.value.size() != 3)
      throw BER_Decoding_Error("Bad size for BITSTRING in usage constraint");
   if(obj.value[0] >= 8)
      throw BER_Decoding_Error("Invalid unused bits in usage constraint");

   const byte mask = (0xFF << obj.value[0]);
   obj.value[obj.value.size()-1] &= mask;

   u16bit usage = 0;
   for(size_t j = 1; j != obj.value.size(); ++j)
      usage = (obj.value[j] << 8) | usage;

   key_usage = Key_Constraints(usage);
   }

}

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
      constraints |= KEY_ENCIPHERMENT | DATA_ENCIPHERMENT;

   if(name == "RSA" || name == "RW" || name == "NR" ||
      name == "DSA" || name == "ECDSA")
      constraints |= DIGITAL_SIGNATURE | NON_REPUDIATION;

   if(limits)
      constraints &= limits;

   return Key_Constraints(constraints);
   }

}

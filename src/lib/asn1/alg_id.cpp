/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>

namespace Botan {

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& alg_id,
                                         const std::vector<uint8_t>& param) :
   oid(alg_id),
   parameters(param)
   {}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         const std::vector<uint8_t>& param) :
   AlgorithmIdentifier(OID::from_string(alg_id), param)
   {}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& alg_id,
                                         Encoding_Option option) :
   oid(alg_id),
   parameters()
   {
   const uint8_t DER_NULL[] = { 0x05, 0x00 };

   if(option == USE_NULL_PARAM)
      parameters.assign(DER_NULL, DER_NULL + 2);
   }

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         Encoding_Option option) :
   oid(OID::from_string(alg_id)),
   parameters()
   {
   const uint8_t DER_NULL[] = { 0x05, 0x00 };

   if(option == USE_NULL_PARAM)
      parameters.assign(DER_NULL, DER_NULL + 2);
   }

bool AlgorithmIdentifier::parameters_are_null() const
   {
   return (parameters.size() == 2 && (parameters[0] == 0x05) && (parameters[1] == 0x00));
   }

bool operator==(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2)
   {
   if(a1.get_oid() != a2.get_oid())
      return false;

   /*
   * Treat NULL and empty as equivalent
   */
   if(a1.parameters_are_null_or_empty() &&
      a2.parameters_are_null_or_empty())
      {
      return true;
      }

   return (a1.get_parameters() == a2.get_parameters());
   }

bool operator!=(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2)
   {
   return !(a1 == a2);
   }

/*
* DER encode an AlgorithmIdentifier
*/
void AlgorithmIdentifier::encode_into(DER_Encoder& codec) const
   {
   codec.start_cons(SEQUENCE)
      .encode(get_oid())
      .raw_bytes(get_parameters())
   .end_cons();
   }

/*
* Decode a BER encoded AlgorithmIdentifier
*/
void AlgorithmIdentifier::decode_from(BER_Decoder& codec)
   {
   codec.start_cons(SEQUENCE)
      .decode(oid)
      .raw_bytes(parameters)
   .end_cons();
   }

}

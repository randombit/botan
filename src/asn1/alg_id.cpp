/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/alg_id.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>

namespace Botan {

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& alg_id,
                                         const MemoryRegion<byte>& param)
   {
   oid = alg_id;
   parameters = param;
   }

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         const MemoryRegion<byte>& param)
   {
   oid = OIDS::lookup(alg_id);
   parameters = param;
   }

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& alg_id,
                                         Encoding_Option option)
   {
   const byte DER_NULL[] = { 0x05, 0x00 };

   oid = alg_id;
   if(option == USE_NULL_PARAM)
      parameters.append(DER_NULL, sizeof(DER_NULL));
   }

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         Encoding_Option option)
   {
   const byte DER_NULL[] = { 0x05, 0x00 };

   oid = OIDS::lookup(alg_id);
   if(option == USE_NULL_PARAM)
      parameters.append(DER_NULL, sizeof(DER_NULL));
   }

/*
* Compare two AlgorithmIdentifiers
*/
bool operator==(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2)
   {
   if(a1.oid != a2.oid)
      return false;
   if(a1.parameters != a2.parameters)
      return false;
   return true;
   }

/*
* Compare two AlgorithmIdentifiers
*/
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
      .encode(oid)
      .raw_bytes(parameters)
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

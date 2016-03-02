/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
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
                                         const std::vector<byte>& param) : oid(alg_id), parameters(param)
   {}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         const std::vector<byte>& param) : oid(OIDS::lookup(alg_id)), parameters(param)
   {}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& alg_id,
                                         Encoding_Option option) : oid(alg_id), parameters()
   {
   const byte DER_NULL[] = { 0x05, 0x00 };

   if(option == USE_NULL_PARAM)
      parameters += std::pair<const byte*, size_t>(DER_NULL, sizeof(DER_NULL));
   }

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         Encoding_Option option) : oid(OIDS::lookup(alg_id)), parameters()
   {
   const byte DER_NULL[] = { 0x05, 0x00 };

   if(option == USE_NULL_PARAM)
      parameters += std::pair<const byte*, size_t>(DER_NULL, sizeof(DER_NULL));
   }

/*
* Compare two AlgorithmIdentifiers
*/
namespace {

bool param_null_or_empty(const std::vector<byte>& p)
   {
   if(p.size() == 2 && (p[0] == 0x05) && (p[1] == 0x00))
      return true;
   return p.empty();
   }

}

bool operator==(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2)
   {
   if(a1.oid != a2.oid)
      return false;

   if(param_null_or_empty(a1.parameters) &&
      param_null_or_empty(a2.parameters))
      return true;

   return (a1.parameters == a2.parameters);
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

/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>

namespace Botan {

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& oid, const std::vector<uint8_t>& param) :
      m_oid(oid), m_parameters(param) {}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(std::string_view oid, const std::vector<uint8_t>& param) :
      AlgorithmIdentifier(OID::from_string(oid), param) {}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& oid, Encoding_Option option) : m_oid(oid), m_parameters() {
   const uint8_t DER_NULL[] = {0x05, 0x00};

   if(option == USE_NULL_PARAM) {
      m_parameters.assign(DER_NULL, DER_NULL + 2);
   }
}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(std::string_view oid, Encoding_Option option) :
      m_oid(OID::from_string(oid)), m_parameters() {
   const uint8_t DER_NULL[] = {0x05, 0x00};

   if(option == USE_NULL_PARAM) {
      m_parameters.assign(DER_NULL, DER_NULL + 2);
   }
}

bool AlgorithmIdentifier::parameters_are_null() const {
   return (m_parameters.size() == 2 && (m_parameters[0] == 0x05) && (m_parameters[1] == 0x00));
}

bool operator==(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2) {
   if(a1.oid() != a2.oid()) {
      return false;
   }

   /*
   * Treat NULL and empty as equivalent
   */
   if(a1.parameters_are_null_or_empty() && a2.parameters_are_null_or_empty()) {
      return true;
   }

   return (a1.parameters() == a2.parameters());
}

bool operator!=(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2) {
   return !(a1 == a2);
}

/*
* DER encode an AlgorithmIdentifier
*/
void AlgorithmIdentifier::encode_into(DER_Encoder& codec) const {
   codec.start_sequence().encode(oid()).raw_bytes(parameters()).end_cons();
}

/*
* Decode a BER encoded AlgorithmIdentifier
*/
void AlgorithmIdentifier::decode_from(BER_Decoder& codec) {
   codec.start_sequence().decode(m_oid).raw_bytes(m_parameters).end_cons();
}

}  // namespace Botan

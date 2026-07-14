/*
* Algorithm Identifier
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/asn1_utils.h>

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
AlgorithmIdentifier::AlgorithmIdentifier(const OID& oid, Encoding_Option option) : m_oid(oid) {
   constexpr uint8_t DER_NULL[] = {0x05, 0x00};

   if(option == USE_NULL_PARAM) {
      m_parameters.assign(DER_NULL, DER_NULL + 2);
   }
}

/*
* Create an AlgorithmIdentifier
*/
AlgorithmIdentifier::AlgorithmIdentifier(std::string_view oid, Encoding_Option option) : m_oid(OID::from_string(oid)) {
   constexpr uint8_t DER_NULL[2] = {0x05, 0x00};

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
   * TODO(Botan4) remove this
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

   /*
   * The parameters field is OPTIONAL ANY but in practice it is one of
   * - empty
   * - NULL
   * - SEQUENCE
   * - OBJECT IDENTIFIER (namedCurve)
   * - OCTET STRING (CBC IV in PBES2)
   *
   * So require it be exactly one of these values. In particular this ensures that
   * there is not any additional trailing data (eg after the SEQUENCE encoding)
   * that might be otherwise skipped over by a reader.
   */

   const bool acceptable_parameters = [&]() {
      if(this->parameters_are_null_or_empty()) {
         return true;
      }
      if(ASN1::is_der_sequence_header(m_parameters)) {
         return true;
      }
      if(ASN1::is_single_der_object(m_parameters, ASN1_Type::ObjectId, ASN1_Class::Universal)) {
         return true;
      }
      if(ASN1::is_single_der_object(m_parameters, ASN1_Type::OctetString, ASN1_Class::Universal)) {
         return true;
      }
      return false;
   }();

   if(!acceptable_parameters) {
      throw Decoding_Error("AlgorithmIdentifier parameters were not NULL, a SEQUENCE, an OID, or an OCTET STRING");
   }
}

}  // namespace Botan

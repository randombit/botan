/*
* Attribute
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>

namespace Botan {

/*
* Create an Attribute
*/
Attribute::Attribute(const OID& attr_oid, const std::vector<uint8_t>& attr_value) :
      m_oid(attr_oid), m_parameters(attr_value) {}

/*
* Create an Attribute
*/
Attribute::Attribute(std::string_view attr_oid, const std::vector<uint8_t>& attr_value) :
      m_oid(OID::from_string(attr_oid)), m_parameters(attr_value) {}

/*
* DER encode a Attribute
*/
void Attribute::encode_into(DER_Encoder& codec) const {
   codec.start_sequence().encode(m_oid).start_set().raw_bytes(m_parameters).end_cons().end_cons();
}

/*
* Decode a BER encoded Attribute
*/
void Attribute::decode_from(BER_Decoder& codec) {
   codec.start_sequence().decode(m_oid).start_set().raw_bytes(m_parameters).end_cons().end_cons();
}

}  // namespace Botan

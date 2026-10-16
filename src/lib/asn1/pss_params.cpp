/*
* (C) 2017 Daniel Neus
*     2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pss_params.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/algorithm_spec.h>
#include <botan/internal/fmt.h>

namespace Botan {

//static
PSS_Params PSS_Params::from_padding_name(std::string_view padding_name) {
   const AlgorithmSpec spec(padding_name);

   const auto m = spec.match("PSS|PSS_Raw({hash},MGF1,{salt_len:int})");
   if(!m) {
      throw Invalid_Argument(fmt("PSS_Params::from_padding_name unexpected param '{}'", padding_name));
   }

   return PSS_Params(m->str("hash"), m->integer("salt_len"));
}

PSS_Params::PSS_Params(std::string_view hash_fn, size_t salt_len) :
      m_hash(hash_fn, AlgorithmIdentifier::USE_NULL_PARAM),
      m_mgf("MGF1", m_hash.BER_encode()),
      m_mgf_hash(m_hash),
      m_salt_len(salt_len),
      m_trailer_field(1) {}

PSS_Params::PSS_Params(std::span<const uint8_t> der) : m_salt_len(0), m_trailer_field(1) {
   BER_Decoder decoder(der, BER_Decoder::Limits::DER());
   this->decode_from(decoder);
   decoder.verify_end();
}

std::vector<uint8_t> PSS_Params::serialize() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(*this);
   return output;
}

void PSS_Params::encode_into(DER_Encoder& to) const {
   to.start_sequence()
      .start_context_specific(0)
      .encode(m_hash)
      .end_cons()
      .start_context_specific(1)
      .encode(m_mgf)
      .end_cons()
      .start_context_specific(2)
      .encode(m_salt_len)
      .end_cons()
      .end_cons();
}

void PSS_Params::decode_from(BER_Decoder& from) {
   const AlgorithmIdentifier default_hash("SHA-1", AlgorithmIdentifier::USE_NULL_PARAM);
   const AlgorithmIdentifier default_mgf("MGF1", default_hash.BER_encode());
   const size_t default_salt_len = 20;
   const size_t default_trailer = 1;

   from.start_sequence()
      .decode_optional(m_hash, ASN1_Type(0), ASN1_Class::ExplicitContextSpecific, default_hash)
      .decode_optional(m_mgf, ASN1_Type(1), ASN1_Class::ExplicitContextSpecific, default_mgf)
      .decode_optional(m_salt_len, ASN1_Type(2), ASN1_Class::ExplicitContextSpecific, default_salt_len)
      .decode_optional(m_trailer_field, ASN1_Type(3), ASN1_Class::ExplicitContextSpecific, default_trailer)
      .end_cons();

   BER_Decoder(m_mgf.parameters(), from.limits()).decode(m_mgf_hash).verify_end();

   if(!m_hash.parameters_are_null_or_empty() || !m_mgf_hash.parameters_are_null_or_empty()) {
      throw Decoding_Error("Unexpected parameters for PSS hash algorithm identifier");
   }
}

}  // namespace Botan

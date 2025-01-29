/*
* (C) 2017 Daniel Neus
*     2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pss_params.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

namespace Botan {

//static
PSS_Params PSS_Params::from_emsa_name(std::string_view emsa_name) {
   SCAN_Name scanner(emsa_name);

   if((scanner.algo_name() != "PSS" && scanner.algo_name() != "PSS_Raw") || scanner.arg_count() != 3) {
      throw Invalid_Argument(fmt("PSS_Params::from_emsa_name unexpected param '{}'", emsa_name));
   }

   const std::string hash_fn = scanner.arg(0);
   BOTAN_ASSERT_NOMSG(scanner.arg(1) == "MGF1");
   const size_t salt_len = scanner.arg_as_integer(2);
   return PSS_Params(hash_fn, salt_len);
}

PSS_Params::PSS_Params(std::string_view hash_fn, size_t salt_len) :
      m_hash(hash_fn, AlgorithmIdentifier::USE_NULL_PARAM),
      m_mgf("MGF1", m_hash.BER_encode()),
      m_mgf_hash(m_hash),
      m_salt_len(salt_len) {}

PSS_Params::PSS_Params(std::span<const uint8_t> der) {
   BER_Decoder decoder(der);
   this->decode_from(decoder);
}

std::vector<uint8_t> PSS_Params::serialize() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(*this);
   return output;
}

void PSS_Params::encode_into(DER_Encoder& to) const {
   const size_t trailer_field = 1;

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
      .start_context_specific(3)
      .encode(trailer_field)
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

   BER_Decoder(m_mgf.parameters()).decode(m_mgf_hash);
}

}  // namespace Botan

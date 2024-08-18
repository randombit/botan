/*
 * XMSS Public Key
 * An XMSS: Extended Hash-Based Siganture public key.
 * The XMSS public key does not support the X509 standard. Instead the
 * raw format described in [1] is used.
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 *
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pk_options.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pk_options_impl.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/xmss_verification_operation.h>

#include <iterator>

namespace Botan {

namespace {

XMSS_Parameters::xmss_algorithm_t deserialize_xmss_oid(std::span<const uint8_t> raw_key) {
   if(raw_key.size() < 4) {
      throw Decoding_Error("XMSS signature OID missing.");
   }

   // extract and convert algorithm id to enum type
   uint32_t raw_id = 0;
   for(size_t i = 0; i < 4; i++) {
      raw_id = ((raw_id << 8) | raw_key[i]);
   }

   return static_cast<XMSS_Parameters::xmss_algorithm_t>(raw_id);
}

// fall back to raw decoding for previous versions, which did not encode an OCTET STRING
std::vector<uint8_t> extract_raw_public_key(std::span<const uint8_t> key_bits) {
   std::vector<uint8_t> raw_key;
   try {
      DataSource_Memory src(key_bits);
      BER_Decoder(src).decode(raw_key, ASN1_Type::OctetString).verify_end();

      // Smoke check the decoded key. Valid raw keys might be decodeable as BER
      // and they might be either a sole public key or a concatenation of public
      // and private key (with the optional WOTS+ derivation identifier).
      XMSS_Parameters params(deserialize_xmss_oid(raw_key));
      if(raw_key.size() != params.raw_public_key_size() && raw_key.size() != params.raw_private_key_size() &&
         raw_key.size() != params.raw_legacy_private_key_size()) {
         throw Decoding_Error("unpacked XMSS key does not have the correct length");
      }
   } catch(Decoding_Error&) {
      raw_key.assign(key_bits.begin(), key_bits.end());
   } catch(Not_Implemented&) {
      raw_key.assign(key_bits.begin(), key_bits.end());
   }

   return raw_key;
}

}  // namespace

XMSS_PublicKey::XMSS_PublicKey(XMSS_Parameters::xmss_algorithm_t xmss_oid, RandomNumberGenerator& rng) :
      m_xmss_params(xmss_oid),
      m_wots_params(m_xmss_params.ots_oid()),
      m_root(m_xmss_params.element_size()),
      m_public_seed(rng.random_vec(m_xmss_params.element_size())) {}

XMSS_PublicKey::XMSS_PublicKey(std::span<const uint8_t> key_bits) :
      m_raw_key(extract_raw_public_key(key_bits)),
      m_xmss_params(deserialize_xmss_oid(m_raw_key)),
      m_wots_params(m_xmss_params.ots_oid()) {
   if(m_raw_key.size() < m_xmss_params.raw_public_key_size()) {
      throw Decoding_Error("Invalid XMSS public key size detected");
   }

   BufferSlicer s(m_raw_key);
   s.skip(4 /* algorithm ID -- already consumed by `deserialize_xmss_oid()` */);

   m_root = s.copy_as_secure_vector(m_xmss_params.element_size());
   m_public_seed = s.copy_as_secure_vector(m_xmss_params.element_size());
}

XMSS_PublicKey::XMSS_PublicKey(XMSS_Parameters::xmss_algorithm_t xmss_oid,
                               secure_vector<uint8_t> root,
                               secure_vector<uint8_t> public_seed) :
      m_xmss_params(xmss_oid),
      m_wots_params(m_xmss_params.ots_oid()),
      m_root(std::move(root)),
      m_public_seed(std::move(public_seed)) {
   BOTAN_ARG_CHECK(m_root.size() == m_xmss_params.element_size(), "XMSS: unexpected byte length of root hash");
   BOTAN_ARG_CHECK(m_public_seed.size() == m_xmss_params.element_size(), "XMSS: unexpected byte length of public seed");
}

std::unique_ptr<PK_Ops::Verification> XMSS_PublicKey::_create_verification_op(
   const PK_Signature_Options& options) const {
   PK_Options_Checks::validate_for_hash_based_signature(options, "XMSS", this->m_xmss_params.hash_function_name());

   if(!options.using_provider()) {
      return std::make_unique<XMSS_Verification_Operation>(*this);
   }

   throw Provider_Not_Found(algo_name(), options.provider().value());
}

std::unique_ptr<PK_Ops::Verification> XMSS_PublicKey::create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                                  std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for XMSS X509 signature");
      }
      return std::make_unique<XMSS_Verification_Operation>(*this);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::vector<uint8_t> XMSS_PublicKey::raw_public_key_bits() const {
   return concat<std::vector<uint8_t>>(store_be(static_cast<uint32_t>(m_xmss_params.oid())), m_root, m_public_seed);
}

std::vector<uint8_t> XMSS_PublicKey::public_key_bits() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(raw_public_key_bits(), ASN1_Type::OctetString);
   return output;
}

std::vector<uint8_t> XMSS_PublicKey::raw_public_key() const {
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> XMSS_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   // Note: Given only an XMSS public key we cannot know which WOTS key
   //       derivation method was used to build the XMSS tree. Hence, we have to
   //       use the default here.
   return std::make_unique<XMSS_PrivateKey>(m_xmss_params.oid(), rng);
}

}  // namespace Botan

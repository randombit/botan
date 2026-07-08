/*
 * XMSS^MT Public Key
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmssmt.h>

#include <botan/rng.h>
#include <botan/xmssmt_parameters.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/xmssmt_verification_operation.h>

namespace Botan {

namespace {

XMSSMT_Parameters::xmssmt_algorithm_t deserialize_xmssmt_oid(std::span<const uint8_t> raw_key) {
   if(raw_key.size() < 4) {
      throw Decoding_Error("XMSS^MT signature OID missing.");
   }
   return XMSSMT_Parameters::parse_oid(raw_key.first(4));
}

}  // namespace

XMSSMT_PublicKey::XMSSMT_PublicKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_oid, RandomNumberGenerator& rng) :
      m_xmssmt_params(xmssmt_oid),
      m_wots_params(m_xmssmt_params.ots_oid()),
      m_root(m_xmssmt_params.element_size()),
      m_public_seed(rng.random_vec(m_xmssmt_params.element_size())) {}

XMSSMT_PublicKey::XMSSMT_PublicKey(std::span<const uint8_t> key_bits) :
      m_raw_key(key_bits.begin(), key_bits.end()),
      m_xmssmt_params(deserialize_xmssmt_oid(m_raw_key)),
      m_wots_params(m_xmssmt_params.ots_oid()) {
   if(m_raw_key.size() < m_xmssmt_params.raw_public_key_size()) {
      throw Decoding_Error(fmt("Invalid XMSS^MT public key size of {} bytes detected, should be {} bytes",
                               m_raw_key.size(),
                               m_xmssmt_params.raw_public_key_size()));
   }

   BufferSlicer s(m_raw_key);
   s.skip(4 /* algorithm ID -- already consumed by `deserialize_xmssmt_oid()` */);

   m_root = s.copy_as_secure_vector(m_xmssmt_params.element_size());
   m_public_seed = s.copy_as_secure_vector(m_xmssmt_params.element_size());
}

XMSSMT_PublicKey::XMSSMT_PublicKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_oid,
                                   secure_vector<uint8_t> root,
                                   secure_vector<uint8_t> public_seed) :
      m_xmssmt_params(xmssmt_oid),
      m_wots_params(m_xmssmt_params.ots_oid()),
      m_root(std::move(root)),
      m_public_seed(std::move(public_seed)) {
   BOTAN_ARG_CHECK(m_root.size() == m_xmssmt_params.element_size(), "XMSS^MT: unexpected byte length of root hash");
   BOTAN_ARG_CHECK(m_public_seed.size() == m_xmssmt_params.element_size(),
                   "XMSS^MT: unexpected byte length of public seed");
}

std::vector<uint8_t> XMSSMT_PublicKey::raw_public_key_bits() const {
   return concat<std::vector<uint8_t>>(store_be(static_cast<uint32_t>(m_xmssmt_params.oid())), m_root, m_public_seed);
}

std::vector<uint8_t> XMSSMT_PublicKey::public_key_bits() const {
   // Contrary to the private key, the public key is not wrapped in an ASN.1
   // OCTET STRING (see RFC 9802 Section 2.3)
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> XMSSMT_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<XMSSMT_PrivateKey>(m_xmssmt_params.oid(), rng);
}

std::unique_ptr<PK_Ops::Verification> XMSSMT_PublicKey::create_verification_op(std::string_view /*params*/,
                                                                               std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<XMSSMT_Verification_Operation>(*this);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> XMSSMT_PublicKey::create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                                    std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for XMSS^MT X.509 signature");
      }
      return std::make_unique<XMSSMT_Verification_Operation>(*this);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan

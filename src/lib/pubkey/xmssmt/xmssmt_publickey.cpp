/*
 * XMSS^MT Public Key
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmssmt.h>

#include <botan/pk_options.h>
#include <botan/rng.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pk_options_impl.h>
#include <botan/internal/xmssmt_verification_operation.h>

namespace Botan {

namespace {

XMSSMT_Parameters::xmssmt_algorithm_t deserialize_xmssmt_oid(std::span<const uint8_t> raw_key) {
   if(raw_key.size() < 4) {
      throw Decoding_Error("XMSS^MT public key OID missing.");
   }
   return XMSSMT_Parameters::parse_oid(raw_key.first(4));
}

}  // namespace

class XMSSMT_PublicKey_Internal final {
   public:
      XMSSMT_PublicKey_Internal(const XMSSMT_Parameters& params,
                                secure_vector<uint8_t> root,
                                secure_vector<uint8_t> public_seed) :
            m_xmssmt_params(params),
            m_wots_params(m_xmssmt_params.wots_parameters()),
            m_root(std::move(root)),
            m_public_seed(std::move(public_seed)) {}

      const XMSSMT_Parameters& xmssmt_parameters() const { return m_xmssmt_params; }

      const XMSS_WOTS_Parameters& wots_parameters() const { return m_wots_params; }

      const secure_vector<uint8_t>& root() const { return m_root; }

      const secure_vector<uint8_t>& public_seed() const { return m_public_seed; }

      std::vector<uint8_t> raw_public_key_bits() const {
         return concat<std::vector<uint8_t>>(
            store_be(static_cast<uint32_t>(m_xmssmt_params.oid())), m_root, m_public_seed);
      }

   private:
      XMSSMT_Parameters m_xmssmt_params;
      XMSS_WOTS_Parameters m_wots_params;
      secure_vector<uint8_t> m_root;
      secure_vector<uint8_t> m_public_seed;
};

XMSSMT_PublicKey::XMSSMT_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   // The XMSS^MT parameter set is carried in the key bits; no AlgorithmIdentifier parameters are defined
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for XMSS^MT public key");
   }

   const auto xmssmt_oid = deserialize_xmssmt_oid(key_bits);
   const auto params = XMSSMT_Parameters::from_id(xmssmt_oid);
   if(key_bits.size() < params.raw_public_key_size()) {
      throw Decoding_Error(fmt("Invalid XMSS^MT public key size of {} bytes detected, should be {} bytes",
                               key_bits.size(),
                               params.raw_public_key_size()));
   }

   BufferSlicer s(key_bits);
   s.skip(4 /* algorithm ID -- already consumed by `deserialize_xmssmt_oid()` */);

   auto root = s.copy_as_secure_vector(params.element_size());
   auto public_seed = s.copy_as_secure_vector(params.element_size());

   m_public_key = std::make_shared<XMSSMT_PublicKey_Internal>(params, std::move(root), std::move(public_seed));
}

XMSSMT_PublicKey::XMSSMT_PublicKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_oid,
                                   secure_vector<uint8_t> root,
                                   secure_vector<uint8_t> public_seed) {
   const auto params = XMSSMT_Parameters::from_id(xmssmt_oid);
   BOTAN_ARG_CHECK(root.size() == params.element_size(), "XMSS^MT: unexpected byte length of root hash");
   BOTAN_ARG_CHECK(public_seed.size() == params.element_size(), "XMSS^MT: unexpected byte length of public seed");
   m_public_key = std::make_shared<XMSSMT_PublicKey_Internal>(params, std::move(root), std::move(public_seed));
}

const secure_vector<uint8_t>& XMSSMT_PublicKey::public_seed() const {
   return m_public_key->public_seed();
}

const secure_vector<uint8_t>& XMSSMT_PublicKey::root() const {
   return m_public_key->root();
}

const XMSSMT_Parameters& XMSSMT_PublicKey::xmssmt_parameters() const {
   return m_public_key->xmssmt_parameters();
}

size_t XMSSMT_PublicKey::estimated_strength() const {
   return xmssmt_parameters().estimated_strength();
}

size_t XMSSMT_PublicKey::key_length() const {
   return xmssmt_parameters().estimated_strength();
}

bool XMSSMT_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   // The public key consists of (OID, root hash, public seed). The OID is
   // validated and the byte lengths of root and public_seed are verified
   // against the parameter set during deserialization. These are opaque
   // hash outputs with no further structural invariants to check.
   return true;
}

std::vector<uint8_t> XMSSMT_PublicKey::raw_public_key_bits() const {
   return m_public_key->raw_public_key_bits();
}

std::vector<uint8_t> XMSSMT_PublicKey::public_key_bits() const {
   // Contrary to the private key, the public key is not wrapped in an ASN.1
   // OCTET STRING (see RFC 9802 Section 5.3)
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> XMSSMT_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<XMSSMT_PrivateKey>(xmssmt_parameters().oid(), rng);
}

std::unique_ptr<PK_Ops::Verification> XMSSMT_PublicKey::_create_verification_op(
   const PK_Signature_Options& options) const {
   validate_for_hash_based_signature(options, "XMSSMT", xmssmt_parameters().hash_function_name());

   if(!options.using_provider()) {
      return std::make_unique<XMSSMT_Verification_Operation>(*this);
   }

   throw Provider_Not_Found(algo_name(), options.provider().value());
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

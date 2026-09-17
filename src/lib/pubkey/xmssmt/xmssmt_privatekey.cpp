/*
 * XMSS^MT Private Key
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmssmt.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pk_options.h>
#include <botan/rng.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pk_options_impl.h>
#include <botan/internal/stateful_key_index_registry.h>
#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmss_tree_builder.h>
#include <botan/internal/xmssmt_signature_operation.h>

namespace Botan {

namespace {

secure_vector<uint8_t> extract_raw_private_key(std::span<const uint8_t> key_bits) {
   secure_vector<uint8_t> raw_key;
   BER_Decoder(key_bits, BER_Decoder::Limits::DER()).decode(raw_key, ASN1_Type::OctetString).verify_end();
   return raw_key;
}

}  // namespace

class XMSSMT_PrivateKey_Internal final {
   public:
      XMSSMT_PrivateKey_Internal(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id,
                                 secure_vector<uint8_t> private_seed,
                                 secure_vector<uint8_t> prf) :
            m_xmssmt_params(XMSSMT_Parameters::from_id(xmssmt_algo_id)),
            m_wots_params(m_xmssmt_params.wots_parameters()),
            m_prf(std::move(prf)),
            m_private_seed(std::move(private_seed)),
            m_keyid(Stateful_Key_Index_Registry::KeyId("XMSSMT",
                                                       store_be(static_cast<uint32_t>(m_xmssmt_params.oid())),
                                                       m_xmssmt_params.total_number_of_signatures(),
                                                       m_private_seed,
                                                       m_prf)) {}

      // @p raw_key must be the OCTET STRING contents of a serialized private key
      // (i.e. already unwrapped, see extract_raw_private_key()).
      XMSSMT_PrivateKey_Internal(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id,
                                 std::span<const uint8_t> raw_key) :
            m_xmssmt_params(XMSSMT_Parameters::from_id(xmssmt_algo_id)),
            m_wots_params(m_xmssmt_params.wots_parameters()) {
         if(raw_key.size() != m_xmssmt_params.raw_private_key_size()) {
            throw Decoding_Error("Invalid XMSS^MT private key size");
         }

         BufferSlicer s(raw_key);

         // We're not interested in the public key here
         s.skip(m_xmssmt_params.raw_public_key_size());

         auto unused_leaf_bytes = s.take(m_xmssmt_params.encoded_idx_size());
         uint64_t unused_leaf = 0;
         for(const uint8_t unused_leaf_byte : unused_leaf_bytes) {
            unused_leaf = (unused_leaf << 8) | static_cast<uint64_t>(unused_leaf_byte);
         }

         m_prf = s.copy_as_secure_vector(m_xmssmt_params.element_size());
         m_private_seed = s.copy_as_secure_vector(m_xmssmt_params.element_size());
         m_keyid = Stateful_Key_Index_Registry::KeyId("XMSSMT",
                                                      store_be(static_cast<uint32_t>(m_xmssmt_params.oid())),
                                                      m_xmssmt_params.total_number_of_signatures(),
                                                      m_private_seed,
                                                      m_prf);

         // Note m_keyid must be initialized before set_unused_leaf_index is called!
         set_unused_leaf_index(unused_leaf);

         BOTAN_ASSERT_NOMSG(s.empty());
      }

      secure_vector<uint8_t> serialize(std::vector<uint8_t> raw_public_key) const {
         std::vector<uint8_t> unused_index(m_xmssmt_params.encoded_idx_size());
         uint64_t idx = unused_leaf_index();
         for(size_t i = 0; i < unused_index.size(); i++) {
            unused_index[unused_index.size() - 1 - i] = static_cast<uint8_t>(idx & 0xFF);
            idx >>= 8;
         }

         return concat<secure_vector<uint8_t>>(raw_public_key, unused_index, m_prf, m_private_seed);
      }

      const secure_vector<uint8_t>& prf_value() const { return m_prf; }

      const secure_vector<uint8_t>& private_seed() const { return m_private_seed; }

      const XMSS_WOTS_Parameters& wots_parameters() const { return m_wots_params; }

      // The signing state (leaf index) lives in the process-wide
      // Stateful_Key_Index_Registry keyed by m_keyid, not in this object, so the
      // methods that advance it leave *this unchanged and are therefore const.
      void set_unused_leaf_index(uint64_t idx) const {
         // An index equal to 2^h is valid and denotes an exhausted key
         if(idx > (1ULL << m_xmssmt_params.tree_height())) {
            throw Decoding_Error("XMSS^MT private key leaf index out of bounds");
         } else {
            Stateful_Key_Index_Registry::global().set_index_lower_bound(m_keyid, idx);
         }
      }

      uint64_t reserve_unused_leaf_index() const {
         const auto idx = Stateful_Key_Index_Registry::global().reserve_next_index(m_keyid);
         if(!idx.has_value()) {
            throw Invalid_State("XMSS^MT private key, one time signatures exhausted");
         }
         return idx.value();
      }

      uint64_t unused_leaf_index() const { return Stateful_Key_Index_Registry::global().current_index(m_keyid); }

      uint64_t remaining_signatures() const {
         return Stateful_Key_Index_Registry::global().remaining_operations(m_keyid);
      }

   private:
      XMSSMT_Parameters m_xmssmt_params;
      XMSS_WOTS_Parameters m_wots_params;
      secure_vector<uint8_t> m_prf;
      secure_vector<uint8_t> m_private_seed;
      Stateful_Key_Index_Registry::KeyId m_keyid;
};

struct XMSSMT_PrivateKey::Decoded_Private_Key {
      XMSSMT_Parameters::xmssmt_algorithm_t oid{};
      secure_vector<uint8_t> root;
      secure_vector<uint8_t> public_seed;
      secure_vector<uint8_t> raw_key;
};

XMSSMT_PrivateKey::Decoded_Private_Key XMSSMT_PrivateKey::decode_private_key(const AlgorithmIdentifier& alg_id,
                                                                             std::span<const uint8_t> key_bits) {
   // The XMSS^MT parameter set is carried in the key bits; no AlgorithmIdentifier parameters are defined
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for XMSS^MT private key");
   }

   Decoded_Private_Key decoded;
   decoded.raw_key = extract_raw_private_key(key_bits);

   if(decoded.raw_key.size() < 4) {
      throw Decoding_Error("XMSS^MT private key OID missing.");
   }

   BufferSlicer s(decoded.raw_key);
   decoded.oid = XMSSMT_Parameters::parse_oid(s.take(4));

   const auto params = XMSSMT_Parameters::from_id(decoded.oid);
   if(decoded.raw_key.size() < params.raw_public_key_size()) {
      throw Decoding_Error("XMSS^MT private key too short");
   }

   decoded.root = s.copy_as_secure_vector(params.element_size());
   decoded.public_seed = s.copy_as_secure_vector(params.element_size());

   return decoded;
}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      XMSSMT_PrivateKey(decode_private_key(alg_id, key_bits)) {}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(Decoded_Private_Key decoded) :
      XMSSMT_PublicKey(decoded.oid, std::move(decoded.root), std::move(decoded.public_seed)),
      m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(decoded.oid, decoded.raw_key)) {}

struct XMSSMT_PrivateKey::Keygen_Material {
      secure_vector<uint8_t> private_seed;
      secure_vector<uint8_t> prf;
      secure_vector<uint8_t> public_seed;
      secure_vector<uint8_t> root;
};

XMSSMT_PrivateKey::Keygen_Material XMSSMT_PrivateKey::generate_keygen_material(
   XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id, RandomNumberGenerator& rng) {
   const auto params = XMSSMT_Parameters::from_id(xmssmt_algo_id);
   const size_t n = params.element_size();

   // The seeds are drawn in the same order as for XMSS (public seed, then prf,
   // then private seed); the keygen reference test relies on this order.
   auto public_seed = rng.random_vec(n);
   auto prf = rng.random_vec(n);
   auto private_seed = rng.random_vec(n);

   XMSS_Address adrs;
   adrs.set_layer_addr(static_cast<uint32_t>(params.tree_layers() - 1));
   XMSS_Hash hash(params.hash_function_name(), params.hash_id_size());
   const XMSS_Tree_Builder builder(
      params.wots_parameters(), WOTS_Derivation_Method::NIST_SP800_208, public_seed, private_seed);
   auto root = builder.tree_hash(0, params.xmss_tree_height(), adrs, hash);

   return Keygen_Material{std::move(private_seed), std::move(prf), std::move(public_seed), std::move(root)};
}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id, RandomNumberGenerator& rng) :
      XMSSMT_PrivateKey(xmssmt_algo_id, generate_keygen_material(xmssmt_algo_id, rng)) {}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id, Keygen_Material material) :
      XMSSMT_PublicKey(xmssmt_algo_id, std::move(material.root), std::move(material.public_seed)),
      m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(
         xmssmt_algo_id, std::move(material.private_seed), std::move(material.prf))) {}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id,
                                     uint64_t idx_leaf,
                                     secure_vector<uint8_t> wots_priv_seed,
                                     secure_vector<uint8_t> prf,
                                     secure_vector<uint8_t> root,
                                     secure_vector<uint8_t> public_seed) :
      XMSSMT_PublicKey(xmssmt_algo_id, std::move(root), std::move(public_seed)),
      m_private(
         std::make_shared<XMSSMT_PrivateKey_Internal>(xmssmt_algo_id, std::move(wots_priv_seed), std::move(prf))) {
   m_private->set_unused_leaf_index(idx_leaf);
   BOTAN_ARG_CHECK(m_private->prf_value().size() == xmssmt_parameters().element_size(),
                   "XMSS^MT: unexpected byte length of PRF value");
   BOTAN_ARG_CHECK(m_private->private_seed().size() == xmssmt_parameters().element_size(),
                   "XMSS^MT: unexpected byte length of private seed");
}

secure_vector<uint8_t> XMSSMT_PrivateKey::tree_hash(uint32_t start_idx,
                                                    size_t target_node_height,
                                                    XMSS_Address adrs,
                                                    XMSS_Hash& hash) const {
   return XMSS_Tree_Builder(m_private->wots_parameters(),
                            WOTS_Derivation_Method::NIST_SP800_208,
                            public_seed(),
                            m_private->private_seed())
      .tree_hash(start_idx, target_node_height, adrs, hash);
}

XMSS_WOTS_PrivateKey XMSSMT_PrivateKey::wots_private_key_for(XMSS_Address& adrs, XMSS_Hash& hash) const {
   return XMSS_Tree_Builder(m_private->wots_parameters(),
                            WOTS_Derivation_Method::NIST_SP800_208,
                            public_seed(),
                            m_private->private_seed())
      .wots_private_key_for(adrs, hash);
}

secure_vector<uint8_t> XMSSMT_PrivateKey::private_key_bits() const {
   return DER_Encoder().encode(raw_private_key(), ASN1_Type::OctetString).get_contents();
}

uint64_t XMSSMT_PrivateKey::reserve_unused_leaf_index() {
   return m_private->reserve_unused_leaf_index();
}

std::optional<uint64_t> XMSSMT_PrivateKey::remaining_operations() const {
   return m_private->remaining_signatures();
}

const secure_vector<uint8_t>& XMSSMT_PrivateKey::prf_value() const {
   return m_private->prf_value();
}

secure_vector<uint8_t> XMSSMT_PrivateKey::raw_private_key() const {
   return m_private->serialize(raw_public_key_bits());
}

std::unique_ptr<Public_Key> XMSSMT_PrivateKey::public_key() const {
   return std::make_unique<XMSSMT_PublicKey>(xmssmt_parameters().oid(), root(), public_seed());
}

std::unique_ptr<PK_Ops::Signature> XMSSMT_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                           const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);

   validate_for_hash_based_signature(options, "XMSSMT", xmssmt_parameters().hash_function_name());
   acknowledge_always_deterministic(options);

   if(!options.using_provider()) {
      return std::make_unique<XMSSMT_Signature_Operation>(*this);
   }

   throw Provider_Not_Found(algo_name(), options.provider().value());
}

}  // namespace Botan

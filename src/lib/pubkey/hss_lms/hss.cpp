/**
 * HSS - Hierarchical Signatures System (RFC 8554)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/hss.h>

#include <botan/internal/fmt.h>
#include <botan/internal/hss_lms_utils.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/stl_util.h>

#include <algorithm>
#include <limits>

namespace Botan {

namespace {

/**
 * @brief The maximum number of levels in a HSS-LMS tree.
 *
 * RFC 8554 Section 6:
 *   The number of levels is denoted as L and is between one
 *   and eight, inclusive.
 */
constexpr HSS_Level HSS_MAX_LEVELS(8);

/**
 * @brief Domain-separation parameter for generation the seed of a child LMS tree.
 *
 * This comes from https://github.com/cisco/hash-sigs.
 */
constexpr uint16_t SEED_CHILD_SEED = 0xfffe;

/**
 * @brief Domain-separation parameter for generation the identifier of a child LMS tree.
 *
 * This comes from https://github.com/cisco/hash-sigs.
 */
constexpr uint16_t SEED_CHILD_I = 0xffff;

/**
 * @brief Check that the given @p hash_name is one of the supported hash functions for HSS-LMS.
 */
constexpr bool is_supported_hash_function(std::string_view hash_name) {
   return hash_name == "SHA-256" || hash_name == "Truncated(SHA-256,192)" || hash_name == "SHAKE-256(256)" ||
          hash_name == "SHAKE-256(192)";
}

/**
 * Given an HSS index, i.e. the number of already created HSS signatures, return the lms leaf indices for
 * the different LMS layers from root layer to bottom layer.
 */
std::vector<LMS_Tree_Node_Idx> derive_lms_leaf_indices_from_hss_index(HSS_Sig_Idx hss_idx,
                                                                      const HSS_LMS_Params& hss_params) {
   std::vector<LMS_Tree_Node_Idx> q(hss_params.L().get());
   for(int32_t layer_ctr = hss_params.L().get() - 1; layer_ctr >= 0; --layer_ctr) {
      HSS_Level layer(layer_ctr);
      const HSS_LMS_Params::LMS_LMOTS_Params_Pair& layer_params = hss_params.params_at_level(layer);
      size_t layer_h = layer_params.lms_params().h();
      q.at(layer.get()) =
         checked_cast_to<LMS_Tree_Node_Idx>(hss_idx.get() % checked_cast_to<uint64_t>(1ULL << layer_h));
      hss_idx = hss_idx >> layer_h;
   }
   BOTAN_ARG_CHECK(hss_idx == HSS_Sig_Idx(0), "HSS Tree is exhausted");

   return q;
}

}  // namespace

HSS_LMS_Params::HSS_LMS_Params(std::vector<LMS_LMOTS_Params_Pair> lm_lmots_params) :
      m_lms_lmots_params(std::move(lm_lmots_params)), m_max_sig_count(calc_max_sig_count()) {
   BOTAN_ARG_CHECK(!m_lms_lmots_params.empty() && m_lms_lmots_params.size() <= HSS_MAX_LEVELS,
                   "Invalid number of levels");
}

HSS_LMS_Params::HSS_LMS_Params(std::string_view algo_params) {
   SCAN_Name scan(fmt("HSS-LMS({})", algo_params));

   BOTAN_ARG_CHECK(scan.arg_count() >= 2 && scan.arg_count() <= HSS_MAX_LEVELS + 1, "Invalid number of arguments");
   std::string hash = scan.arg(0);
   BOTAN_ARG_CHECK(is_supported_hash_function(hash), "Supported HSS-LMS hash function");

   for(size_t i = 1; i < scan.arg_count(); ++i) {
      SCAN_Name scan_layer(scan.arg(i));
      BOTAN_ARG_CHECK(scan_layer.algo_name() == "HW", "Invalid name for layer parameters");
      BOTAN_ARG_CHECK(scan_layer.arg_count() == 2, "Invalid number of layer parameters");
      const auto h =
         checked_cast_to_or_throw<uint8_t, Invalid_Argument>(scan_layer.arg_as_integer(0), "Invalid tree height");
      const auto w = checked_cast_to_or_throw<uint8_t, Invalid_Argument>(scan_layer.arg_as_integer(1),
                                                                         "Invalid Winternitz parameter");
      m_lms_lmots_params.push_back({LMS_Params::create_or_throw(hash, h), LMOTS_Params::create_or_throw(hash, w)});
   }
   m_max_sig_count = calc_max_sig_count();
}

HSS_Sig_Idx HSS_LMS_Params::calc_max_sig_count() const {
   uint32_t total_height_counter = 0;
   for(HSS_Level level(0); level < L(); level++) {
      total_height_counter += params_at_level(level).lms_params().h();
   }
   if(total_height_counter >= sizeof(HSS_Sig_Idx) * 8) {
      return HSS_Sig_Idx(std::numeric_limits<HSS_Sig_Idx::wrapped_type>::max());
   }
   return HSS_Sig_Idx(1) << total_height_counter;
}

HSS_LMS_PrivateKeyInternal::HSS_LMS_PrivateKeyInternal(const HSS_LMS_Params& hss_params, RandomNumberGenerator& rng) :
      m_hss_params(hss_params), m_current_idx(0), m_sig_size(HSS_Signature::size(m_hss_params)) {
   m_hss_seed = rng.random_vec<LMS_Seed>(m_hss_params.params_at_level(HSS_Level(0)).lms_params().m());
   m_identifier = rng.random_vec<LMS_Identifier>(LMS_IDENTIFIER_LEN);
}

std::shared_ptr<HSS_LMS_PrivateKeyInternal> HSS_LMS_PrivateKeyInternal::from_bytes_or_throw(
   std::span<const uint8_t> key_bytes) {
   if(key_bytes.size() < sizeof(HSS_Level) + sizeof(HSS_Sig_Idx)) {
      throw Decoding_Error("Too few private key bytes.");
   }
   BufferSlicer slicer(key_bytes);

   const auto L = load_be<HSS_Level>(slicer.take<sizeof(HSS_Level)>());
   if(L == 0U || L > HSS_MAX_LEVELS) {
      throw Decoding_Error("Invalid number of HSS layers in private HSS-LMS key.");
   }

   const auto sig_idx = load_be<HSS_Sig_Idx>(slicer.take<sizeof(HSS_Sig_Idx)>());

   std::vector<HSS_LMS_Params::LMS_LMOTS_Params_Pair> params;
   for(size_t layer = 1; layer <= L; ++layer) {
      if(slicer.remaining() < sizeof(LMS_Algorithm_Type) + sizeof(LMOTS_Algorithm_Type)) {
         throw Decoding_Error("Out of bytes while parsing private HSS-LMS key.");
      }
      const auto lms_type = load_be<LMS_Algorithm_Type>(slicer.take<sizeof(LMS_Algorithm_Type)>());
      const auto lmots_type = load_be<LMOTS_Algorithm_Type>(slicer.take<sizeof(LMOTS_Algorithm_Type)>());
      params.push_back({LMS_Params::create_or_throw(lms_type), LMOTS_Params::create_or_throw(lmots_type)});
   }
   std::string hash_name = params.at(0).lms_params().hash_name();
   if(std::any_of(params.begin(), params.end(), [&hash_name](HSS_LMS_Params::LMS_LMOTS_Params_Pair& lms_lmots_params) {
         bool invalid_lmots_hash = lms_lmots_params.lmots_params().hash_name() != hash_name;
         bool invalid_lms_hash = lms_lmots_params.lms_params().hash_name() != hash_name;
         return invalid_lmots_hash || invalid_lms_hash;
      })) {
      throw Decoding_Error("Inconsistent hash functions are not allowed.");
   }

   if(slicer.remaining() < params.at(0).lms_params().m() + LMS_IDENTIFIER_LEN) {
      throw Decoding_Error("Out of bytes while parsing private HSS-LMS key.");
   }
   auto hss_seed = slicer.copy<LMS_Seed>(params.at(0).lms_params().m());
   auto identifier = slicer.copy<LMS_Identifier>(LMS_IDENTIFIER_LEN);

   if(!slicer.empty()) {
      throw Decoding_Error("Private HSS-LMS key contains more bytes than expected.");
   }
   auto sk = std::shared_ptr<HSS_LMS_PrivateKeyInternal>(
      new HSS_LMS_PrivateKeyInternal(HSS_LMS_Params(std::move(params)), std::move(hss_seed), std::move(identifier)));

   sk->set_idx(sig_idx);
   return sk;
}

secure_vector<uint8_t> HSS_LMS_PrivateKeyInternal::to_bytes() const {
   secure_vector<uint8_t> sk_bytes(size());
   BufferStuffer stuffer(sk_bytes);

   stuffer.append(store_be(hss_params().L()));
   stuffer.append(store_be(get_idx()));

   for(HSS_Level layer(1); layer <= hss_params().L(); ++layer) {
      const auto& params = hss_params().params_at_level(layer - 1);
      stuffer.append(store_be(params.lms_params().algorithm_type()));
      stuffer.append(store_be(params.lmots_params().algorithm_type()));
   }
   stuffer.append(m_hss_seed);
   stuffer.append(m_identifier);
   BOTAN_ASSERT_NOMSG(stuffer.full());

   return sk_bytes;
}

void HSS_LMS_PrivateKeyInternal::set_idx(HSS_Sig_Idx idx) {
   m_current_idx = idx;
}

HSS_Sig_Idx HSS_LMS_PrivateKeyInternal::reserve_next_idx() {
   HSS_Sig_Idx next_idx = m_current_idx;
   if(next_idx >= m_hss_params.max_sig_count()) {
      throw Decoding_Error("HSS private key is exhausted");
   }
   set_idx(m_current_idx + 1);
   return next_idx;
}

size_t HSS_LMS_PrivateKeyInternal::size() const {
   size_t sk_size = sizeof(HSS_Level) + sizeof(HSS_Sig_Idx);
   // The concatenated algorithm types for all layers
   sk_size += hss_params().L().get() * (sizeof(LMS_Algorithm_Type) + sizeof(LMOTS_Algorithm_Type));
   sk_size += m_hss_seed.size() + m_identifier.size();
   return sk_size;
}

HSS_LMS_PrivateKeyInternal::HSS_LMS_PrivateKeyInternal(HSS_LMS_Params hss_params,
                                                       LMS_Seed hss_seed,
                                                       LMS_Identifier identifier) :
      m_hss_params(std::move(hss_params)),
      m_hss_seed(std::move(hss_seed)),
      m_identifier(std::move(identifier)),
      m_current_idx(0),
      m_sig_size(HSS_Signature::size(m_hss_params)) {
   BOTAN_ARG_CHECK(m_hss_seed.size() == m_hss_params.params_at_level(HSS_Level(0)).lms_params().m(),
                   "Invalid seed size");
   BOTAN_ARG_CHECK(m_identifier.size() == LMS_IDENTIFIER_LEN, "Invalid identifier size");
}

secure_vector<uint8_t> HSS_LMS_PrivateKeyInternal::sign(std::span<const uint8_t> msg) {
   secure_vector<uint8_t> sig(HSS_Signature::size(hss_params()));
   BufferStuffer sig_stuffer(sig);
   sig_stuffer.append(store_be(hss_params().L() - 1));

   std::vector<LMS_Tree_Node_Idx> q = derive_lms_leaf_indices_from_hss_index(reserve_next_idx(), hss_params());

   // Derive LMS private keys and compute buffers
   std::vector<LMS_PrivateKey> lms_key_at_layer;
   std::vector<StrongSpan<LMS_Signature_Bytes>> out_lms_sig_buffer_at_layer;
   std::vector<std::span<uint8_t>> out_child_pk_buffer_at_layer;
   for(HSS_Level layer(0); layer < hss_params().L(); ++layer) {
      // Generate key for current layer
      const HSS_LMS_Params::LMS_LMOTS_Params_Pair& layer_params = hss_params().params_at_level(layer);
      if(layer == HSS_Level(0)) {
         lms_key_at_layer.push_back(hss_derive_root_lms_private_key());
      } else {
         lms_key_at_layer.push_back(
            hss_derive_child_lms_private_key(layer_params, lms_key_at_layer.back(), q.at(layer.get() - 1)));
         out_child_pk_buffer_at_layer.push_back(sig_stuffer.next(LMS_PublicKey::size(layer_params.lms_params())));
      }
      out_lms_sig_buffer_at_layer.push_back(sig_stuffer.next<LMS_Signature_Bytes>(
         LMS_Signature::size(layer_params.lms_params(), layer_params.lmots_params())));
   }
   BOTAN_ASSERT_NOMSG(sig_stuffer.full());

   // Sign and write the signature from bottom layer to root layer
   std::vector<uint8_t> current_pk;
   for(int32_t layer_it = hss_params().L().get() - 1; layer_it >= 0; --layer_it) {
      HSS_Level layer(layer_it);
      if(layer == hss_params().L() - 1) {
         current_pk =
            lms_key_at_layer.at(layer.get())
               .sign_and_get_pk(out_lms_sig_buffer_at_layer.at(layer.get()), q.at(layer.get()), LMS_Message(msg))
               .to_bytes();
      } else {
         copy_mem(out_child_pk_buffer_at_layer.at(layer.get()), current_pk);
         current_pk =
            lms_key_at_layer.at(layer.get())
               .sign_and_get_pk(out_lms_sig_buffer_at_layer.at(layer.get()), q.at(layer.get()), LMS_Message(current_pk))
               .to_bytes();
      }
   }

   return sig;
}

LMS_PrivateKey HSS_LMS_PrivateKeyInternal::hss_derive_root_lms_private_key() const {
   auto& top_params = hss_params().params_at_level(HSS_Level(0));
   return LMS_PrivateKey(top_params.lms_params(), top_params.lmots_params(), m_identifier, m_hss_seed);
}

LMS_PrivateKey HSS_LMS_PrivateKeyInternal::hss_derive_child_lms_private_key(
   const HSS_LMS_Params::LMS_LMOTS_Params_Pair& child_lms_lmots_params,
   const LMS_PrivateKey& parent_sk,
   LMS_Tree_Node_Idx parent_q) {
   const auto hash = HashFunction::create_or_throw(child_lms_lmots_params.lms_params().hash_name());

   // CHILD_SEED = H( PARENT_I || PARENT_Q || SEED_CHILD_SEED || 0xff || PARENT_SEED )
   PseudorandomKeyGeneration seed_generator(parent_sk.identifier());
   seed_generator.set_q(parent_q.get());
   seed_generator.set_i(SEED_CHILD_SEED);
   seed_generator.set_j(0xff);
   auto child_seed = seed_generator.gen<LMS_Seed>(*hash, parent_sk.seed());

   // CHILD_I = H( PARENT_I || PARENT_Q || SEED_CHILD_I || 0xff || PARENT_SEED )
   seed_generator.set_i(SEED_CHILD_I);
   auto child_identifier = seed_generator.gen<LMS_Identifier>(*hash, parent_sk.seed());
   child_identifier.resize(LMS_IDENTIFIER_LEN);

   return LMS_PrivateKey(child_lms_lmots_params.lms_params(),
                         child_lms_lmots_params.lmots_params(),
                         std::move(child_identifier),
                         std::move(child_seed));
}

HSS_LMS_PublicKeyInternal HSS_LMS_PublicKeyInternal::create(const HSS_LMS_PrivateKeyInternal& hss_sk) {
   auto& hss_params = hss_sk.hss_params();

   const auto root_sk = hss_sk.hss_derive_root_lms_private_key();
   LMS_PublicKey top_pub_key = LMS_PublicKey(root_sk);

   return HSS_LMS_PublicKeyInternal(hss_params.L(), std::move(top_pub_key));
}

std::shared_ptr<HSS_LMS_PublicKeyInternal> HSS_LMS_PublicKeyInternal::from_bytes_or_throw(
   std::span<const uint8_t> key_bytes) {
   if(key_bytes.size() < sizeof(HSS_Level)) {
      throw Decoding_Error("Too few public key bytes.");
   }
   BufferSlicer slicer(key_bytes);

   const auto L = load_be<HSS_Level>(slicer.take<sizeof(HSS_Level)>());
   if(L > HSS_MAX_LEVELS) {
      throw Decoding_Error("Invalid number of HSS layers in public HSS-LMS key.");
   }

   LMS_PublicKey lms_pub_key = LMS_PublicKey::from_bytes_or_throw(slicer);

   if(!slicer.empty()) {
      throw Decoding_Error("Public HSS-LMS key contains more bytes than expected.");
   }
   return std::make_shared<HSS_LMS_PublicKeyInternal>(L, std::move(lms_pub_key));
}

std::vector<uint8_t> HSS_LMS_PublicKeyInternal::to_bytes() const {
   return concat<std::vector<uint8_t>>(store_be(m_L), m_top_lms_pub_key.to_bytes());
}

AlgorithmIdentifier HSS_LMS_PublicKeyInternal::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID HSS_LMS_PublicKeyInternal::object_identifier() const {
   return OID::from_string(algo_name());
}

size_t HSS_LMS_PublicKeyInternal::size() const {
   return sizeof(m_L) + LMS_PublicKey::size(m_top_lms_pub_key.lms_params());
}

bool HSS_LMS_PublicKeyInternal::verify_signature(std::span<const uint8_t> msg, const HSS_Signature& sig) const {
   if(checked_cast_to<HSS_Level>(sig.Nspk()) + 1 != m_L) {
      // HSS levels in the public key does not match with the signature's
      return false;
   }

   const LMS_PublicKey* lms_pk = &lms_pub_key();
   const auto hash_name = lms_pk->lms_params().hash_name();

   // Verify the signature by the above layer over the LMS public keys for layer 1 to Nspk.
   for(HSS_Level layer(0); layer < sig.Nspk(); ++layer) {
      const HSS_Signature::Signed_Pub_Key& signed_pub_key = sig.signed_pub_key(layer);
      if(signed_pub_key.public_key().lms_params().hash_name() != hash_name ||
         signed_pub_key.public_key().lmots_params().hash_name() != hash_name) {
         // We do not allow HSS-LMS instances with multiple different hash functions.
         return false;
      }
      if(!lms_pk->verify_signature(LMS_Message(signed_pub_key.public_key().to_bytes()), signed_pub_key.signature())) {
         return false;
      }
      lms_pk = &signed_pub_key.public_key();
   }

   // Verify the signature by the bottom layer over the message.
   return lms_pk->verify_signature(LMS_Message(msg), sig.bottom_sig());
}

HSS_Signature::Signed_Pub_Key::Signed_Pub_Key(LMS_Signature sig, LMS_PublicKey pub) :
      m_sig(std::move(sig)), m_pub(std::move(pub)) {}

HSS_Signature HSS_Signature::from_bytes_or_throw(std::span<const uint8_t> sig_bytes) {
   if(sig_bytes.size() < sizeof(uint32_t)) {
      throw Decoding_Error("Too few HSS signature bytes.");
   }
   BufferSlicer slicer(sig_bytes);

   const auto Nspk = load_be(slicer.take<sizeof(uint32_t)>());
   if(Nspk >= HSS_MAX_LEVELS) {
      throw Decoding_Error("Invalid number of HSS layers in signature.");
   }

   std::vector<Signed_Pub_Key> signed_pub_keys;
   for(size_t i = 0; i < Nspk; ++i) {
      LMS_Signature sig = LMS_Signature::from_bytes_or_throw(slicer);
      LMS_PublicKey pub_key = LMS_PublicKey::from_bytes_or_throw(slicer);
      signed_pub_keys.push_back(Signed_Pub_Key(std::move(sig), std::move(pub_key)));
   }

   auto sig = LMS_Signature::from_bytes_or_throw(slicer);

   if(!slicer.empty()) {
      throw Decoding_Error("HSS-LMS signature contains more bytes than expected.");
   }
   return HSS_Signature(std::move(signed_pub_keys), std::move(sig));
}

size_t HSS_Signature::size(const HSS_LMS_Params& params) {
   size_t size = sizeof(uint32_t);
   size += LMS_Signature::size(params.params_at_level(HSS_Level(0)).lms_params(),
                               params.params_at_level(HSS_Level(0)).lmots_params());
   for(HSS_Level layer(1); layer < params.L(); ++layer) {
      const auto& param = params.params_at_level(layer);
      size += LMS_PublicKey::size(param.lms_params());
      size += LMS_Signature::size(param.lms_params(), param.lmots_params());
   }
   return size;
}

}  // namespace Botan

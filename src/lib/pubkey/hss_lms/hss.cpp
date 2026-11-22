/**
 * HSS - Hierarchical Signatures System (RFC 8554)
 * (C) 2023,2026 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/hss.h>

#include <botan/rng.h>
#include <botan/internal/algorithm_spec.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hss_lms_utils.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stateful_key_index_registry.h>
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
 * Private key section holding the cached public data of one LMS tree
 */
constexpr uint32_t HSS_SECTION_LMS_TREE = 1;

/**
 * Size of an encoded HSS_SECTION_LMS_TREE body for the tree at @p level
 */
size_t encoded_tree_size(const HSS_LMS_Params& params, HSS_Level level) {
   const auto& level_params = params.params_at_level(level);
   size_t size = sizeof(uint32_t) + sizeof(uint64_t) + LMS_Treetop::row_size(level_params.lms_params());
   if(level > 0U) {
      const auto& parent_params = params.params_at_level(level - 1);
      size += LMS_Signature::size(parent_params.lms_params(), parent_params.lmots_params());
      size += LMS_PublicKey::size(level_params.lms_params());
   }
   return size;
}

/**
 * Encode the HSS-LMS parameter set, for use as the algorithm parameters
 * in the key's Stateful_Key_Index_Registry identity.
 */
std::vector<uint8_t> hss_param_encoding(const HSS_LMS_Params& params) {
   std::vector<uint8_t> enc;
   enc.reserve(sizeof(uint32_t) * (1 + 2 * params.L().get()));

   const auto append = [&](std::span<const uint8_t> bytes) { enc.insert(enc.end(), bytes.begin(), bytes.end()); };

   append(store_be(params.L()));
   for(HSS_Level layer(0); layer < params.L(); ++layer) {
      const auto& layer_params = params.params_at_level(layer);
      append(store_be(layer_params.lms_params().algorithm_type()));
      append(store_be(layer_params.lmots_params().algorithm_type()));
   }

   return enc;
}

}  // namespace

HSS_LMS_Params::HSS_LMS_Params(std::vector<LMS_LMOTS_Params_Pair> lm_lmots_params) :
      m_lms_lmots_params(std::move(lm_lmots_params)), m_max_sig_count(calc_max_sig_count()) {
   BOTAN_ARG_CHECK(!m_lms_lmots_params.empty() && m_lms_lmots_params.size() <= HSS_MAX_LEVELS,
                   "Invalid number of levels");

   const auto& hash_name = m_lms_lmots_params.front().lms_params().hash_name();
   for(const auto& param : m_lms_lmots_params) {
      BOTAN_ARG_CHECK(param.lms_params().hash_name() == hash_name && param.lmots_params().hash_name() == hash_name,
                      "Inconsistent hash functions are not allowed");
   }
}

HSS_LMS_Params::HSS_LMS_Params(std::string_view algo_params) : m_max_sig_count(0) {
   const auto wrap_in_hss_lms = [&]() {
      if(algo_params.starts_with("HSS-LMS(")) {
         return std::string(algo_params);
      } else {
         return fmt("HSS-LMS({})", algo_params);
      }
   }();
   const AlgorithmSpec spec(wrap_in_hss_lms);

   const auto m = spec.match("HSS-LMS({hash},{layer}...)");
   BOTAN_ARG_CHECK(m.has_value(), "Invalid HSS-LMS parameters");
   const auto layers = m->rest("layer");
   BOTAN_ARG_CHECK(layers.size() <= HSS_MAX_LEVELS, "Invalid number of layer arguments");
   const std::string hash(m->str("hash"));
   BOTAN_ARG_CHECK(is_supported_hash_function(hash), "Supported HSS-LMS hash function");

   for(const auto& layer : layers) {
      const auto lm = layer.match("HW({h:int},{w:int})");
      BOTAN_ARG_CHECK(lm.has_value(), "Invalid layer parameters");
      const auto h = checked_cast_to_or_throw<uint8_t, Invalid_Argument>(lm->integer("h"), "Invalid tree height");
      const auto w =
         checked_cast_to_or_throw<uint8_t, Invalid_Argument>(lm->integer("w"), "Invalid Winternitz parameter");
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
      m_hss_params(hss_params),
      m_hss_seed(rng.random_vec<LMS_Seed>(m_hss_params.params_at_level(HSS_Level(0)).lms_params().m())),
      m_identifier(rng.random_vec<LMS_Identifier>(LMS_IDENTIFIER_LEN)),
      m_keyid(
         "HSS-LMS", hss_param_encoding(m_hss_params), m_hss_params.max_sig_count().get(), m_hss_seed, m_identifier),
      m_sig_size(HSS_Signature::size(m_hss_params)),
      m_trees(m_hss_params.L().get()),
      m_subtrees(m_hss_params.L().get()) {}

HSS_LMS_PrivateKeyInternal::HSS_LMS_PrivateKeyInternal(HSS_LMS_Params hss_params,
                                                       LMS_Seed hss_seed,
                                                       LMS_Identifier identifier) :
      m_hss_params(std::move(hss_params)),
      m_hss_seed(std::move(hss_seed)),
      m_identifier(std::move(identifier)),
      m_keyid(
         "HSS-LMS", hss_param_encoding(m_hss_params), m_hss_params.max_sig_count().get(), m_hss_seed, m_identifier),
      m_sig_size(HSS_Signature::size(m_hss_params)),
      m_trees(m_hss_params.L().get()),
      m_subtrees(m_hss_params.L().get()) {
   BOTAN_ARG_CHECK(m_hss_seed.size() == m_hss_params.params_at_level(HSS_Level(0)).lms_params().m(),
                   "Invalid HSS-LMS seed size");
   BOTAN_ARG_CHECK(m_identifier.size() == LMS_IDENTIFIER_LEN, "Invalid HSS-LMS identifier size");
}

std::shared_ptr<HSS_LMS_PrivateKeyInternal> HSS_LMS_PrivateKeyInternal::from_bytes_or_throw(
   std::span<const uint8_t> key_bytes, HSS_LMS_PrivateKey_Format format) {
   BufferSlicer slicer(key_bytes);

   if(slicer.remaining() < sizeof(HSS_Level) + sizeof(HSS_Sig_Idx)) {
      throw Decoding_Error("Too few private key bytes.");
   }

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
   const auto& hash_name = params.at(0).lms_params().hash_name();

   for(const auto& param : params) {
      const bool invalid_lmots_hash = param.lmots_params().hash_name() != hash_name;
      const bool invalid_lms_hash = param.lms_params().hash_name() != hash_name;
      if(invalid_lmots_hash || invalid_lms_hash) {
         throw Decoding_Error("Inconsistent hash functions are not allowed.");
      }
   }

   if(slicer.remaining() < params.at(0).lms_params().m() + LMS_IDENTIFIER_LEN) {
      throw Decoding_Error("Out of bytes while parsing private HSS-LMS key.");
   }
   const size_t m = params.at(0).lms_params().m();
   auto hss_seed = slicer.copy<LMS_Seed>(m);
   auto identifier = slicer.copy<LMS_Identifier>(LMS_IDENTIFIER_LEN);

   HSS_LMS_Params hss_params(std::move(params));

   // The legacy format consists of exactly the fields parsed so far
   // TODO(Botan4) Remove the legacy format
   const bool legacy =
      (format == HSS_LMS_PrivateKey_Format::Legacy) || (format == HSS_LMS_PrivateKey_Format::Either && slicer.empty());

   std::optional<LMS_Tree_Node> root;
   std::vector<Encoded_Tree> encoded_trees;

   if(!legacy) {
      const auto take = [](BufferSlicer& s, size_t count) {
         if(s.remaining() < count) {
            throw Decoding_Error("Out of bytes while parsing private HSS-LMS key.");
         }
         return s.take(count);
      };
      const auto take_u32 = [&](BufferSlicer& s) {
         return load_be<uint32_t>(take(s, sizeof(uint32_t)).first<sizeof(uint32_t)>());
      };
      const auto take_u64 = [&](BufferSlicer& s) {
         return load_be<uint64_t>(take(s, sizeof(uint64_t)).first<sizeof(uint64_t)>());
      };

      root = LMS_Tree_Node(take(slicer, m));

      const auto section_count = take_u32(slicer);
      for(uint32_t i = 0; i != section_count; ++i) {
         const auto tag = take_u32(slicer);
         const auto length = take_u32(slicer);
         BufferSlicer body(take(slicer, length));

         // Sections with unknown tags are skipped, to allow adding new ones later
         if(tag != HSS_SECTION_LMS_TREE) {
            continue;
         }

         const HSS_Level level(take_u32(body));
         if(level >= hss_params.L()) {
            throw Decoding_Error("Invalid level of cached LMS tree in private HSS-LMS key.");
         }
         if(!encoded_trees.empty() && level <= encoded_trees.back().level) {
            throw Decoding_Error("Cached LMS trees in private HSS-LMS key are out of order.");
         }
         if(length != encoded_tree_size(hss_params, level)) {
            throw Decoding_Error("Invalid size of cached LMS tree in private HSS-LMS key.");
         }

         const auto tree_number = take_u64(body);
         const auto row = body.take(LMS_Treetop::row_size(hss_params.params_at_level(level).lms_params()));
         const auto signed_pub_key = body.take(body.remaining());
         encoded_trees.push_back(Encoded_Tree{level, tree_number, row, signed_pub_key});
      }
   }

   if(!slicer.empty()) {
      throw Decoding_Error("Private HSS-LMS key contains more bytes than expected.");
   }
   auto sk = std::shared_ptr<HSS_LMS_PrivateKeyInternal>(
      new HSS_LMS_PrivateKeyInternal(std::move(hss_params), std::move(hss_seed), std::move(identifier)));

   sk->set_idx(sig_idx);

   if(root.has_value()) {
      sk->m_root = std::move(root);
      sk->adopt_encoded_trees(sig_idx, encoded_trees);
   }

   return sk;
}

void HSS_LMS_PrivateKeyInternal::adopt_encoded_trees(HSS_Sig_Idx idx, const std::vector<Encoded_Tree>& encoded) {
   if(idx >= hss_params().max_sig_count()) {
      return;
   }
   const auto pos = tree_position(idx);

   // Each tree is only kept if it is the one used for the next signature, and
   // the trees above it were kept, which allows checking it against its parent.
   std::optional<LMS_PublicKey> parent_pub = top_lms_public_key_locked();
   size_t accepted = 0;

   try {
      for(const auto& tree : encoded) {
         const auto level = tree.level;
         if(level.get() != accepted || tree.tree_number != pos.tree_number.at(level.get())) {
            return;
         }
         ++accepted;

         const auto& params = hss_params().params_at_level(level);

         if(level == 0U) {
            auto treetop = LMS_Treetop::from_row(params.lms_params(), m_identifier, tree.row);
            if(!std::ranges::equal(treetop.root(), m_root.value())) {
               return;
            }
            m_trees.at(0) = std::make_shared<const HSS_Cached_Tree>(0, std::move(treetop), std::vector<uint8_t>());
            continue;
         }

         BufferSlicer slicer(tree.signed_pub_key);
         const auto sig = LMS_Signature::from_bytes_or_throw(slicer);
         auto pub = LMS_PublicKey::from_bytes_or_throw(slicer);
         const auto pub_bytes = pub.to_bytes();

         if(!slicer.empty() || pub.lms_params().algorithm_type() != params.lms_params().algorithm_type() ||
            pub.lmots_params().algorithm_type() != params.lmots_params().algorithm_type() ||
            sig.q() != pos.q.at(level.get() - 1) || !parent_pub->verify_signature(LMS_Message(pub_bytes), sig)) {
            return;
         }

         auto treetop = LMS_Treetop::from_row(params.lms_params(), pub.identifier(), tree.row);
         const LMS_PublicKey treetop_pub(
            params.lms_params(), params.lmots_params(), pub.identifier(), LMS_Tree_Node(treetop.root()));
         if(treetop_pub.to_bytes() != pub_bytes) {
            return;
         }

         m_trees.at(level.get()) = std::make_shared<const HSS_Cached_Tree>(
            tree.tree_number,
            std::move(treetop),
            std::vector<uint8_t>(tree.signed_pub_key.begin(), tree.signed_pub_key.end()));
         parent_pub = std::move(pub);
      }
   } catch(const Decoding_Error&) {
      // An unparsable signature or public key; keep the trees accepted so far
   }
}

secure_vector<uint8_t> HSS_LMS_PrivateKeyInternal::to_bytes() const {
   const lock_guard_type<mutex_type> lock(m_cache_mutex);

   const uint64_t current_index = Stateful_Key_Index_Registry::global().current_index(m_keyid);
   const auto& root = root_locked();

   // Only the trees used by the next signature are worth saving
   std::vector<std::shared_ptr<const HSS_Cached_Tree>> trees;
   if(current_index < hss_params().max_sig_count().get()) {
      const auto pos = tree_position(HSS_Sig_Idx(current_index));
      for(size_t level = 0; level != m_trees.size(); ++level) {
         const auto& tree = m_trees[level];
         if(tree == nullptr || tree->tree_number() != pos.tree_number[level]) {
            break;
         }
         trees.push_back(tree);
      }
   }

   secure_vector<uint8_t> sk_bytes;
   const auto append = [&](const auto& bytes) { sk_bytes.insert(sk_bytes.end(), bytes.begin(), bytes.end()); };

   append(store_be(hss_params().L()));
   append(store_be(current_index));

   for(HSS_Level layer(1); layer <= hss_params().L(); ++layer) {
      const auto& params = hss_params().params_at_level(layer - 1);
      append(store_be(params.lms_params().algorithm_type()));
      append(store_be(params.lmots_params().algorithm_type()));
   }
   append(m_hss_seed);
   append(m_identifier);
   append(root);

   append(store_be(checked_cast_to<uint32_t>(trees.size())));
   for(uint32_t level = 0; level != trees.size(); ++level) {
      const auto& tree = *trees[level];
      append(store_be(HSS_SECTION_LMS_TREE));
      append(store_be(checked_cast_to<uint32_t>(encoded_tree_size(hss_params(), HSS_Level(level)))));
      append(store_be(level));
      append(store_be(tree.tree_number()));
      append(tree.treetop().row());
      append(tree.signed_pub_key());
   }

   return sk_bytes;
}

HSS_Sig_Idx HSS_LMS_PrivateKeyInternal::remaining_operations() const {
   return HSS_Sig_Idx(Stateful_Key_Index_Registry::global().remaining_operations(m_keyid));
}

void HSS_LMS_PrivateKeyInternal::set_idx(HSS_Sig_Idx idx) const {
   // An index equal to max_sig_count is valid and denotes an exhausted key
   if(idx > m_hss_params.max_sig_count()) {
      throw Decoding_Error("HSS-LMS private key index out of bounds");
   }
   Stateful_Key_Index_Registry::global().set_index_lower_bound(m_keyid, idx.get());
}

HSS_Sig_Idx HSS_LMS_PrivateKeyInternal::reserve_next_idx() const {
   const auto idx = Stateful_Key_Index_Registry::global().reserve_next_index(m_keyid);
   if(!idx.has_value()) {
      throw Invalid_State("HSS private key is exhausted");
   }
   return HSS_Sig_Idx(idx.value());
}

HSS_LMS_PrivateKeyInternal::Tree_Position HSS_LMS_PrivateKeyInternal::tree_position(HSS_Sig_Idx idx) const {
   const size_t L = hss_params().L().get();
   Tree_Position pos{std::vector<LMS_Tree_Node_Idx>(L), std::vector<uint64_t>(L)};

   uint64_t remaining = idx.get();
   for(size_t level = L; level-- > 0;) {
      const uint32_t h = hss_params().params_at_level(HSS_Level(static_cast<uint32_t>(level))).lms_params().h();
      pos.q[level] = LMS_Tree_Node_Idx(static_cast<uint32_t>(remaining & ((uint64_t(1) << h) - 1)));
      remaining >>= h;
      pos.tree_number[level] = remaining;
   }
   BOTAN_ARG_CHECK(remaining == 0, "HSS Tree is exhausted");

   return pos;
}

std::vector<LMS_PrivateKey> HSS_LMS_PrivateKeyInternal::derive_lms_private_keys(const Tree_Position& pos) const {
   std::vector<LMS_PrivateKey> sks;
   sks.push_back(hss_derive_root_lms_private_key());
   for(HSS_Level level(1); level < hss_params().L(); ++level) {
      sks.push_back(
         hss_derive_child_lms_private_key(hss_params().params_at_level(level), sks.back(), pos.q.at(level.get() - 1)));
   }
   return sks;
}

const LMS_Subtree* HSS_LMS_PrivateKeyInternal::cached_subtree(HSS_Level level) const {
   const auto& subtree = m_subtrees.at(level.get());
   return (subtree != nullptr) ? &subtree->subtree() : nullptr;
}

bool HSS_LMS_PrivateKeyInternal::ensure_subtree(HSS_Level level,
                                                const Tree_Position& pos,
                                                const LMS_PrivateKey& sk) const {
   const uint32_t k = LMS_Treetop::subtree_height(hss_params().params_at_level(level).lms_params());
   if(k == 0) {
      // The treetop is the whole tree
      return true;
   }

   const auto& tree = m_trees.at(level.get());
   BOTAN_ASSERT_NONNULL(tree);
   const auto q = pos.q.at(level.get());

   auto& slot = m_subtrees.at(level.get());
   if(slot != nullptr && slot->tree_number() == tree->tree_number() && slot->subtree().index() == (q.get() >> k)) {
      return true;
   }

   auto subtree = sk.build_subtree(tree->treetop(), q);
   if(!subtree.has_value()) {
      return false;
   }
   slot = std::make_shared<const HSS_Cached_Subtree>(tree->tree_number(), std::move(subtree.value()));
   return true;
}

bool HSS_LMS_PrivateKeyInternal::ensure_tree(HSS_Level level,
                                             const Tree_Position& pos,
                                             const std::vector<LMS_PrivateKey>& sks) const {
   const auto tree_number = pos.tree_number.at(level.get());
   auto& slot = m_trees.at(level.get());
   if(slot != nullptr && slot->tree_number() == tree_number) {
      return true;
   }

   const auto& sk = sks.at(level.get());
   auto [treetop, subtree] = sk.build_tree(pos.q.at(level.get()));

   std::vector<uint8_t> signed_pub_key;
   if(level == 0U) {
      const LMS_Tree_Node root(treetop.root());
      if(m_root.has_value() && !std::ranges::equal(m_root.value(), root)) {
         throw Invalid_State("HSS-LMS private key does not match its public key");
      }
      m_root = root;
   } else {
      // The parent signs the public key just computed from the seed, never
      // one taken from the cache. Since LM-OTS signing is deterministic,
      // signing it again after the cache was lost reproduces the same
      // signature instead of reusing the one-time key for another message.
      const HSS_Level parent(level - 1);
      if(!ensure_subtree(parent, pos, sks.at(parent.get()))) {
         return false;
      }

      const auto& params = hss_params().params_at_level(level);
      const auto& parent_params = hss_params().params_at_level(parent);
      const auto pub_bytes =
         LMS_PublicKey(params.lms_params(), params.lmots_params(), sk.identifier(), LMS_Tree_Node(treetop.root()))
            .to_bytes();

      LMS_Signature_Bytes parent_sig(LMS_Signature::size(parent_params.lms_params(), parent_params.lmots_params()));
      sks.at(parent.get())
         .sign_with_nodes(parent_sig,
                          pos.q.at(parent.get()),
                          LMS_Message(pub_bytes),
                          m_trees.at(parent.get())->treetop(),
                          cached_subtree(parent));
      CT::unpoison(parent_sig);

      signed_pub_key = concat<std::vector<uint8_t>>(parent_sig, pub_bytes);
   }

   slot = std::make_shared<const HSS_Cached_Tree>(tree_number, std::move(treetop), std::move(signed_pub_key));
   m_subtrees.at(level.get()) = std::make_shared<const HSS_Cached_Subtree>(tree_number, std::move(subtree));
   return true;
}

bool HSS_LMS_PrivateKeyInternal::populate_cache(const Tree_Position& pos,
                                                const std::vector<LMS_PrivateKey>& sks) const {
   // Top down, since building a tree requires a signature by its parent
   for(HSS_Level level(0); level < hss_params().L(); ++level) {
      if(!ensure_tree(level, pos, sks)) {
         return false;
      }
   }
   const HSS_Level bottom(hss_params().L() - 1);
   return ensure_subtree(bottom, pos, sks.at(bottom.get()));
}

void HSS_LMS_PrivateKeyInternal::clear_cache_locked() const {
   std::ranges::fill(m_trees, nullptr);
   std::ranges::fill(m_subtrees, nullptr);
}

const LMS_Tree_Node& HSS_LMS_PrivateKeyInternal::root_locked() const {
   if(!m_root.has_value()) {
      // Compute the top tree, keeping the subtree used by the next signature
      const uint64_t idx = Stateful_Key_Index_Registry::global().current_index(m_keyid);
      const auto pos = tree_position(HSS_Sig_Idx(idx < hss_params().max_sig_count().get() ? idx : 0));
      const auto sks = derive_lms_private_keys(pos);
      ensure_tree(HSS_Level(0), pos, sks);
   }
   return m_root.value();
}

LMS_PublicKey HSS_LMS_PrivateKeyInternal::top_lms_public_key_locked() const {
   const auto& top_params = hss_params().params_at_level(HSS_Level(0));
   return LMS_PublicKey(top_params.lms_params(), top_params.lmots_params(), m_identifier, root_locked());
}

LMS_PublicKey HSS_LMS_PrivateKeyInternal::top_lms_public_key() const {
   const lock_guard_type<mutex_type> lock(m_cache_mutex);
   return top_lms_public_key_locked();
}

bool HSS_LMS_PrivateKeyInternal::root_matches_seed() const {
   const LMS_PublicKey computed(hss_derive_root_lms_private_key());
   return computed.to_bytes() == top_lms_public_key().to_bytes();
}

std::vector<uint8_t> HSS_LMS_PrivateKeyInternal::sign(std::span<const uint8_t> msg) const {
   const auto& params = hss_params();
   const HSS_Level bottom(params.L() - 1);
   const auto& bottom_params = params.params_at_level(bottom);

   std::vector<uint8_t> sig(HSS_Signature::size(params));
   BufferStuffer sig_stuffer(sig);
   sig_stuffer.append(store_be(bottom));  // Nspk

   std::optional<LMS_PrivateKey> bottom_sk;
   LMS_Tree_Node_Idx bottom_q(0);
   std::shared_ptr<const HSS_Cached_Tree> bottom_tree;
   std::shared_ptr<const HSS_Cached_Subtree> bottom_subtree;
   std::optional<HSS_LMS_PublicKeyInternal> public_key;

   {
      const lock_guard_type<mutex_type> lock(m_cache_mutex);

      // Reserving the index while holding the lock means the cache of this
      // object only ever moves forward, even when signing concurrently
      const auto pos = tree_position(reserve_next_idx());
      const auto sks = derive_lms_private_keys(pos);

      if(!populate_cache(pos, sks)) {
         // Some loaded data did not match the seed; start over from the seed alone
         clear_cache_locked();
         if(!populate_cache(pos, sks)) {
            throw Internal_Error("HSS-LMS tree computed from the seed is inconsistent");
         }
      }

      // sig[i-1] || pub[i] for each level below the top
      for(HSS_Level level(1); level <= bottom; ++level) {
         sig_stuffer.append(m_trees.at(level.get())->signed_pub_key());
      }

      bottom_sk = sks.at(bottom.get());
      bottom_q = pos.q.at(bottom.get());
      bottom_tree = m_trees.at(bottom.get());
      bottom_subtree = m_subtrees.at(bottom.get());
      public_key.emplace(params.L(), top_lms_public_key_locked());
   }

   const auto bottom_sig = sig_stuffer.next<LMS_Signature_Bytes>(
      LMS_Signature::size(bottom_params.lms_params(), bottom_params.lmots_params()));
   BOTAN_ASSERT_NOMSG(sig_stuffer.full());

   bottom_sk->sign_with_nodes(bottom_sig,
                              bottom_q,
                              LMS_Message(msg),
                              bottom_tree->treetop(),
                              (bottom_subtree != nullptr) ? &bottom_subtree->subtree() : nullptr);

   CT::unpoison(sig);

   const bool valid = [&] {
      try {
         return public_key->verify_signature(msg, HSS_Signature::from_bytes_or_throw(sig));
      } catch(const Decoding_Error&) {
         return false;
      }
   }();

   if(!valid) {
      // Discard the cache so the next signature is computed from the seed alone
      const lock_guard_type<mutex_type> lock(m_cache_mutex);
      clear_cache_locked();
      throw Internal_Error("HSS-LMS signature failed verification");
   }

   return sig;
}

LMS_PrivateKey HSS_LMS_PrivateKeyInternal::hss_derive_root_lms_private_key() const {
   const auto& top_params = hss_params().params_at_level(HSS_Level(0));
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
   CT::unpoison(child_identifier);  // identifiers are part of the signature

   return LMS_PrivateKey(child_lms_lmots_params.lms_params(),
                         child_lms_lmots_params.lmots_params(),
                         std::move(child_identifier),
                         std::move(child_seed));
}

HSS_LMS_PublicKeyInternal HSS_LMS_PublicKeyInternal::create(const HSS_LMS_PrivateKeyInternal& hss_sk) {
   return HSS_LMS_PublicKeyInternal(hss_sk.hss_params().L(), hss_sk.top_lms_public_key());
}

std::shared_ptr<HSS_LMS_PublicKeyInternal> HSS_LMS_PublicKeyInternal::from_bytes_or_throw(
   std::span<const uint8_t> key_bytes) {
   if(key_bytes.size() < sizeof(HSS_Level)) {
      throw Decoding_Error("Too few public key bytes.");
   }
   BufferSlicer slicer(key_bytes);

   const auto L = load_be<HSS_Level>(slicer.take<sizeof(HSS_Level)>());
   if(L == 0U || L > HSS_MAX_LEVELS) {
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

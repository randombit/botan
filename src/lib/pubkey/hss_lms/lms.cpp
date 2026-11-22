/**
 * LMS - Leighton-Micali Hash-Based Signatures (RFC 8554)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/lms.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/hash_engine.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tree_hash.h>
#include <algorithm>

namespace Botan {
namespace {

/**
 * @brief Domain-separation parameter when computing the hash of the leaf of an LMS tree.
 */
constexpr uint16_t D_LEAF = 0x8282;

/**
 * @brief Domain-separation parameter when computing the hash of an interior node of an LMS tree.
 */
constexpr uint16_t D_INTR = 0x8383;

/// Index of the layer in a tree starting with 0 for the bottom level to the root layer
using LMS_TreeLayerIndex = Strong<uint32_t, struct LMS_TreeLayerIndex_, EnableArithmeticWithPlainNumber>;

class TreeAddress final {
   public:
      explicit TreeAddress(uint32_t total_tree_height) : m_h(total_tree_height), m_r(0) {
         BOTAN_ARG_CHECK(total_tree_height > 0 && total_tree_height < 32, "Invalid tree height");
      }

      TreeAddress& set_address(LMS_TreeLayerIndex tree_layer, LMS_Tree_Node_Idx tree_index) {
         BOTAN_ARG_CHECK(tree_index.get() < (1 << m_h), "Invalid tree index");
         BOTAN_ARG_CHECK(tree_layer.get() <= m_h, "Invalid tree index");
         m_r = (1 << (m_h - tree_layer)).get() + tree_index.get();
         return *this;
      }

      uint32_t r() const { return m_r; }

      bool is_leaf() const { return m_r >= (1 << m_h); }

      LMS_Tree_Node_Idx q() const {
         BOTAN_STATE_CHECK(is_leaf());
         return LMS_Tree_Node_Idx(m_r - (1 << m_h.get()));
      }

   private:
      LMS_TreeLayerIndex m_h;
      uint32_t m_r;
};

auto get_hash_pair_func_for_identifier(const LMS_Params& lms_params, LMS_Identifier identifier) {
   return [hash = lms_params.hash(), I = std::move(identifier)](StrongSpan<LMS_Tree_Node> out,
                                                                const TreeAddress& address,
                                                                StrongSpan<const LMS_Tree_Node> left,
                                                                StrongSpan<const LMS_Tree_Node> right) {
      hash->update(I);
      hash->update(store_be(address.r()));
      hash->update(store_be(D_INTR));
      hash->update(left);
      hash->update(right);
      hash->final(out);
   };
}

void lms_gen_leaf(StrongSpan<LMS_Tree_Node> out,
                  const LMOTS_Public_Key& lmots_pk,
                  const TreeAddress& tree_address,
                  HashFunction& hash) {
   hash.update(lmots_pk.identifier());
   hash.update(store_be(tree_address.r()));
   hash.update(store_be(D_LEAF));
   hash.update(lmots_pk.K());
   hash.final(out);
}

auto lms_gen_leaves_func(const LMS_PrivateKey& lms_sk) {
   // The hash engine is created once here and reused for all leaves
   return [engine = Hash_Engine::create_or_throw(lms_sk.lmots_params().hash_name()), lms_sk](
             std::span<uint8_t> out, LMS_Tree_Node_Idx first_idx, size_t count) {
      const size_t m = lms_sk.lms_params().m();
      const auto& identifier = lms_sk.identifier();

      // The OTS public key hashes of all requested leaves
      std::vector<uint8_t> ks(count * m);
      lmots_compute_pubkeys(ks, lms_sk.lmots_params(), identifier, first_idx, count, lms_sk.seed(), *engine);

      // Leaf node hash: H(I || u32str(r) || u16str(D_LEAF) || K)
      const size_t prefix_len = identifier.size() + sizeof(uint32_t) + sizeof(uint16_t);
      std::vector<uint8_t> prefixes(count * prefix_len);
      std::vector<std::span<uint8_t>> outs(count);
      std::vector<std::span<const uint8_t>> prefix_spans(count);
      std::vector<std::span<const uint8_t>> k_spans(count);
      for(size_t i = 0; i != count; ++i) {
         const uint32_t r = (uint32_t(1) << lms_sk.lms_params().h()) + first_idx.get() + static_cast<uint32_t>(i);
         const auto prefix_span = std::span(prefixes).subspan(i * prefix_len, prefix_len);
         BufferStuffer prefix(prefix_span);
         prefix.append(identifier);
         prefix.append(store_be(r));
         prefix.append(store_be(D_LEAF));
         prefix_spans[i] = prefix_span;
         outs[i] = out.subspan(i * m, m);
         k_spans[i] = std::span(ks).subspan(i * m, m);
      }
      engine->batch_hash(outs, prefix_spans, k_spans);
   };
}

/**
 * Interior node hash: H(I || u32str(r) || u16str(D_INTR) || left || right)
 */
void lms_hash_pair(std::span<uint8_t> out,
                   HashFunction& hash,
                   const LMS_Identifier& identifier,
                   uint32_t r,
                   std::span<const uint8_t> left,
                   std::span<const uint8_t> right) {
   hash.update(identifier);
   hash.update(store_be(r));
   hash.update(store_be(D_INTR));
   hash.update(left);
   hash.update(right);
   hash.final(out);
}

/**
 * Compute every node of the subtree of height @p height whose leftmost leaf is
 * @p first_leaf, calling on_node(j, t, node) for each node, where j is the
 * height of the node and t its index within that layer of the whole tree.
 */
template <typename F>
void lms_walk_subtree(const LMS_PrivateKey& sk, uint32_t first_leaf, uint32_t height, F on_node) {
   const uint32_t h = sk.lms_params().h();
   const size_t m = sk.lms_params().m();
   BOTAN_ASSERT_NOMSG(height <= h);
   BOTAN_ASSERT_NOMSG(first_leaf % (uint32_t(1) << height) == 0 && first_leaf < (uint32_t(1) << h));

   const auto gen_leaves = lms_gen_leaves_func(sk);
   const auto hash = sk.lms_params().hash();

   const uint32_t leaf_count = uint32_t(1) << height;
   // Leaves are created in batches to enable batched hashing. Both the
   // batch size and the leaf count are powers of two, so batches are
   // always full.
   const uint32_t leaves_per_batch = std::min<uint32_t>(leaf_count, 32);
   std::vector<uint8_t> leaves(leaves_per_batch * m);
   // The left child at each height which is waiting for its right sibling
   std::vector<uint8_t> left_children(height * m);
   std::vector<uint8_t> node(m);

   // Post-order traversal, combining each right child with its left sibling
   for(uint32_t i = 0; i != leaf_count; ++i) {
      const uint32_t batch_pos = i % leaves_per_batch;
      if(batch_pos == 0) {
         gen_leaves(std::span(leaves), LMS_Tree_Node_Idx(first_leaf + i), leaves_per_batch);
      }
      copy_mem(std::span(node), std::span(leaves).subspan(batch_pos * m, m));

      uint32_t t = first_leaf + i;
      for(uint32_t j = 0; true; ++j) {
         on_node(j, t, std::span<const uint8_t>(node));
         if(j == height) {
            break;
         }
         const auto left = std::span(left_children).subspan(j * m, m);
         if(t % 2 == 0) {
            copy_mem(left, std::span<const uint8_t>(node));
            break;
         }
         t /= 2;
         lms_hash_pair(node, *hash, sk.identifier(), (uint32_t(1) << (h - j - 1)) + t, left, node);
      }
   }
}

}  // namespace

uint32_t LMS_Treetop::subtree_height(const LMS_Params& lms_params) {
   constexpr uint32_t max_row_height = 10;
   return lms_params.h() > max_row_height ? lms_params.h() - max_row_height : 0;
}

size_t LMS_Treetop::row_size(const LMS_Params& lms_params) {
   return (size_t(1) << (lms_params.h() - subtree_height(lms_params))) * lms_params.m();
}

LMS_Treetop::LMS_Treetop(uint32_t h, uint32_t k, size_t m, std::vector<uint8_t> nodes) :
      m_h(h), m_k(k), m_m(m), m_nodes(std::move(nodes)) {
   BOTAN_ASSERT_NOMSG(k <= h && m_nodes.size() == (size_t(1) << (h - k + 1)) * m);
}

LMS_Treetop LMS_Treetop::from_row(const LMS_Params& lms_params,
                                  const LMS_Identifier& identifier,
                                  std::span<const uint8_t> row) {
   BOTAN_ARG_CHECK(row.size() == row_size(lms_params), "Invalid LMS treetop row size");

   const uint32_t h = lms_params.h();
   const uint32_t k = subtree_height(lms_params);
   const size_t m = lms_params.m();
   const uint32_t row_start = uint32_t(1) << (h - k);

   std::vector<uint8_t> nodes(2 * row_start * m);
   copy_mem(std::span(nodes).subspan(row_start * m), row);

   const auto hash = lms_params.hash();
   for(uint32_t r = row_start - 1; r != 0; --r) {
      lms_hash_pair(std::span(nodes).subspan(r * m, m),
                    *hash,
                    identifier,
                    r,
                    std::span(nodes).subspan(2 * r * m, m),
                    std::span(nodes).subspan((2 * r + 1) * m, m));
   }

   return LMS_Treetop(h, k, m, std::move(nodes));
}

std::span<const uint8_t> LMS_Treetop::row() const {
   return std::span(m_nodes).subspan((size_t(1) << (m_h - m_k)) * m_m);
}

std::span<const uint8_t> LMS_Treetop::node(uint32_t r) const {
   BOTAN_ASSERT_NOMSG(r >= 1 && r < (uint32_t(1) << (m_h - m_k + 1)));
   return std::span(m_nodes).subspan(r * m_m, m_m);
}

std::span<const uint8_t> LMS_Subtree::node(uint32_t local_r) const {
   BOTAN_ASSERT_NOMSG(local_r >= 1 && (local_r + 1) * m_m <= m_nodes.size());
   return std::span(m_nodes).subspan(local_r * m_m, m_m);
}

std::unique_ptr<HashFunction> LMS_Params::hash() const {
   return HashFunction::create_or_throw(hash_name());
}

LMS_Params LMS_Params::create_or_throw(LMS_Algorithm_Type type) {
   auto [hash_name, height] = [](const LMS_Algorithm_Type& lms_type) -> std::pair<std::string_view, uint8_t> {
      switch(lms_type) {
         case LMS_Algorithm_Type::SHA256_M32_H5:
            return {"SHA-256", static_cast<uint8_t>(5)};
         case LMS_Algorithm_Type::SHA256_M32_H10:
            return {"SHA-256", static_cast<uint8_t>(10)};
         case LMS_Algorithm_Type::SHA256_M32_H15:
            return {"SHA-256", static_cast<uint8_t>(15)};
         case LMS_Algorithm_Type::SHA256_M32_H20:
            return {"SHA-256", static_cast<uint8_t>(20)};
         case LMS_Algorithm_Type::SHA256_M32_H25:
            return {"SHA-256", static_cast<uint8_t>(25)};
         case LMS_Algorithm_Type::SHA256_M24_H5:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(5)};
         case LMS_Algorithm_Type::SHA256_M24_H10:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(10)};
         case LMS_Algorithm_Type::SHA256_M24_H15:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(15)};
         case LMS_Algorithm_Type::SHA256_M24_H20:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(20)};
         case LMS_Algorithm_Type::SHA256_M24_H25:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(25)};
         case LMS_Algorithm_Type::SHAKE_M32_H5:
            return {"SHAKE-256(256)", static_cast<uint8_t>(5)};
         case LMS_Algorithm_Type::SHAKE_M32_H10:
            return {"SHAKE-256(256)", static_cast<uint8_t>(10)};
         case LMS_Algorithm_Type::SHAKE_M32_H15:
            return {"SHAKE-256(256)", static_cast<uint8_t>(15)};
         case LMS_Algorithm_Type::SHAKE_M32_H20:
            return {"SHAKE-256(256)", static_cast<uint8_t>(20)};
         case LMS_Algorithm_Type::SHAKE_M32_H25:
            return {"SHAKE-256(256)", static_cast<uint8_t>(25)};
         case LMS_Algorithm_Type::SHAKE_M24_H5:
            return {"SHAKE-256(192)", static_cast<uint8_t>(5)};
         case LMS_Algorithm_Type::SHAKE_M24_H10:
            return {"SHAKE-256(192)", static_cast<uint8_t>(10)};
         case LMS_Algorithm_Type::SHAKE_M24_H15:
            return {"SHAKE-256(192)", static_cast<uint8_t>(15)};
         case LMS_Algorithm_Type::SHAKE_M24_H20:
            return {"SHAKE-256(192)", static_cast<uint8_t>(20)};
         case LMS_Algorithm_Type::SHAKE_M24_H25:
            return {"SHAKE-256(192)", static_cast<uint8_t>(25)};
         default:
            throw Decoding_Error("Unsupported LMS algorithm type");
      }
   }(type);

   return LMS_Params(type, hash_name, height);
}

LMS_Params LMS_Params::create_or_throw(std::string_view hash_name, uint8_t height) {
   const LMS_Algorithm_Type type = [](std::string_view hash, uint8_t h) -> LMS_Algorithm_Type {
      if(hash == "SHA-256") {
         switch(h) {
            case 5:
               return LMS_Algorithm_Type::SHA256_M32_H5;
            case 10:
               return LMS_Algorithm_Type::SHA256_M32_H10;
            case 15:
               return LMS_Algorithm_Type::SHA256_M32_H15;
            case 20:
               return LMS_Algorithm_Type::SHA256_M32_H20;
            case 25:
               return LMS_Algorithm_Type::SHA256_M32_H25;
            default:
               throw Decoding_Error("Unsupported height for hash function");
         }
      }
      if(hash == "Truncated(SHA-256,192)") {
         switch(h) {
            case 5:
               return LMS_Algorithm_Type::SHA256_M24_H5;
            case 10:
               return LMS_Algorithm_Type::SHA256_M24_H10;
            case 15:
               return LMS_Algorithm_Type::SHA256_M24_H15;
            case 20:
               return LMS_Algorithm_Type::SHA256_M24_H20;
            case 25:
               return LMS_Algorithm_Type::SHA256_M24_H25;
            default:
               throw Decoding_Error("Unsupported height for hash function");
         }
      }
      if(hash == "SHAKE-256(256)") {
         switch(h) {
            case 5:
               return LMS_Algorithm_Type::SHAKE_M32_H5;
            case 10:
               return LMS_Algorithm_Type::SHAKE_M32_H10;
            case 15:
               return LMS_Algorithm_Type::SHAKE_M32_H15;
            case 20:
               return LMS_Algorithm_Type::SHAKE_M32_H20;
            case 25:
               return LMS_Algorithm_Type::SHAKE_M32_H25;
            default:
               throw Decoding_Error("Unsupported height for hash function");
         }
      }
      if(hash == "SHAKE-256(192)") {
         switch(h) {
            case 5:
               return LMS_Algorithm_Type::SHAKE_M24_H5;
            case 10:
               return LMS_Algorithm_Type::SHAKE_M24_H10;
            case 15:
               return LMS_Algorithm_Type::SHAKE_M24_H15;
            case 20:
               return LMS_Algorithm_Type::SHAKE_M24_H20;
            case 25:
               return LMS_Algorithm_Type::SHAKE_M24_H25;
            default:
               throw Decoding_Error("Unsupported height for hash function");
         }
      }
      throw Decoding_Error("Unsupported hash function");
   }(hash_name, height);

   return LMS_Params(type, hash_name, height);
}

LMS_Params::LMS_Params(LMS_Algorithm_Type algorithm_type, std::string_view hash_name, uint8_t h) :
      m_algorithm_type(algorithm_type), m_h(h), m_hash_name(hash_name) {
   const auto hash = HashFunction::create_or_throw(m_hash_name);
   m_m = hash->output_length();
}

LMS_PublicKey LMS_PrivateKey::sign_and_get_pk(StrongSpan<LMS_Signature_Bytes> out_sig,
                                              LMS_Tree_Node_Idx q,
                                              const LMS_Message& msg) const {
   const auto [treetop, subtree] = build_tree(q);
   sign_with_nodes(out_sig, q, msg, treetop, &subtree);
   const auto root = treetop.root();
   return LMS_PublicKey(lms_params(), lmots_params(), identifier(), LMS_Tree_Node(root.begin(), root.end()));
}

std::pair<LMS_Treetop, LMS_Subtree> LMS_PrivateKey::build_tree(LMS_Tree_Node_Idx q) const {
   const uint32_t h = lms_params().h();
   const uint32_t k = LMS_Treetop::subtree_height(lms_params());
   const size_t m = lms_params().m();
   BOTAN_ARG_CHECK(q.get() < (uint32_t(1) << h), "Invalid LMS leaf index");
   const uint32_t s = q.get() >> k;

   std::vector<uint8_t> top((size_t(1) << (h - k + 1)) * m);
   std::vector<uint8_t> sub((size_t(1) << (k + 1)) * m);

   lms_walk_subtree(*this, 0, h, [&](uint32_t j, uint32_t t, std::span<const uint8_t> node) {
      if(j >= k) {
         const uint32_t r = (uint32_t(1) << (h - j)) + t;
         copy_mem(std::span(top).subspan(r * m, m), node);
      }
      if(j <= k && (t >> (k - j)) == s) {
         const uint32_t layer_mask = (uint32_t(1) << (k - j)) - 1;
         const uint32_t local_r = (uint32_t(1) << (k - j)) + (t & layer_mask);
         copy_mem(std::span(sub).subspan(local_r * m, m), node);
      }
   });

   // The nodes are public, being part of signatures or the public key
   CT::unpoison(top);
   CT::unpoison(sub);

   return {LMS_Treetop(h, k, m, std::move(top)), LMS_Subtree(s, m, std::move(sub))};
}

std::optional<LMS_Subtree> LMS_PrivateKey::build_subtree(const LMS_Treetop& treetop, LMS_Tree_Node_Idx q) const {
   const uint32_t h = lms_params().h();
   const uint32_t k = LMS_Treetop::subtree_height(lms_params());
   const size_t m = lms_params().m();
   BOTAN_ARG_CHECK(treetop.h() == h && treetop.k() == k && treetop.m() == m, "Treetop does not belong to this tree");
   BOTAN_ARG_CHECK(q.get() < (uint32_t(1) << h), "Invalid LMS leaf index");
   const uint32_t s = q.get() >> k;

   std::vector<uint8_t> sub((size_t(1) << (k + 1)) * m);

   lms_walk_subtree(*this, s << k, k, [&](uint32_t j, uint32_t t, std::span<const uint8_t> node) {
      const uint32_t layer_mask = (uint32_t(1) << (k - j)) - 1;
      const uint32_t local_r = (uint32_t(1) << (k - j)) + (t & layer_mask);
      copy_mem(std::span(sub).subspan(local_r * m, m), node);
   });

   CT::unpoison(sub);

   LMS_Subtree subtree(s, m, std::move(sub));
   const auto expected_root = treetop.node((uint32_t(1) << (h - k)) + s);
   if(!std::ranges::equal(subtree.node(1), expected_root)) {
      return std::nullopt;
   }
   return subtree;
}

void LMS_PrivateKey::sign_with_nodes(StrongSpan<LMS_Signature_Bytes> out_sig,
                                     LMS_Tree_Node_Idx q,
                                     const LMS_Message& msg,
                                     const LMS_Treetop& treetop,
                                     const LMS_Subtree* subtree) const {
   const uint32_t h = lms_params().h();
   const uint32_t k = LMS_Treetop::subtree_height(lms_params());
   BOTAN_ARG_CHECK(out_sig.size() == LMS_Signature::size(lms_params(), lmots_params()), "Invalid output buffer size");
   BOTAN_ARG_CHECK(q.get() < (uint32_t(1) << h), "Invalid LMS leaf index");
   BOTAN_ARG_CHECK(treetop.h() == h && treetop.k() == k && treetop.m() == lms_params().m(),
                   "Treetop does not belong to this tree");
   BOTAN_ARG_CHECK(k == 0 || (subtree != nullptr && subtree->index() == (q.get() >> k)),
                   "Subtree does not contain the signing leaf");

   BufferStuffer sig_stuffer(out_sig);
   sig_stuffer.append(store_be(q));
   const LMOTS_Private_Key lmots_sk(lmots_params(), identifier(), q, seed());
   lmots_sk.sign(sig_stuffer.next<LMOTS_Signature_Bytes>(LMOTS_Signature::size(lmots_params())), msg);
   sig_stuffer.append(store_be(lms_params().algorithm_type()));

   // path[j] is the sibling of the node at height j on the way from leaf q to the root
   for(uint32_t j = 0; j != h; ++j) {
      const uint32_t sibling = (q.get() >> j) ^ 1;
      if(j >= k) {
         sig_stuffer.append(treetop.node((uint32_t(1) << (h - j)) + sibling));
      } else {
         const uint32_t layer_mask = (uint32_t(1) << (k - j)) - 1;
         sig_stuffer.append(subtree->node((uint32_t(1) << (k - j)) + (sibling & layer_mask)));
      }
   }

   BOTAN_ASSERT_NOMSG(sig_stuffer.full());
}

LMS_PublicKey LMS_PublicKey::from_bytes_or_throw(BufferSlicer& slicer) {
   const size_t total_remaining_bytes = slicer.remaining();
   // Alg. 6. 1. (4 bytes are sufficient until the next check)
   if(total_remaining_bytes < sizeof(LMS_Algorithm_Type)) {
      throw Decoding_Error("Too few bytes while parsing LMS public key.");
   }
   // Alg. 6. 2.a.
   const auto lms_type = load_be<LMS_Algorithm_Type>(slicer.take<sizeof(LMS_Algorithm_Type)>());
   // Alg. 6. 2.c.
   auto lms_params = LMS_Params::create_or_throw(lms_type);
   // Alg. 6. 2.d.
   if(total_remaining_bytes < LMS_PublicKey::size(lms_params)) {
      throw Decoding_Error("Too few bytes while parsing LMS public key.");
   }
   // Alg. 6. 2.b.
   const auto lmots_type = load_be<LMOTS_Algorithm_Type>(slicer.take<sizeof(LMOTS_Algorithm_Type)>());
   auto lmots_params = LMOTS_Params::create_or_throw(lmots_type);

   if(lms_params.hash_name() != lmots_params.hash_name()) {
      throw Decoding_Error("No support for HSS-LMS instances with multiple hash functions.");
   }

   // Alg. 6. 2.e.
   auto I = slicer.copy<LMS_Identifier>(LMS_IDENTIFIER_LEN);
   // Alg. 6. 2.f.
   auto lms_root = slicer.copy<LMS_Tree_Node>(lms_params.m());

   return LMS_PublicKey(std::move(lms_params), std::move(lmots_params), std::move(I), std::move(lms_root));
}

std::vector<uint8_t> LMS_PublicKey::to_bytes() const {
   // clang-format off
   return concat<std::vector<uint8_t>>(
      store_be(lms_params().algorithm_type()),
      store_be(lmots_params().algorithm_type()),
      identifier(),
      m_lms_root);
   // clang-format on
}

LMS_PublicKey::LMS_PublicKey(LMS_Params lms_params,
                             LMOTS_Params lmots_params,
                             LMS_Identifier I,
                             LMS_Tree_Node lms_root) :
      LMS_Instance(std::move(lms_params), std::move(lmots_params), std::move(I)), m_lms_root(std::move(lms_root)) {
   BOTAN_ARG_CHECK(identifier().size() == LMS_IDENTIFIER_LEN, "Invalid LMS identifier");
   BOTAN_ARG_CHECK(m_lms_root.size() == this->lms_params().m(), "Invalid LMS root");
}

size_t LMS_PublicKey::size(const LMS_Params& lms_params) {
   return sizeof(LMS_Algorithm_Type) + sizeof(LMOTS_Algorithm_Type) + LMS_IDENTIFIER_LEN + lms_params.m();
}

LMS_Signature LMS_Signature::from_bytes_or_throw(BufferSlicer& slicer) {
   const size_t total_remaining_bytes = slicer.remaining();
   // Alg. 6a 1. (next 4 bytes are checked in LMOTS_Signature::from_bytes_or_throw)
   if(total_remaining_bytes < sizeof(LMS_Tree_Node_Idx)) {
      throw Decoding_Error("Too few signature bytes while parsing LMS signature.");
   }
   // Alg. 6a 2.a.
   const auto q = load_be<LMS_Tree_Node_Idx>(slicer.take<sizeof(LMS_Tree_Node_Idx)>());

   // Alg. 6a 2.b.-e.
   auto lmots_sig = LMOTS_Signature::from_bytes_or_throw(slicer);
   const LMOTS_Params lmots_params = LMOTS_Params::create_or_throw(lmots_sig.algorithm_type());

   if(slicer.remaining() < sizeof(LMS_Algorithm_Type)) {
      throw Decoding_Error("Too few signature bytes while parsing LMS signature.");
   }
   // Alg. 6a 2.f.
   const auto lms_type = load_be<LMS_Algorithm_Type>(slicer.take<sizeof(LMS_Algorithm_Type)>());
   // Alg. 6a 2.h.
   const LMS_Params lms_params = LMS_Params::create_or_throw(lms_type);
   // Alg. 6a 2.i. (signature is not exactly [...] bytes long)
   if(total_remaining_bytes < size(lms_params, lmots_params)) {
      throw Decoding_Error("Too few signature bytes while parsing LMS signature.");
   }

   // Alg. 6a 2.j.
   auto auth_path = slicer.copy<LMS_AuthenticationPath>(lms_params.m() * lms_params.h());

   return LMS_Signature(q, std::move(lmots_sig), lms_type, std::move(auth_path));
}

LMS_PublicKey::LMS_PublicKey(const LMS_PrivateKey& sk) :
      /* NOLINT(*-slicing) */ LMS_Instance(sk), m_lms_root(sk.lms_params().m()) {
   const auto treetop = sk.build_tree(LMS_Tree_Node_Idx(0)).first;
   copy_mem(m_lms_root, treetop.root());
}

bool LMS_PublicKey::verify_signature(const LMS_Message& msg, const LMS_Signature& sig) const {
   if(lms_root().size() != lms_params().m()) {
      // LMS public key (T[1] part) has unexpected length
      return false;
   }
   if(lms_params().algorithm_type() != sig.lms_type()) {
      // LMS algorithm type does not match with the signature's
      return false;
   }
   // Alg. 6a 2.g.
   if(lmots_params().algorithm_type() != sig.lmots_sig().algorithm_type()) {
      // LMOTS algorithm type does not match with the signature's
      return false;
   }
   // Alg. 6a 2.i.
   if(sig.q() >= (1ULL << uint64_t(lms_params().h()))) {
      return false;
   }
   // Alg 6. 3.
   std::optional<LMS_Tree_Node> Tc = lms_compute_root_from_sig(msg, sig);
   if(!Tc.has_value()) {
      return false;
   }
   // Alg 6. 4.
   return Tc.value() == lms_root();
}

std::optional<LMS_Tree_Node> LMS_PublicKey::lms_compute_root_from_sig(const LMS_Message& msg,
                                                                      const LMS_Signature& sig) const {
   // Alg. 6a 2.c, 2.g
   if(lms_params().algorithm_type() != sig.lms_type() ||
      lmots_params().algorithm_type() != sig.lmots_sig().algorithm_type()) {
      return std::nullopt;
   }
   try {
      const LMS_Params lms_params = LMS_Params::create_or_throw(sig.lms_type());
      const LMOTS_Signature& lmots_sig = sig.lmots_sig();
      const LMOTS_Params lmots_params = LMOTS_Params::create_or_throw(lmots_sig.algorithm_type());
      const LMOTS_K Kc = lmots_compute_pubkey_from_sig(lmots_sig, msg, identifier(), sig.q());
      const auto hash = lms_params.hash();

      auto hash_pair_func = get_hash_pair_func_for_identifier(lms_params, identifier());

      auto lms_address = TreeAddress(lms_params.h());
      lms_address.set_address(LMS_TreeLayerIndex(0), LMS_Tree_Node_Idx(sig.q().get()));

      const LMOTS_Public_Key pk_candidate(lmots_params, identifier(), sig.q(), Kc);
      LMS_Tree_Node tmp(lms_params.m());
      lms_gen_leaf(tmp, pk_candidate, lms_address, *hash);

      LMS_Tree_Node root(lms_params.m());

      compute_root(StrongSpan<LMS_Tree_Node>(root),
                   sig.auth_path(),
                   sig.q(),
                   StrongSpan<const LMS_Tree_Node>(tmp),
                   lms_params.m(),
                   LMS_TreeLayerIndex(lms_params.h()),
                   0,
                   std::move(hash_pair_func),
                   lms_address);
      return LMS_Tree_Node(root);
   } catch(const Decoding_Error&) {
      return std::nullopt;
   }
}

size_t LMS_Signature::size(const LMS_Params& lms_params, const LMOTS_Params& lmots_params) {
   return sizeof(uint32_t) + LMOTS_Signature::size(lmots_params) + sizeof(uint32_t) + lms_params.h() * lms_params.m();
}

}  // namespace Botan

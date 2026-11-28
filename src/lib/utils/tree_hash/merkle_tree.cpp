/*
 * Merkle trees with a stored treetop
 * (C) 2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/merkle_tree.h>

#include <botan/assert.h>
#include <botan/mem_ops.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <algorithm>

namespace Botan {

uint32_t Merkle_Treetop::subtree_height(uint32_t h) {
   constexpr uint32_t max_row_height = 10;
   return h > max_row_height ? h - max_row_height : 0;
}

size_t Merkle_Treetop::row_size(uint32_t h, size_t n) {
   return (size_t(1) << (h - subtree_height(h))) * n;
}

Merkle_Treetop::Merkle_Treetop(uint32_t h, size_t n, std::vector<uint8_t> nodes) :
      m_h(h), m_k(subtree_height(h)), m_n(n), m_nodes(std::move(nodes)) {
   BOTAN_ASSERT_NOMSG(m_nodes.size() == (size_t(1) << (m_h - m_k + 1)) * m_n);
}

Merkle_Treetop Merkle_Treetop::from_row(uint32_t h,
                                        size_t n,
                                        std::span<const uint8_t> row,
                                        const Merkle_Node_Fn& node_fn) {
   BOTAN_ARG_CHECK(h < 32, "Invalid Merkle tree height");
   BOTAN_ARG_CHECK(row.size() == row_size(h, n), "Invalid Merkle treetop row size");

   const uint32_t k = subtree_height(h);
   const size_t row_start = size_t(1) << (h - k);

   std::vector<uint8_t> nodes(2 * row_start * n);
   copy_mem(std::span(nodes).subspan(row_start * n), row);

   for(uint32_t j = k + 1; j <= h; ++j) {
      // Each layer is directly followed by its children
      const size_t layer_start = size_t(1) << (h - j);
      node_fn(std::span(nodes).subspan(layer_start * n, layer_start * n),
              j,
              0,
              static_cast<uint32_t>(layer_start),
              std::span<const uint8_t>(nodes).subspan(2 * layer_start * n, 2 * layer_start * n));
   }

   return Merkle_Treetop(h, n, std::move(nodes));
}

std::span<const uint8_t> Merkle_Treetop::row() const {
   return std::span(m_nodes).subspan((size_t(1) << (m_h - m_k)) * m_n);
}

std::span<const uint8_t> Merkle_Treetop::node(uint32_t j, uint32_t t) const {
   BOTAN_ASSERT_NOMSG(j >= m_k && j <= m_h && t < (uint32_t(1) << (m_h - j)));
   const size_t pos = (size_t(1) << (m_h - j)) + t;
   return std::span(m_nodes).subspan(pos * m_n, m_n);
}

void Merkle_Treetop::auth_path(std::span<uint8_t> out, uint32_t q, const Merkle_Subtree* subtree) const {
   BOTAN_ARG_CHECK(out.size() == m_h * m_n, "Invalid authentication path buffer size");
   BOTAN_ARG_CHECK(q < (uint32_t(1) << m_h), "Invalid Merkle tree leaf index");
   BOTAN_ARG_CHECK(m_k == 0 || (subtree != nullptr && subtree->index() == (q >> m_k)),
                   "Subtree does not contain the leaf");

   for(uint32_t j = 0; j != m_h; ++j) {
      const uint32_t sibling = (q >> j) ^ 1;
      const auto sibling_node = (j >= m_k) ? node(j, sibling) : subtree->node(j, sibling);
      copy_mem(out.subspan(j * m_n, m_n), sibling_node);
   }
}

Merkle_Subtree::Merkle_Subtree(uint32_t k, uint32_t index, size_t n, std::vector<uint8_t> nodes) :
      m_k(k), m_index(index), m_n(n), m_nodes(std::move(nodes)) {
   BOTAN_ASSERT_NOMSG(m_nodes.size() == (size_t(1) << (m_k + 1)) * m_n);
}

std::span<const uint8_t> Merkle_Subtree::node(uint32_t j, uint32_t t) const {
   BOTAN_ASSERT_NOMSG(j <= m_k && (t >> (m_k - j)) == m_index);
   const uint32_t layer_start = uint32_t(1) << (m_k - j);
   const size_t pos = layer_start + (t & (layer_start - 1));
   return std::span(m_nodes).subspan(pos * m_n, m_n);
}

Merkle_Tree_Builder::Merkle_Tree_Builder(
   uint32_t h, size_t n, uint32_t leaf_batch, Merkle_Leaf_Fn leaf_fn, Merkle_Node_Fn node_fn) :
      m_h(h), m_n(n), m_leaf_batch(leaf_batch), m_leaf_fn(std::move(leaf_fn)), m_node_fn(std::move(node_fn)) {
   BOTAN_ARG_CHECK(h < 32, "Invalid Merkle tree height");
   BOTAN_ARG_CHECK(n > 0, "Invalid Merkle tree node size");
   BOTAN_ARG_CHECK(leaf_batch > 0 && (leaf_batch & (leaf_batch - 1)) == 0, "Leaf batch must be a power of two");
}

/**
 * Compute every node of the subtree of height @p height whose leftmost leaf is
 * @p first_leaf, calling on_node(j, t, node) for each node
 */
template <typename F>
void Merkle_Tree_Builder::walk(uint32_t first_leaf, uint32_t height, F on_node) const {
   BOTAN_ASSERT_NOMSG(height <= m_h);
   BOTAN_ASSERT_NOMSG(first_leaf % (uint32_t(1) << height) == 0 && first_leaf < (uint32_t(1) << m_h));

   const size_t n = m_n;
   const uint32_t leaf_count = uint32_t(1) << height;
   // Both the batch size and the leaf count are powers of two, so batches are
   // always full, and each batch is the bottom of a subtree
   const uint32_t leaves_per_batch = std::min(leaf_count, m_leaf_batch);
   const auto batch_height = static_cast<uint32_t>(ctz(leaves_per_batch));
   std::vector<uint8_t> layer(leaves_per_batch * n);
   std::vector<uint8_t> parents(leaves_per_batch / 2 * n);
   // The left child at each height which is waiting for its right sibling
   std::vector<uint8_t> left_children(height * n);
   // A node at height batch_height or above, preceded by its left sibling
   std::vector<uint8_t> pair(2 * n);
   const auto right = std::span(pair).last(n);

   for(uint32_t b = 0; b != leaf_count; b += leaves_per_batch) {
      m_leaf_fn(layer, first_leaf + b, leaves_per_batch);

      // The subtree above the batch, one layer at a time
      uint32_t t = first_leaf + b;
      for(uint32_t j = 0, count = leaves_per_batch; true; ++j) {
         for(uint32_t i = 0; i != count; ++i) {
            on_node(j, t + i, std::span<const uint8_t>(layer).subspan(i * n, n));
         }
         if(count == 1) {
            break;
         }
         count /= 2;
         t /= 2;
         const auto out = std::span(parents).first(count * n);
         m_node_fn(out, j + 1, t, count, std::span<const uint8_t>(layer).first(2 * count * n));
         copy_mem(std::span(layer).first(count * n), std::span<const uint8_t>(out));
      }

      // Post-order traversal above the batches, combining each right child
      // with its left sibling
      copy_mem(right, std::span<const uint8_t>(layer).first(n));
      for(uint32_t j = batch_height; j != height; ++j) {
         const auto left = std::span(left_children).subspan(j * n, n);
         if(t % 2 == 0) {
            copy_mem(left, std::span<const uint8_t>(right));
            break;
         }
         t /= 2;
         copy_mem(std::span(pair).first(n), std::span<const uint8_t>(left));
         m_node_fn(std::span(layer).first(n), j + 1, t, 1, pair);
         copy_mem(right, std::span<const uint8_t>(layer).first(n));
         on_node(j + 1, t, std::span<const uint8_t>(right));
      }
   }
}

std::vector<uint8_t> Merkle_Tree_Builder::root() const {
   std::vector<uint8_t> root(m_n);
   walk(0, m_h, [&](uint32_t j, uint32_t /*t*/, std::span<const uint8_t> node) {
      if(j == m_h) {
         copy_mem(std::span(root), node);
      }
   });

   // The root is public, being part of the public key
   CT::unpoison(root);
   return root;
}

std::pair<Merkle_Treetop, Merkle_Subtree> Merkle_Tree_Builder::build(uint32_t q) const {
   BOTAN_ARG_CHECK(q < (uint32_t(1) << m_h), "Invalid Merkle tree leaf index");

   const uint32_t h = m_h;
   const uint32_t k = Merkle_Treetop::subtree_height(h);
   const size_t n = m_n;
   const uint32_t s = q >> k;

   std::vector<uint8_t> top((size_t(1) << (h - k + 1)) * n);
   std::vector<uint8_t> sub((size_t(1) << (k + 1)) * n);

   walk(0, h, [&](uint32_t j, uint32_t t, std::span<const uint8_t> node) {
      if(j >= k) {
         const size_t pos = (size_t(1) << (h - j)) + t;
         copy_mem(std::span(top).subspan(pos * n, n), node);
      }
      if(j <= k && (t >> (k - j)) == s) {
         const uint32_t layer_start = uint32_t(1) << (k - j);
         const size_t pos = layer_start + (t & (layer_start - 1));
         copy_mem(std::span(sub).subspan(pos * n, n), node);
      }
   });

   // The nodes are public, being part of signatures or the public key
   CT::unpoison(top);
   CT::unpoison(sub);

   return {Merkle_Treetop(h, n, std::move(top)), Merkle_Subtree(k, s, n, std::move(sub))};
}

std::optional<Merkle_Subtree> Merkle_Tree_Builder::build_subtree(const Merkle_Treetop& treetop, uint32_t q) const {
   BOTAN_ARG_CHECK(treetop.h() == m_h && treetop.n() == m_n, "Treetop does not belong to this tree");
   BOTAN_ARG_CHECK(q < (uint32_t(1) << m_h), "Invalid Merkle tree leaf index");

   const uint32_t k = treetop.k();
   const size_t n = m_n;
   const uint32_t s = q >> k;

   std::vector<uint8_t> sub((size_t(1) << (k + 1)) * n);

   walk(s << k, k, [&](uint32_t j, uint32_t t, std::span<const uint8_t> node) {
      const uint32_t layer_start = uint32_t(1) << (k - j);
      const size_t pos = layer_start + (t & (layer_start - 1));
      copy_mem(std::span(sub).subspan(pos * n, n), node);
   });

   CT::unpoison(sub);

   Merkle_Subtree subtree(k, s, n, std::move(sub));
   if(!std::ranges::equal(subtree.node(k, s), treetop.node(k, s))) {
      return std::nullopt;
   }
   return subtree;
}

}  // namespace Botan

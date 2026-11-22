/*
 * Merkle trees with a stored treetop
 * (C) 2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_MERKLE_TREE_H_
#define BOTAN_MERKLE_TREE_H_

#include <botan/types.h>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace Botan {

/*
 * Nodes of a Merkle tree are identified by their height j, the leaves having
 * height 0, and their index t within that height, counting from the left.
 */

/**
 * Computes the leaves first_leaf, ..., first_leaf + count - 1 into out,
 * which holds count nodes
 */
using Merkle_Leaf_Fn = std::function<void(std::span<uint8_t> out, uint32_t first_leaf, uint32_t count)>;

/**
 * Computes the nodes at height j (at least 1) with indices first_t, ...,
 * first_t + count - 1 into out, which holds count nodes. Their children are
 * the 2 * count nodes in children, from left to right, which do not overlap out.
 */
using Merkle_Node_Fn = std::function<void(
   std::span<uint8_t> out, uint32_t j, uint32_t first_t, uint32_t count, std::span<const uint8_t> children)>;

class Merkle_Subtree;

/**
 * The top part of a Merkle tree of height h: every node at height k or above,
 * where k = subtree_height(h). Together with the Merkle_Subtree containing a
 * leaf, it provides the authentication path of that leaf.
 */
class BOTAN_TEST_API Merkle_Treetop final {
   public:
      /**
       * Height of the subtrees below the treetop, chosen so that the lowest
       * row of the treetop has at most 2^10 nodes
       */
      static uint32_t subtree_height(uint32_t h);

      /**
       * Size in bytes of the lowest row of the treetop of a tree of height
       * @p h with nodes of @p n bytes
       */
      static size_t row_size(uint32_t h, size_t n);

      /**
       * Compute a treetop from its lowest row (see row())
       */
      static Merkle_Treetop from_row(uint32_t h, size_t n, std::span<const uint8_t> row, const Merkle_Node_Fn& node_fn);

      /**
       * The nodes at height k from left to right
       */
      std::span<const uint8_t> row() const;

      std::span<const uint8_t> root() const { return node(m_h, 0); }

      /**
       * The node at height @p j (at least k) with index @p t
       */
      std::span<const uint8_t> node(uint32_t j, uint32_t t) const;

      /**
       * Write the authentication path of leaf @p q into @p out (h nodes):
       * entry j is the sibling of the node at height j on the way from q to
       * the root.
       *
       * @param subtree The subtree containing @p q. Unused, and may be null,
       *                if k is zero.
       */
      void auth_path(std::span<uint8_t> out, uint32_t q, const Merkle_Subtree* subtree) const;

      uint32_t h() const { return m_h; }

      uint32_t k() const { return m_k; }

      size_t n() const { return m_n; }

   private:
      friend class Merkle_Tree_Builder;

      Merkle_Treetop(uint32_t h, size_t n, std::vector<uint8_t> nodes);

      uint32_t m_h;
      uint32_t m_k;
      size_t m_n;
      // Node (j, t) is at position 2^(h-j) + t, so the first entry is unused
      std::vector<uint8_t> m_nodes;
};

/**
 * All nodes of one of the subtrees of height k hanging below a Merkle_Treetop
 */
class BOTAN_TEST_API Merkle_Subtree final {
   public:
      /**
       * The subtree's position, counting from the left. Leaf q is in subtree
       * number q >> k.
       */
      uint32_t index() const { return m_index; }

      /**
       * The node at height @p j (at most k) with index @p t, which must be
       * within this subtree
       */
      std::span<const uint8_t> node(uint32_t j, uint32_t t) const;

   private:
      friend class Merkle_Tree_Builder;

      Merkle_Subtree(uint32_t k, uint32_t index, size_t n, std::vector<uint8_t> nodes);

      uint32_t m_k;
      uint32_t m_index;
      size_t m_n;
      // Node (j, t) is at position 2^(k-j) + t mod 2^(k-j), so the first entry is unused
      std::vector<uint8_t> m_nodes;
};

/**
 * Computes the nodes of a Merkle tree of height h with nodes of n bytes
 */
class BOTAN_TEST_API Merkle_Tree_Builder final {
   public:
      /**
       * @param h The height of the tree
       * @param n The size of each node in bytes
       * @param leaf_batch The number of leaves to request from @p leaf_fn at
       *                   once, a power of two
       * @param leaf_fn Computes the leaves
       * @param node_fn Computes the interior nodes
       */
      Merkle_Tree_Builder(uint32_t h, size_t n, uint32_t leaf_batch, Merkle_Leaf_Fn leaf_fn, Merkle_Node_Fn node_fn);

      /**
       * Compute the root of the tree
       */
      std::vector<uint8_t> root() const;

      /**
       * Compute the whole tree
       *
       * @return The treetop, and the subtree containing leaf @p q
       */
      std::pair<Merkle_Treetop, Merkle_Subtree> build(uint32_t q) const;

      /**
       * Compute the subtree containing leaf @p q
       *
       * @return The subtree, or nullopt if its root does not match @p treetop
       */
      std::optional<Merkle_Subtree> build_subtree(const Merkle_Treetop& treetop, uint32_t q) const;

      /**
       * Compute a treetop from its lowest row (see Merkle_Treetop::row())
       */
      Merkle_Treetop treetop_from_row(std::span<const uint8_t> row) const {
         return Merkle_Treetop::from_row(m_h, m_n, row, m_node_fn);
      }

      uint32_t h() const { return m_h; }

      size_t n() const { return m_n; }

   private:
      template <typename F>
      void walk(uint32_t first_leaf, uint32_t height, F on_node) const;

      uint32_t m_h;
      size_t m_n;
      uint32_t m_leaf_batch;
      Merkle_Leaf_Fn m_leaf_fn;
      Merkle_Node_Fn m_node_fn;
};

}  // namespace Botan

#endif

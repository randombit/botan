/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

// The Merkle tree helper is an internal module pulled in by these
#if defined(BOTAN_HAS_SHA2_32) && (defined(BOTAN_HAS_HSS_LMS) || defined(BOTAN_HAS_XMSS_RFC8391))
   #include <botan/exceptn.h>
   #include <botan/hash.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/merkle_tree.h>
   #include <algorithm>
   #include <bit>
   #include <memory>
   #include <set>
   #include <utility>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_SHA2_32) && (defined(BOTAN_HAS_HSS_LMS) || defined(BOTAN_HAS_XMSS_RFC8391))

class Merkle_Tree_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         return {test_tree(13, 8),
                 test_tree(10, 32),
                 test_tree(4, 32),
                 test_tree(0, 1),
                 test_mismatching_data(),
                 test_argument_checks()};
      }

   private:
      static constexpr size_t N = 32;

      using Reference_Tree = std::vector<std::vector<std::vector<uint8_t>>>;

      /**
       * Leaves depend on @p seed, so that different trees can be built
       */
      static Botan::Merkle_Leaf_Fn leaf_fn(uint8_t seed, std::vector<uint32_t>* batches = nullptr) {
         return [seed,
                 batches,
                 hash = std::shared_ptr<Botan::HashFunction>(Botan::HashFunction::create_or_throw("SHA-256"))](
                   std::span<uint8_t> out, uint32_t first_leaf, uint32_t count) {
            if(batches != nullptr) {
               batches->push_back(count);
            }
            for(uint32_t i = 0; i != count; ++i) {
               hash->update(seed);
               hash->update_be(first_leaf + i);
               hash->final(out.subspan(i * N, N));
            }
         };
      }

      /**
       * Records the height and count of each batch of nodes in @p batches
       */
      static Botan::Merkle_Node_Fn node_fn(std::vector<std::pair<uint32_t, uint32_t>>* batches = nullptr) {
         return [batches, hash = std::shared_ptr<Botan::HashFunction>(Botan::HashFunction::create_or_throw("SHA-256"))](
                   std::span<uint8_t> out,
                   uint32_t j,
                   uint32_t first_t,
                   uint32_t count,
                   std::span<const uint8_t> children) {
            if(batches != nullptr) {
               batches->emplace_back(j, count);
            }
            for(uint32_t i = 0; i != count; ++i) {
               hash->update_be(j);
               hash->update_be(first_t + i);
               hash->update(children.subspan(2 * i * N, 2 * N));
               hash->final(out.subspan(i * N, N));
            }
         };
      }

      /**
       * All nodes, indexed by height and index, computed from the definition
       */
      static Reference_Tree reference_tree(uint32_t h, uint8_t seed) {
         const size_t leaves = size_t(1) << h;
         std::vector<uint8_t> leaf_bytes(leaves * N);
         leaf_fn(seed)(leaf_bytes, 0, static_cast<uint32_t>(leaves));

         Reference_Tree nodes(h + 1);
         for(size_t t = 0; t != leaves; ++t) {
            nodes[0].emplace_back(leaf_bytes.begin() + t * N, leaf_bytes.begin() + (t + 1) * N);
         }

         const auto node = node_fn();
         for(uint32_t j = 1; j <= h; ++j) {
            for(uint32_t t = 0; t != (uint32_t(1) << (h - j)); ++t) {
               std::vector<uint8_t> children = nodes[j - 1][2 * t];
               children.insert(children.end(), nodes[j - 1][2 * t + 1].begin(), nodes[j - 1][2 * t + 1].end());
               std::vector<uint8_t> out(N);
               node(out, j, t, 1, children);
               nodes[j].push_back(out);
            }
         }
         return nodes;
      }

      static void check_auth_path(Test::Result& result,
                                  const Reference_Tree& ref,
                                  uint32_t q,
                                  const Botan::Merkle_Treetop& treetop,
                                  const Botan::Merkle_Subtree* subtree) {
         std::vector<uint8_t> path(treetop.h() * N);
         treetop.auth_path(path, q, subtree);
         for(uint32_t j = 0; j != treetop.h(); ++j) {
            result.test_bin_eq(
               Botan::fmt("leaf {} auth path entry {}", q, j), std::span(path).subspan(j * N, N), ref[j][(q >> j) ^ 1]);
         }
      }

      static void check_subtree(Test::Result& result,
                                const Reference_Tree& ref,
                                uint32_t k,
                                const Botan::Merkle_Subtree& subtree) {
         const uint32_t s = subtree.index();
         for(uint32_t j = 0; j <= k; ++j) {
            for(uint32_t t = s << (k - j); t != (s + 1) << (k - j); ++t) {
               result.test_bin_eq(Botan::fmt("subtree {} node ({}, {})", s, j, t), subtree.node(j, t), ref[j][t]);
            }
         }
      }

      static Test::Result test_tree(uint32_t h, uint32_t leaf_batch) {
         Test::Result result(Botan::fmt("Merkle tree of height {}", h));

         const auto ref = reference_tree(h, 1);
         std::vector<uint32_t> batches;
         std::vector<std::pair<uint32_t, uint32_t>> node_batches;
         const Botan::Merkle_Tree_Builder tree(h, N, leaf_batch, leaf_fn(1, &batches), node_fn(&node_batches));
         const uint32_t k = Botan::Merkle_Treetop::subtree_height(h);
         const uint32_t leaves = uint32_t(1) << h;

         result.test_bin_eq("root", tree.root(), ref[h][0]);
         const uint32_t expected_batch = std::min(leaves, leaf_batch);
         result.test_sz_eq("number of leaf batches", batches.size(), leaves / expected_batch);
         result.test_is_true("leaves are computed in full batches",
                             std::ranges::all_of(batches, [&](uint32_t b) { return b == expected_batch; }));

         // One call per layer above each leaf batch, then one per node above the batches
         const uint32_t leaf_batches = leaves / expected_batch;
         const auto batch_height = static_cast<uint32_t>(std::countr_zero(expected_batch));
         result.test_sz_eq(
            "number of node batches", node_batches.size(), leaf_batches * batch_height + leaf_batches - 1);
         size_t nodes_computed = 0;
         for(const auto& batch : node_batches) {
            nodes_computed += batch.second;
         }
         result.test_sz_eq("every interior node is computed once", nodes_computed, leaves - 1);

         std::set<uint32_t> qs = {0, leaves / 3, leaves - 1};
         if(leaves > 1) {
            qs.insert(1);
         }
         for(const uint32_t q : qs) {
            const auto [treetop, subtree] = tree.build(q);
            result.test_u32_eq("treetop height", treetop.h(), h);
            result.test_u32_eq("subtree height", treetop.k(), k);
            result.test_bin_eq("treetop root", treetop.root(), ref[h][0]);
            result.test_u32_eq("subtree index", subtree.index(), q >> k);

            std::vector<uint8_t> row;
            for(const auto& node : ref[k]) {
               row.insert(row.end(), node.begin(), node.end());
            }
            result.test_bin_eq("treetop row", treetop.row(), row);
            result.test_sz_eq("row size", row.size(), Botan::Merkle_Treetop::row_size(h, N));

            node_batches.clear();
            const auto from_row = tree.treetop_from_row(row);
            result.test_sz_eq("treetop is computed one layer at a time", node_batches.size(), h - k);
            for(const auto& [j, count] : node_batches) {
               result.test_u32_eq("treetop layer size", count, uint32_t(1) << (h - j));
            }
            for(uint32_t j = k; j <= h; ++j) {
               for(uint32_t t = 0; t != (uint32_t(1) << (h - j)); ++t) {
                  if(!std::ranges::equal(from_row.node(j, t), ref[j][t])) {
                     result.test_failure(Botan::fmt("treetop from row node ({}, {})", j, t));
                  }
               }
            }

            check_subtree(result, ref, k, subtree);
            check_auth_path(result, ref, q, treetop, &subtree);

            const auto rebuilt = tree.build_subtree(treetop, q);
            result.require("subtree is rebuilt", rebuilt.has_value());
            check_subtree(result, ref, k, rebuilt.value());

            // Signing with another leaf, which may be in another subtree
            const uint32_t other = (q + leaves / 2 + 1) % leaves;
            const auto other_subtree = tree.build_subtree(from_row, other);
            result.require("other subtree is built", other_subtree.has_value());
            result.test_u32_eq("other subtree index", other_subtree->index(), other >> k);
            check_auth_path(result, ref, other, from_row, &other_subtree.value());

            if(k == 0) {
               check_auth_path(result, ref, other, from_row, nullptr);
            }
         }

         return result;
      }

      static Test::Result test_mismatching_data() {
         Test::Result result("Merkle tree with mismatching data");

         const uint32_t h = 12;
         const Botan::Merkle_Tree_Builder tree(h, N, 16, leaf_fn(1), node_fn());
         const Botan::Merkle_Tree_Builder other_tree(h, N, 16, leaf_fn(2), node_fn());

         const auto [treetop, subtree] = tree.build(5);
         result.test_is_true("subtree of another tree does not match",
                             !other_tree.build_subtree(treetop, 5).has_value());
         result.test_is_true("subtree of the same tree matches", tree.build_subtree(treetop, 100).has_value());

         std::vector<uint8_t> row(treetop.row().begin(), treetop.row().end());
         row.at(row.size() - 1) ^= 0x01;
         const auto corrupted = tree.treetop_from_row(row);
         result.test_is_true("corrupted row changes the root", !std::ranges::equal(corrupted.root(), treetop.root()));
         result.test_is_true("subtree does not match a corrupted treetop",
                             !tree.build_subtree(corrupted, (uint32_t(1) << h) - 1).has_value());

         return result;
      }

      static Test::Result test_argument_checks() {
         Test::Result result("Merkle tree argument checks");

         result.test_throws<Botan::Invalid_Argument>(
            "height 32", [] { const Botan::Merkle_Tree_Builder tree(32, N, 16, leaf_fn(1), node_fn()); });
         result.test_throws<Botan::Invalid_Argument>("leaf batch not a power of two", [] {
            const Botan::Merkle_Tree_Builder tree(5, N, 3, leaf_fn(1), node_fn());
         });

         const uint32_t h = 12;
         const Botan::Merkle_Tree_Builder tree(h, N, 16, leaf_fn(1), node_fn());
         // Not a structured binding, since clang 14 cannot capture those in a lambda
         const auto built = tree.build(0);
         const auto& treetop = built.first;
         const auto& subtree = built.second;
         std::vector<uint8_t> path(h * N);

         result.test_throws<Botan::Invalid_Argument>("leaf out of range", [&] { tree.build(uint32_t(1) << h); });
         result.test_throws<Botan::Invalid_Argument>(
            "row of the wrong size", [&] { tree.treetop_from_row(std::vector<uint8_t>(treetop.row().size() - 1)); });
         result.test_throws<Botan::Invalid_Argument>("missing subtree", [&] { treetop.auth_path(path, 0, nullptr); });
         result.test_throws<Botan::Invalid_Argument>("subtree not containing the leaf",
                                                     [&] { treetop.auth_path(path, 4, &subtree); });
         result.test_throws<Botan::Invalid_Argument>("wrong path size",
                                                     [&] { treetop.auth_path(std::span(path).first(N), 0, &subtree); });

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "merkle_tree", Merkle_Tree_Test);

#endif

}  // namespace

}  // namespace Botan_Tests

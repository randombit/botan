/*
 * XMSS Private Key
 * An XMSS: Extended Hash-Based Siganture private key.
 * The XMSS private key does not support the X509 and PKCS7 standard. Instead
 * the raw format described in [1] is used.
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 *
 * (C) 2016,2017,2018 Matthias Gierlings
 * (C) 2019 Jack Lloyd
 * (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pk_options.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/xmss_common_ops.h>
#include <botan/internal/xmss_index_registry.h>
#include <botan/internal/xmss_signature_operation.h>
#include <iterator>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif

namespace Botan {

namespace {

// fall back to raw decoding for previous versions, which did not encode an OCTET STRING
secure_vector<uint8_t> extract_raw_private_key(std::span<const uint8_t> key_bits, const XMSS_Parameters& xmss_params) {
   secure_vector<uint8_t> raw_key;

   // The public part of the input key bits was already parsed, so we can
   // decide depending on the buffer length whether this must be BER decoded.
   if(key_bits.size() == xmss_params.raw_private_key_size() ||
      key_bits.size() == xmss_params.raw_legacy_private_key_size()) {
      raw_key.assign(key_bits.begin(), key_bits.end());
   } else {
      DataSource_Memory src(key_bits);
      BER_Decoder(src).decode(raw_key, ASN1_Type::OctetString).verify_end();
   }

   return raw_key;
}

}  // namespace

class XMSS_PrivateKey_Internal {
   public:
      XMSS_PrivateKey_Internal(const XMSS_Parameters& xmss_params,
                               const XMSS_WOTS_Parameters& wots_params,
                               WOTS_Derivation_Method wots_derivation_method,
                               RandomNumberGenerator& rng) :
            m_xmss_params(xmss_params),
            m_wots_params(wots_params),
            m_wots_derivation_method(wots_derivation_method),
            m_hash(xmss_params),
            m_prf(rng.random_vec(xmss_params.element_size())),
            m_private_seed(rng.random_vec(xmss_params.element_size())),
            m_index_reg(XMSS_Index_Registry::get_instance()) {}

      XMSS_PrivateKey_Internal(const XMSS_Parameters& xmss_params,
                               const XMSS_WOTS_Parameters& wots_params,
                               WOTS_Derivation_Method wots_derivation_method,
                               secure_vector<uint8_t> private_seed,
                               secure_vector<uint8_t> prf) :
            m_xmss_params(xmss_params),
            m_wots_params(wots_params),
            m_wots_derivation_method(wots_derivation_method),
            m_hash(m_xmss_params),
            m_prf(std::move(prf)),
            m_private_seed(std::move(private_seed)),
            m_index_reg(XMSS_Index_Registry::get_instance()) {}

      XMSS_PrivateKey_Internal(const XMSS_Parameters& xmss_params,
                               const XMSS_WOTS_Parameters& wots_params,
                               std::span<const uint8_t> key_bits) :
            m_xmss_params(xmss_params),
            m_wots_params(wots_params),
            m_hash(m_xmss_params),
            m_index_reg(XMSS_Index_Registry::get_instance()) {
         /*
         The code requires sizeof(size_t) >= ceil(tree_height / 8)

         Maximum supported tree height is 20, ceil(20/8) == 3, so 4 byte
         size_t is sufficient for all defined parameters, or even a
         (hypothetical) tree height 32, which would be extremely slow to
         compute.
         */
         static_assert(sizeof(size_t) >= 4, "size_t is big enough to support leaf index");

         const secure_vector<uint8_t> raw_key = extract_raw_private_key(key_bits, xmss_params);

         if(raw_key.size() != m_xmss_params.raw_private_key_size() &&
            raw_key.size() != m_xmss_params.raw_legacy_private_key_size()) {
            throw Decoding_Error("Invalid XMSS private key size");
         }

         BufferSlicer s(raw_key);

         // We're not interested in the public key here
         s.skip(m_xmss_params.raw_public_key_size());

         auto unused_leaf_bytes = s.take(sizeof(uint32_t));
         size_t unused_leaf = load_be<uint32_t>(unused_leaf_bytes.data(), 0);
         if(unused_leaf >= (1ULL << m_xmss_params.tree_height())) {
            throw Decoding_Error("XMSS private key leaf index out of bounds");
         }

         m_prf = s.copy_as_secure_vector(m_xmss_params.element_size());
         m_private_seed = s.copy_as_secure_vector(m_xmss_params.element_size());
         set_unused_leaf_index(unused_leaf);

         // Legacy keys generated prior to Botan 3.x don't feature a
         // WOTS+ key derivation method encoded in their private key.
         m_wots_derivation_method =
            (s.empty()) ? WOTS_Derivation_Method::Botan2x : static_cast<WOTS_Derivation_Method>(s.take(1).front());

         BOTAN_ASSERT_NOMSG(s.empty());
      }

      secure_vector<uint8_t> serialize(std::vector<uint8_t> raw_public_key) const {
         std::vector<uint8_t> unused_index(4);
         store_be(static_cast<uint32_t>(unused_leaf_index()), unused_index.data());

         std::vector<uint8_t> wots_derivation_method;
         wots_derivation_method.push_back(static_cast<uint8_t>(m_wots_derivation_method));

         return concat<secure_vector<uint8_t>>(
            raw_public_key, unused_index, m_prf, m_private_seed, wots_derivation_method);
      }

      XMSS_Hash& hash() { return m_hash; }

      const secure_vector<uint8_t>& prf_value() const { return m_prf; }

      const secure_vector<uint8_t>& private_seed() { return m_private_seed; }

      const XMSS_WOTS_Parameters& wots_parameters() { return m_wots_params; }

      WOTS_Derivation_Method wots_derivation_method() const { return m_wots_derivation_method; }

      XMSS_Index_Registry& index_registry() { return m_index_reg; }

      std::shared_ptr<Atomic<size_t>> recover_global_leaf_index() const {
         BOTAN_ASSERT(
            m_private_seed.size() == m_xmss_params.element_size() && m_prf.size() == m_xmss_params.element_size(),
            "Trying to retrieve index for partially initialized key");
         return m_index_reg.get(m_private_seed, m_prf);
      }

      void set_unused_leaf_index(size_t idx) {
         if(idx >= (1ULL << m_xmss_params.tree_height())) {
            throw Decoding_Error("XMSS private key leaf index out of bounds");
         } else {
            std::atomic<size_t>& index = static_cast<std::atomic<size_t>&>(*recover_global_leaf_index());
            size_t current = 0;

            do {
               current = index.load();
               if(current > idx) {
                  return;
               }
            } while(!index.compare_exchange_strong(current, idx));
         }
      }

      size_t reserve_unused_leaf_index() {
         size_t idx = (static_cast<std::atomic<size_t>&>(*recover_global_leaf_index())).fetch_add(1);
         if(idx >= m_xmss_params.total_number_of_signatures()) {
            throw Decoding_Error("XMSS private key, one time signatures exhaused");
         }
         return idx;
      }

      size_t unused_leaf_index() const { return *recover_global_leaf_index(); }

      size_t remaining_signatures() const {
         return m_xmss_params.total_number_of_signatures() - *recover_global_leaf_index();
      }

   private:
      XMSS_Parameters m_xmss_params;
      XMSS_WOTS_Parameters m_wots_params;
      WOTS_Derivation_Method m_wots_derivation_method;

      XMSS_Hash m_hash;
      secure_vector<uint8_t> m_prf;
      secure_vector<uint8_t> m_private_seed;
      XMSS_Index_Registry& m_index_reg;
};

XMSS_PrivateKey::XMSS_PrivateKey(std::span<const uint8_t> key_bits) :
      XMSS_PublicKey(key_bits),
      m_private(std::make_shared<XMSS_PrivateKey_Internal>(m_xmss_params, m_wots_params, key_bits)) {}

XMSS_PrivateKey::XMSS_PrivateKey(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                                 RandomNumberGenerator& rng,
                                 WOTS_Derivation_Method wots_derivation_method) :
      XMSS_PublicKey(xmss_algo_id, rng),
      m_private(std::make_shared<XMSS_PrivateKey_Internal>(m_xmss_params, m_wots_params, wots_derivation_method, rng)) {
   XMSS_Address adrs;
   m_root = tree_hash(0, XMSS_PublicKey::m_xmss_params.tree_height(), adrs);
}

XMSS_PrivateKey::XMSS_PrivateKey(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                                 size_t idx_leaf,
                                 secure_vector<uint8_t> wots_priv_seed,
                                 secure_vector<uint8_t> prf,
                                 secure_vector<uint8_t> root,
                                 secure_vector<uint8_t> public_seed,
                                 WOTS_Derivation_Method wots_derivation_method) :
      XMSS_PublicKey(xmss_algo_id, std::move(root), std::move(public_seed)),
      m_private(std::make_shared<XMSS_PrivateKey_Internal>(
         m_xmss_params, m_wots_params, wots_derivation_method, std::move(wots_priv_seed), std::move(prf))) {
   m_private->set_unused_leaf_index(idx_leaf);
   BOTAN_ARG_CHECK(m_private->prf_value().size() == m_xmss_params.element_size(),
                   "XMSS: unexpected byte length of PRF value");
   BOTAN_ARG_CHECK(m_private->private_seed().size() == m_xmss_params.element_size(),
                   "XMSS: unexpected byte length of private seed");
}

secure_vector<uint8_t> XMSS_PrivateKey::tree_hash(size_t start_idx, size_t target_node_height, XMSS_Address& adrs) {
   BOTAN_ASSERT_NOMSG(target_node_height <= 30);
   BOTAN_ASSERT((start_idx % (static_cast<size_t>(1) << target_node_height)) == 0,
                "Start index must be divisible by 2^{target node height}.");

#if defined(BOTAN_HAS_THREAD_UTILS)
   // dertermine number of parallel tasks to split the tree_hashing into.

   Thread_Pool& thread_pool = Thread_Pool::global_instance();

   const size_t split_level = std::min(target_node_height, thread_pool.worker_count());

   // skip parallelization overhead for leaf nodes.
   if(split_level == 0) {
      secure_vector<uint8_t> result;
      tree_hash_subtree(result, start_idx, target_node_height, adrs);
      return result;
   }

   const size_t subtrees = static_cast<size_t>(1) << split_level;
   const size_t last_idx = (static_cast<size_t>(1) << (target_node_height)) + start_idx;
   const size_t offs = (last_idx - start_idx) / subtrees;
   // this cast cannot overflow because target_node_height is limited
   uint8_t level = static_cast<uint8_t>(split_level);  // current level in the tree

   BOTAN_ASSERT((last_idx - start_idx) % subtrees == 0,
                "Number of worker threads in tree_hash need to divide range "
                "of calculated nodes.");

   std::vector<secure_vector<uint8_t>> nodes(subtrees,
                                             secure_vector<uint8_t>(XMSS_PublicKey::m_xmss_params.element_size()));
   std::vector<XMSS_Address> node_addresses(subtrees, adrs);
   std::vector<XMSS_Hash> xmss_hash(subtrees, m_private->hash());
   std::vector<std::future<void>> work;

   // Calculate multiple subtrees in parallel.
   for(size_t i = 0; i < subtrees; i++) {
      using tree_hash_subtree_fn_t =
         void (XMSS_PrivateKey::*)(secure_vector<uint8_t>&, size_t, size_t, XMSS_Address&, XMSS_Hash&);

      tree_hash_subtree_fn_t work_fn = &XMSS_PrivateKey::tree_hash_subtree;

      work.push_back(thread_pool.run(work_fn,
                                     this,
                                     std::ref(nodes[i]),
                                     start_idx + i * offs,
                                     target_node_height - split_level,
                                     std::ref(node_addresses[i]),
                                     std::ref(xmss_hash[i])));
   }

   for(auto& w : work) {
      w.get();
   }
   work.clear();

   // Parallelize the top tree levels horizontally
   while(level-- > 1) {
      std::vector<secure_vector<uint8_t>> ro_nodes(nodes.begin(),
                                                   nodes.begin() + (static_cast<size_t>(1) << (level + 1)));

      for(size_t i = 0; i < (static_cast<size_t>(1) << level); i++) {
         BOTAN_ASSERT_NOMSG(xmss_hash.size() > i);

         node_addresses[i].set_tree_height(static_cast<uint32_t>(target_node_height - (level + 1)));
         node_addresses[i].set_tree_index((node_addresses[2 * i + 1].get_tree_index() - 1) >> 1);

         work.push_back(thread_pool.run(&XMSS_Common_Ops::randomize_tree_hash,
                                        std::ref(nodes[i]),
                                        std::cref(ro_nodes[2 * i]),
                                        std::cref(ro_nodes[2 * i + 1]),
                                        std::ref(node_addresses[i]),
                                        std::cref(this->public_seed()),
                                        std::ref(xmss_hash[i]),
                                        std::cref(m_xmss_params)));
      }

      for(auto& w : work) {
         w.get();
      }
      work.clear();
   }

   // Avoid creation an extra thread to calculate root node.
   node_addresses[0].set_tree_height(static_cast<uint32_t>(target_node_height - 1));
   node_addresses[0].set_tree_index((node_addresses[1].get_tree_index() - 1) >> 1);
   XMSS_Common_Ops::randomize_tree_hash(
      nodes[0], nodes[0], nodes[1], node_addresses[0], this->public_seed(), m_private->hash(), m_xmss_params);
   return nodes[0];
#else
   secure_vector<uint8_t> result;
   tree_hash_subtree(result, start_idx, target_node_height, adrs, m_private->hash());
   return result;
#endif
}

void XMSS_PrivateKey::tree_hash_subtree(secure_vector<uint8_t>& result,
                                        size_t start_idx,
                                        size_t target_node_height,
                                        XMSS_Address& adrs) {
   return tree_hash_subtree(result, start_idx, target_node_height, adrs, m_private->hash());
}

void XMSS_PrivateKey::tree_hash_subtree(
   secure_vector<uint8_t>& result, size_t start_idx, size_t target_node_height, XMSS_Address& adrs, XMSS_Hash& hash) {
   const secure_vector<uint8_t>& seed = this->public_seed();

   std::vector<secure_vector<uint8_t>> nodes(target_node_height + 1,
                                             secure_vector<uint8_t>(XMSS_PublicKey::m_xmss_params.element_size()));

   // node stack, holds all nodes on stack and one extra "pending" node. This
   // temporary node referred to as "node" in the XMSS standard document stays
   // a pending element, meaning it is not regarded as element on the stack
   // until level is increased.
   std::vector<uint8_t> node_levels(target_node_height + 1);

   uint8_t level = 0;  // current level on the node stack.
   const size_t last_idx = (static_cast<size_t>(1) << target_node_height) + start_idx;

   for(size_t i = start_idx; i < last_idx; i++) {
      adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
      adrs.set_ots_address(static_cast<uint32_t>(i));

      XMSS_WOTS_PublicKey pk = this->wots_public_key_for(adrs, hash);

      adrs.set_type(XMSS_Address::Type::LTree_Address);
      adrs.set_ltree_address(static_cast<uint32_t>(i));
      XMSS_Common_Ops::create_l_tree(nodes[level], pk.key_data(), adrs, seed, hash, m_xmss_params);
      node_levels[level] = 0;

      adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
      adrs.set_tree_height(0);
      adrs.set_tree_index(static_cast<uint32_t>(i));

      while(level > 0 && node_levels[level] == node_levels[level - 1]) {
         adrs.set_tree_index(((adrs.get_tree_index() - 1) >> 1));
         XMSS_Common_Ops::randomize_tree_hash(
            nodes[level - 1], nodes[level - 1], nodes[level], adrs, seed, hash, m_xmss_params);
         node_levels[level - 1]++;
         level--;  //Pop stack top element
         adrs.set_tree_height(adrs.get_tree_height() + 1);
      }
      level++;  //push temporary node to stack
   }
   result = nodes[level - 1];
}

XMSS_WOTS_PublicKey XMSS_PrivateKey::wots_public_key_for(XMSS_Address& adrs, XMSS_Hash& hash) const {
   const auto private_key = wots_private_key_for(adrs, hash);
   return XMSS_WOTS_PublicKey(m_private->wots_parameters(), m_public_seed, private_key, adrs, hash);
}

XMSS_WOTS_PrivateKey XMSS_PrivateKey::wots_private_key_for(XMSS_Address& adrs, XMSS_Hash& hash) const {
   switch(wots_derivation_method()) {
      case WOTS_Derivation_Method::NIST_SP800_208:
         return XMSS_WOTS_PrivateKey(
            m_private->wots_parameters(), m_public_seed, m_private->private_seed(), adrs, hash);
      case WOTS_Derivation_Method::Botan2x:
         return XMSS_WOTS_PrivateKey(m_private->wots_parameters(), m_private->private_seed(), adrs, hash);
   }

   throw Invalid_State("WOTS derivation method is out of the enum's range");
}

secure_vector<uint8_t> XMSS_PrivateKey::private_key_bits() const {
   return DER_Encoder().encode(raw_private_key(), ASN1_Type::OctetString).get_contents();
}

size_t XMSS_PrivateKey::reserve_unused_leaf_index() {
   return m_private->reserve_unused_leaf_index();
}

size_t XMSS_PrivateKey::unused_leaf_index() const {
   return m_private->unused_leaf_index();
}

size_t XMSS_PrivateKey::remaining_signatures() const {
   return m_private->remaining_signatures();
}

std::optional<uint64_t> XMSS_PrivateKey::remaining_operations() const {
   return m_private->remaining_signatures();
}

const secure_vector<uint8_t>& XMSS_PrivateKey::prf_value() const {
   return m_private->prf_value();
}

secure_vector<uint8_t> XMSS_PrivateKey::raw_private_key() const {
   return m_private->serialize(raw_public_key());
}

WOTS_Derivation_Method XMSS_PrivateKey::wots_derivation_method() const {
   return m_private->wots_derivation_method();
}

std::unique_ptr<Public_Key> XMSS_PrivateKey::public_key() const {
   return std::make_unique<XMSS_PublicKey>(xmss_parameters().oid(), root(), public_seed());
}

std::unique_ptr<PK_Ops::Signature> XMSS_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                         PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);
   options.exclude_provider();
   options.validate_for_hash_based_signature(m_private->hash().hash_function());
   return std::make_unique<XMSS_Signature_Operation>(*this);
}

}  // namespace Botan

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
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss.h>
#include <botan/internal/xmss_signature_operation.h>
#include <botan/internal/xmss_index_registry.h>
#include <botan/internal/xmss_common_ops.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <iterator>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif

namespace Botan {

namespace {

// fall back to raw decoding for previous versions, which did not encode an OCTET STRING
secure_vector<uint8_t> extract_raw_key(const secure_vector<uint8_t>& key_bits)
   {
   secure_vector<uint8_t> raw_key;
   try
      {
      BER_Decoder(key_bits).decode(raw_key, OCTET_STRING);
      }
   catch(Decoding_Error&)
      {
      raw_key = key_bits;
      }
   return raw_key;
   }

}

XMSS_PrivateKey::XMSS_PrivateKey(const secure_vector<uint8_t>& key_bits)
   : XMSS_PublicKey(unlock(key_bits)),
     m_wots_priv_key(m_wots_params.oid(), m_public_seed),
     m_hash(xmss_hash_function()),
     m_index_reg(XMSS_Index_Registry::get_instance())
   {
   /*
   The code requires sizeof(size_t) >= ceil(tree_height / 8)

   Maximum supported tree height is 20, ceil(20/8) == 3, so 4 byte
   size_t is sufficient for all defined parameters, or even a
   (hypothetical) tree height 32, which would be extremely slow to
   compute.
   */
   static_assert(sizeof(size_t) >= 4, "size_t is big enough to support leaf index");

   secure_vector<uint8_t> raw_key = extract_raw_key(key_bits);

   if(raw_key.size() != XMSS_PrivateKey::size())
      {
      throw Decoding_Error("Invalid XMSS private key size");
      }

   // extract & copy unused leaf index from raw_key
   uint64_t unused_leaf = 0;
   auto begin = (raw_key.begin() + XMSS_PublicKey::size());
   auto end = raw_key.begin() + XMSS_PublicKey::size() + sizeof(uint32_t);

   for(auto& i = begin; i != end; i++)
      {
      unused_leaf = ((unused_leaf << 8) | *i);
      }

   if(unused_leaf >= (1ull << XMSS_PublicKey::m_xmss_params.tree_height()))
      {
      throw Decoding_Error("XMSS private key leaf index out of bounds");
      }

   begin = end;
   end = begin + XMSS_PublicKey::m_xmss_params.element_size();
   m_prf.clear();
   m_prf.reserve(XMSS_PublicKey::m_xmss_params.element_size());
   std::copy(begin, end, std::back_inserter(m_prf));

   begin = end;
   end = begin + m_wots_params.element_size();
   m_wots_priv_key.set_private_seed(secure_vector<uint8_t>(begin, end));
   set_unused_leaf_index(static_cast<size_t>(unused_leaf));
   }

XMSS_PrivateKey::XMSS_PrivateKey(
   XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
   RandomNumberGenerator& rng)
   : XMSS_PublicKey(xmss_algo_id, rng),
     m_wots_priv_key(XMSS_PublicKey::m_xmss_params.ots_oid(),
                     public_seed(),
                     rng),
     m_hash(xmss_hash_function()),
     m_prf(rng.random_vec(XMSS_PublicKey::m_xmss_params.element_size())),
     m_index_reg(XMSS_Index_Registry::get_instance())
   {
   XMSS_Address adrs;
   set_root(tree_hash(0,
                      XMSS_PublicKey::m_xmss_params.tree_height(),
                      adrs));
   }


XMSS_PrivateKey::XMSS_PrivateKey(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                                 size_t idx_leaf,
                                 const secure_vector<uint8_t>& wots_priv_seed,
                                 const secure_vector<uint8_t>& prf,
                                 const secure_vector<uint8_t>& root,
                                 const secure_vector<uint8_t>& public_seed)
   : XMSS_PublicKey(xmss_algo_id, root, public_seed),
     m_wots_priv_key(XMSS_PublicKey::m_xmss_params.ots_oid(),
                     public_seed,
                     wots_priv_seed),
     m_hash(XMSS_PublicKey::m_xmss_params.hash_function_name()),
     m_prf(prf),
     m_index_reg(XMSS_Index_Registry::get_instance())
   {
   set_unused_leaf_index(idx_leaf);
   }

secure_vector<uint8_t>
XMSS_PrivateKey::tree_hash(size_t start_idx,
                           size_t target_node_height,
                           XMSS_Address& adrs)
   {
   BOTAN_ASSERT_NOMSG(target_node_height <= 30);
   BOTAN_ASSERT((start_idx % (static_cast<size_t>(1) << target_node_height)) == 0,
                "Start index must be divisible by 2^{target node height}.");

#if defined(BOTAN_HAS_THREAD_UTILS)
   // dertermine number of parallel tasks to split the tree_hashing into.

   Thread_Pool& thread_pool = Thread_Pool::global_instance();

   const size_t split_level = std::min(target_node_height, thread_pool.worker_count());

   // skip parallelization overhead for leaf nodes.
   if(split_level == 0)
      {
      secure_vector<uint8_t> result;
      tree_hash_subtree(result, start_idx, target_node_height, adrs);
      return result;
      }

   const size_t subtrees = static_cast<size_t>(1) << split_level;
   const size_t last_idx = (static_cast<size_t>(1) << (target_node_height)) + start_idx;
   const size_t offs = (last_idx - start_idx) / subtrees;
   // this cast cannot overflow because target_node_height is limited
   uint8_t level = static_cast<uint8_t>(split_level); // current level in the tree

   BOTAN_ASSERT((last_idx - start_idx) % subtrees == 0,
                "Number of worker threads in tree_hash need to divide range "
                "of calculated nodes.");

   std::vector<secure_vector<uint8_t>> nodes(
       subtrees,
       secure_vector<uint8_t>(XMSS_PublicKey::m_xmss_params.element_size()));
   std::vector<XMSS_Address> node_addresses(subtrees, adrs);
   std::vector<XMSS_Hash> xmss_hash(subtrees, m_hash);
   std::vector<std::future<void>> work;

   // Calculate multiple subtrees in parallel.
   for(size_t i = 0; i < subtrees; i++)
      {
      using tree_hash_subtree_fn_t =
         void (XMSS_PrivateKey::*)(secure_vector<uint8_t>&,
                                   size_t,
                                   size_t,
                                   XMSS_Address&,
                                   XMSS_Hash&);

      tree_hash_subtree_fn_t work_fn = &XMSS_PrivateKey::tree_hash_subtree;

      work.push_back(thread_pool.run(
                        work_fn,
                        this,
                        std::ref(nodes[i]),
                        start_idx + i * offs,
                        target_node_height - split_level,
                        std::ref(node_addresses[i]),
                        std::ref(xmss_hash[i])));
      }

   for(auto& w : work)
      {
      w.get();
      }
   work.clear();

   // Parallelize the top tree levels horizontally
   while(level-- > 1)
      {
      std::vector<secure_vector<uint8_t>> ro_nodes(
         nodes.begin(), nodes.begin() + (static_cast<size_t>(1) << (level+1)));

      for(size_t i = 0; i < (static_cast<size_t>(1) << level); i++)
         {
         BOTAN_ASSERT_NOMSG(xmss_hash.size() > i);

         node_addresses[i].set_tree_height(static_cast<uint32_t>(target_node_height - (level + 1)));
         node_addresses[i].set_tree_index(
            (node_addresses[2 * i + 1].get_tree_index() - 1) >> 1);

         work.push_back(thread_pool.run(
               &XMSS_Common_Ops::randomize_tree_hash,
               std::ref(nodes[i]),
               std::cref(ro_nodes[2 * i]),
               std::cref(ro_nodes[2 * i + 1]),
               std::ref(node_addresses[i]),
               std::cref(this->public_seed()),
               std::ref(xmss_hash[i]),
               std::cref(m_xmss_params)));
         }

      for(auto &w : work)
         {
         w.get();
         }
      work.clear();
      }

   // Avoid creation an extra thread to calculate root node.
   node_addresses[0].set_tree_height(static_cast<uint32_t>(target_node_height - 1));
   node_addresses[0].set_tree_index(
      (node_addresses[1].get_tree_index() - 1) >> 1);
   XMSS_Common_Ops::randomize_tree_hash(nodes[0],
                                        nodes[0],
                                        nodes[1],
                                        node_addresses[0],
                                        this->public_seed(),
                                        m_hash,
                                        m_xmss_params);
   return nodes[0];
#else
   secure_vector<uint8_t> result;
   tree_hash_subtree(result, start_idx, target_node_height, adrs, m_hash);
   return result;
#endif
   }

void
XMSS_PrivateKey::tree_hash_subtree(secure_vector<uint8_t>& result,
                                   size_t start_idx,
                                   size_t target_node_height,
                                   XMSS_Address& adrs,
                                   XMSS_Hash& hash)
   {
   const secure_vector<uint8_t>& seed = this->public_seed();

   std::vector<secure_vector<uint8_t>> nodes(
      target_node_height + 1,
      secure_vector<uint8_t>(XMSS_PublicKey::m_xmss_params.element_size()));

   // node stack, holds all nodes on stack and one extra "pending" node. This
   // temporary node referred to as "node" in the XMSS standard document stays
   // a pending element, meaning it is not regarded as element on the stack
   // until level is increased.
   std::vector<uint8_t> node_levels(target_node_height + 1);

   uint8_t level = 0; // current level on the node stack.
   XMSS_WOTS_PublicKey pk(m_wots_priv_key.wots_parameters().oid(), seed);
   const size_t last_idx = (static_cast<size_t>(1) << target_node_height) + start_idx;

   for(size_t i = start_idx; i < last_idx; i++)
      {
      adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
      adrs.set_ots_address(static_cast<uint32_t>(i));
      this->wots_private_key().generate_public_key(
         pk,
         // getWOTS_SK(SK, s + i), reference implementation uses adrs
         // instead of zero padded index s + i.
         this->wots_private_key().at(adrs, hash),
         adrs,
         hash);
      adrs.set_type(XMSS_Address::Type::LTree_Address);
      adrs.set_ltree_address(static_cast<uint32_t>(i));
      XMSS_Common_Ops::create_l_tree(nodes[level], pk, adrs, seed, hash, m_xmss_params);
      node_levels[level] = 0;

      adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
      adrs.set_tree_height(0);
      adrs.set_tree_index(static_cast<uint32_t>(i));

      while(level > 0 && node_levels[level] ==
            node_levels[level - 1])
         {
         adrs.set_tree_index(((adrs.get_tree_index() - 1) >> 1));
         XMSS_Common_Ops::randomize_tree_hash(nodes[level - 1],
                                              nodes[level - 1],
                                              nodes[level],
                                              adrs,
                                              seed,
                                              hash,
                                              m_xmss_params);
         node_levels[level - 1]++;
         level--; //Pop stack top element
         adrs.set_tree_height(adrs.get_tree_height() + 1);
         }
      level++; //push temporary node to stack
      }
   result = nodes[level - 1];
   }

secure_vector<uint8_t> XMSS_PrivateKey::private_key_bits() const
   {
   return DER_Encoder().encode(raw_private_key(), OCTET_STRING).get_contents();
   }

std::shared_ptr<Atomic<size_t>>
XMSS_PrivateKey::recover_global_leaf_index() const
   {
   BOTAN_ASSERT(m_wots_priv_key.private_seed().size() ==
                XMSS_PublicKey::m_xmss_params.element_size() &&
                m_prf.size() == XMSS_PublicKey::m_xmss_params.element_size(),
                "Trying to retrieve index for partially initialized key");
   return m_index_reg.get(m_wots_priv_key.private_seed(), m_prf);
   }

void XMSS_PrivateKey::set_unused_leaf_index(size_t idx)
   {
   if(idx >= (1ull << XMSS_PublicKey::m_xmss_params.tree_height()))
      {
      throw Decoding_Error("XMSS private key leaf index out of bounds");
      }
   else
      {
      std::atomic<size_t>& index =
         static_cast<std::atomic<size_t>&>(*recover_global_leaf_index());
      size_t current = 0;

      do
         {
         current = index.load();
         if(current > idx)
            { return; }
         }
      while(!index.compare_exchange_strong(current, idx));
      }
   }

size_t XMSS_PrivateKey::reserve_unused_leaf_index()
   {
   size_t idx = (static_cast<std::atomic<size_t>&>(
                    *recover_global_leaf_index())).fetch_add(1);
   if(idx >= (1ull << XMSS_PublicKey::m_xmss_params.tree_height()))
      {
      throw Decoding_Error("XMSS private key, one time signatures exhaused");
      }
   return idx;
   }

size_t XMSS_PrivateKey::unused_leaf_index() const
   {
   return *recover_global_leaf_index();
   }

secure_vector<uint8_t> XMSS_PrivateKey::raw_private_key() const
   {
   std::vector<uint8_t> pk { raw_public_key() };
   secure_vector<uint8_t> result(pk.begin(), pk.end());
   result.reserve(size());

   for(int i = 3; i >= 0; i--)
      {
      result.push_back(
         static_cast<uint8_t>(
            static_cast<uint64_t>(unused_leaf_index()) >> 8 * i));
      }

   std::copy(m_prf.begin(), m_prf.end(), std::back_inserter(result));
   std::copy(m_wots_priv_key.private_seed().begin(),
             m_wots_priv_key.private_seed().end(),
             std::back_inserter(result));

   return result;
   }

std::unique_ptr<PK_Ops::Signature>
XMSS_PrivateKey::create_signature_op(RandomNumberGenerator&,
                                     const std::string&,
                                     const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(
         new XMSS_Signature_Operation(*this));

   throw Provider_Not_Found(algo_name(), provider);
   }

}

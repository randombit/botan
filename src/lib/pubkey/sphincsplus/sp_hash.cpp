/*
 * SPHINCS+ Hashes
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include "botan/assert.h"
#include "botan/hash.h"
#include <botan/exceptn.h>
#include <botan/sp_parameters.h>
#include <botan/assert.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/mgf1.h>
#include <botan/internal/shake.h>
#include <botan/internal/trunc_hash.h>
#include <botan/internal/sha2_32.h>
#include <botan/internal/sha2_64.h>

#include <cstdint>
#include <memory>

namespace Botan {

namespace {

/**
 * Implementation of SPHINCS+ hash function abstraction for SHAKE256
 */
class Shake_Hash_Functions : public Sphincs_Hash_Functions
   {
   private:
      HashFunction& tweak_hash(const SphincsPublicSeed& pub_seed,
                               const Sphincs_Address& address,
                               size_t input_length) override
         {
         BOTAN_UNUSED(input_length);

         // TODO: It might be worthwhile to pre-calculate the hash state with
         //       pub_seed already applied. (That's what the ref impl does, too.)
         m_hash.update(pub_seed);
         address.apply_to_hash(m_hash);
         return m_hash;
         }

   public:
      Shake_Hash_Functions(const Sphincs_Parameters& sphincs_params)
      : m_hash(sphincs_params.n() * 8)
      , m_h_msg_hash(8 * sphincs_params.h_msg_digest_bytes())
      , m_sphincs_params(sphincs_params)
         {
         }

      // TODO: Some logic to base class
      std::pair<uint64_t, uint32_t>
      H_msg(std::span<uint8_t> out_message_hash,
            const std::span<const uint8_t> r,
            const SphincsPublicSeed& pub_seed,
            const std::vector<uint8_t>& root,
            const std::vector<uint8_t>& message) override
         {
         m_h_msg_hash.update(r);
         m_h_msg_hash.update(pub_seed);
         m_h_msg_hash.update(root);
         m_h_msg_hash.update(message);

         std::vector<uint8_t> digest = m_h_msg_hash.final_stdvec();
         std::copy(digest.begin(), digest.begin() + m_sphincs_params.fors_message_bytes(),
                   out_message_hash.begin());

         auto tree_bytes_loc = std::span(digest).subspan(m_sphincs_params.fors_message_bytes(),
                                                         m_sphincs_params.tree_digest_bytes());

         const uint64_t tree_idx_bits = m_sphincs_params.tree_height() * (m_sphincs_params.d() - 1);
         std::vector<uint8_t> tree_idx_bytes(8 - m_sphincs_params.tree_digest_bytes(), 0);
         tree_idx_bytes.insert(tree_idx_bytes.end(), tree_bytes_loc.begin(), tree_bytes_loc.end());
         uint64_t tree_idx = load_be<uint64_t>(tree_idx_bytes.data(), 0);
         tree_idx &= (~static_cast<uint64_t>(0)) >> (64 - tree_idx_bits);

         const uint32_t leaf_idx_bits = m_sphincs_params.tree_height();
         auto leaf_idx_loc = std::span(digest).subspan(m_sphincs_params.fors_message_bytes() + m_sphincs_params.tree_digest_bytes(),
                                                       m_sphincs_params.tree_digest_bytes());
         std::vector<uint8_t> leaf_idx_bytes(4 - m_sphincs_params.leaf_digest_bytes(), 0);
         leaf_idx_bytes.insert(leaf_idx_bytes.end(), leaf_idx_loc.begin(), leaf_idx_loc.end());
         uint32_t leaf_idx = load_be<uint32_t>(leaf_idx_bytes.data(), 0);
         leaf_idx &= (~static_cast<uint32_t>(0)) >> (32 - leaf_idx_bits);

         return std::make_pair(tree_idx, leaf_idx);
         }

      void PRF_msg(std::span<uint8_t> out_r,
                   const SphincsSecretPRF& sk_prf,
                   const SphincsOptionalRandomness& opt_rand,
                   std::span<const uint8_t> in) override
         {
         m_hash.update(sk_prf);
         m_hash.update(opt_rand);
         m_hash.update(in);
         m_hash.final(out_r);
         }

   private:
      SHAKE_256 m_hash;
      SHAKE_256 m_h_msg_hash;
      const Sphincs_Parameters& m_sphincs_params;
   };

/**
 * Implementation of SPHINCS+ hash function abstraction for SHA2
 */
class Sha2_Hash_Functions : public Sphincs_Hash_Functions
   {
   private:
      HashFunction& tweak_hash(const SphincsPublicSeed& pub_seed,
                               const Sphincs_Address& address,
                               size_t input_length) override
         {
         // Depending on the input length we decide to use SHA-256 (Function F in the spec)
         // or SHA-X (Function T_l and H in the spec).
         auto& hash = (input_length > m_sphincs_params.n()) ? *m_sha_x : *m_sha_256;
         const auto& padding = (input_length > m_sphincs_params.n()) ? m_padding_x : m_padding_256;

         // TODO: Pre-Compute Hash state after Hash(pub_seed || padding) and
         //       reuse instead of re-calculating this hash application for
         //       every invoctation. Change Sphincs_Hash_Functions::create()
         //       interface to take pub_seed to allow doing that.
         hash.update(pub_seed);
         hash.update(padding);

         address.apply_to_hash_compressed(hash);

         return hash;
         }

   public:
      Sha2_Hash_Functions(const Sphincs_Parameters& sphincs_params)
         : m_sphincs_params(sphincs_params)
         , m_padding_256(64 - sphincs_params.n(), '\0')
         {
         if(sphincs_params.n() == 16)
            {
            m_sha_x = std::make_unique<Truncated_Hash>(std::make_unique<SHA_256>(), sphincs_params.n() * 8);
            m_padding_x = m_padding_256;
            }
         else
            {
            BOTAN_ASSERT_NOMSG(sphincs_params.n() <= 128);
            m_sha_x = std::make_unique<Truncated_Hash>(std::make_unique<SHA_512>(), sphincs_params.n() * 8);
            m_padding_x = std::vector<uint8_t> (128 - sphincs_params.n(), '\0');
            }

         if (m_sphincs_params.n() < 32)
            {
            m_sha_256 = std::make_unique<Truncated_Hash>(std::make_unique<SHA_256>(), m_sphincs_params.n() * 8);
            }
         else
            {
            m_sha_256 = std::make_unique<SHA_256>();
            }

         }

      std::pair<uint64_t, uint32_t>
      H_msg(std::span<uint8_t> out_message_hash,
            const std::span<const uint8_t> r,
            const SphincsPublicSeed& pub_seed,
            const std::vector<uint8_t>& root,
            const std::vector<uint8_t>& message) override
         {
         throw Not_Implemented("H_msg to be implemented for SHA-2");
         }

      void PRF_msg(std::span<uint8_t> out_r,
                   const SphincsSecretPRF& sk_prf,
                   const SphincsOptionalRandomness& opt_rand,
                   std::span<const uint8_t> in) override
         {
         // TODO
         throw Not_Implemented("PRF_msg to be implemented for SHA-2");
         }


   private:
      const Sphincs_Parameters& m_sphincs_params;
      std::unique_ptr<HashFunction> m_sha_256;
      std::unique_ptr<HashFunction> m_sha_x;
      std::vector<uint8_t> m_padding_256;
      std::vector<uint8_t> m_padding_x;
   };


}

std::unique_ptr<Sphincs_Hash_Functions> Sphincs_Hash_Functions::create(const Sphincs_Parameters& sphincs_params)
   {
   switch(sphincs_params.hash_type())
      {
      case Sphincs_Hash_Type::Sha256:
         return std::make_unique<Sha2_Hash_Functions>(sphincs_params);
      case Sphincs_Hash_Type::Haraka:
         throw Not_Implemented("Haraka is not yet implemented");
      case Sphincs_Hash_Type::Shake256:
         return std::make_unique<Shake_Hash_Functions>(sphincs_params);
      }

   Botan::unreachable();
   }

}

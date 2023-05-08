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
      Shake_Hash_Functions(const Sphincs_Parameters& sphincs_params) : m_hash(sphincs_params.n() * 8) {}

      void PRF_msg(std::span<uint8_t> out,
                   const SphincsSecretPRF& sk_prf,
                   const SphincsOptionalRandomness& opt_rand,
                   std::span<const uint8_t> in) override
         {
         m_hash.update(sk_prf);
         m_hash.update(opt_rand);
         m_hash.update(in);
         m_hash.final(out);
         }

      SHAKE_256 m_hash;
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

      void PRF_msg(std::span<uint8_t> out,
                   const SphincsSecretPRF& sk_prf,
                   const SphincsOptionalRandomness& opt_rand,
                   std::span<const uint8_t> in) override
         {
         // TODO
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

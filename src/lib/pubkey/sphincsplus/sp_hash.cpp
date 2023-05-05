/*
 * SPHINCS+ Hashes
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include "botan/hash.h"
#include <botan/exceptn.h>
#include <botan/sp_parameters.h>
#include <botan/assert.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/mgf1.h>
#include <botan/internal/shake.h>
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
      void tweak_hash(const SphincsPublicSeed& pub_seed,
                      const Sphincs_Address& address)
         {
         // TODO: It might be worthwhile to pre-calculate the hash state with
         //       pub_seed already applied. (That's what the ref impl does, too.)
         m_hash.update(pub_seed);
         address.apply_to_hash(m_hash);
         }

   public:
      Shake_Hash_Functions(const Sphincs_Parameters& sphincs_params) : m_hash(sphincs_params.n() * 8) {}

      void PRF(std::span<uint8_t> out,
               const SphincsPublicSeed& pub_seed,
               const SphincsSecretSeed& sk_seed,
               const Sphincs_Address& address) override
         {
         tweak_hash(pub_seed, address);
         m_hash.update(sk_seed);
         m_hash.final(out);
         }

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

      void F(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             std::span<const uint8_t> in1) override
         {
         T(out, pub_seed, address, in1);
         }

      void H(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             std::span<const uint8_t> in1,
             std::span<const uint8_t> in2) override
         {
         tweak_hash(pub_seed, address);
         m_hash.update(in1);
         m_hash.update(in2);
         m_hash.final(out);
         }

      void T(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             std::span<const uint8_t> in) override
         {
         tweak_hash(pub_seed, address);
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
      //TODO: Integrate with padded versions for sha2
      void tweak_hash(const SphincsPublicSeed& pub_seed,
                      const Sphincs_Address& address)
         {
         m_sha_256.update(pub_seed);
         address.apply_to_hash(m_sha_256);
         }

   public:
      Sha2_Hash_Functions(const Sphincs_Parameters& sphincs_params)
         : m_sphincs_params(sphincs_params)
         {
         if(sphincs_params.n() == 16)
            {
            m_sha_x = std::make_unique<SHA_256>();
            m_pk_block_size_h = 64;
            }
         else
            {
            m_sha_x = std::make_unique<SHA_512>();
            m_pk_block_size_h = 128;
            }

         }

      void PRF(std::span<uint8_t> out,
               const SphincsPublicSeed& pub_seed,
               const SphincsSecretSeed& sk_seed,
               const Sphincs_Address& address) override
         {
         std::vector<uint8_t> padded_pub_seed(pub_seed.get());
         padded_pub_seed.resize(m_pk_block_size_256, 0);
         m_sha_256.update(padded_pub_seed);
         address.apply_to_hash_compressed(m_sha_256);
         m_sha_256.update(sk_seed);
         std::vector out_full = m_sha_256.final();
         std::copy(out_full.begin(), out_full.begin() + m_sphincs_params.n(), out.begin());
         }

      void PRF_msg(std::span<uint8_t> out,
                   const SphincsSecretPRF& sk_prf,
                   const SphincsOptionalRandomness& opt_rand,
                   std::span<const uint8_t> in) override
         {
         // TODO
         }

      void F(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             std::span<const uint8_t> in1) override
         {
         std::vector<uint8_t> padded_pub_seed(pub_seed.get());
         padded_pub_seed.resize(m_pk_block_size_256, 0);
         m_sha_256.update(padded_pub_seed);

         address.apply_to_hash_compressed(m_sha_256);
         m_sha_256.update(in1);

         std::vector out_full = m_sha_256.final();
         std::copy(out_full.begin(), out_full.begin() + m_sphincs_params.n(), out.begin());
         }

      void H(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             std::span<const uint8_t> in1,
             std::span<const uint8_t> in2) override
         {
         std::vector<uint8_t> padded_pub_seed(pub_seed.get());
         padded_pub_seed.resize(m_pk_block_size_h, 0);
         m_sha_x->update(padded_pub_seed);

         address.apply_to_hash_compressed(*m_sha_x);
         m_sha_x->update(in1);
         m_sha_x->update(in2);

         std::vector out_full = m_sha_x->final();
         std::copy(out_full.begin(), out_full.begin() + m_sphincs_params.n(), out.begin());
         }

      void T(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             std::span<const uint8_t> in) override
         {
         // TODO: Precompute padded public seed
         std::vector<uint8_t> padded_pub_seed(pub_seed.get());
         padded_pub_seed.resize(m_pk_block_size_h, 0);
         m_sha_x->update(padded_pub_seed);

         address.apply_to_hash_compressed(*m_sha_x);
         m_sha_x->update(in);

         std::vector out_full = m_sha_x->final();
         std::copy(out_full.begin(), out_full.begin() + m_sphincs_params.n(), out.begin());
         }

   private:
      //SHAKE_256 m_hash;
      SHA_256 m_sha_256;
      std::unique_ptr<HashFunction> m_sha_x;
      size_t m_pk_block_size_h;
      const Sphincs_Parameters& m_sphincs_params;

      const size_t m_pk_block_size_256 = 64;
   };


}


// Sphincs_Hash_Functions::Sphincs_Hash_Functions(const Sphincs_Parameters& params):
// m_sphincs_params(params)
//    {
//    switch(params.hash_type())
//       {
//       case Sphincs_Hash_Type::Sha256:
//          m_hash = HashFunction::create_or_throw("SHA-256");
//          if(m_sphincs_params.n() == 16)
//             m_h_hash = HashFunction::create_or_throw("SHA-256");
//          else
//             m_h_hash = HashFunction::create_or_throw("SHA-512");
//          break;
//       case Sphincs_Hash_Type::Haraka:
//          throw Not_Implemented("XOF based on Haraka is not yet implemented");
//       case Sphincs_Hash_Type::Shake256:
//          m_hash = HashFunction::create_or_throw(params.hash_name());
//          m_h_hash = HashFunction::create_or_throw(params.hash_name());
//          break;
//       }
//    //m_hash = HashFunction::create_or_throw(params.hash_name());
//    }

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

// void Sphincs_Hash_Functions::PRF(std::span<uint8_t> out,
//                                  const SphincsPublicSeed& pub_seed,
//                                  const SphincsSecretSeed& sk_seed,
//                                  const Sphincs_Address& address)
//    {
//    // TODO: Optimization potential: We could pre-compute the internal hash state of pub_seed
//    //       and avoid re-calculating this for each hash application.

//    // TODO: Separate SHA-2 and SHAKE
//    if(m_sphincs_params.hash_type() == Sphincs_Hash_Type::Sha256)
//       {
//       std::vector<uint8_t> padded_pub_seed(pub_seed.get());
//       padded_pub_seed.resize(padded_pub_seed.size() + 64 - m_sphincs_params.n());
//       m_hash->update(padded_pub_seed);
//       address.apply_to_hash_compressed(*m_hash);
//       m_hash->update(sk_seed);
//       std::vector out_full = m_hash->final();
//       std::copy(out_full.begin(), out_full.begin() + m_sphincs_params.n(), out.begin());
//       }
//    else
//       {
//       m_hash->update(pub_seed);
//       address.apply_to_hash(*m_hash);
//       m_hash->update(sk_seed);
//       m_hash->final(out);
//       }
//    }

// void Sphincs_Hash_Functions::PRF_msg(std::span<uint8_t> out,
//                                      const SphincsSecretPRF& sk_prf,
//                                      const SphincsOptionalRandomness& opt_rand,
//                                      std::span<const uint8_t> in)
//    {
//    m_hash->update(sk_prf);
//    m_hash->update(opt_rand);
//    m_hash->update(in);
//    m_hash->final(out);
//    }


// void Sphincs_Hash_Functions::F(std::span<uint8_t> out,
//                                const SphincsPublicSeed& pub_seed,
//                                const Sphincs_Address& address,
//                                std::span<const uint8_t> in1)
//    {
//    auto& tweaked_hash = T(pub_seed, address, m_hash.get());
//    tweaked_hash.update(in1);

//    if(m_sphincs_params.hash_type() == Sphincs_Hash_Type::Sha256)
//       {
//       std::vector out_full = m_hash->final();
//       std::copy(out_full.begin(), out_full.begin() + m_sphincs_params.n(), out.begin());
//       }
//    else
//       {
//       m_hash->final(out);
//       }

//    }

// void Sphincs_Hash_Functions::H(std::span<uint8_t> out,
//                                const SphincsPublicSeed& pub_seed,
//                                const Sphincs_Address& address,
//                                std::span<const uint8_t> in1,
//                                std::span<const uint8_t> in2)
//    {
//    auto& tweaked_hash = T(pub_seed, address, m_h_hash.get());
//    tweaked_hash.update(in1);
//    tweaked_hash.update(in2);

//    if(m_sphincs_params.hash_type() == Sphincs_Hash_Type::Sha256)
//       {
//       std::vector out_full = m_h_hash->final();
//       std::copy(out_full.begin(), out_full.begin() + m_sphincs_params.n(), out.begin());
//       }
//    else
//       {
//       m_h_hash->final(out);
//       }
//    }

// HashFunction& Sphincs_Hash_Functions::T(const SphincsPublicSeed& pub_seed,
//                                         const Sphincs_Address& address,
//                                         HashFunction* hash_function)
//    {
//    // TODO: For SHA the pub_seed must be adapted using "BlockPad()" (see Spec 3.1 p. 40)
//    // TODO: Optimization potential: We could pre-compute the internal hash state of pub_seed
//    //       and avoid re-calculating this for each hash application.
//    if(m_sphincs_params.hash_type() == Sphincs_Hash_Type::Sha256)
//       {
//       size_t padding_length = (m_sphincs_params.n() == 16) ? 64 : 128;
//       std::vector<uint8_t> padded_pub_seed(pub_seed.get());
//       padded_pub_seed.resize(padded_pub_seed.size() + padding_length - m_sphincs_params.n());
//       hash_function->update(padded_pub_seed);
//       address.apply_to_hash_compressed(*hash_function);
//       }
//    else
//       {
//       hash_function->update(pub_seed);
//       address.apply_to_hash(*hash_function);
//       }
//    return *hash_function;
//    }

}

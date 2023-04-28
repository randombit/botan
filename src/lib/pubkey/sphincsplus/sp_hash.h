/*
 * SPHINCS+ Hashes
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_HASH_H_
#define BOTAN_SP_HASH_H_

#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/sp_parameters.h>
#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_types.h>

#include <cstdint>
#include <memory>

namespace Botan {

class StreamCipher;

/**
 * A collection of pseudorandom hash functions required for SPHINCS+
 * computations.
 **/
class Sphincs_Hash_Functions final
   {
   public:
      Sphincs_Hash_Functions(const Sphincs_Parameters& sphincs_params);
      ~Sphincs_Hash_Functions();

   public:
      void PRF(std::span<uint8_t> out,
               const SphincsPublicSeed& pub_seed,
               const SphincsSecretSeed& sk_seed,
               const Sphincs_Address& address);

      void PRF_msg(std::span<uint8_t> out,
                   const SphincsSecretPRF& sk_prf,
                   const SphincsOptionalRandomness& opt_rand,
                   std::span<const uint8_t> in);

      void F(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             std::span<const uint8_t> in1);

      void H(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             std::span<const uint8_t> in1,
             std::span<const uint8_t> in2);

   private:
      /**
       * "tweaks" the hash function and returns a reference to m_hash.
       */
      HashFunction& T(const SphincsPublicSeed& pub_seed,
                      const Sphincs_Address& address);

   private:
      std::unique_ptr<HashFunction> m_hash;
   };



}

#endif

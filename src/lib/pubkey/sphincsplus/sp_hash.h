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
class Sphincs_Hash_Functions
   {
   public:
      virtual ~Sphincs_Hash_Functions() = default;

      static std::unique_ptr<Sphincs_Hash_Functions> create(const Sphincs_Parameters& sphincs_params);

   public:
      virtual void PRF(std::span<uint8_t> out,
                       const SphincsPublicSeed& pub_seed,
                       const SphincsSecretSeed& sk_seed,
                       const Sphincs_Address& address) = 0;

      virtual void PRF_msg(std::span<uint8_t> out,
                           const SphincsSecretPRF& sk_prf,
                           const SphincsOptionalRandomness& opt_rand,
                           std::span<const uint8_t> in) = 0;

      virtual void F(std::span<uint8_t> out,
                     const SphincsPublicSeed& pub_seed,
                     const Sphincs_Address& address,
                     std::span<const uint8_t> in1) = 0;

      virtual void H(std::span<uint8_t> out,
                     const SphincsPublicSeed& pub_seed,
                     const Sphincs_Address& address,
                     std::span<const uint8_t> in1,
                     std::span<const uint8_t> in2) = 0;

      virtual void T(std::span<uint8_t> out,
                     const SphincsPublicSeed& pub_seed,
                     const Sphincs_Address& address,
                     std::span<const uint8_t> in) = 0;
   };



}

#endif

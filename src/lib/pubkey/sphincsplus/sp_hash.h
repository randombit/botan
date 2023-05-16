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
#include <botan/concepts.h>

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

      std::tuple<SphincsHashedMessage, uint64_t, uint32_t>
      H_msg(const SphincsMessageRandomness& r,
            const SphincsPublicSeed& pub_seed,
            const SphincsXmssRootNode& root,
            std::span<const uint8_t> message);

      /**
       * Using SK.PRF, the optional randomness, and a message, computes the message random R,
       * and the tree and leaf indices.
       *
       * @param out_message_hash output location for the message hash
       * @param sk_prf SK.PRF
       * @param opt_rand optional randomness
       * @param msg message
       * @return (tree index, leaf index)
       */
      virtual SphincsMessageRandomness PRF_msg(const SphincsSecretPRF& sk_prf,
                                               const SphincsOptionalRandomness& opt_rand,
                                               std::span<const uint8_t> msg) = 0;

      template<typename... BufferTs>
      void T(std::span<uint8_t> out,
             const SphincsPublicSeed& pub_seed,
             const Sphincs_Address& address,
             BufferTs&&... in)
         {
         auto& hash = tweak_hash(pub_seed, address, (in.size() + ...));
         (hash.update(in), ...);
         hash.final(out);
         }

      void PRF(std::span<uint8_t> out,
               const SphincsPublicSeed& pub_seed,
               const SphincsSecretSeed& sk_seed,
               const Sphincs_Address& address)
         {
         T(out, pub_seed, address, sk_seed);
         }

      virtual std::string msg_hash_function_name() const = 0;

   protected:
      Sphincs_Hash_Functions(const Sphincs_Parameters& sphincs_params);

      /**
       * Prepare the underlying hash function for hashing any given input
       * depending on the expected input length.
       *
       * @param pub_seed      the public seed to use for tweaking
       * @param address       the SPHINCS+ address of the hash to be tweaked
       * @param input_length  the input buffer length that will be processed
       *                      with the tweaked hash (typically N or 2*N)
       * @returns a reference to a Botan::HashFunction that is preconditioned
       *          with the given tweaking parameters.
       *
       * @note Callers are expected to finalize (i.e. reset) the returned
       *       HashFunction after use.
       */
      virtual HashFunction& tweak_hash(const SphincsPublicSeed& pub_seed,
                                       const Sphincs_Address& address,
                                       size_t input_length) = 0;

      virtual std::vector<uint8_t> H_msg_digest(const SphincsMessageRandomness& r,
                                                const SphincsPublicSeed& pub_seed,
                                                const SphincsXmssRootNode& root,
                                                std::span<const uint8_t> message) = 0;

      const Sphincs_Parameters m_sphincs_params;
   };

}

#endif

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
#include <botan/sp_parameters.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_types.h>

namespace Botan {

/**
 * A collection of pseudorandom hash functions required for SPHINCS+
 * computations.
 **/
class BOTAN_TEST_API Sphincs_Hash_Functions {
   public:
      virtual ~Sphincs_Hash_Functions() = default;

      /**
       * Creates a Sphincs_Hash_Functions object instantiating the hash
       * functions used for the specified @p sphincs_params. The @p pub_seed is
       * used to seed the hash functions (possibly padded). This is pre-computed
       * and the respective state is copied on the further calls on H(seed) with
       * tweak_hash, i.e., T and PRF.
       */
      static std::unique_ptr<Sphincs_Hash_Functions> create(const Sphincs_Parameters& sphincs_params,
                                                            const SphincsPublicSeed& pub_seed);

   public:
      std::tuple<SphincsHashedMessage, XmssTreeIndexInLayer, TreeNodeIndex> H_msg(
         StrongSpan<const SphincsMessageRandomness> r, const SphincsTreeNode& root, std::span<const uint8_t> message);

      /**
       * Using SK.PRF, the optional randomness, and a message, computes the message random R,
       * and the tree and leaf indices.
       *
       * @param out output location for the message hash
       * @param sk_prf SK.PRF
       * @param opt_rand optional randomness
       * @param msg message
       */
      virtual void PRF_msg(StrongSpan<SphincsMessageRandomness> out,
                           const SphincsSecretPRF& sk_prf,
                           const SphincsOptionalRandomness& opt_rand,
                           std::span<const uint8_t> msg) = 0;

      template <typename... BufferTs>
      void T(std::span<uint8_t> out, const Sphincs_Address& address, BufferTs&&... in) {
         auto& hash = tweak_hash(address, (std::forward<BufferTs>(in).size() + ...));
         (hash.update(std::forward<BufferTs>(in)), ...);
         hash.final(out);
      }

      template <typename OutT = std::vector<uint8_t>, typename... BufferTs>
      OutT T(const Sphincs_Address& address, BufferTs&&... in) {
         OutT t(m_sphincs_params.n());
         T(t, address, std::forward<BufferTs>(in)...);
         return t;
      }

      void PRF(StrongSpan<ForsLeafSecret> out, const SphincsSecretSeed& sk_seed, const Sphincs_Address& address) {
         T(out, address, sk_seed);
      }

      void PRF(StrongSpan<WotsNode> out, const SphincsSecretSeed& sk_seed, const Sphincs_Address& address) {
         T(out, address, sk_seed);
      }

      virtual std::string msg_hash_function_name() const = 0;

   protected:
      Sphincs_Hash_Functions(const Sphincs_Parameters& sphincs_params, const SphincsPublicSeed& pub_seed);

      /**
       * Prepare the underlying hash function for hashing any given input
       * depending on the expected input length.
       *
       * @param address       the SPHINCS+ address of the hash to be tweaked
       * @param input_length  the input buffer length that will be processed
       *                      with the tweaked hash (typically N or 2*N)
       * @returns a reference to a Botan::HashFunction that is preconditioned
       *          with the given tweaking parameters.
       *
       * @note Callers are expected to finalize (i.e. reset) the returned
       *       HashFunction after use.
       */
      virtual HashFunction& tweak_hash(const Sphincs_Address& address, size_t input_length) = 0;

      virtual std::vector<uint8_t> H_msg_digest(StrongSpan<const SphincsMessageRandomness> r,
                                                const SphincsTreeNode& root,
                                                std::span<const uint8_t> message) = 0;

      const Sphincs_Parameters& m_sphincs_params;
      const SphincsPublicSeed& m_pub_seed;
};

}  // namespace Botan

#endif

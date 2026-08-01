/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_POLYVAL_H_
#define BOTAN_POLYVAL_H_

#include <botan/sym_algo.h>
#include <botan/internal/alignment_buffer.h>

namespace Botan {

/**
* POLYVAL universal hash (RFC 8452), used by AES-GCM-SIV
*
* This is not a secure MAC; it must only be used as a component of a
* construction (like GCM-SIV) which encrypts its output.
*/
class BOTAN_TEST_API Polyval final : public SymmetricAlgorithm {
   private:
      static constexpr size_t BS = 16;

   public:
      void update(std::span<const uint8_t> input);

      /// Zero pad the input to a multiple of the block size
      void zero_pad();

      /// Write the current state to out, and reset the state
      void final(std::span<uint8_t, BS> out);

      Key_Length_Specification key_spec() const override { return Key_Length_Specification(BS); }

      bool has_keying_material() const override;

      void clear() override;

      std::string name() const override { return "Polyval"; }

      std::string provider() const;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      void polyval_multiply(std::span<uint8_t, BS> x, std::span<const uint8_t> input, size_t blocks);

#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
      static void polyval_precompute_cpu(const uint8_t H[16], secure_vector<uint64_t>& H_pow);

      static void polyval_multiply_cpu(uint8_t x[16],
                                       secure_vector<uint64_t>& H_pow,
                                       const uint8_t input[],
                                       size_t blocks);
#endif

#if defined(BOTAN_HAS_GHASH_AVX512_CLMUL)
      static void polyval_precompute_avx512_clmul(const uint8_t H[16], uint64_t H_pow[16 * 2]);

      static void polyval_multiply_avx512_clmul(uint8_t x[16],
                                                const uint64_t H_pow[16 * 2],
                                                const uint8_t input[],
                                                size_t blocks);
#endif

   private:
      AlignmentBuffer<uint8_t, BS> m_buffer;

      /// hash state; in the GHASH byte order if the fallback path is in use
      std::array<uint8_t, BS> m_state{};
      secure_vector<uint64_t> m_HM;
      secure_vector<uint64_t> m_H_pow;
};

}  // namespace Botan

#endif

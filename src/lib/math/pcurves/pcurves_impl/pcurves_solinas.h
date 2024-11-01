/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_SOLINAS_REDC_HELPER_H_
#define BOTAN_PCURVES_SOLINAS_REDC_HELPER_H_

#include <botan/internal/mp_core.h>

namespace Botan {

/*
Helpers for modular reduction of Solinas primes, such as P-256 and P-384.

Instead of explicitly forming the various integers and adding/subtracting them
row-by-row, we compute the entire sum in one pass, column by column. To prevent
overflow/underflow the accumulator is a signed 64-bit integer, while the various
limbs are (at least for all NIST curves aside from P-192) 32 bit integers.

For more background on Solinas primes / Solinas reduction see

* J. Solinas 'Generalized Mersenne Numbers'
  <https://cacr.uwaterloo.ca/techreports/1999/corr99-39.pdf>
* NIST SP 800-186 Appendix G.1
  <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf>
* Handbook of Elliptic And Hyperelliptic Curve Cryptography § 10.4.3

*/

template <WordType W>
constexpr uint32_t get_uint32(const W xw[], size_t i) {
   static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

   if constexpr(WordInfo<W>::bits == 32) {
      return xw[i];
   } else {
      return static_cast<uint32_t>(xw[i / 2] >> ((i % 2) * 32));
   }
}

template <WordType W, size_t N>
class SolinasAccum final {
   public:
      static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

      static constexpr size_t N32 = N * (WordInfo<W>::bits / 32);

      constexpr SolinasAccum(std::array<W, N>& r) : m_r(r), m_S(0), m_idx(0) {}

      constexpr void accum(int64_t v) {
         BOTAN_DEBUG_ASSERT(m_idx < N32);

         m_S += v;
         const uint32_t r = static_cast<uint32_t>(m_S);
         m_S >>= 32;

         if constexpr(WordInfo<W>::bits == 32) {
            m_r[m_idx] = r;
         } else {
            m_r[m_idx / 2] |= static_cast<uint64_t>(r) << (32 * (m_idx % 2));
         }

         m_idx += 1;
      }

      constexpr W final_carry(int64_t C) {
         m_S += C;
         BOTAN_DEBUG_ASSERT(m_S >= 0);
         return static_cast<W>(m_S);
      }

   private:
      std::array<W, N>& m_r;
      int64_t m_S;
      size_t m_idx;
};

}  // namespace Botan

#endif

/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_NIST_REDC_HELPER_H_
#define BOTAN_PCURVES_NIST_REDC_HELPER_H_

#include <botan/internal/mp_core.h>

namespace Botan {

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
class SumAccum {
   public:
      static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

      static constexpr size_t N32 = N * (WordInfo<W>::bits / 32);

      SumAccum(std::array<W, N>& r) : m_r(r), m_S(0), m_idx(0) {}

      void accum(int64_t v) {
         BOTAN_STATE_CHECK(m_idx < N32);

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

      W final_carry(int64_t C) {
         BOTAN_STATE_CHECK(m_idx == N32);
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

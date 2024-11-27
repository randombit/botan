/*
* Classic McEliece GF arithmetic
* Based on the public domain reference implementation by the designers
* (https://classic.mceliece.org/impl.html - released in Oct 2022 for NISTPQC-R4)
*
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/cmce_gf.h>

namespace Botan {

namespace {
// Only for moduli 0b0010000000011011 and 0b0001000000001001
inline CmceGfElem internal_reduce(uint32_t x, CmceGfMod mod) {
   // Optimization for the specific moduli used in Classic McEliece
   // Taken from the reference implementation
   if(mod == 0b0010000000011011) {
      uint32_t t = x & 0x1FF0000;
      x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

      t = x & 0x000E000;
      x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

      return CmceGfElem(x & 0x1fff);
   } else if(mod == 0b0001000000001001) {
      uint32_t t = x & 0x7FC000;
      x ^= t >> 9;
      x ^= t >> 12;

      t = x & 0x3000;
      x ^= t >> 9;
      x ^= t >> 12;

      x &= 0xfff;

      return CmceGfElem(static_cast<uint16_t>(x & 0xfff));
   }
   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace

Classic_McEliece_GF Classic_McEliece_GF::operator*(Classic_McEliece_GF other) const {
   BOTAN_ASSERT_NOMSG(m_modulus == other.m_modulus);

   uint32_t a = m_elem.get();
   uint32_t b = other.m_elem.get();

   uint32_t acc = a * (b & CT::value_barrier<uint32_t>(1));

   for(size_t i = 1; i < log_q(); i++) {
      acc ^= (a * (b & (1 << i)));
   }

   return Classic_McEliece_GF(internal_reduce(acc, m_modulus), m_modulus);
}

Classic_McEliece_GF Classic_McEliece_GF::inv() const {
   // Compute the inverse using fermat's little theorem: a^(q-1) = 1 => a^(q-2) = a^-1

   // exponent = (q-2). This is public information, therefore the workflow is constant time.
   size_t exponent = (size_t(1) << log_q()) - 2;
   Classic_McEliece_GF base = *this;

   // Compute base^exponent using the square-and-multiply algorithm
   Classic_McEliece_GF result = {CmceGfElem(1), m_modulus};
   while(exponent > 0) {
      if(exponent % 2 == 1) {
         // multiply
         result = (result * base);
      }
      // square
      base = base.square();
      exponent /= 2;
   }

   return result;
}

}  // namespace Botan

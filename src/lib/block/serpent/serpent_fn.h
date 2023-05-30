/*
* (C) 1999-2007,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SERPENT_FUNCS_H_
#define BOTAN_SERPENT_FUNCS_H_

#include <botan/types.h>
#include <botan/internal/rotate.h>

namespace Botan::Serpent_F {

template <size_t S>
BOTAN_FORCE_INLINE uint32_t shl(uint32_t v) {
   return v << S;
}

/*
* Serpent's Linear Transform
*/
template <typename T>
BOTAN_FORCE_INLINE void transform(T& B0, T& B1, T& B2, T& B3) {
   B0 = rotl<13>(B0);
   B2 = rotl<3>(B2);
   B1 ^= B0 ^ B2;
   B3 ^= B2 ^ shl<3>(B0);
   B1 = rotl<1>(B1);
   B3 = rotl<7>(B3);
   B0 ^= B1 ^ B3;
   B2 ^= B3 ^ shl<7>(B1);
   B0 = rotl<5>(B0);
   B2 = rotl<22>(B2);
}

/*
* Serpent's Inverse Linear Transform
*/
template <typename T>
BOTAN_FORCE_INLINE void i_transform(T& B0, T& B1, T& B2, T& B3) {
   B2 = rotr<22>(B2);
   B0 = rotr<5>(B0);
   B2 ^= B3 ^ shl<7>(B1);
   B0 ^= B1 ^ B3;
   B3 = rotr<7>(B3);
   B1 = rotr<1>(B1);
   B3 ^= B2 ^ shl<3>(B0);
   B1 ^= B0 ^ B2;
   B2 = rotr<3>(B2);
   B0 = rotr<13>(B0);
}

class Key_Inserter final {
   public:
      Key_Inserter(const uint32_t* RK) : m_RK(RK) {}

      template <typename T>
      inline void operator()(size_t R, T& B0, T& B1, T& B2, T& B3) const {
         B0 ^= m_RK[4 * R];
         B1 ^= m_RK[4 * R + 1];
         B2 ^= m_RK[4 * R + 2];
         B3 ^= m_RK[4 * R + 3];
      }

   private:
      const uint32_t* m_RK;
};

}  // namespace Botan::Serpent_F

#endif

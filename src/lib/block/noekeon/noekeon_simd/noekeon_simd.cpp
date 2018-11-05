/*
* Noekeon in SIMD
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/noekeon.h>
#include <botan/internal/simd_32.h>

namespace Botan {

/*
* Noekeon's Theta Operation
*/
#define NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3)  \
   do {                                                 \
      SIMD_4x32 T = A0 ^ A2;                            \
      T ^= T.rotl<8>() ^ T.rotr<8>();                   \
      A1 ^= T;                                          \
      A3 ^= T;                                          \
                                                        \
      A0 ^= K0;                                         \
      A1 ^= K1;                                         \
      A2 ^= K2;                                         \
      A3 ^= K3;                                         \
                                                        \
      T = A1 ^ A3;                                      \
      T ^= T.rotl<8>() ^ T.rotr<8>();                   \
      A0 ^= T;                                          \
      A2 ^= T;                                          \
      } while(0)

/*
* Noekeon's Gamma S-Box Layer
*/
#define NOK_SIMD_GAMMA(A0, A1, A2, A3)                                  \
   do                                                                   \
      {                                                                 \
      A1 ^= A3.andc(~A2);                                               \
      A0 ^= A2 & A1;                                                    \
                                                                        \
      SIMD_4x32 T = A3;                                                 \
      A3 = A0;                                                          \
      A0 = T;                                                           \
                                                                        \
      A2 ^= A0 ^ A1 ^ A3;                                               \
                                                                        \
      A1 ^= A3.andc(~A2);                                               \
      A0 ^= A2 & A1;                                                    \
      } while(0)

/*
* Noekeon Encryption
*/
void Noekeon::simd_encrypt_4(const uint8_t in[], uint8_t out[]) const
   {
   const SIMD_4x32 K0 = SIMD_4x32::splat(m_EK[0]);
   const SIMD_4x32 K1 = SIMD_4x32::splat(m_EK[1]);
   const SIMD_4x32 K2 = SIMD_4x32::splat(m_EK[2]);
   const SIMD_4x32 K3 = SIMD_4x32::splat(m_EK[3]);

   SIMD_4x32 A0 = SIMD_4x32::load_be(in     );
   SIMD_4x32 A1 = SIMD_4x32::load_be(in + 16);
   SIMD_4x32 A2 = SIMD_4x32::load_be(in + 32);
   SIMD_4x32 A3 = SIMD_4x32::load_be(in + 48);

   SIMD_4x32::transpose(A0, A1, A2, A3);

   for(size_t i = 0; i != 16; ++i)
      {
      A0 ^= SIMD_4x32::splat(RC[i]);

      NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3);

      A1 = A1.rotl<1>();
      A2 = A2.rotl<5>();
      A3 = A3.rotl<2>();

      NOK_SIMD_GAMMA(A0, A1, A2, A3);

      A1 = A1.rotr<1>();
      A2 = A2.rotr<5>();
      A3 = A3.rotr<2>();
      }

   A0 ^= SIMD_4x32::splat(RC[16]);
   NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3);

   SIMD_4x32::transpose(A0, A1, A2, A3);

   A0.store_be(out);
   A1.store_be(out + 16);
   A2.store_be(out + 32);
   A3.store_be(out + 48);
   }

/*
* Noekeon Encryption
*/
void Noekeon::simd_decrypt_4(const uint8_t in[], uint8_t out[]) const
   {
   const SIMD_4x32 K0 = SIMD_4x32::splat(m_DK[0]);
   const SIMD_4x32 K1 = SIMD_4x32::splat(m_DK[1]);
   const SIMD_4x32 K2 = SIMD_4x32::splat(m_DK[2]);
   const SIMD_4x32 K3 = SIMD_4x32::splat(m_DK[3]);

   SIMD_4x32 A0 = SIMD_4x32::load_be(in     );
   SIMD_4x32 A1 = SIMD_4x32::load_be(in + 16);
   SIMD_4x32 A2 = SIMD_4x32::load_be(in + 32);
   SIMD_4x32 A3 = SIMD_4x32::load_be(in + 48);

   SIMD_4x32::transpose(A0, A1, A2, A3);

   for(size_t i = 0; i != 16; ++i)
      {
      NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3);

      A0 ^= SIMD_4x32::splat(RC[16-i]);

      A1 = A1.rotl<1>();
      A2 = A2.rotl<5>();
      A3 = A3.rotl<2>();

      NOK_SIMD_GAMMA(A0, A1, A2, A3);

      A1 = A1.rotr<1>();
      A2 = A2.rotr<5>();
      A3 = A3.rotr<2>();
      }

   NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3);
   A0 ^= SIMD_4x32::splat(RC[0]);

   SIMD_4x32::transpose(A0, A1, A2, A3);

   A0.store_be(out);
   A1.store_be(out + 16);
   A2.store_be(out + 32);
   A3.store_be(out + 48);
   }

}

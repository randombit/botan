/*
* Noekeon in SIMD
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/block_utils.h>
#include <botan/noekeon_simd.h>
#include <botan/internal/simd_32.h>

namespace Botan {

BOTAN_REGISTER_BLOCK_CIPHER_NOARGS_IF(SIMD_32::enabled(), Noekeon_SIMD, "Noekeon",
                                      "simd32", BOTAN_SIMD_ALGORITHM_PRIO);

/*
* Noekeon's Theta Operation
*/
#define NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3)  \
   do {                                                 \
      SIMD_32 T = A0 ^ A2;                              \
      SIMD_32 T_l8 = T;                                 \
      SIMD_32 T_r8 = T;                                 \
      T_l8.rotate_left(8);                              \
      T_r8.rotate_right(8);                             \
      T ^= T_l8;                                        \
      T ^= T_r8;                                        \
      A1 ^= T;                                          \
      A3 ^= T;                                          \
                                                        \
      A0 ^= K0;                                         \
      A1 ^= K1;                                         \
      A2 ^= K2;                                         \
      A3 ^= K3;                                         \
                                                        \
      T = A1 ^ A3;                                      \
      T_l8 = T;                                         \
      T_r8 = T;                                         \
      T_l8.rotate_left(8);                              \
      T_r8.rotate_right(8);                             \
      T ^= T_l8;                                        \
      T ^= T_r8;                                        \
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
      SIMD_32 T = A3;                                                   \
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
void Noekeon_SIMD::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const secure_vector<u32bit>& EK = this->get_EK();

   SIMD_32 K0 = SIMD_32(EK[0]);
   SIMD_32 K1 = SIMD_32(EK[1]);
   SIMD_32 K2 = SIMD_32(EK[2]);
   SIMD_32 K3 = SIMD_32(EK[3]);

   while(blocks >= 4)
      {
      SIMD_32 A0 = SIMD_32::load_be(in     );
      SIMD_32 A1 = SIMD_32::load_be(in + 16);
      SIMD_32 A2 = SIMD_32::load_be(in + 32);
      SIMD_32 A3 = SIMD_32::load_be(in + 48);

      SIMD_32::transpose(A0, A1, A2, A3);

      for(size_t i = 0; i != 16; ++i)
         {
         A0 ^= SIMD_32(RC[i]);

         NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3);

         A1.rotate_left(1);
         A2.rotate_left(5);
         A3.rotate_left(2);

         NOK_SIMD_GAMMA(A0, A1, A2, A3);

         A1.rotate_right(1);
         A2.rotate_right(5);
         A3.rotate_right(2);
         }

      A0 ^= SIMD_32(RC[16]);
      NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3);

      SIMD_32::transpose(A0, A1, A2, A3);

      A0.store_be(out);
      A1.store_be(out + 16);
      A2.store_be(out + 32);
      A3.store_be(out + 48);

      in += 64;
      out += 64;
      blocks -= 4;
      }

   if(blocks)
     Noekeon::encrypt_n(in, out, blocks);
   }

/*
* Noekeon Encryption
*/
void Noekeon_SIMD::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const secure_vector<u32bit>& DK = this->get_DK();

   SIMD_32 K0 = SIMD_32(DK[0]);
   SIMD_32 K1 = SIMD_32(DK[1]);
   SIMD_32 K2 = SIMD_32(DK[2]);
   SIMD_32 K3 = SIMD_32(DK[3]);

   while(blocks >= 4)
      {
      SIMD_32 A0 = SIMD_32::load_be(in     );
      SIMD_32 A1 = SIMD_32::load_be(in + 16);
      SIMD_32 A2 = SIMD_32::load_be(in + 32);
      SIMD_32 A3 = SIMD_32::load_be(in + 48);

      SIMD_32::transpose(A0, A1, A2, A3);

      for(size_t i = 0; i != 16; ++i)
         {
         NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3);

         A0 ^= SIMD_32(RC[16-i]);

         A1.rotate_left(1);
         A2.rotate_left(5);
         A3.rotate_left(2);

         NOK_SIMD_GAMMA(A0, A1, A2, A3);

         A1.rotate_right(1);
         A2.rotate_right(5);
         A3.rotate_right(2);
         }

      NOK_SIMD_THETA(A0, A1, A2, A3, K0, K1, K2, K3);
      A0 ^= SIMD_32(RC[0]);

      SIMD_32::transpose(A0, A1, A2, A3);

      A0.store_be(out);
      A1.store_be(out + 16);
      A2.store_be(out + 32);
      A3.store_be(out + 48);

      in += 64;
      out += 64;
      blocks -= 4;
      }

   if(blocks)
     Noekeon::decrypt_n(in, out, blocks);
   }

}

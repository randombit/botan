/*
* SHACAL-2 using SIMD
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/shacal2.h>
#include <botan/internal/simd_32.h>

namespace Botan {

namespace {

inline
void SHACAL2_Fwd(const SIMD_4x32& A, const SIMD_4x32& B, const SIMD_4x32& C, SIMD_4x32& D,
                 const SIMD_4x32& E, const SIMD_4x32& F, const SIMD_4x32& G, SIMD_4x32& H,
                 uint32_t RK)
   {
   H += E.rho<6,11,25>() + ((E & F) ^ (~E & G)) + SIMD_4x32::splat(RK);
   D += H;
   H += A.rho<2,13,22>() + ((A & B) | ((A | B) & C));
   }

inline
void SHACAL2_Rev(const SIMD_4x32& A, const SIMD_4x32& B, const SIMD_4x32& C, SIMD_4x32& D,
                 const SIMD_4x32& E, const SIMD_4x32& F, const SIMD_4x32& G, SIMD_4x32& H,
                 uint32_t RK)
   {
   H -= A.rho<2,13,22>() + ((A & B) | ((A | B) & C));
   D -= H;
   H -= E.rho<6,11,25>() + ((E & F) ^ (~E & G)) + SIMD_4x32::splat(RK);
   }

}

void SHACAL2::simd_encrypt_4(const uint8_t in[], uint8_t out[]) const
   {
   SIMD_4x32 A = SIMD_4x32::load_be(in);
   SIMD_4x32 E = SIMD_4x32::load_be(in+16);
   SIMD_4x32 B = SIMD_4x32::load_be(in+32);
   SIMD_4x32 F = SIMD_4x32::load_be(in+48);

   SIMD_4x32 C = SIMD_4x32::load_be(in+64);
   SIMD_4x32 G = SIMD_4x32::load_be(in+80);
   SIMD_4x32 D = SIMD_4x32::load_be(in+96);
   SIMD_4x32 H = SIMD_4x32::load_be(in+112);

   SIMD_4x32::transpose(A, B, C, D);
   SIMD_4x32::transpose(E, F, G, H);

   for(size_t r = 0; r != 64; r += 8)
      {
      SHACAL2_Fwd(A, B, C, D, E, F, G, H, m_RK[r+0]);
      SHACAL2_Fwd(H, A, B, C, D, E, F, G, m_RK[r+1]);
      SHACAL2_Fwd(G, H, A, B, C, D, E, F, m_RK[r+2]);
      SHACAL2_Fwd(F, G, H, A, B, C, D, E, m_RK[r+3]);
      SHACAL2_Fwd(E, F, G, H, A, B, C, D, m_RK[r+4]);
      SHACAL2_Fwd(D, E, F, G, H, A, B, C, m_RK[r+5]);
      SHACAL2_Fwd(C, D, E, F, G, H, A, B, m_RK[r+6]);
      SHACAL2_Fwd(B, C, D, E, F, G, H, A, m_RK[r+7]);
      }

   SIMD_4x32::transpose(A, B, C, D);
   SIMD_4x32::transpose(E, F, G, H);

   A.store_be(out);
   E.store_be(out+16);
   B.store_be(out+32);
   F.store_be(out+48);

   C.store_be(out+64);
   G.store_be(out+80);
   D.store_be(out+96);
   H.store_be(out+112);
   }

void SHACAL2::simd_decrypt_4(const uint8_t in[], uint8_t out[]) const
   {
   SIMD_4x32 A = SIMD_4x32::load_be(in);
   SIMD_4x32 E = SIMD_4x32::load_be(in+16);
   SIMD_4x32 B = SIMD_4x32::load_be(in+32);
   SIMD_4x32 F = SIMD_4x32::load_be(in+48);

   SIMD_4x32 C = SIMD_4x32::load_be(in+64);
   SIMD_4x32 G = SIMD_4x32::load_be(in+80);
   SIMD_4x32 D = SIMD_4x32::load_be(in+96);
   SIMD_4x32 H = SIMD_4x32::load_be(in+112);

   SIMD_4x32::transpose(A, B, C, D);
   SIMD_4x32::transpose(E, F, G, H);

   for(size_t r = 0; r != 64; r += 8)
      {
      SHACAL2_Rev(B, C, D, E, F, G, H, A, m_RK[63-r]);
      SHACAL2_Rev(C, D, E, F, G, H, A, B, m_RK[62-r]);
      SHACAL2_Rev(D, E, F, G, H, A, B, C, m_RK[61-r]);
      SHACAL2_Rev(E, F, G, H, A, B, C, D, m_RK[60-r]);
      SHACAL2_Rev(F, G, H, A, B, C, D, E, m_RK[59-r]);
      SHACAL2_Rev(G, H, A, B, C, D, E, F, m_RK[58-r]);
      SHACAL2_Rev(H, A, B, C, D, E, F, G, m_RK[57-r]);
      SHACAL2_Rev(A, B, C, D, E, F, G, H, m_RK[56-r]);
      }

   SIMD_4x32::transpose(A, B, C, D);
   SIMD_4x32::transpose(E, F, G, H);

   A.store_be(out);
   E.store_be(out+16);
   B.store_be(out+32);
   F.store_be(out+48);

   C.store_be(out+64);
   G.store_be(out+80);
   D.store_be(out+96);
   H.store_be(out+112);
   }

}

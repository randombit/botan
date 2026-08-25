/*
* (C) 2010,2016,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KECCAK_PERM_ROUND_H_
#define BOTAN_KECCAK_PERM_ROUND_H_

#include <botan/types.h>
#include <botan/internal/rotate.h>
#include <concepts>

namespace Botan {

alignas(64) inline constexpr uint64_t KECCAK_RC[24] = {
   0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
   0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
   0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
   0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
   0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

/*
* One Keccak-f[1600] round, on plain uint64_t words or on any of the
* SIMD wrapper types, computing several states in parallel with one
* Keccak word per SIMD lane
*/

template <size_t R, typename W>
BOTAN_FORCE_INLINE W keccak_rotl(const W& v) {
   if constexpr(std::unsigned_integral<W>) {
      return rotl<R>(v);
   } else {
      return v.template rotl<R>();
   }
}

template <typename W>
BOTAN_FORCE_INLINE W keccak_chi(const W& x, const W& y, const W& z) {
   if constexpr(std::unsigned_integral<W>) {
      return x ^ (~y & z);
   } else {
      return W::chi(x, y, z);
   }
}

template <typename W>
BOTAN_FORCE_INLINE W keccak_iota(uint64_t rc) {
   if constexpr(std::unsigned_integral<W>) {
      return rc;
   } else {
      return W::splat(rc);
   }
}

template <typename W>
BOTAN_FORCE_INLINE void Keccak_Permutation_round(W T[25], const W A[25], uint64_t RC) {
   const W C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
   const W C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
   const W C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
   const W C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
   const W C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

   const W D0 = keccak_rotl<1>(C0) ^ C3;
   const W D1 = keccak_rotl<1>(C1) ^ C4;
   const W D2 = keccak_rotl<1>(C2) ^ C0;
   const W D3 = keccak_rotl<1>(C3) ^ C1;
   const W D4 = keccak_rotl<1>(C4) ^ C2;

   const W B00 = A[0] ^ D1;
   const W B01 = keccak_rotl<44>(A[6] ^ D2);
   const W B02 = keccak_rotl<43>(A[12] ^ D3);
   const W B03 = keccak_rotl<21>(A[18] ^ D4);
   const W B04 = keccak_rotl<14>(A[24] ^ D0);
   T[0] = keccak_chi(B00, B01, B02) ^ keccak_iota<W>(RC);
   T[1] = keccak_chi(B01, B02, B03);
   T[2] = keccak_chi(B02, B03, B04);
   T[3] = keccak_chi(B03, B04, B00);
   T[4] = keccak_chi(B04, B00, B01);

   const W B05 = keccak_rotl<28>(A[3] ^ D4);
   const W B06 = keccak_rotl<20>(A[9] ^ D0);
   const W B07 = keccak_rotl<3>(A[10] ^ D1);
   const W B08 = keccak_rotl<45>(A[16] ^ D2);
   const W B09 = keccak_rotl<61>(A[22] ^ D3);
   T[5] = keccak_chi(B05, B06, B07);
   T[6] = keccak_chi(B06, B07, B08);
   T[7] = keccak_chi(B07, B08, B09);
   T[8] = keccak_chi(B08, B09, B05);
   T[9] = keccak_chi(B09, B05, B06);

   const W B10 = keccak_rotl<1>(A[1] ^ D2);
   const W B11 = keccak_rotl<6>(A[7] ^ D3);
   const W B12 = keccak_rotl<25>(A[13] ^ D4);
   const W B13 = keccak_rotl<8>(A[19] ^ D0);
   const W B14 = keccak_rotl<18>(A[20] ^ D1);
   T[10] = keccak_chi(B10, B11, B12);
   T[11] = keccak_chi(B11, B12, B13);
   T[12] = keccak_chi(B12, B13, B14);
   T[13] = keccak_chi(B13, B14, B10);
   T[14] = keccak_chi(B14, B10, B11);

   const W B15 = keccak_rotl<27>(A[4] ^ D0);
   const W B16 = keccak_rotl<36>(A[5] ^ D1);
   const W B17 = keccak_rotl<10>(A[11] ^ D2);
   const W B18 = keccak_rotl<15>(A[17] ^ D3);
   const W B19 = keccak_rotl<56>(A[23] ^ D4);
   T[15] = keccak_chi(B15, B16, B17);
   T[16] = keccak_chi(B16, B17, B18);
   T[17] = keccak_chi(B17, B18, B19);
   T[18] = keccak_chi(B18, B19, B15);
   T[19] = keccak_chi(B19, B15, B16);

   const W B20 = keccak_rotl<62>(A[2] ^ D3);
   const W B21 = keccak_rotl<55>(A[8] ^ D4);
   const W B22 = keccak_rotl<39>(A[14] ^ D0);
   const W B23 = keccak_rotl<41>(A[15] ^ D1);
   const W B24 = keccak_rotl<2>(A[21] ^ D2);
   T[20] = keccak_chi(B20, B21, B22);
   T[21] = keccak_chi(B21, B22, B23);
   T[22] = keccak_chi(B22, B23, B24);
   T[23] = keccak_chi(B23, B24, B20);
   T[24] = keccak_chi(B24, B20, B21);
}

}  // namespace Botan

#endif

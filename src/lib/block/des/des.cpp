/*
* DES
* (C) 1999-2008,2018,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/des.h>

#include <botan/compiler.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

template <typename T>
concept BitsliceT = requires(T& a, const T& b) {
   a ^= b;
   a &= b;
   a |= b;
   ~a;
};

/*
* The circuits for the DES sboxes used here were found by Roman Rusakov and
* Solar Designer for use in JtR. The designers explicitly disclaimed all
* copyright with regards to the circuits themselves ("Being mathematical
* formulas, they are not copyrighted and are free for reuse by anyone.")
*
* John The Ripper also contains Sbox circuit descriptions making use of select
* and ternlogd-style instruction sets which are significantly more compact than
* these circuits. Sadly, very few CPUs support such instructions on GPRs.
*/

template <BitsliceT T>
BOTAN_FORCE_INLINE void SBox1(T a1, T a2, T a3, T a4, T a5, T a6, T& out1, T& out2, T& out3, T& out4) {
   const T x1 = a1 & ~a5;
   const T x2 = a4 ^ x1;
   const T x3 = a3 | a6;
   const T x4 = a1 ^ a3;
   const T x5 = x3 & x4;
   const T x6 = a4 ^ x5;
   const T x7 = x6 & ~x2;

   const T x8 = a5 ^ a6;
   const T x9 = a3 ^ x8;
   const T x10 = x2 & ~x9;
   const T x11 = a6 | x5;
   const T x12 = x10 ^ x11;
   const T x13 = x12 & ~x7;

   const T x14 = a1 | a6;
   const T x15 = x12 | x14;
   const T x16 = a5 & ~x6;
   const T x17 = x15 ^ x16;

   const T x18 = a4 & ~x14;
   const T x19 = x16 ^ x18;
   const T x20 = x8 & ~x4;
   const T x21 = x19 | x20;

   const T x22 = a3 & ~x1;
   const T x23 = x2 ^ x15;
   const T x24 = x23 & ~x22;
   const T x25 = ~x24;
   const T x26 = x3 & x12;
   const T x27 = x25 ^ x26;
   const T x28 = x17 & ~a2;
   const T x29 = x28 ^ x27;
   out3 ^= x29;

   const T x30 = x8 ^ x24;
   const T x31 = x16 | x30;
   const T x32 = x3 ^ x31;
   const T x33 = a1 ^ x32;
   const T x34 = x27 ^ x33;
   const T x35 = x7 | a2;
   const T x36 = x35 ^ x34;
   out1 ^= x36;

   const T x37 = x2 & ~x21;
   const T x38 = x30 ^ x37;
   const T x39 = x16 ^ x32;
   const T x40 = x34 & ~x39;
   const T x41 = x38 ^ x40;
   const T x42 = a2 & ~x13;
   const T x43 = x42 ^ x41;
   out2 ^= x43;

   const T x44 = x9 ^ x20;
   const T x45 = x14 ^ x40;
   const T x46 = x45 & ~x44;
   const T x47 = x41 ^ x46;
   const T x48 = x47 | a2;
   const T x49 = x48 ^ x21;
   out4 ^= x49;
}

template <BitsliceT T>
BOTAN_FORCE_INLINE void SBox2(T a1, T a2, T a3, T a4, T a5, T a6, T& out1, T& out2, T& out3, T& out4) {
   const T x1 = a2 ^ a5;

   const T x2 = a1 & ~a6;
   const T x3 = a5 & ~x2;
   const T x4 = a2 | x3;

   const T x5 = x1 & ~a6;
   const T x6 = a1 & x1;
   const T x7 = a5 ^ x6;
   const T x8 = x7 & ~x5;

   const T x9 = a3 & a6;
   const T x10 = x3 ^ x5;
   const T x11 = x4 & x10;
   const T x12 = x11 & ~x9;

   const T x13 = a3 & x11;
   const T x14 = ~a1;
   const T x15 = x13 ^ x14;
   const T x16 = a6 ^ x1;
   const T x17 = x16 & ~x9;
   const T x18 = x15 ^ x17;
   const T x19 = a4 & ~x12;
   const T x20 = x19 ^ x18;
   out2 ^= x20;

   const T x21 = a2 & ~x17;
   const T x22 = x7 ^ x21;
   const T x23 = x15 & ~x22;
   const T x24 = a3 ^ x16;
   const T x25 = x23 ^ x24;
   const T x26 = x4 & ~a4;
   const T x27 = x26 ^ x25;
   out1 ^= x27;

   const T x28 = a2 & ~x9;
   const T x29 = x24 | x28;
   const T x30 = x4 ^ x18;
   const T x31 = x9 | x30;
   const T x32 = x29 ^ x31;

   const T x33 = x11 ^ x18;
   const T x34 = x25 ^ x33;
   const T x35 = x31 & x34;
   const T x36 = x1 & x29;
   const T x37 = x35 ^ x36;
   const T x38 = x37 | a4;
   const T x39 = x38 ^ x32;
   out3 ^= x39;

   const T x40 = x37 & ~x22;
   const T x41 = x16 | x30;
   const T x42 = x40 ^ x41;
   const T x43 = x8 | a4;
   const T x44 = x43 ^ x42;
   out4 ^= x44;
}

template <BitsliceT T>
BOTAN_FORCE_INLINE void SBox3(T a1, T a2, T a3, T a4, T a5, T a6, T& out1, T& out2, T& out3, T& out4) {
   const T x1 = a1 & ~a2;
   const T x2 = a3 ^ a6;
   const T x3 = x1 | x2;
   const T x4 = a4 ^ a6;
   const T x5 = x4 & ~a1;
   const T x6 = x3 ^ x5;

   const T x7 = a2 ^ x2;
   const T x8 = x7 & ~a6;
   const T x9 = x3 ^ x8;
   const T x10 = x6 & ~x9;

   const T x11 = a6 & x6;
   const T x12 = a4 | x11;
   const T x13 = a1 & x12;
   const T x14 = x7 ^ x13;
   const T x15 = x6 & ~a5;
   const T x16 = x15 ^ x14;
   out4 ^= x16;

   const T x17 = x2 & x4;
   const T x18 = a1 ^ a4;
   const T x19 = x9 ^ x18;
   const T x20 = a3 | x19;
   const T x21 = x20 & ~x17;

   const T x22 = x5 | x18;
   const T x23 = x14 & ~x22;
   const T x24 = a4 & a6;
   const T x25 = x24 & ~a2;
   const T x26 = x23 ^ x25;

   const T x27 = x9 & x26;
   const T x28 = x7 | x24;
   const T x29 = x28 & ~x27;
   const T x30 = a1 ^ x29;
   const T x31 = x21 & a5;
   const T x32 = x31 ^ x30;
   out2 ^= x32;

   const T x33 = x6 & ~a2;
   const T x34 = x33 & ~a3;
   const T x35 = ~x7;
   const T x36 = x22 ^ x35;
   const T x37 = x34 ^ x36;
   const T x38 = a5 & ~x10;
   const T x39 = x38 ^ x37;
   out1 ^= x39;

   const T x40 = x34 | x36;
   const T x41 = x5 | x33;
   const T x42 = x40 ^ x41;
   const T x43 = a4 & ~x6;
   const T x44 = x42 | x43;
   const T x45 = a5 & ~x26;
   const T x46 = x45 ^ x44;
   out3 ^= x46;
}

template <BitsliceT T>
BOTAN_FORCE_INLINE void SBox4(T a1, T a2, T a3, T a4, T a5, T a6, T& out1, T& out2, T& out3, T& out4) {
   const T x1 = a1 ^ a3;
   const T x2 = a3 ^ a5;
   const T x3 = a2 | a4;
   const T x4 = a5 ^ x3;
   const T x5 = x2 & ~x4;
   const T x6 = x2 & ~a2;
   const T x7 = a4 ^ x6;
   const T x8 = x1 | x7;
   const T x9 = x8 & ~x5;
   const T x10 = a2 ^ x9;

   const T x11 = x7 & x10;
   const T x12 = x2 & ~x11;
   const T x13 = x1 ^ x10;
   const T x14 = x13 & ~x12;
   const T x15 = x5 ^ x14;

   const T x16 = a2 ^ a4;
   const T x17 = a5 | x6;
   const T x18 = x13 ^ x17;
   const T x19 = x18 & ~x16;
   const T x20 = x9 ^ x19;
   const T x21 = a6 & ~x15;
   const T x22 = x21 ^ x20;
   out1 ^= x22;

   const T x23 = ~x20;
   const T x24 = x15 & ~a6;
   const T x25 = x24 ^ x23;
   out2 ^= x25;

   const T x26 = x15 ^ x23;
   const T x27 = x26 & ~x16;
   const T x28 = x11 | x27;
   const T x29 = x18 ^ x28;
   const T x30 = x10 | a6;
   const T x31 = x30 ^ x29;
   out3 ^= x31;

   const T x32 = a6 & x10;
   const T x33 = x32 ^ x29;
   out4 ^= x33;
}

template <BitsliceT T>
BOTAN_FORCE_INLINE void SBox5(T a1, T a2, T a3, T a4, T a5, T a6, T& out1, T& out2, T& out3, T& out4) {
   const T x1 = a1 | a3;
   const T x2 = x1 & ~a6;
   const T x3 = a1 ^ x2;
   const T x4 = a3 ^ x3;
   const T x5 = a4 | x4;

   const T x6 = x2 & ~a4;
   const T x7 = a3 ^ x6;
   const T x8 = a5 & x7;
   const T x9 = a1 | x4;
   const T x10 = x8 ^ x9;
   const T x11 = a4 ^ x10;

   const T x12 = a6 ^ x11;
   const T x13 = x3 | x12;
   const T x14 = a5 & x13;
   const T x15 = x3 ^ x14;
   const T x16 = a4 & x9;
   const T x17 = x15 ^ x16;

   const T x18 = x13 & ~a1;
   const T x19 = x7 ^ x18;
   const T x20 = a5 ^ x5;
   const T x21 = x20 & ~x19;
   const T x22 = ~x21;
   const T x23 = x22 & ~a2;
   const T x24 = x23 ^ x11;
   out3 ^= x24;

   const T x25 = x7 & ~x14;
   const T x26 = x18 ^ x20;
   const T x27 = x17 | x26;
   const T x28 = x27 & ~x25;
   const T x29 = x5 & ~x28;

   const T x30 = x12 & x28;
   const T x31 = x20 ^ x30;
   const T x32 = x7 & x9;
   const T x33 = x31 | x32;
   const T x34 = x14 ^ x33;
   const T x35 = x34 & a2;
   const T x36 = x35 ^ x17;
   out4 ^= x36;

   const T x37 = x1 ^ x28;
   const T x38 = a1 ^ x37;
   const T x39 = a4 & x31;
   const T x40 = x38 ^ x39;
   const T x41 = x29 | a2;
   const T x42 = x41 ^ x40;
   out1 ^= x42;

   const T x43 = x5 ^ x7;
   const T x44 = x43 & ~x40;
   const T x45 = x3 ^ x31;
   const T x46 = x44 ^ x45;
   const T x47 = x5 & a2;
   const T x48 = x47 ^ x46;
   out2 ^= x48;
}

template <BitsliceT T>
BOTAN_FORCE_INLINE void SBox6(T a1, T a2, T a3, T a4, T a5, T a6, T& out1, T& out2, T& out3, T& out4) {
   const T x1 = a2 ^ a5;

   const T x2 = a2 | a6;
   const T x3 = a1 & x2;
   const T x4 = x1 ^ x3;
   const T x5 = a6 ^ x4;
   const T x6 = a5 & ~x5;

   const T x7 = a1 & x5;
   const T x8 = a2 ^ x7;
   const T x9 = a1 ^ a3;
   const T x10 = x8 | x9;
   const T x11 = x4 ^ x10;

   const T x12 = a3 & x11;
   const T x13 = x12 & ~a6;
   const T x14 = x6 | x8;
   const T x15 = x13 ^ x14;
   const T x16 = x15 & a4;
   const T x17 = x16 ^ x11;
   out4 ^= x17;

   const T x18 = a2 ^ x10;
   const T x19 = a6 & ~x18;
   const T x20 = a3 ^ x19;
   const T x21 = a5 & ~x12;
   const T x22 = x20 | x21;

   const T x23 = a2 | x9;
   const T x24 = x15 ^ x23;
   const T x25 = x3 | x22;
   const T x26 = x24 ^ x25;

   const T x27 = a1 | x11;
   const T x28 = x14 & x27;
   const T x29 = x20 ^ x28;
   const T x30 = x29 & ~x13;
   const T x31 = x6 | a4;
   const T x32 = x31 ^ x30;
   out3 ^= x32;

   const T x33 = x4 ^ x29;
   const T x34 = a5 & ~x33;
   const T x35 = ~x23;
   const T x36 = x18 ^ x35;
   const T x37 = x34 ^ x36;
   const T x38 = x37 & ~a4;
   const T x39 = x38 ^ x26;
   out2 ^= x39;

   const T x40 = a6 ^ x7;
   const T x41 = a1 ^ x20;
   const T x42 = x40 & x41;
   const T x43 = x12 ^ x36;
   const T x44 = x42 ^ x43;
   const T x45 = x22 & ~a4;
   const T x46 = x45 ^ x44;
   out1 ^= x46;
}

template <BitsliceT T>
BOTAN_FORCE_INLINE void SBox7(T a1, T a2, T a3, T a4, T a5, T a6, T& out1, T& out2, T& out3, T& out4) {
   const T x1 = a4 ^ a5;
   const T x2 = a3 ^ x1;
   const T x3 = a6 & x2;
   const T x4 = a4 & x1;
   const T x5 = a2 ^ x4;
   const T x6 = x3 & x5;

   const T x7 = a6 & x4;
   const T x8 = a3 ^ x7;
   const T x9 = x5 | x8;
   const T x10 = a6 ^ x1;
   const T x11 = x9 ^ x10;
   const T x12 = a1 & ~x6;
   const T x13 = x12 ^ x11;
   out4 ^= x13;

   const T x14 = a5 & ~x2;
   const T x15 = x5 | x14;
   const T x16 = x3 ^ x8;
   const T x17 = x15 ^ x16;

   const T x18 = x3 ^ x10;
   const T x19 = a4 & ~x18;
   const T x20 = x5 & ~x19;
   const T x21 = a5 ^ x16;
   const T x22 = x20 ^ x21;

   const T x23 = x18 & ~x7;
   const T x24 = x19 | x23;
   const T x25 = a2 ^ x9;
   const T x26 = x22 & x25;
   const T x27 = x24 ^ x26;
   const T x28 = x27 & a1;
   const T x29 = x28 ^ x22;
   out3 ^= x29;

   const T x30 = x5 & ~a3;
   const T x31 = x23 | x30;
   const T x32 = x4 | x22;
   const T x33 = x31 & x32;
   const T x34 = x27 ^ x33;

   const T x35 = x17 | x24;
   const T x36 = x14 ^ x35;
   const T x37 = a6 & x36;
   const T x38 = x33 ^ x37;
   const T x39 = x38 & ~a1;
   const T x40 = x39 ^ x17;
   out1 ^= x40;

   const T x41 = ~x37;
   const T x42 = a2 | x41;
   const T x43 = x17 ^ x33;
   const T x44 = x42 ^ x43;
   const T x45 = x34 | a1;
   const T x46 = x45 ^ x44;
   out2 ^= x46;
}

template <BitsliceT T>
BOTAN_FORCE_INLINE void SBox8(T a1, T a2, T a3, T a4, T a5, T a6, T& out1, T& out2, T& out3, T& out4) {
   const T x1 = a3 & ~a2;
   const T x2 = a5 & ~a3;
   const T x3 = a4 ^ x2;
   const T x4 = a1 & x3;
   const T x5 = x4 & ~x1;

   const T x6 = a2 & ~x3;
   const T x7 = a1 | x6;
   const T x8 = a2 & ~a3;
   const T x9 = a5 ^ x8;
   const T x10 = x7 & x9;
   const T x11 = x4 | x10;

   const T x12 = ~x3;
   const T x13 = x10 ^ x12;
   const T x14 = a3 & ~x7;
   const T x15 = x13 ^ x14;
   const T x16 = x1 ^ x15;
   const T x17 = x5 | a6;
   const T x18 = x17 ^ x16;
   out2 ^= x18;

   const T x19 = a1 ^ x16;
   const T x20 = a5 & x19;
   const T x21 = a2 ^ x15;
   const T x22 = x20 ^ x21;
   const T x23 = x6 ^ x22;

   const T x24 = x11 ^ x22;
   const T x25 = a2 | x24;
   const T x26 = a5 ^ x19;
   const T x27 = x25 ^ x26;
   const T x28 = x11 & a6;
   const T x29 = x28 ^ x27;
   out3 ^= x29;

   const T x30 = x9 ^ x23;
   const T x31 = a4 | x21;
   const T x32 = x30 ^ x31;
   const T x33 = a1 ^ x32;
   const T x34 = x33 & a6;
   const T x35 = x34 ^ x23;
   out4 ^= x35;

   const T x36 = x30 & ~a4;
   const T x37 = x27 & x36;
   const T x38 = x5 ^ x32;
   const T x39 = x37 ^ x38;
   const T x40 = x39 | a6;
   const T x41 = x40 ^ x23;
   out1 ^= x41;
}

void des_transpose(uint64_t M[32]) {
   for(size_t i = 0; i != 16; ++i) {
      swap_bits<uint64_t>(M[i], M[i + 16], 0x0000FFFF0000FFFF, 16);
   }

   for(size_t i = 0; i != 32; i += 16) {
      for(size_t j = 0; j != 8; ++j) {
         swap_bits<uint64_t>(M[i + j], M[i + j + 8], 0x00FF00FF00FF00FF, 8);
      }
   }

   for(size_t i = 0; i != 32; i += 8) {
      for(size_t j = 0; j != 4; ++j) {
         swap_bits<uint64_t>(M[i + j + 0], M[i + j + 4], 0x0F0F0F0F0F0F0F0F, 4);
      }
   }

   for(size_t i = 0; i != 32; i += 4) {
      for(size_t j = 0; j != 2; ++j) {
         swap_bits<uint64_t>(M[i + j + 0], M[i + j + 2], 0x3333333333333333, 2);
      }
   }

   for(size_t i = 0; i != 32; i += 2) {
      swap_bits<uint64_t>(M[i], M[i + 1], 0x5555555555555555, 1);
   }
}

void transpose_in(uint32_t B[64], const uint8_t in[], size_t n_blocks) {
   uint64_t M[32] = {};

   load_be<uint64_t>(M, in, n_blocks);

   des_transpose(M);

   // clang-format off
   static constexpr uint8_t IP[64] = {
      57, 49, 41, 33, 25, 17, 9,  1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7,
      56, 48, 40, 32, 24, 16, 8,  0,
      58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6
   };
   // clang-format on

   for(size_t i = 0; i < 64; ++i) {
      const uint8_t src = IP[i];
      if(src < 32) {
         B[i] = static_cast<uint32_t>(M[31 - src] >> 32);
      } else {
         B[i] = static_cast<uint32_t>(M[63 - src]);
      }
   }
}

void transpose_out(uint8_t out[], const uint32_t B[64], size_t n_blocks) {
   // clang-format off
   static constexpr uint8_t FP[64] = {
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41,  9, 49, 17, 57, 25,
      32, 0, 40,  8, 48, 16, 56, 24
   };
   // clang-format on

   uint64_t M[32];
   for(size_t i = 0; i != 32; ++i) {
      // XOR with 32 here absorbs the DES output swap into the FP
      M[i] = (static_cast<uint64_t>(B[FP[31 - i] ^ 32]) << 32) | B[FP[63 - i] ^ 32];
   }

   des_transpose(M);

   for(size_t i = 0; i != n_blocks; ++i) {
      store_be(out + i * 8, M[i]);
   }
}

/*
* DES round - L ^= P(S(E(R) ^ K))
*
* Each S-box takes 6 bits from E(R) XORed with 6 round key bits,
* and XORs 4 output bits into L at positions given by the P permutation.
* The E expansion, key XOR, S-box evaluation, and P permutation are
* all fused into the calls below.
*/
void des_round(uint32_t L[32], const uint32_t R[32], const uint32_t RK[48]) {
   // clang-format off
   SBox1(R[31] ^ RK[ 0], R[ 0] ^ RK[ 1], R[ 1] ^ RK[ 2],
         R[ 2] ^ RK[ 3], R[ 3] ^ RK[ 4], R[ 4] ^ RK[ 5],
         L[ 8], L[16], L[22], L[30]);

   SBox2(R[ 3] ^ RK[ 6], R[ 4] ^ RK[ 7], R[ 5] ^ RK[ 8],
         R[ 6] ^ RK[ 9], R[ 7] ^ RK[10], R[ 8] ^ RK[11],
         L[12], L[27], L[ 1], L[17]);

   SBox3(R[ 7] ^ RK[12], R[ 8] ^ RK[13], R[ 9] ^ RK[14],
         R[10] ^ RK[15], R[11] ^ RK[16], R[12] ^ RK[17],
         L[23], L[15], L[29], L[ 5]);

   SBox4(R[11] ^ RK[18], R[12] ^ RK[19], R[13] ^ RK[20],
         R[14] ^ RK[21], R[15] ^ RK[22], R[16] ^ RK[23],
         L[25], L[19], L[ 9], L[ 0]);

   SBox5(R[15] ^ RK[24], R[16] ^ RK[25], R[17] ^ RK[26],
         R[18] ^ RK[27], R[19] ^ RK[28], R[20] ^ RK[29],
         L[ 7], L[13], L[24], L[ 2]);

   SBox6(R[19] ^ RK[30], R[20] ^ RK[31], R[21] ^ RK[32],
         R[22] ^ RK[33], R[23] ^ RK[34], R[24] ^ RK[35],
         L[ 3], L[28], L[10], L[18]);

   SBox7(R[23] ^ RK[36], R[24] ^ RK[37], R[25] ^ RK[38],
         R[26] ^ RK[39], R[27] ^ RK[40], R[28] ^ RK[41],
         L[31], L[11], L[21], L[ 6]);

   SBox8(R[27] ^ RK[42], R[28] ^ RK[43], R[29] ^ RK[44],
         R[30] ^ RK[45], R[31] ^ RK[46], R[ 0] ^ RK[47],
         L[ 4], L[26], L[14], L[20]);
   // clang-format on
}

void des_encrypt(uint32_t L[32], uint32_t R[32], const uint32_t round_key[]) {
   for(size_t round = 0; round < 16; round += 2) {
      des_round(L, R, &round_key[round * 48]);
      des_round(R, L, &round_key[(round + 1) * 48]);
   }
}

void des_decrypt(uint32_t L[32], uint32_t R[32], const uint32_t round_key[]) {
   for(size_t round = 16; round > 0; round -= 2) {
      des_round(L, R, &round_key[(round - 1) * 48]);
      des_round(R, L, &round_key[(round - 2) * 48]);
   }
}

/*
* The usual DES key schedule except that each round key is instead of 48 bits,
* is 48 32-bit values which are either all-1 or all-0
*/
void des_key_schedule(uint32_t round_key[], const uint8_t key[8]) {
   static const uint8_t ROT[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

   uint32_t C = ((key[7] & 0x80) << 20) | ((key[6] & 0x80) << 19) | ((key[5] & 0x80) << 18) | ((key[4] & 0x80) << 17) |
                ((key[3] & 0x80) << 16) | ((key[2] & 0x80) << 15) | ((key[1] & 0x80) << 14) | ((key[0] & 0x80) << 13) |
                ((key[7] & 0x40) << 13) | ((key[6] & 0x40) << 12) | ((key[5] & 0x40) << 11) | ((key[4] & 0x40) << 10) |
                ((key[3] & 0x40) << 9) | ((key[2] & 0x40) << 8) | ((key[1] & 0x40) << 7) | ((key[0] & 0x40) << 6) |
                ((key[7] & 0x20) << 6) | ((key[6] & 0x20) << 5) | ((key[5] & 0x20) << 4) | ((key[4] & 0x20) << 3) |
                ((key[3] & 0x20) << 2) | ((key[2] & 0x20) << 1) | ((key[1] & 0x20)) | ((key[0] & 0x20) >> 1) |
                ((key[7] & 0x10) >> 1) | ((key[6] & 0x10) >> 2) | ((key[5] & 0x10) >> 3) | ((key[4] & 0x10) >> 4);
   uint32_t D = ((key[7] & 0x02) << 26) | ((key[6] & 0x02) << 25) | ((key[5] & 0x02) << 24) | ((key[4] & 0x02) << 23) |
                ((key[3] & 0x02) << 22) | ((key[2] & 0x02) << 21) | ((key[1] & 0x02) << 20) | ((key[0] & 0x02) << 19) |
                ((key[7] & 0x04) << 17) | ((key[6] & 0x04) << 16) | ((key[5] & 0x04) << 15) | ((key[4] & 0x04) << 14) |
                ((key[3] & 0x04) << 13) | ((key[2] & 0x04) << 12) | ((key[1] & 0x04) << 11) | ((key[0] & 0x04) << 10) |
                ((key[7] & 0x08) << 8) | ((key[6] & 0x08) << 7) | ((key[5] & 0x08) << 6) | ((key[4] & 0x08) << 5) |
                ((key[3] & 0x08) << 4) | ((key[2] & 0x08) << 3) | ((key[1] & 0x08) << 2) | ((key[0] & 0x08) << 1) |
                ((key[3] & 0x10) >> 1) | ((key[2] & 0x10) >> 2) | ((key[1] & 0x10) >> 3) | ((key[0] & 0x10) >> 4);

   static const uint8_t PC2_C[24] = {13, 16, 10, 23, 0,  4, 2,  27, 14, 5,  20, 9,
                                     22, 18, 11, 3,  25, 7, 15, 6,  26, 19, 12, 1};

   static const uint8_t PC2_D[24] = {12, 23, 2,  8,  18, 26, 1,  11, 22, 16, 4, 19,
                                     15, 20, 10, 27, 5,  24, 17, 13, 21, 7,  0, 3};

   for(size_t i = 0; i != 16; ++i) {
      C = ((C << ROT[i]) | (C >> (28 - ROT[i]))) & 0x0FFFFFFF;
      D = ((D << ROT[i]) | (D >> (28 - ROT[i]))) & 0x0FFFFFFF;

      uint32_t* rk = &round_key[i * 48];

      for(size_t j = 0; j < 24; ++j) {
         const uint32_t bit = (C >> (27 - PC2_C[j])) & 1;
         rk[j] = static_cast<uint32_t>(0) - bit;
      }

      for(size_t j = 0; j < 24; ++j) {
         const uint32_t bit = (D >> (27 - PC2_D[j])) & 1;
         rk[24 + j] = static_cast<uint32_t>(0) - bit;
      }
   }
}

}  // namespace

/*
* DES Encryption
*/
void DES::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   uint32_t B[64];

   while(blocks >= 32) {
      transpose_in(B, in, 32);
      des_encrypt(&B[0], &B[32], m_round_key.data());
      transpose_out(out, B, 32);

      in += 32 * BLOCK_SIZE;
      out += 32 * BLOCK_SIZE;
      blocks -= 32;
   }

   if(blocks > 0) {
      transpose_in(B, in, blocks);
      des_encrypt(&B[0], &B[32], m_round_key.data());
      transpose_out(out, B, blocks);
   }
}

/*
* DES Decryption
*/
void DES::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   uint32_t B[64];

   while(blocks >= 32) {
      transpose_in(B, in, 32);
      des_decrypt(&B[0], &B[32], m_round_key.data());
      transpose_out(out, B, 32);

      in += 32 * BLOCK_SIZE;
      out += 32 * BLOCK_SIZE;
      blocks -= 32;
   }

   if(blocks > 0) {
      transpose_in(B, in, blocks);
      des_decrypt(&B[0], &B[32], m_round_key.data());
      transpose_out(out, B, blocks);
   }
}

bool DES::has_keying_material() const {
   return !m_round_key.empty();
}

/*
* DES Key Schedule
*/
void DES::key_schedule(std::span<const uint8_t> key) {
   m_round_key.resize(16 * 48);
   des_key_schedule(m_round_key.data(), key.data());
}

void DES::clear() {
   zap(m_round_key);
}

/*
* TripleDES Encryption
*/
void TripleDES::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   const uint32_t* k1 = m_round_key.data();
   const uint32_t* k2 = k1 + 16 * 48;
   const uint32_t* k3 = k2 + 16 * 48;

   uint32_t B[64];

   while(blocks >= 32) {
      transpose_in(B, in, 32);
      des_encrypt(&B[0], &B[32], k1);
      des_decrypt(&B[32], &B[0], k2);
      des_encrypt(&B[0], &B[32], k3);
      transpose_out(out, B, 32);

      in += 32 * BLOCK_SIZE;
      out += 32 * BLOCK_SIZE;
      blocks -= 32;
   }

   if(blocks > 0) {
      transpose_in(B, in, blocks);
      des_encrypt(&B[0], &B[32], k1);
      des_decrypt(&B[32], &B[0], k2);
      des_encrypt(&B[0], &B[32], k3);
      transpose_out(out, B, blocks);
   }
}

/*
* TripleDES Decryption
*/
void TripleDES::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   const uint32_t* k1 = m_round_key.data();
   const uint32_t* k2 = k1 + 16 * 48;
   const uint32_t* k3 = k2 + 16 * 48;

   uint32_t B[64];

   while(blocks >= 32) {
      transpose_in(B, in, 32);
      des_decrypt(&B[0], &B[32], k3);
      des_encrypt(&B[32], &B[0], k2);
      des_decrypt(&B[0], &B[32], k1);
      transpose_out(out, B, 32);

      in += 32 * BLOCK_SIZE;
      out += 32 * BLOCK_SIZE;
      blocks -= 32;
   }

   if(blocks > 0) {
      transpose_in(B, in, blocks);
      des_decrypt(&B[0], &B[32], k3);
      des_encrypt(&B[32], &B[0], k2);
      des_decrypt(&B[0], &B[32], k1);
      transpose_out(out, B, blocks);
   }
}

bool TripleDES::has_keying_material() const {
   return !m_round_key.empty();
}

/*
* TripleDES Key Schedule
*/
void TripleDES::key_schedule(std::span<const uint8_t> key) {
   m_round_key.resize(3 * 16 * 48);
   des_key_schedule(m_round_key.data(), key.first(8).data());
   des_key_schedule(m_round_key.data() + 16 * 48, key.subspan(8, 8).data());

   if(key.size() == 24) {
      des_key_schedule(m_round_key.data() + 2 * 16 * 48, key.last(8).data());
   } else {
      copy_mem(m_round_key.data() + 2 * 16 * 48, m_round_key.data(), 16 * 48);
   }
}

void TripleDES::clear() {
   zap(m_round_key);
}

}  // namespace Botan

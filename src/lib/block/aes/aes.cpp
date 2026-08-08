/*
* (C) 1999-2010,2015,2017,2018,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/bswap.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <concepts>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

#if defined(BOTAN_HAS_AES_POWER8) || defined(BOTAN_HAS_AES_ARMV8) || defined(BOTAN_HAS_AES_NI)
   #define BOTAN_HAS_HW_AES_SUPPORT
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   #include <bit>
#endif

namespace Botan {

/*
* One of three AES implementation strategies are used to get a constant time
* implementation which is immune to common cache/timing based side channels:
*
* - If AES hardware support is available (AES-NI, POWER8, Aarch64) use that
*
* - If 128-bit SIMD with byte shuffles are available (SSSE3, NEON, or Altivec),
*   use the vperm technique published by Mike Hamburg at CHES 2009.
*
* - If no hardware or SIMD support, fall back to a constant time bitsliced
*   implementation. This uses the native word size: 32-bit words process 2
*   blocks in parallel, 64-bit words process 4 blocks. Each 64-bit word is
*   treated as two independent 32-bit halves (one pair of blocks each), so
*   the bitsliced layout within each half is identical to the 32-bit case.
*
* Useful references
*
* - "Accelerating AES with Vector Permute Instructions" Mike Hamburg
*   https://www.shiftleft.org/papers/vector_aes/vector_aes.pdf
*
* - "Faster and Timing-Attack Resistant AES-GCM" Käsper and Schwabe
*   https://eprint.iacr.org/2009/129.pdf
*
* - "A new combinational logic minimization technique with applications to cryptology."
*   Boyar and Peralta https://eprint.iacr.org/2009/191.pdf
*
* - "A depth-16 circuit for the AES S-box" Boyar and Peralta
*    https://eprint.iacr.org/2011/332.pdf
*
* - "A Very Compact S-box for AES" Canright
*   https://www.iacr.org/archive/ches2005/032.pdf
*   https://core.ac.uk/download/pdf/36694529.pdf (extended)
*/

namespace {

/*
* The word type used for bitsliced AES operations.
*
* On 64-bit platforms each word holds two independent 32-bit halves,
* each encoding one pair of AES blocks, for 4 blocks total.
* On 32-bit platforms each word encodes one pair of blocks (2 total).
*/
using aes_bs_word = word;
static_assert(std::same_as<aes_bs_word, uint32_t> || std::same_as<aes_bs_word, uint64_t>);

constexpr size_t AES_BITSLICED_BLOCKS = 8 * sizeof(aes_bs_word) / 16;

/**
* Replicate a 32-bit pattern into each 32-bit half of a wider word
*/
template <std::unsigned_integral W>
constexpr inline W rep32(uint32_t x) {
   if constexpr(std::same_as<W, uint32_t>) {
      return x;
   } else {
      return (static_cast<W>(x) << 32) | x;
   }
}

/**
* Rotate right within each 32-bit half of a word.
*
* For 32-bit words this is a plain rotation. For 64-bit words each
* 32-bit half is rotated independently, which preserves the invariant
* that the two halves represent separate block-pairs.
*/
template <size_t N, std::unsigned_integral W>
BOTAN_FORCE_INLINE constexpr W column_rotr(W x) {
   if constexpr(std::same_as<W, uint32_t>) {
      return rotr<N>(x);
   } else {
      static_assert(N > 0 && N < 32);
      constexpr W mask = rep32<W>(0xFFFFFFFFU >> N);
      return ((x >> N) & mask) | ((x << (32 - N)) & ~mask);
   }
}

/*
This is an AES sbox circuit which can execute in bitsliced mode up to 32x in
parallel.

The circuit is from the "Circuit Minimization Team" group
http://www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt

This circuit has size 113 and depth 27. In software it is much faster than
circuits which are considered faster for hardware purposes (where circuit depth
is the critical constraint), because unlike in hardware, on common CPUs we can
only execute - at best - 3 or 4 logic operations per cycle. So a smaller circuit
is superior. On an x86-64 machine this circuit is about 15% faster than the
circuit of size 128 and depth 16 given in "A depth-16 circuit for the AES S-box".

Another circuit for AES Sbox of size 102 and depth 24 is describted in "New
Circuit Minimization Techniques for Smaller and Faster AES SBoxes"
[https://eprint.iacr.org/2019/802] however it relies on "non-standard" gates
like MUX, NOR, NAND, etc and so in practice in bitsliced software, its size is
actually a bit larger than this circuit, as few CPUs have such instructions and
otherwise they must be emulated using a sequence of available bit operations.
*/
template <std::unsigned_integral W>
void AES_SBOX(W V[8]) {
   const W U0 = V[0];
   const W U1 = V[1];
   const W U2 = V[2];
   const W U3 = V[3];
   const W U4 = V[4];
   const W U5 = V[5];
   const W U6 = V[6];
   const W U7 = V[7];

   const W y14 = U3 ^ U5;
   const W y13 = U0 ^ U6;
   const W y9 = U0 ^ U3;
   const W y8 = U0 ^ U5;
   const W t0 = U1 ^ U2;
   const W y1 = t0 ^ U7;
   const W y4 = y1 ^ U3;
   const W y12 = y13 ^ y14;
   const W y2 = y1 ^ U0;
   const W y5 = y1 ^ U6;
   const W y3 = y5 ^ y8;
   const W t1 = U4 ^ y12;
   const W y15 = t1 ^ U5;
   const W y20 = t1 ^ U1;
   const W y6 = y15 ^ U7;
   const W y10 = y15 ^ t0;
   const W y11 = y20 ^ y9;
   const W y7 = U7 ^ y11;
   const W y17 = y10 ^ y11;
   const W y19 = y10 ^ y8;
   const W y16 = t0 ^ y11;
   const W y21 = y13 ^ y16;
   const W y18 = U0 ^ y16;
   const W t2 = y12 & y15;
   const W t3 = y3 & y6;
   const W t4 = t3 ^ t2;
   const W t5 = y4 & U7;
   const W t6 = t5 ^ t2;
   const W t7 = y13 & y16;
   const W t8 = y5 & y1;
   const W t9 = t8 ^ t7;
   const W t10 = y2 & y7;
   const W t11 = t10 ^ t7;
   const W t12 = y9 & y11;
   const W t13 = y14 & y17;
   const W t14 = t13 ^ t12;
   const W t15 = y8 & y10;
   const W t16 = t15 ^ t12;
   const W t17 = t4 ^ y20;
   const W t18 = t6 ^ t16;
   const W t19 = t9 ^ t14;
   const W t20 = t11 ^ t16;
   const W t21 = t17 ^ t14;
   const W t22 = t18 ^ y19;
   const W t23 = t19 ^ y21;
   const W t24 = t20 ^ y18;
   const W t25 = t21 ^ t22;
   const W t26 = t21 & t23;
   const W t27 = t24 ^ t26;
   const W t28 = t25 & t27;
   const W t29 = t28 ^ t22;
   const W t30 = t23 ^ t24;
   const W t31 = t22 ^ t26;
   const W t32 = t31 & t30;
   const W t33 = t32 ^ t24;
   const W t34 = t23 ^ t33;
   const W t35 = t27 ^ t33;
   const W t36 = t24 & t35;
   const W t37 = t36 ^ t34;
   const W t38 = t27 ^ t36;
   const W t39 = t29 & t38;
   const W t40 = t25 ^ t39;
   const W t41 = t40 ^ t37;
   const W t42 = t29 ^ t33;
   const W t43 = t29 ^ t40;
   const W t44 = t33 ^ t37;
   const W t45 = t42 ^ t41;
   const W z0 = t44 & y15;
   const W z1 = t37 & y6;
   const W z2 = t33 & U7;
   const W z3 = t43 & y16;
   const W z4 = t40 & y1;
   const W z5 = t29 & y7;
   const W z6 = t42 & y11;
   const W z7 = t45 & y17;
   const W z8 = t41 & y10;
   const W z9 = t44 & y12;
   const W z10 = t37 & y3;
   const W z11 = t33 & y4;
   const W z12 = t43 & y13;
   const W z13 = t40 & y5;
   const W z14 = t29 & y2;
   const W z15 = t42 & y9;
   const W z16 = t45 & y14;
   const W z17 = t41 & y8;
   const W tc1 = z15 ^ z16;
   const W tc2 = z10 ^ tc1;
   const W tc3 = z9 ^ tc2;
   const W tc4 = z0 ^ z2;
   const W tc5 = z1 ^ z0;
   const W tc6 = z3 ^ z4;
   const W tc7 = z12 ^ tc4;
   const W tc8 = z7 ^ tc6;
   const W tc9 = z8 ^ tc7;
   const W tc10 = tc8 ^ tc9;
   const W tc11 = tc6 ^ tc5;
   const W tc12 = z3 ^ z5;
   const W tc13 = z13 ^ tc1;
   const W tc14 = tc4 ^ tc12;
   const W S3 = tc3 ^ tc11;
   const W tc16 = z6 ^ tc8;
   const W tc17 = z14 ^ tc10;
   const W tc18 = ~tc13 ^ tc14;
   const W S7 = z12 ^ tc18;
   const W tc20 = z15 ^ tc16;
   const W tc21 = tc2 ^ z11;
   const W S0 = tc3 ^ tc16;
   const W S6 = tc10 ^ tc18;
   const W S4 = tc14 ^ S3;
   const W S1 = ~(S3 ^ tc16);
   const W tc26 = tc17 ^ tc20;
   const W S2 = ~(tc26 ^ z17);
   const W S5 = tc21 ^ tc17;

   V[0] = S0;
   V[1] = S1;
   V[2] = S2;
   V[3] = S3;
   V[4] = S4;
   V[5] = S5;
   V[6] = S6;
   V[7] = S7;
}

/*
A circuit for inverse AES Sbox of size 121 and depth 21 from
http://www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
http://www.cs.yale.edu/homes/peralta/CircuitStuff/Sinv.txt
*/
template <std::unsigned_integral W>
void AES_INV_SBOX(W V[8]) {
   const W U0 = V[0];
   const W U1 = V[1];
   const W U2 = V[2];
   const W U3 = V[3];
   const W U4 = V[4];
   const W U5 = V[5];
   const W U6 = V[6];
   const W U7 = V[7];

   const W Y0 = U0 ^ U3;
   const W Y2 = ~(U1 ^ U3);
   const W Y4 = U0 ^ Y2;
   const W RTL0 = U6 ^ U7;
   const W Y1 = Y2 ^ RTL0;
   const W Y7 = ~(U2 ^ Y1);
   const W RTL1 = U3 ^ U4;
   const W Y6 = ~(U7 ^ RTL1);
   const W Y3 = Y1 ^ RTL1;
   const W RTL2 = ~(U0 ^ U2);
   const W Y5 = U5 ^ RTL2;
   const W sa1 = Y0 ^ Y2;
   const W sa0 = Y1 ^ Y3;
   const W sb1 = Y4 ^ Y6;
   const W sb0 = Y5 ^ Y7;
   const W ah = Y0 ^ Y1;
   const W al = Y2 ^ Y3;
   const W aa = sa0 ^ sa1;
   const W bh = Y4 ^ Y5;
   const W bl = Y6 ^ Y7;
   const W bb = sb0 ^ sb1;
   const W ab20 = sa0 ^ sb0;
   const W ab22 = al ^ bl;
   const W ab23 = Y3 ^ Y7;
   const W ab21 = sa1 ^ sb1;
   const W abcd1 = ah & bh;
   const W rr1 = Y0 & Y4;
   const W ph11 = ab20 ^ abcd1;
   const W t01 = Y1 & Y5;
   const W ph01 = t01 ^ abcd1;
   const W abcd2 = al & bl;
   const W r1 = Y2 & Y6;
   const W pl11 = ab22 ^ abcd2;
   const W r2 = Y3 & Y7;
   const W pl01 = r2 ^ abcd2;
   const W r3 = sa0 & sb0;
   const W vr1 = aa & bb;
   const W pr1 = vr1 ^ r3;
   const W wr1 = sa1 & sb1;
   const W qr1 = wr1 ^ r3;
   const W ab0 = ph11 ^ rr1;
   const W ab1 = ph01 ^ ab21;
   const W ab2 = pl11 ^ r1;
   const W ab3 = pl01 ^ qr1;
   const W cp1 = ab0 ^ pr1;
   const W cp2 = ab1 ^ qr1;
   const W cp3 = ab2 ^ pr1;
   const W cp4 = ab3 ^ ab23;
   const W tinv1 = cp3 ^ cp4;
   const W tinv2 = cp3 & cp1;
   const W tinv3 = cp2 ^ tinv2;
   const W tinv4 = cp1 ^ cp2;
   const W tinv5 = cp4 ^ tinv2;
   const W tinv6 = tinv5 & tinv4;
   const W tinv7 = tinv3 & tinv1;
   const W d2 = cp4 ^ tinv7;
   const W d0 = cp2 ^ tinv6;
   const W tinv8 = cp1 & cp4;
   const W tinv9 = tinv4 & tinv8;
   const W tinv10 = tinv4 ^ tinv2;
   const W d1 = tinv9 ^ tinv10;
   const W tinv11 = cp2 & cp3;
   const W tinv12 = tinv1 & tinv11;
   const W tinv13 = tinv1 ^ tinv2;
   const W d3 = tinv12 ^ tinv13;
   const W sd1 = d1 ^ d3;
   const W sd0 = d0 ^ d2;
   const W dl = d0 ^ d1;  // NOLINT(misc-confusable-identifiers)
   const W dh = d2 ^ d3;
   const W dd = sd0 ^ sd1;
   const W abcd3 = dh & bh;
   const W rr2 = d3 & Y4;
   const W t02 = d2 & Y5;
   const W abcd4 = dl & bl;
   const W r4 = d1 & Y6;
   const W r5 = d0 & Y7;
   const W r6 = sd0 & sb0;
   const W vr2 = dd & bb;
   const W wr2 = sd1 & sb1;
   const W abcd5 = dh & ah;
   const W r7 = d3 & Y0;
   const W r8 = d2 & Y1;
   const W abcd6 = dl & al;
   const W r9 = d1 & Y2;
   const W r10 = d0 & Y3;
   const W r11 = sd0 & sa0;
   const W vr3 = dd & aa;
   const W wr3 = sd1 & sa1;
   const W ph12 = rr2 ^ abcd3;
   const W ph02 = t02 ^ abcd3;
   const W pl12 = r4 ^ abcd4;
   const W pl02 = r5 ^ abcd4;
   const W pr2 = vr2 ^ r6;
   const W qr2 = wr2 ^ r6;
   const W p0 = ph12 ^ pr2;
   const W p1 = ph02 ^ qr2;
   const W p2 = pl12 ^ pr2;
   const W p3 = pl02 ^ qr2;
   const W ph13 = r7 ^ abcd5;
   const W ph03 = r8 ^ abcd5;
   const W pl13 = r9 ^ abcd6;
   const W pl03 = r10 ^ abcd6;
   const W pr3 = vr3 ^ r11;
   const W qr3 = wr3 ^ r11;
   const W p4 = ph13 ^ pr3;
   const W S7 = ph03 ^ qr3;
   const W p6 = pl13 ^ pr3;
   const W p7 = pl03 ^ qr3;
   const W S3 = p1 ^ p6;
   const W S6 = p2 ^ p6;
   const W S0 = p3 ^ p6;
   const W X11 = p0 ^ p2;
   const W S5 = S0 ^ X11;
   const W X13 = p4 ^ p7;
   const W X14 = X11 ^ X13;
   const W S1 = S3 ^ X14;
   const W X16 = p1 ^ S7;
   const W S2 = X14 ^ X16;
   const W X18 = p0 ^ p4;
   const W X19 = S5 ^ X16;
   const W S4 = X18 ^ X19;

   V[0] = S0;
   V[1] = S1;
   V[2] = S2;
   V[3] = S3;
   V[4] = S4;
   V[5] = S5;
   V[6] = S6;
   V[7] = S7;
}

template <std::unsigned_integral W>
inline void bit_transpose(W B[8]) {
   swap_bits<W>(B[1], B[0], rep32<W>(0x55555555), 1);
   swap_bits<W>(B[3], B[2], rep32<W>(0x55555555), 1);
   swap_bits<W>(B[5], B[4], rep32<W>(0x55555555), 1);
   swap_bits<W>(B[7], B[6], rep32<W>(0x55555555), 1);

   swap_bits<W>(B[2], B[0], rep32<W>(0x33333333), 2);
   swap_bits<W>(B[3], B[1], rep32<W>(0x33333333), 2);
   swap_bits<W>(B[6], B[4], rep32<W>(0x33333333), 2);
   swap_bits<W>(B[7], B[5], rep32<W>(0x33333333), 2);

   swap_bits<W>(B[4], B[0], rep32<W>(0x0F0F0F0F), 4);
   swap_bits<W>(B[5], B[1], rep32<W>(0x0F0F0F0F), 4);
   swap_bits<W>(B[6], B[2], rep32<W>(0x0F0F0F0F), 4);
   swap_bits<W>(B[7], B[3], rep32<W>(0x0F0F0F0F), 4);
}

template <std::unsigned_integral W>
inline void ks_expand(W B[8], const uint32_t K[], size_t r) {
   /*
   This is bit_transpose of K[r..r+4] || K[r..r+4], we can save some computation
   due to knowing the first and second halves are the same data.

   For 64-bit words each key word is replicated into both 32-bit halves
   so that the same round key applies to all block-pairs.
   */
   for(size_t i = 0; i != 4; ++i) {
      B[i] = rep32<W>(K[r + i]);
   }

   swap_bits<W>(B[1], B[0], rep32<W>(0x55555555), 1);
   swap_bits<W>(B[3], B[2], rep32<W>(0x55555555), 1);

   swap_bits<W>(B[2], B[0], rep32<W>(0x33333333), 2);
   swap_bits<W>(B[3], B[1], rep32<W>(0x33333333), 2);

   B[4] = B[0];
   B[5] = B[1];
   B[6] = B[2];
   B[7] = B[3];

   swap_bits<W>(B[4], B[0], rep32<W>(0x0F0F0F0F), 4);
   swap_bits<W>(B[5], B[1], rep32<W>(0x0F0F0F0F), 4);
   swap_bits<W>(B[6], B[2], rep32<W>(0x0F0F0F0F), 4);
   swap_bits<W>(B[7], B[3], rep32<W>(0x0F0F0F0F), 4);
}

template <std::unsigned_integral W>
inline void shift_rows(W B[8]) {
   // 3 0 1 2 7 4 5 6 10 11 8 9 14 15 12 13 17 18 19 16 21 22 23 20 24 25 26 27 28 29 30 31
   //
   // For 64-bit words the replicated masks operate on each 32-bit half independently
   for(size_t i = 0; i != 8; ++i) {
      B[i] = bit_permute_step<W>(B[i], rep32<W>(0x00223311), 2);
      B[i] = bit_permute_step<W>(B[i], rep32<W>(0x00550055), 1);
   }
}

template <std::unsigned_integral W>
inline void inv_shift_rows(W B[8]) {
   for(size_t i = 0; i != 8; ++i) {
      B[i] = bit_permute_step<W>(B[i], rep32<W>(0x00550055), 1);
      B[i] = bit_permute_step<W>(B[i], rep32<W>(0x00223311), 2);
   }
}

template <std::unsigned_integral W>
inline void mix_columns(W B[8]) {
   // carry high bits in B[0] to positions in 0x1b == 0b11011
   const W X2[8] = {
      B[1],
      B[2],
      B[3],
      B[4] ^ B[0],
      B[5] ^ B[0],
      B[6],
      B[7] ^ B[0],
      B[0],
   };

   for(size_t i = 0; i != 8; i++) {
      const W X3 = B[i] ^ X2[i];
      B[i] = X2[i] ^ column_rotr<8>(B[i]) ^ column_rotr<16>(B[i]) ^ column_rotr<24>(X3);
   }
}

template <std::unsigned_integral W>
void inv_mix_columns(W B[8]) {
   /*
   OpenSSL's bsaes implementation credits Jussi Kivilinna with the lovely
   matrix decomposition

   | 0e 0b 0d 09 |   | 02 03 01 01 |   | 05 00 04 00 |
   | 09 0e 0b 0d | = | 01 02 03 01 | x | 00 05 00 04 |
   | 0d 09 0e 0b |   | 01 01 02 03 |   | 04 00 05 00 |
   | 0b 0d 09 0e |   | 03 01 01 02 |   | 00 04 00 05 |

   Notice the first component is simply the MixColumns matrix. So we can
   multiply first by (05,00,04,00) then perform MixColumns to get the equivalent
   of InvMixColumn.
   */
   const W X4[8] = {
      B[2],
      B[3],
      B[4] ^ B[0],
      B[5] ^ B[0] ^ B[1],
      B[6] ^ B[1],
      B[7] ^ B[0],
      B[0] ^ B[1],
      B[1],
   };

   for(size_t i = 0; i != 8; i++) {
      const W X5 = X4[i] ^ B[i];
      B[i] = X5 ^ column_rotr<16>(X4[i]);
   }

   mix_columns(B);
}

/*
* Load up to AES_BITSLICED_BLOCKS blocks from in[] into the bitsliced state B[8].
*
* For 32-bit W this is a direct load.  For 64-bit W the data is loaded
* as uint32_t words and then packed so that each 64-bit word holds two
* independent 32-bit halves (one from each block-pair).
*/
template <std::unsigned_integral W>
inline void bs_load(W B[8], const uint8_t in[], size_t n_blocks) {
   if constexpr(std::same_as<W, uint32_t>) {
      load_be(B, in, n_blocks * 4);
   } else {
      uint32_t T[16] = {0};
      load_be(T, in, n_blocks * 4);
      for(size_t i = 0; i != 8; ++i) {
         B[i] = (static_cast<W>(T[i]) << 32) | T[i + 8];
      }
   }
}

/*
* Store the bitsliced state B[8] to out[], reversing the packing done by bs_load.
*/
template <std::unsigned_integral W>
inline void bs_store(uint8_t out[], const W B[8], size_t n_blocks) {
   if constexpr(std::same_as<W, uint32_t>) {
      copy_out_be(std::span(out, n_blocks * 16), std::span(B, 8));
   } else {
      uint32_t T[16];
      for(size_t i = 0; i != 8; ++i) {
         T[i] = static_cast<uint32_t>(B[i] >> 32);
         T[i + 8] = static_cast<uint32_t>(B[i]);
      }
      copy_out_be(std::span(out, n_blocks * 16), T);
   }
}

/*
* AES Encryption
*/
void aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, const secure_vector<uint32_t>& EK) {
   BOTAN_ASSERT(EK.size() == 44 || EK.size() == 52 || EK.size() == 60, "Key was set");

   const size_t rounds = (EK.size() - 4) / 4;

   using W = aes_bs_word;

   W KS[13 * 8] = {0};  // actual maximum is (rounds - 1) * 8
   for(size_t i = 0; i < rounds - 1; i += 1) {
      ks_expand(&KS[8 * i], EK.data(), 4 * i + 4);
   }

   while(blocks > 0) {
      const size_t this_loop = std::min(blocks, AES_BITSLICED_BLOCKS);

      W B[8] = {0};

      bs_load(B, in, this_loop);

      CT::poison(B, 8);

      for(size_t i = 0; i != 8; ++i) {
         B[i] ^= rep32<W>(EK[i % 4]);
      }

      bit_transpose(B);

      for(size_t r = 0; r != rounds - 1; ++r) {
         AES_SBOX(B);
         shift_rows(B);
         mix_columns(B);

         for(size_t i = 0; i != 8; ++i) {
            B[i] ^= KS[8 * r + i];
         }
      }

      // Final round:
      AES_SBOX(B);
      shift_rows(B);
      bit_transpose(B);

      for(size_t i = 0; i != 8; ++i) {
         B[i] ^= rep32<W>(EK[4 * rounds + i % 4]);
      }

      CT::unpoison(B, 8);

      bs_store(out, B, this_loop);

      in += this_loop * 16;
      out += this_loop * 16;
      blocks -= this_loop;
   }
}

/*
* AES Decryption
*/
void aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, const secure_vector<uint32_t>& DK) {
   BOTAN_ASSERT(DK.size() == 44 || DK.size() == 52 || DK.size() == 60, "Key was set");

   const size_t rounds = (DK.size() - 4) / 4;

   using W = aes_bs_word;

   W KS[13 * 8] = {0};  // actual maximum is (rounds - 1) * 8
   for(size_t i = 0; i < rounds - 1; i += 1) {
      ks_expand(&KS[8 * i], DK.data(), 4 * i + 4);
   }

   while(blocks > 0) {
      const size_t this_loop = std::min(blocks, AES_BITSLICED_BLOCKS);

      W B[8] = {0};

      bs_load(B, in, this_loop);

      CT::poison(B, 8);

      for(size_t i = 0; i != 8; ++i) {
         B[i] ^= rep32<W>(DK[i % 4]);
      }

      bit_transpose(B);

      for(size_t r = 0; r != rounds - 1; ++r) {
         AES_INV_SBOX(B);
         inv_shift_rows(B);
         inv_mix_columns(B);

         for(size_t i = 0; i != 8; ++i) {
            B[i] ^= KS[8 * r + i];
         }
      }

      // Final round:
      AES_INV_SBOX(B);
      inv_shift_rows(B);
      bit_transpose(B);

      for(size_t i = 0; i != 8; ++i) {
         B[i] ^= rep32<W>(DK[4 * rounds + i % 4]);
      }

      CT::unpoison(B, 8);

      bs_store(out, B, this_loop);

      in += this_loop * 16;
      out += this_loop * 16;
      blocks -= this_loop;
   }
}

inline uint32_t xtime32(uint32_t s) {
   const uint32_t lo_bit = 0x01010101;
   const uint32_t mask = 0x7F7F7F7F;
   const uint32_t poly = 0x1B;

   return ((s & mask) << 1) ^ (((s >> 7) & lo_bit) * poly);
}

inline uint32_t InvMixColumn(uint32_t s1) {
   const uint32_t s2 = xtime32(s1);
   const uint32_t s4 = xtime32(s2);
   const uint32_t s8 = xtime32(s4);
   const uint32_t s9 = s8 ^ s1;
   const uint32_t s11 = s9 ^ s2;
   const uint32_t s13 = s9 ^ s4;
   const uint32_t s14 = s8 ^ s4 ^ s2;

   return s14 ^ rotr<8>(s9) ^ rotr<16>(s13) ^ rotr<24>(s11);
}

void InvMixColumn_x4(uint32_t x[4]) {
   x[0] = InvMixColumn(x[0]);
   x[1] = InvMixColumn(x[1]);
   x[2] = InvMixColumn(x[2]);
   x[3] = InvMixColumn(x[3]);
}

uint32_t SE_word(uint32_t x) {
   aes_bs_word I[8] = {0};

   for(size_t i = 0; i != 8; ++i) {
      I[i] = (x >> (7 - i)) & 0x01010101;
   }

   AES_SBOX(I);

   x = 0;

   for(size_t i = 0; i != 8; ++i) {
      x |= static_cast<uint32_t>((I[i] & 0x01010101) << (7 - i));
   }

   return x;
}

void aes_key_schedule(const uint8_t key[],
                      size_t length,
                      secure_vector<uint32_t>& EK,
                      secure_vector<uint32_t>& DK,
                      bool bswap_keys = false) {
   static const uint32_t RC[10] = {0x01000000,
                                   0x02000000,
                                   0x04000000,
                                   0x08000000,
                                   0x10000000,
                                   0x20000000,
                                   0x40000000,
                                   0x80000000,
                                   0x1B000000,
                                   0x36000000};

   const size_t X = length / 4;

   // Can't happen, but make static analyzers happy
   BOTAN_ASSERT_NOMSG(X == 4 || X == 6 || X == 8);

   const size_t rounds = (length / 4) + 6;

   // Help the optimizer
   BOTAN_ASSERT_NOMSG(rounds == 10 || rounds == 12 || rounds == 14);

   CT::poison(key, length);

   const size_t KS_len = length + 28;
   EK.resize(KS_len);
   DK.resize(KS_len);

   for(size_t i = 0; i != X; ++i) {
      EK[i] = load_be<uint32_t>(key, i);
   }

   for(size_t i = X; i < 4 * (rounds + 1); i += X) {
      EK[i] = EK[i - X] ^ RC[(i - X) / X] ^ rotl<8>(SE_word(EK[i - 1]));

      for(size_t j = 1; j != X && (i + j) < EK.size(); ++j) {
         EK[i + j] = EK[i + j - X];

         if(X == 8 && j == 4) {
            EK[i + j] ^= SE_word(EK[i + j - 1]);
         } else {
            EK[i + j] ^= EK[i + j - 1];
         }
      }
   }

   for(size_t i = 0; i != 4 * (rounds + 1); i += 4) {
      DK[i] = EK[4 * rounds - i];
      DK[i + 1] = EK[4 * rounds - i + 1];
      DK[i + 2] = EK[4 * rounds - i + 2];
      DK[i + 3] = EK[4 * rounds - i + 3];
   }

   for(size_t i = 4; i != 4 * rounds; i += 4) {
      InvMixColumn_x4(&DK[i]);
   }

   if(bswap_keys) {
      // HW AES on little endian needs the subkeys to be byte reversed
      for(size_t i = 0; i != KS_len; ++i) {
         EK[i] = reverse_bytes(EK[i]);
         DK[i] = reverse_bytes(DK[i]);
      }
   }

   CT::unpoison(EK.data(), EK.size());
   CT::unpoison(DK.data(), DK.size());
   CT::unpoison(key, length);
}

size_t aes_parallelism() {
#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return 8;  // pipelined
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return 4;  // pipelined
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return 2;  // pipelined
   }
#endif

   // bitsliced:
   return AES_BITSLICED_BLOCKS;
}

std::string aes_provider() {
#if defined(BOTAN_HAS_AES_VAES)
   if(auto feat = CPUID::check(CPUID::Feature::AVX2_AES)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(auto feat = CPUID::check(CPUID::Feature::HW_AES)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(auto feat = CPUID::check(CPUID::Feature::SIMD_4X32)) {
      return *feat;
   }
#endif

   return "base";
}

}  // namespace

std::string AES_128::provider() const {
   return aes_provider();
}

std::string AES_192::provider() const {
   return aes_provider();
}

std::string AES_256::provider() const {
   return aes_provider();
}

size_t AES_128::parallelism() const {
   return aes_parallelism();
}

size_t AES_192::parallelism() const {
   return aes_parallelism();
}

size_t AES_256::parallelism() const {
   return aes_parallelism();
}

bool AES_128::has_keying_material() const {
   return !m_EK.empty();
}

bool AES_192::has_keying_material() const {
   return !m_EK.empty();
}

bool AES_256::has_keying_material() const {
   return !m_EK.empty();
}

void AES_128::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return x86_vaes_encrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return hw_aes_encrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_encrypt_n(in, out, blocks);
   }
#endif

   aes_encrypt_n(in, out, blocks, m_EK);
}

void AES_128::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return x86_vaes_decrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return hw_aes_decrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_decrypt_n(in, out, blocks);
   }
#endif

   aes_decrypt_n(in, out, blocks, m_DK);
}

void AES_128::key_schedule(std::span<const uint8_t> key) {
#if defined(BOTAN_HAS_AES_NI)
   if(CPUID::has(CPUID::Feature::AESNI)) {
      return aesni_key_schedule(key.data(), key.size());
   }
#endif

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return aes_key_schedule(key.data(), key.size(), m_EK, m_DK, true);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      constexpr bool is_little_endian = std::endian::native == std::endian::little;
      return aes_key_schedule(key.data(), key.size(), m_EK, m_DK, is_little_endian);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_key_schedule(key.data(), key.size());
   }
#endif

   aes_key_schedule(key.data(), key.size(), m_EK, m_DK);
}

void AES_128::clear() {
   zap(m_EK);
   zap(m_DK);
}

void AES_192::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return x86_vaes_encrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return hw_aes_encrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_encrypt_n(in, out, blocks);
   }
#endif

   aes_encrypt_n(in, out, blocks, m_EK);
}

void AES_192::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return x86_vaes_decrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return hw_aes_decrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_decrypt_n(in, out, blocks);
   }
#endif

   aes_decrypt_n(in, out, blocks, m_DK);
}

void AES_192::key_schedule(std::span<const uint8_t> key) {
#if defined(BOTAN_HAS_AES_NI)
   if(CPUID::has(CPUID::Feature::AESNI)) {
      return aesni_key_schedule(key.data(), key.size());
   }
#endif

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return aes_key_schedule(key.data(), key.size(), m_EK, m_DK, true);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      constexpr bool is_little_endian = std::endian::native == std::endian::little;
      return aes_key_schedule(key.data(), key.size(), m_EK, m_DK, is_little_endian);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_key_schedule(key.data(), key.size());
   }
#endif

   aes_key_schedule(key.data(), key.size(), m_EK, m_DK);
}

void AES_192::clear() {
   zap(m_EK);
   zap(m_DK);
}

void AES_256::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return x86_vaes_encrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return hw_aes_encrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_encrypt_n(in, out, blocks);
   }
#endif

   aes_encrypt_n(in, out, blocks, m_EK);
}

void AES_256::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return x86_vaes_decrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return hw_aes_decrypt_n(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_decrypt_n(in, out, blocks);
   }
#endif

   aes_decrypt_n(in, out, blocks, m_DK);
}

void AES_256::key_schedule(std::span<const uint8_t> key) {
#if defined(BOTAN_HAS_AES_NI)
   if(CPUID::has(CPUID::Feature::AESNI)) {
      return aesni_key_schedule(key.data(), key.size());
   }
#endif

#if defined(BOTAN_HAS_AES_VAES)
   if(CPUID::has(CPUID::Feature::AVX2_AES)) {
      return aes_key_schedule(key.data(), key.size(), m_EK, m_DK, true);
   }
#endif

#if defined(BOTAN_HAS_HW_AES_SUPPORT)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      constexpr bool is_little_endian = std::endian::native == std::endian::little;
      return aes_key_schedule(key.data(), key.size(), m_EK, m_DK, is_little_endian);
   }
#endif

#if defined(BOTAN_HAS_AES_VPERM)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return vperm_key_schedule(key.data(), key.size());
   }
#endif

   aes_key_schedule(key.data(), key.size(), m_EK, m_DK);
}

void AES_256::clear() {
   zap(m_EK);
   zap(m_DK);
}

}  // namespace Botan

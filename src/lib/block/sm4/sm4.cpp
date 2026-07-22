/*
* SM4
* (C) 2017 Ribose Inc
* (C) 2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm4.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

/*
The baseline implementation is constant time and bitsliced.

The SM4 sbox is an affine equivalent of the AES sbox; both are inversion
in GF(2^8) composed with affine transformations, and the two fields are
isomorphic. Following https://eprint.iacr.org/2022/1154 section 3.3 (the
same decomposition used by sm4_gfni and sm4_hwaes),

   S_SM4(x) = A2 * S_AES(A1 * x ^ 0x3E) ^ 0x6C

where A1 is the input matrix given in the paper and A2 is the paper's
output matrix composed with the inverse of the AES sbox's own output
affine transformation.

The sbox circuit is derived from the size 113 AES sbox circuit of the
"Circuit Minimization Team" that aes.cpp uses, which is a linear top
layer expanding the 8 inputs to 22 signals, a nonlinear middle section,
and a linear bottom layer. Affine equivalence only changes the outer
linear layers, so the middle section is used unchanged, while A1 and A2
are folded into the top and bottom layers respectively, each re-optimized
with the Boyar-Peralta SLP heuristic (27 and 35 gates, 124 in total).
The same construction, applied to the depth 16 variant of the circuit,
appears in "A Lightweight ISA Extension for AES and SM4"
(https://arxiv.org/abs/2002.07041).

Bitsliced layout

The state is kept in bitsliced form for the entire cipher. Each of the
four 32-bit state words is represented by eight plane words; plane i
holds bit 7-i of every byte. Within a plane, the bits of byte j from all
blocks in the batch occupy the group of LANES consecutive bits starting
at bit LANES*j, where LANES is the number of blocks per batch: 8 with
32-bit words and 16 with 64-bit words.

In this layout the round key becomes a set of plane constants, the sbox
is the circuit above applied plane-wise, and the linear layer L (rotations
of the 32-bit word by 2, 10, 18 and 24) becomes a fixed permutation of the
planes combined with rotations of the plane words by multiples of LANES.
*/

using sm4_bs_word = word;
static_assert(std::same_as<sm4_bs_word, uint32_t> || std::same_as<sm4_bs_word, uint64_t>);

template <std::unsigned_integral W>
constexpr size_t sm4_bs_lanes() {
   return 8 * sizeof(W) / 4;
}

constexpr size_t SM4_BITSLICED_BLOCKS = sm4_bs_lanes<sm4_bs_word>();

/**
* Rotate a plane word by N bytes of the original 32-bit word
*/
template <size_t N, std::unsigned_integral W>
BOTAN_FORCE_INLINE constexpr W sm4_bs_byte_rotl(W x) {
   return rotl<N * sm4_bs_lanes<W>()>(x);
}

/*
* Apply the SM4 sbox to the eight planes B[]
*/
template <std::unsigned_integral W>
BOTAN_FORCE_INLINE void SM4_SBOX(W B[8]) {
   // Top linear layer: A1 (with constant 0x3E) merged with the AES
   // circuit's top layer
   const W a0 = ~B[3];
   const W y4 = B[5] ^ B[2];
   const W y12 = B[6] ^ a0;
   const W a1 = B[0] ^ y12;
   const W y6 = B[4] ^ a1;
   const W a2 = B[7] ^ B[1];
   const W a3 = B[5] ^ B[1];
   const W y10 = B[0] ^ y4;
   const W y8 = ~B[2];
   const W a4 = B[6] ^ y4;
   const W y14 = a2 ^ a4;
   const W y19 = y10 ^ y8;
   const W y9 = y8 ^ y14;
   const W y11 = y6 ^ a4;
   const W y15 = a1 ^ a3;
   const W y17 = B[4] ^ a0;
   const W y1 = a4 ^ y17;
   const W y16 = y15 ^ y17;
   const W y13 = y12 ^ y14;
   const W U7 = y6 ^ y15;
   const W y7 = a4 ^ y15;
   const W y2 = y4 ^ y9;
   const W y20 = y9 ^ y11;
   const W y21 = y16 ^ y13;
   const W y5 = y13 ^ y2;
   const W y18 = y7 ^ y2;
   const W y3 = B[4] ^ y1;

   // The nonlinear middle section of the AES sbox circuit, from the
   // "Circuit Minimization Team" group
   // http://www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
   // http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt
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

   // Bottom linear layer: the AES circuit's bottom layer merged with A2
   // (with constant 0x6C)
   const W c0 = z0 ^ z7;
   const W c1 = z2 ^ z4;
   const W c2 = z11 ^ z14;
   const W c3 = ~z9;
   const W c4 = c0 ^ c1;
   const W c5 = z15 ^ c3;
   const W c6 = z3 ^ z8;
   const W c7 = z10 ^ c6;
   const W c8 = c4 ^ c7;
   const W c9 = z5 ^ z6;
   const W c10 = z13 ^ c2;
   const W c11 = z16 ^ c5;
   const W c12 = z12 ^ c2;
   const W c14 = z14 ^ z17;
   const W c15 = z13 ^ c14;
   const W B0 = c8 ^ c11;
   const W B2 = c8 ^ c10;
   const W c16 = ~c4;
   const W B7 = c9 ^ c16;
   const W c17 = z9 ^ c12;
   const W c18 = B0 ^ c17;
   const W B5 = B7 ^ c18;
   const W c19 = c5 ^ c15;
   const W c20 = z6 ^ c0;
   const W c21 = z1 ^ c20;
   const W B4 = c17 ^ c21;
   const W B1 = z10 ^ c19;
   const W c22 = c19 ^ B4;
   const W c23 = B7 ^ c22;
   const W B3 = c11 ^ c23;
   const W c24 = z4 ^ c10;
   const W c25 = c11 ^ c24;
   const W c26 = z0 ^ z1;
   const W c27 = c25 ^ c26;
   const W B6 = z3 ^ c27;

   B[0] = B0;
   B[1] = B1;
   B[2] = B2;
   B[3] = B3;
   B[4] = B4;
   B[5] = B5;
   B[6] = B6;
   B[7] = B7;
}

/*
* Apply the linear layer L to the planes T[] and xor the result into X[]
*
* Written in terms of rotations of the underlying 32-bit word, L(t) is
* t ^ rotl<2>(t) ^ rotl<10>(t) ^ rotl<18>(t) ^ rotl<24>(t). A rotation by
* 8*n moves each byte to byte n higher, which is a rotation of each plane
* word by n lane groups. A rotation by 2 moves bit b of a byte to bit b+2,
* which is plane i to plane i-2, except for the top two bits, which move
* into the next byte and become planes 6 and 7.
*/
template <std::unsigned_integral W>
BOTAN_FORCE_INLINE void SM4_L_xor(W X[8], const W T[8]) {
   W A[8];
   W E[8];

   for(size_t i = 0; i != 8; ++i) {
      const W r1 = sm4_bs_byte_rotl<1>(T[i]);
      const W r2 = sm4_bs_byte_rotl<2>(T[i]);
      const W r3 = sm4_bs_byte_rotl<3>(T[i]);
      const W r12 = r1 ^ r2;
      A[i] = T[i] ^ r3;
      E[i] = (i < 2) ? (r12 ^ r3) : (T[i] ^ r12);
   }

   for(size_t i = 0; i != 6; ++i) {
      X[i] ^= A[i] ^ E[i + 2];
   }
   X[6] ^= A[6] ^ E[0];
   X[7] ^= A[7] ^ E[1];
}

template <std::unsigned_integral W>
BOTAN_FORCE_INLINE void SM4_round(W X0[8], const W X1[8], const W X2[8], const W X3[8], const W K[8]) {
   W T[8];
   for(size_t i = 0; i != 8; ++i) {
      T[i] = X1[i] ^ X2[i] ^ X3[i] ^ K[i];
   }
   SM4_SBOX(T);
   SM4_L_xor(X0, T);
}

/*
* Transpose the 8x8 bit matrix formed by the bytes of B[]. Afterwards,
* plane B[i] holds bit 7-i of each byte, and the lane order within each
* byte is reversed; the transpose is an involution so this cancels when
* converting back.
*/
inline void sm4_bit_transpose(uint32_t B[8]) {
   swap_bits<uint32_t>(B[1], B[0], 0x55555555, 1);
   swap_bits<uint32_t>(B[3], B[2], 0x55555555, 1);
   swap_bits<uint32_t>(B[5], B[4], 0x55555555, 1);
   swap_bits<uint32_t>(B[7], B[6], 0x55555555, 1);

   swap_bits<uint32_t>(B[2], B[0], 0x33333333, 2);
   swap_bits<uint32_t>(B[3], B[1], 0x33333333, 2);
   swap_bits<uint32_t>(B[6], B[4], 0x33333333, 2);
   swap_bits<uint32_t>(B[7], B[5], 0x33333333, 2);

   swap_bits<uint32_t>(B[4], B[0], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[5], B[1], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[6], B[2], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[7], B[3], 0x0F0F0F0F, 4);
}

/*
* Interleave the bytes of two 32-bit planes into one 64-bit plane with
* 16-bit lane groups: byte j of lo becomes the low half of group j and
* byte j of hi the high half.
*
* Only used for 64-bit
*/
[[maybe_unused]] inline uint64_t sm4_bs_zip(uint32_t lo, uint32_t hi) {
   uint64_t x = (static_cast<uint64_t>(hi) << 32) | lo;
   x = bit_permute_step<uint64_t>(x, 0x00000000FFFF0000, 16);
   x = bit_permute_step<uint64_t>(x, 0x0000FF000000FF00, 8);
   return x;
}

[[maybe_unused]] inline void sm4_bs_unzip(uint64_t x, uint32_t& lo, uint32_t& hi) {
   x = bit_permute_step<uint64_t>(x, 0x0000FF000000FF00, 8);
   x = bit_permute_step<uint64_t>(x, 0x00000000FFFF0000, 16);
   lo = static_cast<uint32_t>(x);
   hi = static_cast<uint32_t>(x >> 32);
}

/*
* Load word w of each of the n_blocks input blocks into the planes P[]
*/
template <std::unsigned_integral W>
void sm4_bs_load(W P[8], const uint8_t in[], size_t w, size_t n_blocks) {
   constexpr size_t LANES = sm4_bs_lanes<W>();

   uint32_t T[LANES] = {0};
   for(size_t k = 0; k != n_blocks; ++k) {
      T[k] = load_be<uint32_t>(in + 16 * k, w);
   }

   for(size_t g = 0; g != LANES; g += 8) {
      sm4_bit_transpose(&T[g]);
   }

   for(size_t i = 0; i != 8; ++i) {
      if constexpr(std::same_as<W, uint32_t>) {
         P[i] = T[i];
      } else {
         P[i] = sm4_bs_zip(T[i], T[i + 8]);
      }
   }
}

/*
* Store the planes P[] as word w of each of the n_blocks output blocks
*/
template <std::unsigned_integral W>
void sm4_bs_store(uint8_t out[], const W P[8], size_t w, size_t n_blocks) {
   constexpr size_t LANES = sm4_bs_lanes<W>();

   uint32_t T[LANES];
   for(size_t i = 0; i != 8; ++i) {
      if constexpr(std::same_as<W, uint32_t>) {
         T[i] = P[i];
      } else {
         sm4_bs_unzip(P[i], T[i], T[i + 8]);
      }
   }

   for(size_t g = 0; g != LANES; g += 8) {
      sm4_bit_transpose(&T[g]);
   }

   for(size_t k = 0; k != n_blocks; ++k) {
      store_be(T[k], out + 16 * k + 4 * w);
   }
}

/*
* Expand round key rk into plane i: each lane group j is all ones if
* bit 7-i of byte j of rk is set
*/
template <std::unsigned_integral W>
W sm4_bs_key_plane(uint32_t rk, size_t i) {
   constexpr size_t LANES = sm4_bs_lanes<W>();
   constexpr W lane_mask = (static_cast<W>(1) << LANES) - 1;

   W p = 0;
   for(size_t j = 0; j != 4; ++j) {
      const W bit = (rk >> (8 * j + 7 - i)) & 1;
      p |= (static_cast<W>(0) - bit) & (lane_mask << (LANES * j));
   }
   return p;
}

template <bool DECRYPT, std::unsigned_integral W>
void sm4_bitsliced_blocks(const uint8_t in[], uint8_t out[], size_t blocks, const W KS[32 * 8]) {
   BOTAN_ASSERT_NOMSG(blocks >= 1 && blocks <= sm4_bs_lanes<W>());

   W X[4][8];
   for(size_t w = 0; w != 4; ++w) {
      sm4_bs_load(X[w], in, w, blocks);
   }

   CT::poison(&X[0][0], 4 * 8);

   for(size_t r = 0; r != 32; r += 4) {
      auto key = [&](size_t i) { return &KS[8 * (DECRYPT ? 31 - i : i)]; };
      SM4_round(X[0], X[1], X[2], X[3], key(r + 0));
      SM4_round(X[1], X[2], X[3], X[0], key(r + 1));
      SM4_round(X[2], X[3], X[0], X[1], key(r + 2));
      SM4_round(X[3], X[0], X[1], X[2], key(r + 3));
   }

   CT::unpoison(&X[0][0], 4 * 8);

   for(size_t w = 0; w != 4; ++w) {
      sm4_bs_store(out, X[3 - w], w, blocks);
   }
}

template <bool DECRYPT>
void sm4_bitsliced(const uint8_t in[], uint8_t out[], size_t blocks, const secure_vector<sm4_bs_word>& KS) {
   BOTAN_ASSERT_NOMSG(KS.size() == 32 * 8);

   while(blocks > 0) {
      const size_t this_loop = std::min(blocks, SM4_BITSLICED_BLOCKS);
      sm4_bitsliced_blocks<DECRYPT>(in, out, this_loop, KS.data());
      in += this_loop * 16;
      out += this_loop * 16;
      blocks -= this_loop;
   }
}

/*
* Returns true if the bitsliced implementation will be used
*/
bool sm4_use_bitsliced() {
#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return false;
   }
#endif

#if defined(BOTAN_HAS_SM4_X86)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return false;
   }
#endif

#if defined(BOTAN_HAS_SM4_AVX512_GFNI)
   if(CPUID::has(CPUID::Feature::AVX512, CPUID::Feature::GFNI)) {
      return false;
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(CPUID::has(CPUID::Feature::GFNI)) {
      return false;
   }
#endif

#if defined(BOTAN_HAS_SM4_HWAES)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return false;
   }
#endif

   return true;
}

}  // namespace

/*
* SM4 Encryption
*/
void SM4::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return sm4_armv8_encrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_X86)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return sm4_x86_encrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_AVX512_GFNI)
   if(CPUID::has(CPUID::Feature::AVX512, CPUID::Feature::GFNI)) {
      return sm4_avx512_gfni_encrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(CPUID::has(CPUID::Feature::GFNI)) {
      return sm4_gfni_encrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_HWAES)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return sm4_hwaes_encrypt(in, out, blocks);
   }
#endif

   sm4_bitsliced<false>(in, out, blocks, m_BSK);
}

/*
* SM4 Decryption
*/
void SM4::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return sm4_armv8_decrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_X86)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return sm4_x86_decrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_AVX512_GFNI)
   if(CPUID::has(CPUID::Feature::AVX512, CPUID::Feature::GFNI)) {
      return sm4_avx512_gfni_decrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(CPUID::has(CPUID::Feature::GFNI)) {
      return sm4_gfni_decrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_HWAES)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return sm4_hwaes_decrypt(in, out, blocks);
   }
#endif

   sm4_bitsliced<true>(in, out, blocks, m_BSK);
}

bool SM4::has_keying_material() const {
   return !m_RK.empty();
}

/*
* SM4 Key Schedule
*/

//static
uint32_t SM4::SM4_Tp(uint32_t b) {
#if defined(BOTAN_HAS_SM4_HWAES)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      const uint32_t t = sm4_hwaes_sbox(b);
      // L' linear transform
      return t ^ rotl<13>(t) ^ rotl<23>(t);
   }
#endif

   uint32_t T[8] = {b, 0, 0, 0, 0, 0, 0, 0};
   sm4_bit_transpose(T);
   SM4_SBOX(T);
   sm4_bit_transpose(T);

   const uint32_t t = T[0];
   // L' linear transform
   return t ^ rotl<13>(t) ^ rotl<23>(t);
}

void SM4::key_schedule(std::span<const uint8_t> key) {
   // System parameter or family key
   const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

   const uint32_t CK[32] = {0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD,
                            0xC4CBD2D9, 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81,
                            0x888F969D, 0xA4ABB2B9, 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45,
                            0x4C535A61, 0x686F767D, 0x848B9299, 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
                            0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279};

   CT::poison(key.data(), key.size());

   uint32_t K0 = load_be<uint32_t>(key.data(), 0) ^ FK[0];
   uint32_t K1 = load_be<uint32_t>(key.data(), 1) ^ FK[1];
   uint32_t K2 = load_be<uint32_t>(key.data(), 2) ^ FK[2];
   uint32_t K3 = load_be<uint32_t>(key.data(), 3) ^ FK[3];

   m_RK.resize(32);

   for(size_t i = 0; i != 32; i += 4) {
      K0 ^= SM4_Tp(K1 ^ K2 ^ K3 ^ CK[i + 0]);
      K1 ^= SM4_Tp(K0 ^ K2 ^ K3 ^ CK[i + 1]);
      K2 ^= SM4_Tp(K0 ^ K1 ^ K3 ^ CK[i + 2]);
      K3 ^= SM4_Tp(K0 ^ K1 ^ K2 ^ CK[i + 3]);
      m_RK[i + 0] = K0;
      m_RK[i + 1] = K1;
      m_RK[i + 2] = K2;
      m_RK[i + 3] = K3;
   }

   if(sm4_use_bitsliced()) {
      m_BSK.resize(32 * 8);
      for(size_t r = 0; r != 32; ++r) {
         for(size_t i = 0; i != 8; ++i) {
            m_BSK[8 * r + i] = sm4_bs_key_plane<sm4_bs_word>(m_RK[r], i);
         }
      }
   }

   CT::unpoison(m_RK.data(), m_RK.size());
   CT::unpoison(key.data(), key.size());
}

void SM4::clear() {
   zap(m_RK);
   zap(m_BSK);
}

size_t SM4::parallelism() const {
#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return 4;
   }
#endif

#if defined(BOTAN_HAS_SM4_X86)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return 8;
   }
#endif

#if defined(BOTAN_HAS_SM4_AVX512_GFNI)
   if(CPUID::has(CPUID::Feature::AVX512, CPUID::Feature::GFNI)) {
      return 16;
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(CPUID::has(CPUID::Feature::GFNI)) {
      return 8;
   }
#endif

#if defined(BOTAN_HAS_SM4_HWAES)
   if(CPUID::has(CPUID::Feature::HW_AES)) {
      return 4;
   }
#endif

   return SM4_BITSLICED_BLOCKS;
}

std::string SM4::provider() const {
#if defined(BOTAN_HAS_SM4_ARMV8)
   if(auto feat = CPUID::check(CPUID::Feature::SM4)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SM4_X86)
   if(auto feat = CPUID::check(CPUID::Feature::SM4)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SM4_AVX512_GFNI)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512, CPUID::Feature::GFNI)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(auto feat = CPUID::check(CPUID::Feature::GFNI)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SM4_HWAES)
   if(auto feat = CPUID::check(CPUID::Feature::HW_AES)) {
      return *feat;
   }
#endif

   return "base";
}

}  // namespace Botan

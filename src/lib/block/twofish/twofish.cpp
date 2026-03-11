/*
* Twofish
* (C) 1999-2007,2017,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/twofish.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

namespace Botan {

namespace {

namespace Twofish_KS {

// Twofish q-permutation derived from four 4-bit sboxes
// ("Twofish: A 128-Bit Block Cipher", section 4.3.5)
consteval std::array<uint8_t, 256> twofish_q_perm(std::array<uint8_t, 16> t0,
                                                  std::array<uint8_t, 16> t1,
                                                  std::array<uint8_t, 16> t2,
                                                  std::array<uint8_t, 16> t3) noexcept {
   std::array<uint8_t, 256> Q = {};
   for(size_t x = 0; x != 256; ++x) {
      const uint8_t a0 = static_cast<uint8_t>((x >> 4) & 0x0F);
      const uint8_t b0 = static_cast<uint8_t>(x & 0x0F);

      const uint8_t a1 = a0 ^ b0;
      const uint8_t b1 = a0 ^ ((b0 >> 1) | ((b0 & 1) << 3)) ^ ((8 * a0) & 0x0F);

      const uint8_t a2 = t0[a1];
      const uint8_t b2 = t1[b1];

      const uint8_t a3 = a2 ^ b2;
      const uint8_t b3 = a2 ^ ((b2 >> 1) | ((b2 & 1) << 3)) ^ ((8 * a2) & 0x0F);

      const uint8_t a4 = t2[a3];
      const uint8_t b4 = t3[b3];

      Q[x] = static_cast<uint8_t>((b4 << 4) | a4);
   }
   return Q;
}

// clang-format off
alignas(256) constexpr auto Q0 = twofish_q_perm(
   {8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4},
   {14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13},
   {11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1},
   {13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10});

alignas(256) constexpr auto Q1 = twofish_q_perm(
   {2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5},
   {1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8},
   {4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15},
   {11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10});

// clang-format on

/*
* MDS matrix multiplication (Twofish paper Section 4.2)
*
* MDS = [01, EF, 5B, 5B]
*       [5B, EF, EF, 01]
*       [EF, 5B, 01, EF]
*       [EF, 01, EF, 5B]
*
* The MDS coefficients are 01, 5B, and EF. These were chosen so that
*
*   5B = 1 + 1/x^2
*   EF = 1 + 1/x + 1/x^2
*
* in GF(2^8) mod x^8+x^6+x^5+x^3+1, where 1/x is computed by shifting
* right and conditionally XORing with 0xB4 (which is itself just the
* irreducible polynomial 0x169 shifted right by 1).
*
* This property of the MDS constants is described (briefly) in Section 7.3
* of the Twofish paper.
*/

inline uint8_t mds_div_x(uint8_t q) {
   return (q >> 1) ^ (CT::value_barrier<uint8_t>(q & 1) * 0xB4);
}

inline uint32_t mds0(uint8_t q) {
   const uint8_t q_div_x = mds_div_x(q);
   const uint8_t q5b = q ^ mds_div_x(q_div_x);
   const uint8_t qef = q5b ^ q_div_x;
   return make_uint32(qef, qef, q5b, q);
}

inline uint32_t mds1(uint8_t q) {
   const uint8_t q_div_x = mds_div_x(q);
   const uint8_t q5b = q ^ mds_div_x(q_div_x);
   const uint8_t qef = q5b ^ q_div_x;
   return make_uint32(q, q5b, qef, qef);
}

inline uint32_t mds2(uint8_t q) {
   const uint8_t q_div_x = mds_div_x(q);
   const uint8_t q5b = q ^ mds_div_x(q_div_x);
   const uint8_t qef = q5b ^ q_div_x;
   return make_uint32(qef, q, qef, q5b);
}

inline uint32_t mds3(uint8_t q) {
   const uint8_t q_div_x = mds_div_x(q);
   const uint8_t q5b = q ^ mds_div_x(q_div_x);
   const uint8_t qef = q5b ^ q_div_x;
   return make_uint32(q5b, qef, q, q5b);
}

// Constant-time GF(2^8) multiply in the RS field (irreducible polynomial 0x14D)
inline uint32_t gf_mul_rs32(uint32_t rs, uint8_t k) {
   constexpr uint32_t lo_bit = 0x01010101;
   constexpr uint32_t mask = 0x7F7F7F7F;
   constexpr uint32_t poly = 0x4D;

   uint32_t r = 0;
   for(size_t i = 0; i != 8; ++i) {
      const auto k_lo = CT::Mask<uint32_t>::expand(k & 1);
      r ^= k_lo.if_set_return(rs);
      rs = ((rs & mask) << 1) ^ (((rs >> 7) & lo_bit) * poly);
      k >>= 1;
   }
   return r;
}

}  // namespace Twofish_KS

inline void TF_E(
   uint32_t A, uint32_t B, uint32_t& C, uint32_t& D, uint32_t RK1, uint32_t RK2, const secure_vector<uint32_t>& SB) {
   uint32_t X = SB[get_byte<3>(A)] ^ SB[256 + get_byte<2>(A)] ^ SB[512 + get_byte<1>(A)] ^ SB[768 + get_byte<0>(A)];
   uint32_t Y = SB[get_byte<0>(B)] ^ SB[256 + get_byte<3>(B)] ^ SB[512 + get_byte<2>(B)] ^ SB[768 + get_byte<1>(B)];

   X += Y;
   Y += X;

   X += RK1;
   Y += RK2;

   C = rotr<1>(C ^ X);
   D = rotl<1>(D) ^ Y;
}

inline void TF_D(
   uint32_t A, uint32_t B, uint32_t& C, uint32_t& D, uint32_t RK1, uint32_t RK2, const secure_vector<uint32_t>& SB) {
   uint32_t X = SB[get_byte<3>(A)] ^ SB[256 + get_byte<2>(A)] ^ SB[512 + get_byte<1>(A)] ^ SB[768 + get_byte<0>(A)];
   uint32_t Y = SB[get_byte<0>(B)] ^ SB[256 + get_byte<3>(B)] ^ SB[512 + get_byte<2>(B)] ^ SB[768 + get_byte<1>(B)];

   X += Y;
   Y += X;

   X += RK1;
   Y += RK2;

   C = rotl<1>(C) ^ X;
   D = rotr<1>(D ^ Y);
}

}  // namespace

/*
* Twofish Encryption
*/
void Twofish::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   while(blocks >= 2) {
      uint32_t A0 = 0;
      uint32_t B0 = 0;
      uint32_t C0 = 0;
      uint32_t D0 = 0;
      uint32_t A1 = 0;
      uint32_t B1 = 0;
      uint32_t C1 = 0;
      uint32_t D1 = 0;
      load_le(in, A0, B0, C0, D0, A1, B1, C1, D1);

      A0 ^= m_RK[0];
      A1 ^= m_RK[0];
      B0 ^= m_RK[1];
      B1 ^= m_RK[1];
      C0 ^= m_RK[2];
      C1 ^= m_RK[2];
      D0 ^= m_RK[3];
      D1 ^= m_RK[3];

      for(size_t k = 8; k != 40; k += 4) {
         TF_E(A0, B0, C0, D0, m_RK[k + 0], m_RK[k + 1], m_SB);
         TF_E(A1, B1, C1, D1, m_RK[k + 0], m_RK[k + 1], m_SB);

         TF_E(C0, D0, A0, B0, m_RK[k + 2], m_RK[k + 3], m_SB);
         TF_E(C1, D1, A1, B1, m_RK[k + 2], m_RK[k + 3], m_SB);
      }

      C0 ^= m_RK[4];
      C1 ^= m_RK[4];
      D0 ^= m_RK[5];
      D1 ^= m_RK[5];
      A0 ^= m_RK[6];
      A1 ^= m_RK[6];
      B0 ^= m_RK[7];
      B1 ^= m_RK[7];

      store_le(out, C0, D0, A0, B0, C1, D1, A1, B1);

      blocks -= 2;
      out += 2 * BLOCK_SIZE;
      in += 2 * BLOCK_SIZE;
   }

   if(blocks > 0) {
      uint32_t A = 0;
      uint32_t B = 0;
      uint32_t C = 0;
      uint32_t D = 0;
      load_le(in, A, B, C, D);

      A ^= m_RK[0];
      B ^= m_RK[1];
      C ^= m_RK[2];
      D ^= m_RK[3];

      for(size_t k = 8; k != 40; k += 4) {
         TF_E(A, B, C, D, m_RK[k], m_RK[k + 1], m_SB);
         TF_E(C, D, A, B, m_RK[k + 2], m_RK[k + 3], m_SB);
      }

      C ^= m_RK[4];
      D ^= m_RK[5];
      A ^= m_RK[6];
      B ^= m_RK[7];

      store_le(out, C, D, A, B);
   }
}

/*
* Twofish Decryption
*/
void Twofish::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   while(blocks >= 2) {
      uint32_t A0 = 0;
      uint32_t B0 = 0;
      uint32_t C0 = 0;
      uint32_t D0 = 0;
      uint32_t A1 = 0;
      uint32_t B1 = 0;
      uint32_t C1 = 0;
      uint32_t D1 = 0;
      load_le(in, A0, B0, C0, D0, A1, B1, C1, D1);

      A0 ^= m_RK[4];
      A1 ^= m_RK[4];
      B0 ^= m_RK[5];
      B1 ^= m_RK[5];
      C0 ^= m_RK[6];
      C1 ^= m_RK[6];
      D0 ^= m_RK[7];
      D1 ^= m_RK[7];

      for(size_t k = 40; k != 8; k -= 4) {
         TF_D(A0, B0, C0, D0, m_RK[k - 2], m_RK[k - 1], m_SB);
         TF_D(A1, B1, C1, D1, m_RK[k - 2], m_RK[k - 1], m_SB);

         TF_D(C0, D0, A0, B0, m_RK[k - 4], m_RK[k - 3], m_SB);
         TF_D(C1, D1, A1, B1, m_RK[k - 4], m_RK[k - 3], m_SB);
      }

      C0 ^= m_RK[0];
      C1 ^= m_RK[0];
      D0 ^= m_RK[1];
      D1 ^= m_RK[1];
      A0 ^= m_RK[2];
      A1 ^= m_RK[2];
      B0 ^= m_RK[3];
      B1 ^= m_RK[3];

      store_le(out, C0, D0, A0, B0, C1, D1, A1, B1);

      blocks -= 2;
      out += 2 * BLOCK_SIZE;
      in += 2 * BLOCK_SIZE;
   }

   if(blocks > 0) {
      uint32_t A = 0;
      uint32_t B = 0;
      uint32_t C = 0;
      uint32_t D = 0;
      load_le(in, A, B, C, D);

      A ^= m_RK[4];
      B ^= m_RK[5];
      C ^= m_RK[6];
      D ^= m_RK[7];

      for(size_t k = 40; k != 8; k -= 4) {
         TF_D(A, B, C, D, m_RK[k - 2], m_RK[k - 1], m_SB);
         TF_D(C, D, A, B, m_RK[k - 4], m_RK[k - 3], m_SB);
      }

      C ^= m_RK[0];
      D ^= m_RK[1];
      A ^= m_RK[2];
      B ^= m_RK[3];

      store_le(out, C, D, A, B);
   }
}

bool Twofish::has_keying_material() const {
   return !m_SB.empty();
}

/*
* Twofish Key Schedule
*/
void Twofish::key_schedule(std::span<const uint8_t> key) {
   using namespace Twofish_KS;

   // Reed-Solomon matrix for key schedule (Twofish paper Section 4.3)
   // in column-major form

   // clang-format off
   constexpr uint32_t RS32[8] = {
      0x01A402A4,
      0xA456A155,
      0x5582FC87,
      0x87F3C15A,
      0x5A1E4758,
      0x58C6AEDB,
      0xDB683D9E,
      0x9EE51903
   };
   // clang-format on

   m_SB.resize(1024);
   m_RK.resize(40);

   secure_vector<uint8_t> S(16);

   for(size_t i = 0; i != key.size(); ++i) {
      const uint8_t ki = key[i];
      const size_t s_off = 4 * (i / 8);

      const uint32_t p = gf_mul_rs32(RS32[i % 8], ki);

      S[s_off + 0] ^= get_byte<0>(p);
      S[s_off + 1] ^= get_byte<1>(p);
      S[s_off + 2] ^= get_byte<2>(p);
      S[s_off + 3] ^= get_byte<3>(p);
   }

   if(key.size() == 16) {
      for(size_t i = 0; i != 256; ++i) {
         m_SB[i] = mds0(Q1[Q0[Q0[i] ^ S[0]] ^ S[4]]);
         m_SB[256 + i] = mds1(Q0[Q0[Q1[i] ^ S[1]] ^ S[5]]);
         m_SB[512 + i] = mds2(Q1[Q1[Q0[i] ^ S[2]] ^ S[6]]);
         m_SB[768 + i] = mds3(Q0[Q1[Q1[i] ^ S[3]] ^ S[7]]);
      }

      for(size_t i = 0; i < 40; i += 2) {
         uint32_t X = mds0(Q1[Q0[Q0[i] ^ key[8]] ^ key[0]]) ^ mds1(Q0[Q0[Q1[i] ^ key[9]] ^ key[1]]) ^
                      mds2(Q1[Q1[Q0[i] ^ key[10]] ^ key[2]]) ^ mds3(Q0[Q1[Q1[i] ^ key[11]] ^ key[3]]);
         uint32_t Y = mds0(Q1[Q0[Q0[i + 1] ^ key[12]] ^ key[4]]) ^ mds1(Q0[Q0[Q1[i + 1] ^ key[13]] ^ key[5]]) ^
                      mds2(Q1[Q1[Q0[i + 1] ^ key[14]] ^ key[6]]) ^ mds3(Q0[Q1[Q1[i + 1] ^ key[15]] ^ key[7]]);
         Y = rotl<8>(Y);
         X += Y;
         Y += X;

         m_RK[i] = X;
         m_RK[i + 1] = rotl<9>(Y);
      }
   } else if(key.size() == 24) {
      for(size_t i = 0; i != 256; ++i) {
         m_SB[i] = mds0(Q1[Q0[Q0[Q1[i] ^ S[0]] ^ S[4]] ^ S[8]]);
         m_SB[256 + i] = mds1(Q0[Q0[Q1[Q1[i] ^ S[1]] ^ S[5]] ^ S[9]]);
         m_SB[512 + i] = mds2(Q1[Q1[Q0[Q0[i] ^ S[2]] ^ S[6]] ^ S[10]]);
         m_SB[768 + i] = mds3(Q0[Q1[Q1[Q0[i] ^ S[3]] ^ S[7]] ^ S[11]]);
      }

      for(size_t i = 0; i < 40; i += 2) {
         uint32_t X =
            mds0(Q1[Q0[Q0[Q1[i] ^ key[16]] ^ key[8]] ^ key[0]]) ^ mds1(Q0[Q0[Q1[Q1[i] ^ key[17]] ^ key[9]] ^ key[1]]) ^
            mds2(Q1[Q1[Q0[Q0[i] ^ key[18]] ^ key[10]] ^ key[2]]) ^ mds3(Q0[Q1[Q1[Q0[i] ^ key[19]] ^ key[11]] ^ key[3]]);
         uint32_t Y = mds0(Q1[Q0[Q0[Q1[i + 1] ^ key[20]] ^ key[12]] ^ key[4]]) ^
                      mds1(Q0[Q0[Q1[Q1[i + 1] ^ key[21]] ^ key[13]] ^ key[5]]) ^
                      mds2(Q1[Q1[Q0[Q0[i + 1] ^ key[22]] ^ key[14]] ^ key[6]]) ^
                      mds3(Q0[Q1[Q1[Q0[i + 1] ^ key[23]] ^ key[15]] ^ key[7]]);
         Y = rotl<8>(Y);
         X += Y;
         Y += X;

         m_RK[i] = X;
         m_RK[i + 1] = rotl<9>(Y);
      }
   } else if(key.size() == 32) {
      for(size_t i = 0; i != 256; ++i) {
         m_SB[i] = mds0(Q1[Q0[Q0[Q1[Q1[i] ^ S[0]] ^ S[4]] ^ S[8]] ^ S[12]]);
         m_SB[256 + i] = mds1(Q0[Q0[Q1[Q1[Q0[i] ^ S[1]] ^ S[5]] ^ S[9]] ^ S[13]]);
         m_SB[512 + i] = mds2(Q1[Q1[Q0[Q0[Q0[i] ^ S[2]] ^ S[6]] ^ S[10]] ^ S[14]]);
         m_SB[768 + i] = mds3(Q0[Q1[Q1[Q0[Q1[i] ^ S[3]] ^ S[7]] ^ S[11]] ^ S[15]]);
      }

      for(size_t i = 0; i < 40; i += 2) {
         uint32_t X = mds0(Q1[Q0[Q0[Q1[Q1[i] ^ key[24]] ^ key[16]] ^ key[8]] ^ key[0]]) ^
                      mds1(Q0[Q0[Q1[Q1[Q0[i] ^ key[25]] ^ key[17]] ^ key[9]] ^ key[1]]) ^
                      mds2(Q1[Q1[Q0[Q0[Q0[i] ^ key[26]] ^ key[18]] ^ key[10]] ^ key[2]]) ^
                      mds3(Q0[Q1[Q1[Q0[Q1[i] ^ key[27]] ^ key[19]] ^ key[11]] ^ key[3]]);
         uint32_t Y = mds0(Q1[Q0[Q0[Q1[Q1[i + 1] ^ key[28]] ^ key[20]] ^ key[12]] ^ key[4]]) ^
                      mds1(Q0[Q0[Q1[Q1[Q0[i + 1] ^ key[29]] ^ key[21]] ^ key[13]] ^ key[5]]) ^
                      mds2(Q1[Q1[Q0[Q0[Q0[i + 1] ^ key[30]] ^ key[22]] ^ key[14]] ^ key[6]]) ^
                      mds3(Q0[Q1[Q1[Q0[Q1[i + 1] ^ key[31]] ^ key[23]] ^ key[15]] ^ key[7]]);
         Y = rotl<8>(Y);
         X += Y;
         Y += X;

         m_RK[i] = X;
         m_RK[i + 1] = rotl<9>(Y);
      }
   }
}

/*
* Clear memory of sensitive data
*/
void Twofish::clear() {
   zap(m_SB);
   zap(m_RK);
}

}  // namespace Botan

/*
* IDEA
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/idea.h>

#include <botan/internal/cpuid.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

/*
* Multiplication modulo 65537
*/
inline uint16_t mul(uint16_t x, uint16_t y) {
   const uint32_t P = static_cast<uint32_t>(x) * y;
   const auto P_mask = CT::Mask<uint16_t>(CT::Mask<uint32_t>::is_zero(P));

   const uint32_t P_hi = P >> 16;
   const uint32_t P_lo = P & 0xFFFF;

   const uint16_t carry = (P_lo < P_hi);
   const uint16_t r_1 = static_cast<uint16_t>((P_lo - P_hi) + carry);
   const uint16_t r_2 = 1 - x - y;

   return P_mask.select(r_2, r_1);
}

/*
* Find multiplicative inverses modulo 65537
*
* 65537 is prime; thus Fermat's little theorem tells us that
* x^65537 == x modulo 65537, which means
* x^(65537-2) == x^-1 modulo 65537 since
* x^(65537-2) * x == 1 mod 65537
*
* Do the exponentiation with a basic square and multiply: all bits are
* of exponent are 1 so we always multiply
*/
uint16_t mul_inv(uint16_t x) {
   uint16_t y = x;

   for(size_t i = 0; i != 15; ++i) {
      y = mul(y, y);  // square
      y = mul(y, x);
   }

   return y;
}

/**
* IDEA is involutional, depending only on the key schedule
*/
void idea_op(const uint8_t in[], uint8_t out[], size_t blocks, const uint16_t K[52]) {
   const size_t BLOCK_SIZE = 8;

   CT::poison(in, blocks * 8);
   CT::poison(out, blocks * 8);
   CT::poison(K, 52);

   for(size_t i = 0; i < blocks; ++i) {
      uint16_t X1, X2, X3, X4;
      load_be(in + BLOCK_SIZE * i, X1, X2, X3, X4);

      for(size_t j = 0; j != 8; ++j) {
         X1 = mul(X1, K[6 * j + 0]);
         X2 += K[6 * j + 1];
         X3 += K[6 * j + 2];
         X4 = mul(X4, K[6 * j + 3]);

         const uint16_t T0 = X3;
         X3 = mul(X3 ^ X1, K[6 * j + 4]);

         const uint16_t T1 = X2;
         X2 = mul((X2 ^ X4) + X3, K[6 * j + 5]);
         X3 += X2;

         X1 ^= X2;
         X4 ^= X3;
         X2 ^= T0;
         X3 ^= T1;
      }

      X1 = mul(X1, K[48]);
      X2 += K[50];
      X3 += K[49];
      X4 = mul(X4, K[51]);

      store_be(out + BLOCK_SIZE * i, X1, X3, X2, X4);
   }

   CT::unpoison(in, blocks * 8);
   CT::unpoison(out, blocks * 8);
   CT::unpoison(K, 52);
}

}  // namespace

size_t IDEA::parallelism() const {
#if defined(BOTAN_HAS_IDEA_SSE2)
   if(CPUID::has_sse2()) {
      return 8;
   }
#endif

   return 1;
}

std::string IDEA::provider() const {
#if defined(BOTAN_HAS_IDEA_SSE2)
   if(CPUID::has_sse2()) {
      return "sse2";
   }
#endif

   return "base";
}

/*
* IDEA Encryption
*/
void IDEA::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_IDEA_SSE2)
   if(CPUID::has_sse2()) {
      while(blocks >= 8) {
         sse2_idea_op_8(in, out, m_EK.data());
         in += 8 * BLOCK_SIZE;
         out += 8 * BLOCK_SIZE;
         blocks -= 8;
      }
   }
#endif

   idea_op(in, out, blocks, m_EK.data());
}

/*
* IDEA Decryption
*/
void IDEA::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_IDEA_SSE2)
   if(CPUID::has_sse2()) {
      while(blocks >= 8) {
         sse2_idea_op_8(in, out, m_DK.data());
         in += 8 * BLOCK_SIZE;
         out += 8 * BLOCK_SIZE;
         blocks -= 8;
      }
   }
#endif

   idea_op(in, out, blocks, m_DK.data());
}

bool IDEA::has_keying_material() const {
   return !m_EK.empty();
}

/*
* IDEA Key Schedule
*/
void IDEA::key_schedule(std::span<const uint8_t> key) {
   m_EK.resize(52);
   m_DK.resize(52);

   CT::poison(key.data(), 16);
   CT::poison(m_EK.data(), 52);
   CT::poison(m_DK.data(), 52);

   secure_vector<uint64_t> K(2);

   K[0] = load_be<uint64_t>(key.data(), 0);
   K[1] = load_be<uint64_t>(key.data(), 1);

   for(size_t off = 0; off != 48; off += 8) {
      for(size_t i = 0; i != 8; ++i) {
         m_EK[off + i] = static_cast<uint16_t>(K[i / 4] >> (48 - 16 * (i % 4)));
      }

      const uint64_t Kx = (K[0] >> 39);
      const uint64_t Ky = (K[1] >> 39);

      K[0] = (K[0] << 25) | Ky;
      K[1] = (K[1] << 25) | Kx;
   }

   for(size_t i = 0; i != 4; ++i) {
      m_EK[48 + i] = static_cast<uint16_t>(K[i / 4] >> (48 - 16 * (i % 4)));
   }

   m_DK[0] = mul_inv(m_EK[48]);
   m_DK[1] = -m_EK[49];
   m_DK[2] = -m_EK[50];
   m_DK[3] = mul_inv(m_EK[51]);

   for(size_t i = 0; i != 8 * 6; i += 6) {
      m_DK[i + 4] = m_EK[46 - i];
      m_DK[i + 5] = m_EK[47 - i];
      m_DK[i + 6] = mul_inv(m_EK[42 - i]);
      m_DK[i + 7] = -m_EK[44 - i];
      m_DK[i + 8] = -m_EK[43 - i];
      m_DK[i + 9] = mul_inv(m_EK[45 - i]);
   }

   std::swap(m_DK[49], m_DK[50]);

   CT::unpoison(key.data(), 16);
   CT::unpoison(m_EK.data(), 52);
   CT::unpoison(m_DK.data(), 52);
}

void IDEA::clear() {
   zap(m_EK);
   zap(m_DK);
}

}  // namespace Botan

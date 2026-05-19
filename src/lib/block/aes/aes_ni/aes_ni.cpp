/*
* AES using AES-NI instructions
* (C) 2009,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/simd_4x32.h>
#include <wmmintrin.h>

namespace Botan {

namespace {

// NOLINTBEGIN(portability-simd-intrinsics)

template <uint8_t RC>
BOTAN_FN_ISA_AESNI inline SIMD_4x32 aes_128_key_expansion(SIMD_4x32 key, SIMD_4x32 key_getting_rcon) {
   __m128i key_with_rcon = _mm_aeskeygenassist_si128(key_getting_rcon.raw(), RC);
   key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(3, 3, 3, 3));
   key ^= key.shift_elems_left<1>();
   key ^= key.shift_elems_left<1>();
   key ^= key.shift_elems_left<1>();
   key ^= SIMD_4x32(key_with_rcon);
   return key;
}

BOTAN_FN_ISA_AESNI
void aes_192_key_expansion(
   SIMD_4x32& K1, SIMD_4x32& K2, SIMD_4x32 key2_with_rcon, secure_vector<uint32_t>& out, size_t offset) {
   const SIMD_4x32 rcon = SIMD_4x32(_mm_shuffle_epi32(key2_with_rcon.raw(), _MM_SHUFFLE(1, 1, 1, 1)));
   K1 ^= K1.shift_elems_left<1>();
   K1 ^= K1.shift_elems_left<1>();
   K1 ^= K1.shift_elems_left<1>();
   K1 ^= rcon;

   K1.store_le(&out[offset]);

   if(offset == 48) {
      return;
   }

   K2 ^= K2.shift_elems_left<1>();
   K2 ^= SIMD_4x32(_mm_shuffle_epi32(K1.raw(), _MM_SHUFFLE(3, 3, 3, 3)));

   out[offset + 4] = _mm_cvtsi128_si32(K2.raw());
   out[offset + 5] = _mm_cvtsi128_si32(K2.shift_elems_right<1>().raw());
}

/*
* The second half of the AES-256 key expansion (other half same as AES-128)
*/
BOTAN_FN_ISA_AESNI SIMD_4x32 aes_256_key_expansion(SIMD_4x32 key, SIMD_4x32 key2) {
   __m128i key_with_rcon = _mm_aeskeygenassist_si128(key2.raw(), 0x00);
   key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(2, 2, 2, 2));

   key ^= key.shift_elems_left<1>();
   key ^= key.shift_elems_left<1>();
   key ^= key.shift_elems_left<1>();
   key ^= SIMD_4x32(key_with_rcon);
   return key;
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void keyxor(
   SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 ^= K;
   B1 ^= K;
   B2 ^= K;
   B3 ^= K;
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void aesenc(SIMD_4x32 K, SIMD_4x32& B) {
   B = SIMD_4x32(_mm_aesenc_si128(B.raw(), K.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void aesenc(
   SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 = SIMD_4x32(_mm_aesenc_si128(B0.raw(), K.raw()));
   B1 = SIMD_4x32(_mm_aesenc_si128(B1.raw(), K.raw()));
   B2 = SIMD_4x32(_mm_aesenc_si128(B2.raw(), K.raw()));
   B3 = SIMD_4x32(_mm_aesenc_si128(B3.raw(), K.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void aesenclast(SIMD_4x32 K, SIMD_4x32& B) {
   B = SIMD_4x32(_mm_aesenclast_si128(B.raw(), K.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void aesenclast(
   SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 = SIMD_4x32(_mm_aesenclast_si128(B0.raw(), K.raw()));
   B1 = SIMD_4x32(_mm_aesenclast_si128(B1.raw(), K.raw()));
   B2 = SIMD_4x32(_mm_aesenclast_si128(B2.raw(), K.raw()));
   B3 = SIMD_4x32(_mm_aesenclast_si128(B3.raw(), K.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void aesdec(SIMD_4x32 K, SIMD_4x32& B) {
   B = SIMD_4x32(_mm_aesdec_si128(B.raw(), K.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void aesdec(
   SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 = SIMD_4x32(_mm_aesdec_si128(B0.raw(), K.raw()));
   B1 = SIMD_4x32(_mm_aesdec_si128(B1.raw(), K.raw()));
   B2 = SIMD_4x32(_mm_aesdec_si128(B2.raw(), K.raw()));
   B3 = SIMD_4x32(_mm_aesdec_si128(B3.raw(), K.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void aesdeclast(SIMD_4x32 K, SIMD_4x32& B) {
   B = SIMD_4x32(_mm_aesdeclast_si128(B.raw(), K.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI void aesdeclast(
   SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 = SIMD_4x32(_mm_aesdeclast_si128(B0.raw(), K.raw()));
   B1 = SIMD_4x32(_mm_aesdeclast_si128(B1.raw(), K.raw()));
   B2 = SIMD_4x32(_mm_aesdeclast_si128(B2.raw(), K.raw()));
   B3 = SIMD_4x32(_mm_aesdeclast_si128(B3.raw(), K.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AESNI SIMD_4x32 aesimc(SIMD_4x32 B) {
   return SIMD_4x32(_mm_aesimc_si128(B.raw()));
}

// NOLINTEND(portability-simd-intrinsics)

}  // namespace

/*
* AES-128 Encryption
*/
BOTAN_FN_ISA_AESNI void AES_128::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_4x32 K0 = SIMD_4x32::load_le(&m_EK[4 * 0]);
   const SIMD_4x32 K1 = SIMD_4x32::load_le(&m_EK[4 * 1]);
   const SIMD_4x32 K2 = SIMD_4x32::load_le(&m_EK[4 * 2]);
   const SIMD_4x32 K3 = SIMD_4x32::load_le(&m_EK[4 * 3]);
   const SIMD_4x32 K4 = SIMD_4x32::load_le(&m_EK[4 * 4]);
   const SIMD_4x32 K5 = SIMD_4x32::load_le(&m_EK[4 * 5]);
   const SIMD_4x32 K6 = SIMD_4x32::load_le(&m_EK[4 * 6]);
   const SIMD_4x32 K7 = SIMD_4x32::load_le(&m_EK[4 * 7]);
   const SIMD_4x32 K8 = SIMD_4x32::load_le(&m_EK[4 * 8]);
   const SIMD_4x32 K9 = SIMD_4x32::load_le(&m_EK[4 * 9]);
   const SIMD_4x32 K10 = SIMD_4x32::load_le(&m_EK[4 * 10]);

   while(blocks >= 4) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * 0);
      SIMD_4x32 B1 = SIMD_4x32::load_le(in + 16 * 1);
      SIMD_4x32 B2 = SIMD_4x32::load_le(in + 16 * 2);
      SIMD_4x32 B3 = SIMD_4x32::load_le(in + 16 * 3);

      keyxor(K0, B0, B1, B2, B3);
      aesenc(K1, B0, B1, B2, B3);
      aesenc(K2, B0, B1, B2, B3);
      aesenc(K3, B0, B1, B2, B3);
      aesenc(K4, B0, B1, B2, B3);
      aesenc(K5, B0, B1, B2, B3);
      aesenc(K6, B0, B1, B2, B3);
      aesenc(K7, B0, B1, B2, B3);
      aesenc(K8, B0, B1, B2, B3);
      aesenc(K9, B0, B1, B2, B3);
      aesenclast(K10, B0, B1, B2, B3);

      B0.store_le(out + 16 * 0);
      B1.store_le(out + 16 * 1);
      B2.store_le(out + 16 * 2);
      B3.store_le(out + 16 * 3);

      blocks -= 4;
      in += 4 * 16;
      out += 4 * 16;
   }

   for(size_t i = 0; i != blocks; ++i) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * i);

      B0 ^= K0;
      aesenc(K1, B0);
      aesenc(K2, B0);
      aesenc(K3, B0);
      aesenc(K4, B0);
      aesenc(K5, B0);
      aesenc(K6, B0);
      aesenc(K7, B0);
      aesenc(K8, B0);
      aesenc(K9, B0);
      aesenclast(K10, B0);

      B0.store_le(out + 16 * i);
   }
}

/*
* AES-128 Decryption
*/
BOTAN_FN_ISA_AESNI void AES_128::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_4x32 K0 = SIMD_4x32::load_le(&m_DK[4 * 0]);
   const SIMD_4x32 K1 = SIMD_4x32::load_le(&m_DK[4 * 1]);
   const SIMD_4x32 K2 = SIMD_4x32::load_le(&m_DK[4 * 2]);
   const SIMD_4x32 K3 = SIMD_4x32::load_le(&m_DK[4 * 3]);
   const SIMD_4x32 K4 = SIMD_4x32::load_le(&m_DK[4 * 4]);
   const SIMD_4x32 K5 = SIMD_4x32::load_le(&m_DK[4 * 5]);
   const SIMD_4x32 K6 = SIMD_4x32::load_le(&m_DK[4 * 6]);
   const SIMD_4x32 K7 = SIMD_4x32::load_le(&m_DK[4 * 7]);
   const SIMD_4x32 K8 = SIMD_4x32::load_le(&m_DK[4 * 8]);
   const SIMD_4x32 K9 = SIMD_4x32::load_le(&m_DK[4 * 9]);
   const SIMD_4x32 K10 = SIMD_4x32::load_le(&m_DK[4 * 10]);

   while(blocks >= 4) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * 0);
      SIMD_4x32 B1 = SIMD_4x32::load_le(in + 16 * 1);
      SIMD_4x32 B2 = SIMD_4x32::load_le(in + 16 * 2);
      SIMD_4x32 B3 = SIMD_4x32::load_le(in + 16 * 3);

      keyxor(K0, B0, B1, B2, B3);
      aesdec(K1, B0, B1, B2, B3);
      aesdec(K2, B0, B1, B2, B3);
      aesdec(K3, B0, B1, B2, B3);
      aesdec(K4, B0, B1, B2, B3);
      aesdec(K5, B0, B1, B2, B3);
      aesdec(K6, B0, B1, B2, B3);
      aesdec(K7, B0, B1, B2, B3);
      aesdec(K8, B0, B1, B2, B3);
      aesdec(K9, B0, B1, B2, B3);
      aesdeclast(K10, B0, B1, B2, B3);

      B0.store_le(out + 16 * 0);
      B1.store_le(out + 16 * 1);
      B2.store_le(out + 16 * 2);
      B3.store_le(out + 16 * 3);

      blocks -= 4;
      in += 4 * 16;
      out += 4 * 16;
   }

   for(size_t i = 0; i != blocks; ++i) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * i);

      B0 ^= K0;
      aesdec(K1, B0);
      aesdec(K2, B0);
      aesdec(K3, B0);
      aesdec(K4, B0);
      aesdec(K5, B0);
      aesdec(K6, B0);
      aesdec(K7, B0);
      aesdec(K8, B0);
      aesdec(K9, B0);
      aesdeclast(K10, B0);

      B0.store_le(out + 16 * i);
   }
}

/*
* AES-128 Key Schedule
*/
BOTAN_FN_ISA_AESNI void AES_128::aesni_key_schedule(const uint8_t key[], size_t /*length*/) {
   m_EK.resize(44);
   m_DK.resize(44);

   const SIMD_4x32 K0 = SIMD_4x32::load_le(key);
   const SIMD_4x32 K1 = aes_128_key_expansion<0x01>(K0, K0);
   const SIMD_4x32 K2 = aes_128_key_expansion<0x02>(K1, K1);
   const SIMD_4x32 K3 = aes_128_key_expansion<0x04>(K2, K2);
   const SIMD_4x32 K4 = aes_128_key_expansion<0x08>(K3, K3);
   const SIMD_4x32 K5 = aes_128_key_expansion<0x10>(K4, K4);
   const SIMD_4x32 K6 = aes_128_key_expansion<0x20>(K5, K5);
   const SIMD_4x32 K7 = aes_128_key_expansion<0x40>(K6, K6);
   const SIMD_4x32 K8 = aes_128_key_expansion<0x80>(K7, K7);
   const SIMD_4x32 K9 = aes_128_key_expansion<0x1B>(K8, K8);
   const SIMD_4x32 K10 = aes_128_key_expansion<0x36>(K9, K9);

   K0.store_le(&m_EK[4 * 0]);
   K1.store_le(&m_EK[4 * 1]);
   K2.store_le(&m_EK[4 * 2]);
   K3.store_le(&m_EK[4 * 3]);
   K4.store_le(&m_EK[4 * 4]);
   K5.store_le(&m_EK[4 * 5]);
   K6.store_le(&m_EK[4 * 6]);
   K7.store_le(&m_EK[4 * 7]);
   K8.store_le(&m_EK[4 * 8]);
   K9.store_le(&m_EK[4 * 9]);
   K10.store_le(&m_EK[4 * 10]);

   // Now generate decryption keys
   K10.store_le(&m_DK[4 * 0]);
   aesimc(K9).store_le(&m_DK[4 * 1]);
   aesimc(K8).store_le(&m_DK[4 * 2]);
   aesimc(K7).store_le(&m_DK[4 * 3]);
   aesimc(K6).store_le(&m_DK[4 * 4]);
   aesimc(K5).store_le(&m_DK[4 * 5]);
   aesimc(K4).store_le(&m_DK[4 * 6]);
   aesimc(K3).store_le(&m_DK[4 * 7]);
   aesimc(K2).store_le(&m_DK[4 * 8]);
   aesimc(K1).store_le(&m_DK[4 * 9]);
   K0.store_le(&m_DK[4 * 10]);
}

/*
* AES-192 Encryption
*/
BOTAN_FN_ISA_AESNI void AES_192::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_4x32 K0 = SIMD_4x32::load_le(&m_EK[4 * 0]);
   const SIMD_4x32 K1 = SIMD_4x32::load_le(&m_EK[4 * 1]);
   const SIMD_4x32 K2 = SIMD_4x32::load_le(&m_EK[4 * 2]);
   const SIMD_4x32 K3 = SIMD_4x32::load_le(&m_EK[4 * 3]);
   const SIMD_4x32 K4 = SIMD_4x32::load_le(&m_EK[4 * 4]);
   const SIMD_4x32 K5 = SIMD_4x32::load_le(&m_EK[4 * 5]);
   const SIMD_4x32 K6 = SIMD_4x32::load_le(&m_EK[4 * 6]);
   const SIMD_4x32 K7 = SIMD_4x32::load_le(&m_EK[4 * 7]);
   const SIMD_4x32 K8 = SIMD_4x32::load_le(&m_EK[4 * 8]);
   const SIMD_4x32 K9 = SIMD_4x32::load_le(&m_EK[4 * 9]);
   const SIMD_4x32 K10 = SIMD_4x32::load_le(&m_EK[4 * 10]);
   const SIMD_4x32 K11 = SIMD_4x32::load_le(&m_EK[4 * 11]);
   const SIMD_4x32 K12 = SIMD_4x32::load_le(&m_EK[4 * 12]);

   while(blocks >= 4) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * 0);
      SIMD_4x32 B1 = SIMD_4x32::load_le(in + 16 * 1);
      SIMD_4x32 B2 = SIMD_4x32::load_le(in + 16 * 2);
      SIMD_4x32 B3 = SIMD_4x32::load_le(in + 16 * 3);

      keyxor(K0, B0, B1, B2, B3);
      aesenc(K1, B0, B1, B2, B3);
      aesenc(K2, B0, B1, B2, B3);
      aesenc(K3, B0, B1, B2, B3);
      aesenc(K4, B0, B1, B2, B3);
      aesenc(K5, B0, B1, B2, B3);
      aesenc(K6, B0, B1, B2, B3);
      aesenc(K7, B0, B1, B2, B3);
      aesenc(K8, B0, B1, B2, B3);
      aesenc(K9, B0, B1, B2, B3);
      aesenc(K10, B0, B1, B2, B3);
      aesenc(K11, B0, B1, B2, B3);
      aesenclast(K12, B0, B1, B2, B3);

      B0.store_le(out + 16 * 0);
      B1.store_le(out + 16 * 1);
      B2.store_le(out + 16 * 2);
      B3.store_le(out + 16 * 3);

      blocks -= 4;
      in += 4 * 16;
      out += 4 * 16;
   }

   for(size_t i = 0; i != blocks; ++i) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * i);

      B0 ^= K0;

      aesenc(K1, B0);
      aesenc(K2, B0);
      aesenc(K3, B0);
      aesenc(K4, B0);
      aesenc(K5, B0);
      aesenc(K6, B0);
      aesenc(K7, B0);
      aesenc(K8, B0);
      aesenc(K9, B0);
      aesenc(K10, B0);
      aesenc(K11, B0);
      aesenclast(K12, B0);

      B0.store_le(out + 16 * i);
   }
}

/*
* AES-192 Decryption
*/
BOTAN_FN_ISA_AESNI void AES_192::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_4x32 K0 = SIMD_4x32::load_le(&m_DK[4 * 0]);
   const SIMD_4x32 K1 = SIMD_4x32::load_le(&m_DK[4 * 1]);
   const SIMD_4x32 K2 = SIMD_4x32::load_le(&m_DK[4 * 2]);
   const SIMD_4x32 K3 = SIMD_4x32::load_le(&m_DK[4 * 3]);
   const SIMD_4x32 K4 = SIMD_4x32::load_le(&m_DK[4 * 4]);
   const SIMD_4x32 K5 = SIMD_4x32::load_le(&m_DK[4 * 5]);
   const SIMD_4x32 K6 = SIMD_4x32::load_le(&m_DK[4 * 6]);
   const SIMD_4x32 K7 = SIMD_4x32::load_le(&m_DK[4 * 7]);
   const SIMD_4x32 K8 = SIMD_4x32::load_le(&m_DK[4 * 8]);
   const SIMD_4x32 K9 = SIMD_4x32::load_le(&m_DK[4 * 9]);
   const SIMD_4x32 K10 = SIMD_4x32::load_le(&m_DK[4 * 10]);
   const SIMD_4x32 K11 = SIMD_4x32::load_le(&m_DK[4 * 11]);
   const SIMD_4x32 K12 = SIMD_4x32::load_le(&m_DK[4 * 12]);

   while(blocks >= 4) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * 0);
      SIMD_4x32 B1 = SIMD_4x32::load_le(in + 16 * 1);
      SIMD_4x32 B2 = SIMD_4x32::load_le(in + 16 * 2);
      SIMD_4x32 B3 = SIMD_4x32::load_le(in + 16 * 3);

      keyxor(K0, B0, B1, B2, B3);
      aesdec(K1, B0, B1, B2, B3);
      aesdec(K2, B0, B1, B2, B3);
      aesdec(K3, B0, B1, B2, B3);
      aesdec(K4, B0, B1, B2, B3);
      aesdec(K5, B0, B1, B2, B3);
      aesdec(K6, B0, B1, B2, B3);
      aesdec(K7, B0, B1, B2, B3);
      aesdec(K8, B0, B1, B2, B3);
      aesdec(K9, B0, B1, B2, B3);
      aesdec(K10, B0, B1, B2, B3);
      aesdec(K11, B0, B1, B2, B3);
      aesdeclast(K12, B0, B1, B2, B3);

      B0.store_le(out + 16 * 0);
      B1.store_le(out + 16 * 1);
      B2.store_le(out + 16 * 2);
      B3.store_le(out + 16 * 3);

      blocks -= 4;
      in += 4 * 16;
      out += 4 * 16;
   }

   for(size_t i = 0; i != blocks; ++i) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * i);

      B0 ^= K0;

      aesdec(K1, B0);
      aesdec(K2, B0);
      aesdec(K3, B0);
      aesdec(K4, B0);
      aesdec(K5, B0);
      aesdec(K6, B0);
      aesdec(K7, B0);
      aesdec(K8, B0);
      aesdec(K9, B0);
      aesdec(K10, B0);
      aesdec(K11, B0);
      aesdeclast(K12, B0);

      B0.store_le(out + 16 * i);
   }
}

/*
* AES-192 Key Schedule
*/
BOTAN_FN_ISA_AESNI void AES_192::aesni_key_schedule(const uint8_t key[], size_t /*length*/) {
   m_EK.resize(52);
   m_DK.resize(52);

   SIMD_4x32 K0 = SIMD_4x32::load_le(key);
   SIMD_4x32 K1 = SIMD_4x32::load_le(key + 8).shift_elems_right<2>();

   load_le(m_EK.data(), key, 6);

   aes_192_key_expansion(K0, K1, SIMD_4x32(_mm_aeskeygenassist_si128(K1.raw(), 0x01)), m_EK, 6);
   aes_192_key_expansion(K0, K1, SIMD_4x32(_mm_aeskeygenassist_si128(K1.raw(), 0x02)), m_EK, 12);
   aes_192_key_expansion(K0, K1, SIMD_4x32(_mm_aeskeygenassist_si128(K1.raw(), 0x04)), m_EK, 18);
   aes_192_key_expansion(K0, K1, SIMD_4x32(_mm_aeskeygenassist_si128(K1.raw(), 0x08)), m_EK, 24);
   aes_192_key_expansion(K0, K1, SIMD_4x32(_mm_aeskeygenassist_si128(K1.raw(), 0x10)), m_EK, 30);
   aes_192_key_expansion(K0, K1, SIMD_4x32(_mm_aeskeygenassist_si128(K1.raw(), 0x20)), m_EK, 36);
   aes_192_key_expansion(K0, K1, SIMD_4x32(_mm_aeskeygenassist_si128(K1.raw(), 0x40)), m_EK, 42);
   aes_192_key_expansion(K0, K1, SIMD_4x32(_mm_aeskeygenassist_si128(K1.raw(), 0x80)), m_EK, 48);

   // Now generate decryption keys
   SIMD_4x32::load_le(&m_EK[4 * 12]).store_le(&m_DK[4 * 0]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 11])).store_le(&m_DK[4 * 1]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 10])).store_le(&m_DK[4 * 2]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 9])).store_le(&m_DK[4 * 3]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 8])).store_le(&m_DK[4 * 4]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 7])).store_le(&m_DK[4 * 5]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 6])).store_le(&m_DK[4 * 6]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 5])).store_le(&m_DK[4 * 7]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 4])).store_le(&m_DK[4 * 8]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 3])).store_le(&m_DK[4 * 9]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 2])).store_le(&m_DK[4 * 10]);
   aesimc(SIMD_4x32::load_le(&m_EK[4 * 1])).store_le(&m_DK[4 * 11]);
   SIMD_4x32::load_le(&m_EK[4 * 0]).store_le(&m_DK[4 * 12]);
}

/*
* AES-256 Encryption
*/
BOTAN_FN_ISA_AESNI void AES_256::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_4x32 K0 = SIMD_4x32::load_le(&m_EK[4 * 0]);
   const SIMD_4x32 K1 = SIMD_4x32::load_le(&m_EK[4 * 1]);
   const SIMD_4x32 K2 = SIMD_4x32::load_le(&m_EK[4 * 2]);
   const SIMD_4x32 K3 = SIMD_4x32::load_le(&m_EK[4 * 3]);
   const SIMD_4x32 K4 = SIMD_4x32::load_le(&m_EK[4 * 4]);
   const SIMD_4x32 K5 = SIMD_4x32::load_le(&m_EK[4 * 5]);
   const SIMD_4x32 K6 = SIMD_4x32::load_le(&m_EK[4 * 6]);
   const SIMD_4x32 K7 = SIMD_4x32::load_le(&m_EK[4 * 7]);
   const SIMD_4x32 K8 = SIMD_4x32::load_le(&m_EK[4 * 8]);
   const SIMD_4x32 K9 = SIMD_4x32::load_le(&m_EK[4 * 9]);
   const SIMD_4x32 K10 = SIMD_4x32::load_le(&m_EK[4 * 10]);
   const SIMD_4x32 K11 = SIMD_4x32::load_le(&m_EK[4 * 11]);
   const SIMD_4x32 K12 = SIMD_4x32::load_le(&m_EK[4 * 12]);
   const SIMD_4x32 K13 = SIMD_4x32::load_le(&m_EK[4 * 13]);
   const SIMD_4x32 K14 = SIMD_4x32::load_le(&m_EK[4 * 14]);

   while(blocks >= 4) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * 0);
      SIMD_4x32 B1 = SIMD_4x32::load_le(in + 16 * 1);
      SIMD_4x32 B2 = SIMD_4x32::load_le(in + 16 * 2);
      SIMD_4x32 B3 = SIMD_4x32::load_le(in + 16 * 3);

      keyxor(K0, B0, B1, B2, B3);
      aesenc(K1, B0, B1, B2, B3);
      aesenc(K2, B0, B1, B2, B3);
      aesenc(K3, B0, B1, B2, B3);
      aesenc(K4, B0, B1, B2, B3);
      aesenc(K5, B0, B1, B2, B3);
      aesenc(K6, B0, B1, B2, B3);
      aesenc(K7, B0, B1, B2, B3);
      aesenc(K8, B0, B1, B2, B3);
      aesenc(K9, B0, B1, B2, B3);
      aesenc(K10, B0, B1, B2, B3);
      aesenc(K11, B0, B1, B2, B3);
      aesenc(K12, B0, B1, B2, B3);
      aesenc(K13, B0, B1, B2, B3);
      aesenclast(K14, B0, B1, B2, B3);

      B0.store_le(out + 16 * 0);
      B1.store_le(out + 16 * 1);
      B2.store_le(out + 16 * 2);
      B3.store_le(out + 16 * 3);

      blocks -= 4;
      in += 4 * 16;
      out += 4 * 16;
   }

   for(size_t i = 0; i != blocks; ++i) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * i);

      B0 ^= K0;

      aesenc(K1, B0);
      aesenc(K2, B0);
      aesenc(K3, B0);
      aesenc(K4, B0);
      aesenc(K5, B0);
      aesenc(K6, B0);
      aesenc(K7, B0);
      aesenc(K8, B0);
      aesenc(K9, B0);
      aesenc(K10, B0);
      aesenc(K11, B0);
      aesenc(K12, B0);
      aesenc(K13, B0);
      aesenclast(K14, B0);

      B0.store_le(out + 16 * i);
   }
}

/*
* AES-256 Decryption
*/
BOTAN_FN_ISA_AESNI void AES_256::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_4x32 K0 = SIMD_4x32::load_le(&m_DK[4 * 0]);
   const SIMD_4x32 K1 = SIMD_4x32::load_le(&m_DK[4 * 1]);
   const SIMD_4x32 K2 = SIMD_4x32::load_le(&m_DK[4 * 2]);
   const SIMD_4x32 K3 = SIMD_4x32::load_le(&m_DK[4 * 3]);
   const SIMD_4x32 K4 = SIMD_4x32::load_le(&m_DK[4 * 4]);
   const SIMD_4x32 K5 = SIMD_4x32::load_le(&m_DK[4 * 5]);
   const SIMD_4x32 K6 = SIMD_4x32::load_le(&m_DK[4 * 6]);
   const SIMD_4x32 K7 = SIMD_4x32::load_le(&m_DK[4 * 7]);
   const SIMD_4x32 K8 = SIMD_4x32::load_le(&m_DK[4 * 8]);
   const SIMD_4x32 K9 = SIMD_4x32::load_le(&m_DK[4 * 9]);
   const SIMD_4x32 K10 = SIMD_4x32::load_le(&m_DK[4 * 10]);
   const SIMD_4x32 K11 = SIMD_4x32::load_le(&m_DK[4 * 11]);
   const SIMD_4x32 K12 = SIMD_4x32::load_le(&m_DK[4 * 12]);
   const SIMD_4x32 K13 = SIMD_4x32::load_le(&m_DK[4 * 13]);
   const SIMD_4x32 K14 = SIMD_4x32::load_le(&m_DK[4 * 14]);

   while(blocks >= 4) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * 0);
      SIMD_4x32 B1 = SIMD_4x32::load_le(in + 16 * 1);
      SIMD_4x32 B2 = SIMD_4x32::load_le(in + 16 * 2);
      SIMD_4x32 B3 = SIMD_4x32::load_le(in + 16 * 3);

      keyxor(K0, B0, B1, B2, B3);
      aesdec(K1, B0, B1, B2, B3);
      aesdec(K2, B0, B1, B2, B3);
      aesdec(K3, B0, B1, B2, B3);
      aesdec(K4, B0, B1, B2, B3);
      aesdec(K5, B0, B1, B2, B3);
      aesdec(K6, B0, B1, B2, B3);
      aesdec(K7, B0, B1, B2, B3);
      aesdec(K8, B0, B1, B2, B3);
      aesdec(K9, B0, B1, B2, B3);
      aesdec(K10, B0, B1, B2, B3);
      aesdec(K11, B0, B1, B2, B3);
      aesdec(K12, B0, B1, B2, B3);
      aesdec(K13, B0, B1, B2, B3);
      aesdeclast(K14, B0, B1, B2, B3);

      B0.store_le(out + 16 * 0);
      B1.store_le(out + 16 * 1);
      B2.store_le(out + 16 * 2);
      B3.store_le(out + 16 * 3);

      blocks -= 4;
      in += 4 * 16;
      out += 4 * 16;
   }

   for(size_t i = 0; i != blocks; ++i) {
      SIMD_4x32 B0 = SIMD_4x32::load_le(in + 16 * i);

      B0 ^= K0;

      aesdec(K1, B0);
      aesdec(K2, B0);
      aesdec(K3, B0);
      aesdec(K4, B0);
      aesdec(K5, B0);
      aesdec(K6, B0);
      aesdec(K7, B0);
      aesdec(K8, B0);
      aesdec(K9, B0);
      aesdec(K10, B0);
      aesdec(K11, B0);
      aesdec(K12, B0);
      aesdec(K13, B0);
      aesdeclast(K14, B0);

      B0.store_le(out + 16 * i);
   }
}

/*
* AES-256 Key Schedule
*/
BOTAN_FN_ISA_AESNI void AES_256::aesni_key_schedule(const uint8_t key[], size_t /*length*/) {
   m_EK.resize(60);
   m_DK.resize(60);

   const SIMD_4x32 K0 = SIMD_4x32::load_le(key);
   const SIMD_4x32 K1 = SIMD_4x32::load_le(key + 16);

   const SIMD_4x32 K2 = aes_128_key_expansion<0x01>(K0, K1);
   const SIMD_4x32 K3 = aes_256_key_expansion(K1, K2);

   const SIMD_4x32 K4 = aes_128_key_expansion<0x02>(K2, K3);
   const SIMD_4x32 K5 = aes_256_key_expansion(K3, K4);

   const SIMD_4x32 K6 = aes_128_key_expansion<0x04>(K4, K5);
   const SIMD_4x32 K7 = aes_256_key_expansion(K5, K6);

   const SIMD_4x32 K8 = aes_128_key_expansion<0x08>(K6, K7);
   const SIMD_4x32 K9 = aes_256_key_expansion(K7, K8);

   const SIMD_4x32 K10 = aes_128_key_expansion<0x10>(K8, K9);
   const SIMD_4x32 K11 = aes_256_key_expansion(K9, K10);

   const SIMD_4x32 K12 = aes_128_key_expansion<0x20>(K10, K11);
   const SIMD_4x32 K13 = aes_256_key_expansion(K11, K12);

   const SIMD_4x32 K14 = aes_128_key_expansion<0x40>(K12, K13);

   K0.store_le(&m_EK[4 * 0]);
   K1.store_le(&m_EK[4 * 1]);
   K2.store_le(&m_EK[4 * 2]);
   K3.store_le(&m_EK[4 * 3]);
   K4.store_le(&m_EK[4 * 4]);
   K5.store_le(&m_EK[4 * 5]);
   K6.store_le(&m_EK[4 * 6]);
   K7.store_le(&m_EK[4 * 7]);
   K8.store_le(&m_EK[4 * 8]);
   K9.store_le(&m_EK[4 * 9]);
   K10.store_le(&m_EK[4 * 10]);
   K11.store_le(&m_EK[4 * 11]);
   K12.store_le(&m_EK[4 * 12]);
   K13.store_le(&m_EK[4 * 13]);
   K14.store_le(&m_EK[4 * 14]);

   K14.store_le(&m_DK[4 * 0]);
   aesimc(K13).store_le(&m_DK[4 * 1]);
   aesimc(K12).store_le(&m_DK[4 * 2]);
   aesimc(K11).store_le(&m_DK[4 * 3]);
   aesimc(K10).store_le(&m_DK[4 * 4]);
   aesimc(K9).store_le(&m_DK[4 * 5]);
   aesimc(K8).store_le(&m_DK[4 * 6]);
   aesimc(K7).store_le(&m_DK[4 * 7]);
   aesimc(K6).store_le(&m_DK[4 * 8]);
   aesimc(K5).store_le(&m_DK[4 * 9]);
   aesimc(K4).store_le(&m_DK[4 * 10]);
   aesimc(K3).store_le(&m_DK[4 * 11]);
   aesimc(K2).store_le(&m_DK[4 * 12]);
   aesimc(K1).store_le(&m_DK[4 * 13]);
   K0.store_le(&m_DK[4 * 14]);
}

}  // namespace Botan

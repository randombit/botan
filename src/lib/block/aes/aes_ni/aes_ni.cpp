/*
* AES using AES-NI instructions
* (C) 2009,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/simd_32.h>
#include <wmmintrin.h>

namespace Botan {

namespace {

template <uint8_t RC>
BOTAN_FUNC_ISA("ssse3,aes")
inline __m128i aes_128_key_expansion(__m128i key, __m128i key_getting_rcon) {
   __m128i key_with_rcon = _mm_aeskeygenassist_si128(key_getting_rcon, RC);
   key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(3, 3, 3, 3));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   return _mm_xor_si128(key, key_with_rcon);
}

BOTAN_FUNC_ISA("ssse3")
void aes_192_key_expansion(
   __m128i* K1, __m128i* K2, __m128i key2_with_rcon, secure_vector<uint32_t>& out, size_t offset) {
   __m128i key1 = *K1;
   __m128i key2 = *K2;

   key2_with_rcon = _mm_shuffle_epi32(key2_with_rcon, _MM_SHUFFLE(1, 1, 1, 1));
   key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
   key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
   key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
   key1 = _mm_xor_si128(key1, key2_with_rcon);

   *K1 = key1;
   _mm_storeu_si128(reinterpret_cast<__m128i*>(&out[offset]), key1);

   if(offset == 48) {  // last key
      return;
   }

   key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
   key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(key1, _MM_SHUFFLE(3, 3, 3, 3)));

   *K2 = key2;
   out[offset + 4] = _mm_cvtsi128_si32(key2);
   out[offset + 5] = _mm_cvtsi128_si32(_mm_srli_si128(key2, 4));
}

/*
* The second half of the AES-256 key expansion (other half same as AES-128)
*/
BOTAN_FUNC_ISA("ssse3,aes") __m128i aes_256_key_expansion(__m128i key, __m128i key2) {
   __m128i key_with_rcon = _mm_aeskeygenassist_si128(key2, 0x00);
   key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(2, 2, 2, 2));

   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   return _mm_xor_si128(key, key_with_rcon);
}

BOTAN_FORCE_INLINE void keyxor(SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 ^= K;
   B1 ^= K;
   B2 ^= K;
   B3 ^= K;
}

BOTAN_FUNC_ISA_INLINE("aes") void aesenc(SIMD_4x32 K, SIMD_4x32& B) {
   B = SIMD_4x32(_mm_aesenc_si128(B.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("aes") void aesenc(SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 = SIMD_4x32(_mm_aesenc_si128(B0.raw(), K.raw()));
   B1 = SIMD_4x32(_mm_aesenc_si128(B1.raw(), K.raw()));
   B2 = SIMD_4x32(_mm_aesenc_si128(B2.raw(), K.raw()));
   B3 = SIMD_4x32(_mm_aesenc_si128(B3.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("aes") void aesenclast(SIMD_4x32 K, SIMD_4x32& B) {
   B = SIMD_4x32(_mm_aesenclast_si128(B.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("aes") void aesenclast(SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 = SIMD_4x32(_mm_aesenclast_si128(B0.raw(), K.raw()));
   B1 = SIMD_4x32(_mm_aesenclast_si128(B1.raw(), K.raw()));
   B2 = SIMD_4x32(_mm_aesenclast_si128(B2.raw(), K.raw()));
   B3 = SIMD_4x32(_mm_aesenclast_si128(B3.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("aes") void aesdec(SIMD_4x32 K, SIMD_4x32& B) {
   B = SIMD_4x32(_mm_aesdec_si128(B.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("aes") void aesdec(SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 = SIMD_4x32(_mm_aesdec_si128(B0.raw(), K.raw()));
   B1 = SIMD_4x32(_mm_aesdec_si128(B1.raw(), K.raw()));
   B2 = SIMD_4x32(_mm_aesdec_si128(B2.raw(), K.raw()));
   B3 = SIMD_4x32(_mm_aesdec_si128(B3.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("aes") void aesdeclast(SIMD_4x32 K, SIMD_4x32& B) {
   B = SIMD_4x32(_mm_aesdeclast_si128(B.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("aes") void aesdeclast(SIMD_4x32 K, SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) {
   B0 = SIMD_4x32(_mm_aesdeclast_si128(B0.raw(), K.raw()));
   B1 = SIMD_4x32(_mm_aesdeclast_si128(B1.raw(), K.raw()));
   B2 = SIMD_4x32(_mm_aesdeclast_si128(B2.raw(), K.raw()));
   B3 = SIMD_4x32(_mm_aesdeclast_si128(B3.raw(), K.raw()));
}

}  // namespace

/*
* AES-128 Encryption
*/
BOTAN_FUNC_ISA("ssse3,aes") void AES_128::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
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
BOTAN_FUNC_ISA("ssse3,aes") void AES_128::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
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
BOTAN_FUNC_ISA("ssse3,aes") void AES_128::aesni_key_schedule(const uint8_t key[], size_t /*length*/) {
   m_EK.resize(44);
   m_DK.resize(44);

   const __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
   const __m128i K1 = aes_128_key_expansion<0x01>(K0, K0);
   const __m128i K2 = aes_128_key_expansion<0x02>(K1, K1);
   const __m128i K3 = aes_128_key_expansion<0x04>(K2, K2);
   const __m128i K4 = aes_128_key_expansion<0x08>(K3, K3);
   const __m128i K5 = aes_128_key_expansion<0x10>(K4, K4);
   const __m128i K6 = aes_128_key_expansion<0x20>(K5, K5);
   const __m128i K7 = aes_128_key_expansion<0x40>(K6, K6);
   const __m128i K8 = aes_128_key_expansion<0x80>(K7, K7);
   const __m128i K9 = aes_128_key_expansion<0x1B>(K8, K8);
   const __m128i K10 = aes_128_key_expansion<0x36>(K9, K9);

   __m128i* EK_mm = reinterpret_cast<__m128i*>(m_EK.data());
   _mm_storeu_si128(EK_mm, K0);
   _mm_storeu_si128(EK_mm + 1, K1);
   _mm_storeu_si128(EK_mm + 2, K2);
   _mm_storeu_si128(EK_mm + 3, K3);
   _mm_storeu_si128(EK_mm + 4, K4);
   _mm_storeu_si128(EK_mm + 5, K5);
   _mm_storeu_si128(EK_mm + 6, K6);
   _mm_storeu_si128(EK_mm + 7, K7);
   _mm_storeu_si128(EK_mm + 8, K8);
   _mm_storeu_si128(EK_mm + 9, K9);
   _mm_storeu_si128(EK_mm + 10, K10);

   // Now generate decryption keys

   __m128i* DK_mm = reinterpret_cast<__m128i*>(m_DK.data());
   _mm_storeu_si128(DK_mm, K10);
   _mm_storeu_si128(DK_mm + 1, _mm_aesimc_si128(K9));
   _mm_storeu_si128(DK_mm + 2, _mm_aesimc_si128(K8));
   _mm_storeu_si128(DK_mm + 3, _mm_aesimc_si128(K7));
   _mm_storeu_si128(DK_mm + 4, _mm_aesimc_si128(K6));
   _mm_storeu_si128(DK_mm + 5, _mm_aesimc_si128(K5));
   _mm_storeu_si128(DK_mm + 6, _mm_aesimc_si128(K4));
   _mm_storeu_si128(DK_mm + 7, _mm_aesimc_si128(K3));
   _mm_storeu_si128(DK_mm + 8, _mm_aesimc_si128(K2));
   _mm_storeu_si128(DK_mm + 9, _mm_aesimc_si128(K1));
   _mm_storeu_si128(DK_mm + 10, K0);
}

/*
* AES-192 Encryption
*/
BOTAN_FUNC_ISA("ssse3,aes") void AES_192::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
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
BOTAN_FUNC_ISA("ssse3,aes") void AES_192::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
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
BOTAN_FUNC_ISA("ssse3,aes") void AES_192::aesni_key_schedule(const uint8_t key[], size_t /*length*/) {
   m_EK.resize(52);
   m_DK.resize(52);

   __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
   __m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 8));
   K1 = _mm_srli_si128(K1, 8);

   load_le(m_EK.data(), key, 6);

   aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, 0x01), m_EK, 6);
   aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, 0x02), m_EK, 12);
   aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, 0x04), m_EK, 18);
   aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, 0x08), m_EK, 24);
   aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, 0x10), m_EK, 30);
   aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, 0x20), m_EK, 36);
   aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, 0x40), m_EK, 42);
   aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, 0x80), m_EK, 48);

   // Now generate decryption keys
   const __m128i* EK_mm = reinterpret_cast<const __m128i*>(m_EK.data());

   __m128i* DK_mm = reinterpret_cast<__m128i*>(m_DK.data());
   _mm_storeu_si128(DK_mm, _mm_loadu_si128(EK_mm + 12));
   _mm_storeu_si128(DK_mm + 1, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 11)));
   _mm_storeu_si128(DK_mm + 2, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 10)));
   _mm_storeu_si128(DK_mm + 3, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 9)));
   _mm_storeu_si128(DK_mm + 4, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 8)));
   _mm_storeu_si128(DK_mm + 5, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 7)));
   _mm_storeu_si128(DK_mm + 6, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 6)));
   _mm_storeu_si128(DK_mm + 7, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 5)));
   _mm_storeu_si128(DK_mm + 8, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 4)));
   _mm_storeu_si128(DK_mm + 9, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 3)));
   _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 2)));
   _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 1)));
   _mm_storeu_si128(DK_mm + 12, _mm_loadu_si128(EK_mm + 0));
}

/*
* AES-256 Encryption
*/
BOTAN_FUNC_ISA("ssse3,aes") void AES_256::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
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
BOTAN_FUNC_ISA("ssse3,aes") void AES_256::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
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
BOTAN_FUNC_ISA("ssse3,aes") void AES_256::aesni_key_schedule(const uint8_t key[], size_t /*length*/) {
   m_EK.resize(60);
   m_DK.resize(60);

   const __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
   const __m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));

   const __m128i K2 = aes_128_key_expansion<0x01>(K0, K1);
   const __m128i K3 = aes_256_key_expansion(K1, K2);

   const __m128i K4 = aes_128_key_expansion<0x02>(K2, K3);
   const __m128i K5 = aes_256_key_expansion(K3, K4);

   const __m128i K6 = aes_128_key_expansion<0x04>(K4, K5);
   const __m128i K7 = aes_256_key_expansion(K5, K6);

   const __m128i K8 = aes_128_key_expansion<0x08>(K6, K7);
   const __m128i K9 = aes_256_key_expansion(K7, K8);

   const __m128i K10 = aes_128_key_expansion<0x10>(K8, K9);
   const __m128i K11 = aes_256_key_expansion(K9, K10);

   const __m128i K12 = aes_128_key_expansion<0x20>(K10, K11);
   const __m128i K13 = aes_256_key_expansion(K11, K12);

   const __m128i K14 = aes_128_key_expansion<0x40>(K12, K13);

   __m128i* EK_mm = reinterpret_cast<__m128i*>(m_EK.data());
   _mm_storeu_si128(EK_mm, K0);
   _mm_storeu_si128(EK_mm + 1, K1);
   _mm_storeu_si128(EK_mm + 2, K2);
   _mm_storeu_si128(EK_mm + 3, K3);
   _mm_storeu_si128(EK_mm + 4, K4);
   _mm_storeu_si128(EK_mm + 5, K5);
   _mm_storeu_si128(EK_mm + 6, K6);
   _mm_storeu_si128(EK_mm + 7, K7);
   _mm_storeu_si128(EK_mm + 8, K8);
   _mm_storeu_si128(EK_mm + 9, K9);
   _mm_storeu_si128(EK_mm + 10, K10);
   _mm_storeu_si128(EK_mm + 11, K11);
   _mm_storeu_si128(EK_mm + 12, K12);
   _mm_storeu_si128(EK_mm + 13, K13);
   _mm_storeu_si128(EK_mm + 14, K14);

   // Now generate decryption keys
   __m128i* DK_mm = reinterpret_cast<__m128i*>(m_DK.data());
   _mm_storeu_si128(DK_mm, K14);
   _mm_storeu_si128(DK_mm + 1, _mm_aesimc_si128(K13));
   _mm_storeu_si128(DK_mm + 2, _mm_aesimc_si128(K12));
   _mm_storeu_si128(DK_mm + 3, _mm_aesimc_si128(K11));
   _mm_storeu_si128(DK_mm + 4, _mm_aesimc_si128(K10));
   _mm_storeu_si128(DK_mm + 5, _mm_aesimc_si128(K9));
   _mm_storeu_si128(DK_mm + 6, _mm_aesimc_si128(K8));
   _mm_storeu_si128(DK_mm + 7, _mm_aesimc_si128(K7));
   _mm_storeu_si128(DK_mm + 8, _mm_aesimc_si128(K6));
   _mm_storeu_si128(DK_mm + 9, _mm_aesimc_si128(K5));
   _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(K4));
   _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(K3));
   _mm_storeu_si128(DK_mm + 12, _mm_aesimc_si128(K2));
   _mm_storeu_si128(DK_mm + 13, _mm_aesimc_si128(K1));
   _mm_storeu_si128(DK_mm + 14, K0);
}

}  // namespace Botan

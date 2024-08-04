/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/simd_avx2.h>
#include <wmmintrin.h>

namespace Botan {

namespace {

BOTAN_FORCE_INLINE void keyxor(SIMD_8x32 K, SIMD_8x32& B0, SIMD_8x32& B1, SIMD_8x32& B2, SIMD_8x32& B3) {
   B0 ^= K;
   B1 ^= K;
   B2 ^= K;
   B3 ^= K;
}

BOTAN_FUNC_ISA_INLINE("vaes,avx2") void aesenc(SIMD_8x32 K, SIMD_8x32& B) {
   B = SIMD_8x32(_mm256_aesenc_epi128(B.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("vaes,avx2")
void aesenc(SIMD_8x32 K, SIMD_8x32& B0, SIMD_8x32& B1, SIMD_8x32& B2, SIMD_8x32& B3) {
   B0 = SIMD_8x32(_mm256_aesenc_epi128(B0.raw(), K.raw()));
   B1 = SIMD_8x32(_mm256_aesenc_epi128(B1.raw(), K.raw()));
   B2 = SIMD_8x32(_mm256_aesenc_epi128(B2.raw(), K.raw()));
   B3 = SIMD_8x32(_mm256_aesenc_epi128(B3.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("vaes,avx2") void aesenclast(SIMD_8x32 K, SIMD_8x32& B) {
   B = SIMD_8x32(_mm256_aesenclast_epi128(B.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("vaes,avx2")
void aesenclast(SIMD_8x32 K, SIMD_8x32& B0, SIMD_8x32& B1, SIMD_8x32& B2, SIMD_8x32& B3) {
   B0 = SIMD_8x32(_mm256_aesenclast_epi128(B0.raw(), K.raw()));
   B1 = SIMD_8x32(_mm256_aesenclast_epi128(B1.raw(), K.raw()));
   B2 = SIMD_8x32(_mm256_aesenclast_epi128(B2.raw(), K.raw()));
   B3 = SIMD_8x32(_mm256_aesenclast_epi128(B3.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("vaes,avx2") void aesdec(SIMD_8x32 K, SIMD_8x32& B) {
   B = SIMD_8x32(_mm256_aesdec_epi128(B.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("vaes,avx2")
void aesdec(SIMD_8x32 K, SIMD_8x32& B0, SIMD_8x32& B1, SIMD_8x32& B2, SIMD_8x32& B3) {
   B0 = SIMD_8x32(_mm256_aesdec_epi128(B0.raw(), K.raw()));
   B1 = SIMD_8x32(_mm256_aesdec_epi128(B1.raw(), K.raw()));
   B2 = SIMD_8x32(_mm256_aesdec_epi128(B2.raw(), K.raw()));
   B3 = SIMD_8x32(_mm256_aesdec_epi128(B3.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("vaes,avx2") void aesdeclast(SIMD_8x32 K, SIMD_8x32& B) {
   B = SIMD_8x32(_mm256_aesdeclast_epi128(B.raw(), K.raw()));
}

BOTAN_FUNC_ISA_INLINE("vaes,avx2")
void aesdeclast(SIMD_8x32 K, SIMD_8x32& B0, SIMD_8x32& B1, SIMD_8x32& B2, SIMD_8x32& B3) {
   B0 = SIMD_8x32(_mm256_aesdeclast_epi128(B0.raw(), K.raw()));
   B1 = SIMD_8x32(_mm256_aesdeclast_epi128(B1.raw(), K.raw()));
   B2 = SIMD_8x32(_mm256_aesdeclast_epi128(B2.raw(), K.raw()));
   B3 = SIMD_8x32(_mm256_aesdeclast_epi128(B3.raw(), K.raw()));
}

}  // namespace

/*
* AES-128 Encryption
*/
BOTAN_FUNC_ISA("vaes,avx2") void AES_128::x86_vaes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_8x32 K0 = SIMD_8x32::load_le128(&m_EK[4 * 0]);
   const SIMD_8x32 K1 = SIMD_8x32::load_le128(&m_EK[4 * 1]);
   const SIMD_8x32 K2 = SIMD_8x32::load_le128(&m_EK[4 * 2]);
   const SIMD_8x32 K3 = SIMD_8x32::load_le128(&m_EK[4 * 3]);
   const SIMD_8x32 K4 = SIMD_8x32::load_le128(&m_EK[4 * 4]);
   const SIMD_8x32 K5 = SIMD_8x32::load_le128(&m_EK[4 * 5]);
   const SIMD_8x32 K6 = SIMD_8x32::load_le128(&m_EK[4 * 6]);
   const SIMD_8x32 K7 = SIMD_8x32::load_le128(&m_EK[4 * 7]);
   const SIMD_8x32 K8 = SIMD_8x32::load_le128(&m_EK[4 * 8]);
   const SIMD_8x32 K9 = SIMD_8x32::load_le128(&m_EK[4 * 9]);
   const SIMD_8x32 K10 = SIMD_8x32::load_le128(&m_EK[4 * 10]);

   while(blocks >= 8) {
      SIMD_8x32 B0 = SIMD_8x32::load_le(in);
      SIMD_8x32 B1 = SIMD_8x32::load_le(in + 16 * 2);
      SIMD_8x32 B2 = SIMD_8x32::load_le(in + 16 * 4);
      SIMD_8x32 B3 = SIMD_8x32::load_le(in + 16 * 6);

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

      B0.store_le(out);
      B1.store_le(out + 16 * 2);
      B2.store_le(out + 16 * 4);
      B3.store_le(out + 16 * 6);

      blocks -= 8;
      in += 8 * 16;
      out += 8 * 16;
   }

   while(blocks >= 2) {
      SIMD_8x32 B = SIMD_8x32::load_le(in);

      B ^= K0;
      aesenc(K1, B);
      aesenc(K2, B);
      aesenc(K3, B);
      aesenc(K4, B);
      aesenc(K5, B);
      aesenc(K6, B);
      aesenc(K7, B);
      aesenc(K8, B);
      aesenc(K9, B);
      aesenclast(K10, B);

      B.store_le(out);

      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      SIMD_8x32 B = SIMD_8x32::load_le128(in);

      B ^= K0;
      aesenc(K1, B);
      aesenc(K2, B);
      aesenc(K3, B);
      aesenc(K4, B);
      aesenc(K5, B);
      aesenc(K6, B);
      aesenc(K7, B);
      aesenc(K8, B);
      aesenc(K9, B);
      aesenclast(K10, B);

      B.store_le128(out);
   }
}

/*
* AES-128 Decryption
*/
BOTAN_FUNC_ISA("vaes,avx2") void AES_128::x86_vaes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_8x32 K0 = SIMD_8x32::load_le128(&m_DK[4 * 0]);
   const SIMD_8x32 K1 = SIMD_8x32::load_le128(&m_DK[4 * 1]);
   const SIMD_8x32 K2 = SIMD_8x32::load_le128(&m_DK[4 * 2]);
   const SIMD_8x32 K3 = SIMD_8x32::load_le128(&m_DK[4 * 3]);
   const SIMD_8x32 K4 = SIMD_8x32::load_le128(&m_DK[4 * 4]);
   const SIMD_8x32 K5 = SIMD_8x32::load_le128(&m_DK[4 * 5]);
   const SIMD_8x32 K6 = SIMD_8x32::load_le128(&m_DK[4 * 6]);
   const SIMD_8x32 K7 = SIMD_8x32::load_le128(&m_DK[4 * 7]);
   const SIMD_8x32 K8 = SIMD_8x32::load_le128(&m_DK[4 * 8]);
   const SIMD_8x32 K9 = SIMD_8x32::load_le128(&m_DK[4 * 9]);
   const SIMD_8x32 K10 = SIMD_8x32::load_le128(&m_DK[4 * 10]);

   while(blocks >= 8) {
      SIMD_8x32 B0 = SIMD_8x32::load_le(in + 16 * 0);
      SIMD_8x32 B1 = SIMD_8x32::load_le(in + 16 * 2);
      SIMD_8x32 B2 = SIMD_8x32::load_le(in + 16 * 4);
      SIMD_8x32 B3 = SIMD_8x32::load_le(in + 16 * 6);

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
      B1.store_le(out + 16 * 2);
      B2.store_le(out + 16 * 4);
      B3.store_le(out + 16 * 6);

      blocks -= 8;
      in += 8 * 16;
      out += 8 * 16;
   }

   while(blocks >= 2) {
      SIMD_8x32 B = SIMD_8x32::load_le(in);

      B ^= K0;
      aesdec(K1, B);
      aesdec(K2, B);
      aesdec(K3, B);
      aesdec(K4, B);
      aesdec(K5, B);
      aesdec(K6, B);
      aesdec(K7, B);
      aesdec(K8, B);
      aesdec(K9, B);
      aesdeclast(K10, B);

      B.store_le(out);

      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      SIMD_8x32 B = SIMD_8x32::load_le128(in);

      B ^= K0;
      aesdec(K1, B);
      aesdec(K2, B);
      aesdec(K3, B);
      aesdec(K4, B);
      aesdec(K5, B);
      aesdec(K6, B);
      aesdec(K7, B);
      aesdec(K8, B);
      aesdec(K9, B);
      aesdeclast(K10, B);

      B.store_le128(out);
   }
}

/*
* AES-192 Encryption
*/
BOTAN_FUNC_ISA("vaes,avx2") void AES_192::x86_vaes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_8x32 K0 = SIMD_8x32::load_le128(&m_EK[4 * 0]);
   const SIMD_8x32 K1 = SIMD_8x32::load_le128(&m_EK[4 * 1]);
   const SIMD_8x32 K2 = SIMD_8x32::load_le128(&m_EK[4 * 2]);
   const SIMD_8x32 K3 = SIMD_8x32::load_le128(&m_EK[4 * 3]);
   const SIMD_8x32 K4 = SIMD_8x32::load_le128(&m_EK[4 * 4]);
   const SIMD_8x32 K5 = SIMD_8x32::load_le128(&m_EK[4 * 5]);
   const SIMD_8x32 K6 = SIMD_8x32::load_le128(&m_EK[4 * 6]);
   const SIMD_8x32 K7 = SIMD_8x32::load_le128(&m_EK[4 * 7]);
   const SIMD_8x32 K8 = SIMD_8x32::load_le128(&m_EK[4 * 8]);
   const SIMD_8x32 K9 = SIMD_8x32::load_le128(&m_EK[4 * 9]);
   const SIMD_8x32 K10 = SIMD_8x32::load_le128(&m_EK[4 * 10]);
   const SIMD_8x32 K11 = SIMD_8x32::load_le128(&m_EK[4 * 11]);
   const SIMD_8x32 K12 = SIMD_8x32::load_le128(&m_EK[4 * 12]);

   while(blocks >= 8) {
      SIMD_8x32 B0 = SIMD_8x32::load_le(in + 16 * 0);
      SIMD_8x32 B1 = SIMD_8x32::load_le(in + 16 * 2);
      SIMD_8x32 B2 = SIMD_8x32::load_le(in + 16 * 4);
      SIMD_8x32 B3 = SIMD_8x32::load_le(in + 16 * 6);

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
      B1.store_le(out + 16 * 2);
      B2.store_le(out + 16 * 4);
      B3.store_le(out + 16 * 6);

      blocks -= 8;
      in += 8 * 16;
      out += 8 * 16;
   }

   while(blocks >= 2) {
      SIMD_8x32 B = SIMD_8x32::load_le(in);

      B ^= K0;
      aesenc(K1, B);
      aesenc(K2, B);
      aesenc(K3, B);
      aesenc(K4, B);
      aesenc(K5, B);
      aesenc(K6, B);
      aesenc(K7, B);
      aesenc(K8, B);
      aesenc(K9, B);
      aesenc(K10, B);
      aesenc(K11, B);
      aesenclast(K12, B);

      B.store_le(out);

      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      SIMD_8x32 B = SIMD_8x32::load_le128(in);

      B ^= K0;
      aesenc(K1, B);
      aesenc(K2, B);
      aesenc(K3, B);
      aesenc(K4, B);
      aesenc(K5, B);
      aesenc(K6, B);
      aesenc(K7, B);
      aesenc(K8, B);
      aesenc(K9, B);
      aesenc(K10, B);
      aesenc(K11, B);
      aesenclast(K12, B);

      B.store_le128(out);
   }
}

/*
* AES-192 Decryption
*/
BOTAN_FUNC_ISA("vaes,avx2") void AES_192::x86_vaes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_8x32 K0 = SIMD_8x32::load_le128(&m_DK[4 * 0]);
   const SIMD_8x32 K1 = SIMD_8x32::load_le128(&m_DK[4 * 1]);
   const SIMD_8x32 K2 = SIMD_8x32::load_le128(&m_DK[4 * 2]);
   const SIMD_8x32 K3 = SIMD_8x32::load_le128(&m_DK[4 * 3]);
   const SIMD_8x32 K4 = SIMD_8x32::load_le128(&m_DK[4 * 4]);
   const SIMD_8x32 K5 = SIMD_8x32::load_le128(&m_DK[4 * 5]);
   const SIMD_8x32 K6 = SIMD_8x32::load_le128(&m_DK[4 * 6]);
   const SIMD_8x32 K7 = SIMD_8x32::load_le128(&m_DK[4 * 7]);
   const SIMD_8x32 K8 = SIMD_8x32::load_le128(&m_DK[4 * 8]);
   const SIMD_8x32 K9 = SIMD_8x32::load_le128(&m_DK[4 * 9]);
   const SIMD_8x32 K10 = SIMD_8x32::load_le128(&m_DK[4 * 10]);
   const SIMD_8x32 K11 = SIMD_8x32::load_le128(&m_DK[4 * 11]);
   const SIMD_8x32 K12 = SIMD_8x32::load_le128(&m_DK[4 * 12]);

   while(blocks >= 8) {
      SIMD_8x32 B0 = SIMD_8x32::load_le(in + 16 * 0);
      SIMD_8x32 B1 = SIMD_8x32::load_le(in + 16 * 2);
      SIMD_8x32 B2 = SIMD_8x32::load_le(in + 16 * 4);
      SIMD_8x32 B3 = SIMD_8x32::load_le(in + 16 * 6);

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
      B1.store_le(out + 16 * 2);
      B2.store_le(out + 16 * 4);
      B3.store_le(out + 16 * 6);

      blocks -= 8;
      in += 8 * 16;
      out += 8 * 16;
   }

   while(blocks >= 2) {
      SIMD_8x32 B = SIMD_8x32::load_le(in);

      B ^= K0;
      aesdec(K1, B);
      aesdec(K2, B);
      aesdec(K3, B);
      aesdec(K4, B);
      aesdec(K5, B);
      aesdec(K6, B);
      aesdec(K7, B);
      aesdec(K8, B);
      aesdec(K9, B);
      aesdec(K10, B);
      aesdec(K11, B);
      aesdeclast(K12, B);

      B.store_le(out);

      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      SIMD_8x32 B = SIMD_8x32::load_le128(in);

      B ^= K0;
      aesdec(K1, B);
      aesdec(K2, B);
      aesdec(K3, B);
      aesdec(K4, B);
      aesdec(K5, B);
      aesdec(K6, B);
      aesdec(K7, B);
      aesdec(K8, B);
      aesdec(K9, B);
      aesdec(K10, B);
      aesdec(K11, B);
      aesdeclast(K12, B);

      B.store_le128(out);
   }
}

BOTAN_FUNC_ISA("vaes,avx2") void AES_256::x86_vaes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_8x32 K0 = SIMD_8x32::load_le128(&m_EK[4 * 0]);
   const SIMD_8x32 K1 = SIMD_8x32::load_le128(&m_EK[4 * 1]);
   const SIMD_8x32 K2 = SIMD_8x32::load_le128(&m_EK[4 * 2]);
   const SIMD_8x32 K3 = SIMD_8x32::load_le128(&m_EK[4 * 3]);
   const SIMD_8x32 K4 = SIMD_8x32::load_le128(&m_EK[4 * 4]);
   const SIMD_8x32 K5 = SIMD_8x32::load_le128(&m_EK[4 * 5]);
   const SIMD_8x32 K6 = SIMD_8x32::load_le128(&m_EK[4 * 6]);
   const SIMD_8x32 K7 = SIMD_8x32::load_le128(&m_EK[4 * 7]);
   const SIMD_8x32 K8 = SIMD_8x32::load_le128(&m_EK[4 * 8]);
   const SIMD_8x32 K9 = SIMD_8x32::load_le128(&m_EK[4 * 9]);
   const SIMD_8x32 K10 = SIMD_8x32::load_le128(&m_EK[4 * 10]);
   const SIMD_8x32 K11 = SIMD_8x32::load_le128(&m_EK[4 * 11]);
   const SIMD_8x32 K12 = SIMD_8x32::load_le128(&m_EK[4 * 12]);
   const SIMD_8x32 K13 = SIMD_8x32::load_le128(&m_EK[4 * 13]);
   const SIMD_8x32 K14 = SIMD_8x32::load_le128(&m_EK[4 * 14]);

   while(blocks >= 8) {
      SIMD_8x32 B0 = SIMD_8x32::load_le(in + 16 * 0);
      SIMD_8x32 B1 = SIMD_8x32::load_le(in + 16 * 2);
      SIMD_8x32 B2 = SIMD_8x32::load_le(in + 16 * 4);
      SIMD_8x32 B3 = SIMD_8x32::load_le(in + 16 * 6);

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
      B1.store_le(out + 16 * 2);
      B2.store_le(out + 16 * 4);
      B3.store_le(out + 16 * 6);

      blocks -= 8;
      in += 8 * 16;
      out += 8 * 16;
   }

   while(blocks >= 2) {
      SIMD_8x32 B = SIMD_8x32::load_le(in);

      B ^= K0;
      aesenc(K1, B);
      aesenc(K2, B);
      aesenc(K3, B);
      aesenc(K4, B);
      aesenc(K5, B);
      aesenc(K6, B);
      aesenc(K7, B);
      aesenc(K8, B);
      aesenc(K9, B);
      aesenc(K10, B);
      aesenc(K11, B);
      aesenc(K12, B);
      aesenc(K13, B);
      aesenclast(K14, B);

      B.store_le(out);

      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      SIMD_8x32 B = SIMD_8x32::load_le128(in);

      B ^= K0;
      aesenc(K1, B);
      aesenc(K2, B);
      aesenc(K3, B);
      aesenc(K4, B);
      aesenc(K5, B);
      aesenc(K6, B);
      aesenc(K7, B);
      aesenc(K8, B);
      aesenc(K9, B);
      aesenc(K10, B);
      aesenc(K11, B);
      aesenc(K12, B);
      aesenc(K13, B);
      aesenclast(K14, B);

      B.store_le128(out);
   }
}

/*
* AES-256 Decryption
*/
BOTAN_FUNC_ISA("vaes,avx2") void AES_256::x86_vaes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const SIMD_8x32 K0 = SIMD_8x32::load_le128(&m_DK[4 * 0]);
   const SIMD_8x32 K1 = SIMD_8x32::load_le128(&m_DK[4 * 1]);
   const SIMD_8x32 K2 = SIMD_8x32::load_le128(&m_DK[4 * 2]);
   const SIMD_8x32 K3 = SIMD_8x32::load_le128(&m_DK[4 * 3]);
   const SIMD_8x32 K4 = SIMD_8x32::load_le128(&m_DK[4 * 4]);
   const SIMD_8x32 K5 = SIMD_8x32::load_le128(&m_DK[4 * 5]);
   const SIMD_8x32 K6 = SIMD_8x32::load_le128(&m_DK[4 * 6]);
   const SIMD_8x32 K7 = SIMD_8x32::load_le128(&m_DK[4 * 7]);
   const SIMD_8x32 K8 = SIMD_8x32::load_le128(&m_DK[4 * 8]);
   const SIMD_8x32 K9 = SIMD_8x32::load_le128(&m_DK[4 * 9]);
   const SIMD_8x32 K10 = SIMD_8x32::load_le128(&m_DK[4 * 10]);
   const SIMD_8x32 K11 = SIMD_8x32::load_le128(&m_DK[4 * 11]);
   const SIMD_8x32 K12 = SIMD_8x32::load_le128(&m_DK[4 * 12]);
   const SIMD_8x32 K13 = SIMD_8x32::load_le128(&m_DK[4 * 13]);
   const SIMD_8x32 K14 = SIMD_8x32::load_le128(&m_DK[4 * 14]);

   while(blocks >= 8) {
      SIMD_8x32 B0 = SIMD_8x32::load_le(in + 16 * 0);
      SIMD_8x32 B1 = SIMD_8x32::load_le(in + 16 * 2);
      SIMD_8x32 B2 = SIMD_8x32::load_le(in + 16 * 4);
      SIMD_8x32 B3 = SIMD_8x32::load_le(in + 16 * 6);

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
      B1.store_le(out + 16 * 2);
      B2.store_le(out + 16 * 4);
      B3.store_le(out + 16 * 6);

      blocks -= 8;
      in += 8 * 16;
      out += 8 * 16;
   }

   while(blocks >= 2) {
      SIMD_8x32 B = SIMD_8x32::load_le(in);

      B ^= K0;
      aesdec(K1, B);
      aesdec(K2, B);
      aesdec(K3, B);
      aesdec(K4, B);
      aesdec(K5, B);
      aesdec(K6, B);
      aesdec(K7, B);
      aesdec(K8, B);
      aesdec(K9, B);
      aesdec(K10, B);
      aesdec(K11, B);
      aesdec(K12, B);
      aesdec(K13, B);
      aesdeclast(K14, B);

      B.store_le(out);

      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      SIMD_8x32 B = SIMD_8x32::load_le128(in);

      B ^= K0;
      aesdec(K1, B);
      aesdec(K2, B);
      aesdec(K3, B);
      aesdec(K4, B);
      aesdec(K5, B);
      aesdec(K6, B);
      aesdec(K7, B);
      aesdec(K8, B);
      aesdec(K9, B);
      aesdec(K10, B);
      aesdec(K11, B);
      aesdec(K12, B);
      aesdec(K13, B);
      aesdeclast(K14, B);

      B.store_le128(out);
   }
}

}  // namespace Botan

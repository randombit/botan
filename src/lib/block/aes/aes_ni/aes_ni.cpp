/*
* AES using AES-NI instructions
* (C) 2009,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x32.h>
#include <wmmintrin.h>

namespace Botan {

namespace {

// NOLINTBEGIN(portability-simd-intrinsics)

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

}  // namespace Botan

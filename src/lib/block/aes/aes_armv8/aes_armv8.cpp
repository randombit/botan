/*
* AES using ARMv8
* Contributed by Jeffrey Walton
*
* Further changes
* (C) 2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes.h>

#include <botan/internal/loadstor.h>
#include <arm_neon.h>

namespace Botan {

namespace AES_AARCH64 {

BOTAN_FUNC_ISA_INLINE("+crypto+aes") void enc(uint8x16_t& B, uint8x16_t K) {
   B = vaesmcq_u8(vaeseq_u8(B, K));
}

BOTAN_FUNC_ISA_INLINE("+crypto+aes")
void enc4(uint8x16_t& B0, uint8x16_t& B1, uint8x16_t& B2, uint8x16_t& B3, uint8x16_t K) {
   B0 = vaesmcq_u8(vaeseq_u8(B0, K));
   B1 = vaesmcq_u8(vaeseq_u8(B1, K));
   B2 = vaesmcq_u8(vaeseq_u8(B2, K));
   B3 = vaesmcq_u8(vaeseq_u8(B3, K));
}

BOTAN_FUNC_ISA_INLINE("+crypto+aes") void enc_last(uint8x16_t& B, uint8x16_t K, uint8x16_t K2) {
   B = veorq_u8(vaeseq_u8(B, K), K2);
}

BOTAN_FUNC_ISA_INLINE("+crypto+aes")
void enc4_last(uint8x16_t& B0, uint8x16_t& B1, uint8x16_t& B2, uint8x16_t& B3, uint8x16_t K, uint8x16_t K2) {
   B0 = veorq_u8(vaeseq_u8(B0, K), K2);
   B1 = veorq_u8(vaeseq_u8(B1, K), K2);
   B2 = veorq_u8(vaeseq_u8(B2, K), K2);
   B3 = veorq_u8(vaeseq_u8(B3, K), K2);
}

BOTAN_FUNC_ISA_INLINE("+crypto+aes") void dec(uint8x16_t& B, uint8x16_t K) {
   B = vaesimcq_u8(vaesdq_u8(B, K));
}

BOTAN_FUNC_ISA_INLINE("+crypto+aes")
void dec4(uint8x16_t& B0, uint8x16_t& B1, uint8x16_t& B2, uint8x16_t& B3, uint8x16_t K) {
   B0 = vaesimcq_u8(vaesdq_u8(B0, K));
   B1 = vaesimcq_u8(vaesdq_u8(B1, K));
   B2 = vaesimcq_u8(vaesdq_u8(B2, K));
   B3 = vaesimcq_u8(vaesdq_u8(B3, K));
}

BOTAN_FUNC_ISA_INLINE("+crypto+aes") void dec_last(uint8x16_t& B, uint8x16_t K, uint8x16_t K2) {
   B = veorq_u8(vaesdq_u8(B, K), K2);
}

BOTAN_FUNC_ISA_INLINE("+crypto+aes")
void dec4_last(uint8x16_t& B0, uint8x16_t& B1, uint8x16_t& B2, uint8x16_t& B3, uint8x16_t K, uint8x16_t K2) {
   B0 = veorq_u8(vaesdq_u8(B0, K), K2);
   B1 = veorq_u8(vaesdq_u8(B1, K), K2);
   B2 = veorq_u8(vaesdq_u8(B2, K), K2);
   B3 = veorq_u8(vaesdq_u8(B3, K), K2);
}

}  // namespace AES_AARCH64

/*
* AES-128 Encryption
*/
BOTAN_FUNC_ISA("+crypto+aes") void AES_128::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const uint8_t* skey = reinterpret_cast<const uint8_t*>(m_EK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0 * 16);
   const uint8x16_t K1 = vld1q_u8(skey + 1 * 16);
   const uint8x16_t K2 = vld1q_u8(skey + 2 * 16);
   const uint8x16_t K3 = vld1q_u8(skey + 3 * 16);
   const uint8x16_t K4 = vld1q_u8(skey + 4 * 16);
   const uint8x16_t K5 = vld1q_u8(skey + 5 * 16);
   const uint8x16_t K6 = vld1q_u8(skey + 6 * 16);
   const uint8x16_t K7 = vld1q_u8(skey + 7 * 16);
   const uint8x16_t K8 = vld1q_u8(skey + 8 * 16);
   const uint8x16_t K9 = vld1q_u8(skey + 9 * 16);
   const uint8x16_t K10 = vld1q_u8(skey + 10 * 16);

   using namespace AES_AARCH64;

   while(blocks >= 4) {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in + 16);
      uint8x16_t B2 = vld1q_u8(in + 32);
      uint8x16_t B3 = vld1q_u8(in + 48);

      enc4(B0, B1, B2, B3, K0);
      enc4(B0, B1, B2, B3, K1);
      enc4(B0, B1, B2, B3, K2);
      enc4(B0, B1, B2, B3, K3);
      enc4(B0, B1, B2, B3, K4);
      enc4(B0, B1, B2, B3, K5);
      enc4(B0, B1, B2, B3, K6);
      enc4(B0, B1, B2, B3, K7);
      enc4(B0, B1, B2, B3, K8);
      enc4_last(B0, B1, B2, B3, K9, K10);

      vst1q_u8(out, B0);
      vst1q_u8(out + 16, B1);
      vst1q_u8(out + 32, B2);
      vst1q_u8(out + 48, B3);

      in += 16 * 4;
      out += 16 * 4;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint8x16_t B = vld1q_u8(in + 16 * i);
      enc(B, K0);
      enc(B, K1);
      enc(B, K2);
      enc(B, K3);
      enc(B, K4);
      enc(B, K5);
      enc(B, K6);
      enc(B, K7);
      enc(B, K8);
      enc_last(B, K9, K10);
      vst1q_u8(out + 16 * i, B);
   }
}

/*
* AES-128 Decryption
*/
BOTAN_FUNC_ISA("+crypto+aes") void AES_128::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const uint8_t* skey = reinterpret_cast<const uint8_t*>(m_DK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0 * 16);
   const uint8x16_t K1 = vld1q_u8(skey + 1 * 16);
   const uint8x16_t K2 = vld1q_u8(skey + 2 * 16);
   const uint8x16_t K3 = vld1q_u8(skey + 3 * 16);
   const uint8x16_t K4 = vld1q_u8(skey + 4 * 16);
   const uint8x16_t K5 = vld1q_u8(skey + 5 * 16);
   const uint8x16_t K6 = vld1q_u8(skey + 6 * 16);
   const uint8x16_t K7 = vld1q_u8(skey + 7 * 16);
   const uint8x16_t K8 = vld1q_u8(skey + 8 * 16);
   const uint8x16_t K9 = vld1q_u8(skey + 9 * 16);
   const uint8x16_t K10 = vld1q_u8(skey + 10 * 16);

   using namespace AES_AARCH64;

   while(blocks >= 4) {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in + 16);
      uint8x16_t B2 = vld1q_u8(in + 32);
      uint8x16_t B3 = vld1q_u8(in + 48);

      dec4(B0, B1, B2, B3, K0);
      dec4(B0, B1, B2, B3, K1);
      dec4(B0, B1, B2, B3, K2);
      dec4(B0, B1, B2, B3, K3);
      dec4(B0, B1, B2, B3, K4);
      dec4(B0, B1, B2, B3, K5);
      dec4(B0, B1, B2, B3, K6);
      dec4(B0, B1, B2, B3, K7);
      dec4(B0, B1, B2, B3, K8);
      dec4_last(B0, B1, B2, B3, K9, K10);

      vst1q_u8(out, B0);
      vst1q_u8(out + 16, B1);
      vst1q_u8(out + 32, B2);
      vst1q_u8(out + 48, B3);

      in += 16 * 4;
      out += 16 * 4;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint8x16_t B = vld1q_u8(in + 16 * i);
      dec(B, K0);
      dec(B, K1);
      dec(B, K2);
      dec(B, K3);
      dec(B, K4);
      dec(B, K5);
      dec(B, K6);
      dec(B, K7);
      dec(B, K8);
      B = veorq_u8(vaesdq_u8(B, K9), K10);
      vst1q_u8(out + 16 * i, B);
   }
}

/*
* AES-192 Encryption
*/
BOTAN_FUNC_ISA("+crypto+aes") void AES_192::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const uint8_t* skey = reinterpret_cast<const uint8_t*>(m_EK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0 * 16);
   const uint8x16_t K1 = vld1q_u8(skey + 1 * 16);
   const uint8x16_t K2 = vld1q_u8(skey + 2 * 16);
   const uint8x16_t K3 = vld1q_u8(skey + 3 * 16);
   const uint8x16_t K4 = vld1q_u8(skey + 4 * 16);
   const uint8x16_t K5 = vld1q_u8(skey + 5 * 16);
   const uint8x16_t K6 = vld1q_u8(skey + 6 * 16);
   const uint8x16_t K7 = vld1q_u8(skey + 7 * 16);
   const uint8x16_t K8 = vld1q_u8(skey + 8 * 16);
   const uint8x16_t K9 = vld1q_u8(skey + 9 * 16);
   const uint8x16_t K10 = vld1q_u8(skey + 10 * 16);
   const uint8x16_t K11 = vld1q_u8(skey + 11 * 16);
   const uint8x16_t K12 = vld1q_u8(skey + 12 * 16);

   using namespace AES_AARCH64;

   while(blocks >= 4) {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in + 16);
      uint8x16_t B2 = vld1q_u8(in + 32);
      uint8x16_t B3 = vld1q_u8(in + 48);

      enc4(B0, B1, B2, B3, K0);
      enc4(B0, B1, B2, B3, K1);
      enc4(B0, B1, B2, B3, K2);
      enc4(B0, B1, B2, B3, K3);
      enc4(B0, B1, B2, B3, K4);
      enc4(B0, B1, B2, B3, K5);
      enc4(B0, B1, B2, B3, K6);
      enc4(B0, B1, B2, B3, K7);
      enc4(B0, B1, B2, B3, K8);
      enc4(B0, B1, B2, B3, K9);
      enc4(B0, B1, B2, B3, K10);
      enc4_last(B0, B1, B2, B3, K11, K12);

      vst1q_u8(out, B0);
      vst1q_u8(out + 16, B1);
      vst1q_u8(out + 32, B2);
      vst1q_u8(out + 48, B3);

      in += 16 * 4;
      out += 16 * 4;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint8x16_t B = vld1q_u8(in + 16 * i);
      enc(B, K0);
      enc(B, K1);
      enc(B, K2);
      enc(B, K3);
      enc(B, K4);
      enc(B, K5);
      enc(B, K6);
      enc(B, K7);
      enc(B, K8);
      enc(B, K9);
      enc(B, K10);
      B = veorq_u8(vaeseq_u8(B, K11), K12);
      vst1q_u8(out + 16 * i, B);
   }
}

/*
* AES-192 Decryption
*/
BOTAN_FUNC_ISA("+crypto+aes") void AES_192::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const uint8_t* skey = reinterpret_cast<const uint8_t*>(m_DK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0 * 16);
   const uint8x16_t K1 = vld1q_u8(skey + 1 * 16);
   const uint8x16_t K2 = vld1q_u8(skey + 2 * 16);
   const uint8x16_t K3 = vld1q_u8(skey + 3 * 16);
   const uint8x16_t K4 = vld1q_u8(skey + 4 * 16);
   const uint8x16_t K5 = vld1q_u8(skey + 5 * 16);
   const uint8x16_t K6 = vld1q_u8(skey + 6 * 16);
   const uint8x16_t K7 = vld1q_u8(skey + 7 * 16);
   const uint8x16_t K8 = vld1q_u8(skey + 8 * 16);
   const uint8x16_t K9 = vld1q_u8(skey + 9 * 16);
   const uint8x16_t K10 = vld1q_u8(skey + 10 * 16);
   const uint8x16_t K11 = vld1q_u8(skey + 11 * 16);
   const uint8x16_t K12 = vld1q_u8(skey + 12 * 16);

   using namespace AES_AARCH64;

   while(blocks >= 4) {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in + 16);
      uint8x16_t B2 = vld1q_u8(in + 32);
      uint8x16_t B3 = vld1q_u8(in + 48);

      dec4(B0, B1, B2, B3, K0);
      dec4(B0, B1, B2, B3, K1);
      dec4(B0, B1, B2, B3, K2);
      dec4(B0, B1, B2, B3, K3);
      dec4(B0, B1, B2, B3, K4);
      dec4(B0, B1, B2, B3, K5);
      dec4(B0, B1, B2, B3, K6);
      dec4(B0, B1, B2, B3, K7);
      dec4(B0, B1, B2, B3, K8);
      dec4(B0, B1, B2, B3, K9);
      dec4(B0, B1, B2, B3, K10);
      dec4_last(B0, B1, B2, B3, K11, K12);

      vst1q_u8(out, B0);
      vst1q_u8(out + 16, B1);
      vst1q_u8(out + 32, B2);
      vst1q_u8(out + 48, B3);

      in += 16 * 4;
      out += 16 * 4;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint8x16_t B = vld1q_u8(in + 16 * i);
      dec(B, K0);
      dec(B, K1);
      dec(B, K2);
      dec(B, K3);
      dec(B, K4);
      dec(B, K5);
      dec(B, K6);
      dec(B, K7);
      dec(B, K8);
      dec(B, K9);
      dec(B, K10);
      B = veorq_u8(vaesdq_u8(B, K11), K12);
      vst1q_u8(out + 16 * i, B);
   }
}

/*
* AES-256 Encryption
*/
BOTAN_FUNC_ISA("+crypto+aes") void AES_256::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const uint8_t* skey = reinterpret_cast<const uint8_t*>(m_EK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0 * 16);
   const uint8x16_t K1 = vld1q_u8(skey + 1 * 16);
   const uint8x16_t K2 = vld1q_u8(skey + 2 * 16);
   const uint8x16_t K3 = vld1q_u8(skey + 3 * 16);
   const uint8x16_t K4 = vld1q_u8(skey + 4 * 16);
   const uint8x16_t K5 = vld1q_u8(skey + 5 * 16);
   const uint8x16_t K6 = vld1q_u8(skey + 6 * 16);
   const uint8x16_t K7 = vld1q_u8(skey + 7 * 16);
   const uint8x16_t K8 = vld1q_u8(skey + 8 * 16);
   const uint8x16_t K9 = vld1q_u8(skey + 9 * 16);
   const uint8x16_t K10 = vld1q_u8(skey + 10 * 16);
   const uint8x16_t K11 = vld1q_u8(skey + 11 * 16);
   const uint8x16_t K12 = vld1q_u8(skey + 12 * 16);
   const uint8x16_t K13 = vld1q_u8(skey + 13 * 16);
   const uint8x16_t K14 = vld1q_u8(skey + 14 * 16);

   using namespace AES_AARCH64;

   using namespace AES_AARCH64;

   while(blocks >= 4) {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in + 16);
      uint8x16_t B2 = vld1q_u8(in + 32);
      uint8x16_t B3 = vld1q_u8(in + 48);

      enc4(B0, B1, B2, B3, K0);
      enc4(B0, B1, B2, B3, K1);
      enc4(B0, B1, B2, B3, K2);
      enc4(B0, B1, B2, B3, K3);
      enc4(B0, B1, B2, B3, K4);
      enc4(B0, B1, B2, B3, K5);
      enc4(B0, B1, B2, B3, K6);
      enc4(B0, B1, B2, B3, K7);
      enc4(B0, B1, B2, B3, K8);
      enc4(B0, B1, B2, B3, K9);
      enc4(B0, B1, B2, B3, K10);
      enc4(B0, B1, B2, B3, K11);
      enc4(B0, B1, B2, B3, K12);
      enc4_last(B0, B1, B2, B3, K13, K14);

      vst1q_u8(out, B0);
      vst1q_u8(out + 16, B1);
      vst1q_u8(out + 32, B2);
      vst1q_u8(out + 48, B3);

      in += 16 * 4;
      out += 16 * 4;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint8x16_t B = vld1q_u8(in + 16 * i);
      enc(B, K0);
      enc(B, K1);
      enc(B, K2);
      enc(B, K3);
      enc(B, K4);
      enc(B, K5);
      enc(B, K6);
      enc(B, K7);
      enc(B, K8);
      enc(B, K9);
      enc(B, K10);
      enc(B, K11);
      enc(B, K12);
      B = veorq_u8(vaeseq_u8(B, K13), K14);
      vst1q_u8(out + 16 * i, B);
   }
}

/*
* AES-256 Decryption
*/
BOTAN_FUNC_ISA("+crypto+aes") void AES_256::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const uint8_t* skey = reinterpret_cast<const uint8_t*>(m_DK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0 * 16);
   const uint8x16_t K1 = vld1q_u8(skey + 1 * 16);
   const uint8x16_t K2 = vld1q_u8(skey + 2 * 16);
   const uint8x16_t K3 = vld1q_u8(skey + 3 * 16);
   const uint8x16_t K4 = vld1q_u8(skey + 4 * 16);
   const uint8x16_t K5 = vld1q_u8(skey + 5 * 16);
   const uint8x16_t K6 = vld1q_u8(skey + 6 * 16);
   const uint8x16_t K7 = vld1q_u8(skey + 7 * 16);
   const uint8x16_t K8 = vld1q_u8(skey + 8 * 16);
   const uint8x16_t K9 = vld1q_u8(skey + 9 * 16);
   const uint8x16_t K10 = vld1q_u8(skey + 10 * 16);
   const uint8x16_t K11 = vld1q_u8(skey + 11 * 16);
   const uint8x16_t K12 = vld1q_u8(skey + 12 * 16);
   const uint8x16_t K13 = vld1q_u8(skey + 13 * 16);
   const uint8x16_t K14 = vld1q_u8(skey + 14 * 16);

   using namespace AES_AARCH64;

   while(blocks >= 4) {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in + 16);
      uint8x16_t B2 = vld1q_u8(in + 32);
      uint8x16_t B3 = vld1q_u8(in + 48);

      dec4(B0, B1, B2, B3, K0);
      dec4(B0, B1, B2, B3, K1);
      dec4(B0, B1, B2, B3, K2);
      dec4(B0, B1, B2, B3, K3);
      dec4(B0, B1, B2, B3, K4);
      dec4(B0, B1, B2, B3, K5);
      dec4(B0, B1, B2, B3, K6);
      dec4(B0, B1, B2, B3, K7);
      dec4(B0, B1, B2, B3, K8);
      dec4(B0, B1, B2, B3, K9);
      dec4(B0, B1, B2, B3, K10);
      dec4(B0, B1, B2, B3, K11);
      dec4(B0, B1, B2, B3, K12);
      dec4_last(B0, B1, B2, B3, K13, K14);

      vst1q_u8(out, B0);
      vst1q_u8(out + 16, B1);
      vst1q_u8(out + 32, B2);
      vst1q_u8(out + 48, B3);

      in += 16 * 4;
      out += 16 * 4;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint8x16_t B = vld1q_u8(in + 16 * i);
      dec(B, K0);
      dec(B, K1);
      dec(B, K2);
      dec(B, K3);
      dec(B, K4);
      dec(B, K5);
      dec(B, K6);
      dec(B, K7);
      dec(B, K8);
      dec(B, K9);
      dec(B, K10);
      dec(B, K11);
      dec(B, K12);
      B = veorq_u8(vaesdq_u8(B, K13), K14);
      vst1q_u8(out + 16 * i, B);
   }
}

}  // namespace Botan

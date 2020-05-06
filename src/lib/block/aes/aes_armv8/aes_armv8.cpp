/*
* AES using ARMv8
* Contributed by Jeffrey Walton
*
* Further changes
* (C) 2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aes.h>
#include <botan/loadstor.h>
#include <arm_neon.h>

namespace Botan {

#define AES_ENC_4_ROUNDS(K)                \
   do                                      \
      {                                    \
      B0 = vaesmcq_u8(vaeseq_u8(B0, K));   \
      B1 = vaesmcq_u8(vaeseq_u8(B1, K));   \
      B2 = vaesmcq_u8(vaeseq_u8(B2, K));   \
      B3 = vaesmcq_u8(vaeseq_u8(B3, K));   \
      } while(0)

#define AES_ENC_4_LAST_ROUNDS(K, K2)       \
   do                                      \
      {                                    \
      B0 = veorq_u8(vaeseq_u8(B0, K), K2); \
      B1 = veorq_u8(vaeseq_u8(B1, K), K2); \
      B2 = veorq_u8(vaeseq_u8(B2, K), K2); \
      B3 = veorq_u8(vaeseq_u8(B3, K), K2); \
      } while(0)

#define AES_DEC_4_ROUNDS(K)                \
   do                                      \
      {                                    \
      B0 = vaesimcq_u8(vaesdq_u8(B0, K));  \
      B1 = vaesimcq_u8(vaesdq_u8(B1, K));  \
      B2 = vaesimcq_u8(vaesdq_u8(B2, K));  \
      B3 = vaesimcq_u8(vaesdq_u8(B3, K));  \
      } while(0)

#define AES_DEC_4_LAST_ROUNDS(K, K2)       \
   do                                      \
      {                                    \
      B0 = veorq_u8(vaesdq_u8(B0, K), K2); \
      B1 = veorq_u8(vaesdq_u8(B1, K), K2); \
      B2 = veorq_u8(vaesdq_u8(B2, K), K2); \
      B3 = veorq_u8(vaesdq_u8(B3, K), K2); \
      } while(0)

/*
* AES-128 Encryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_128::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_EK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0*16);
   const uint8x16_t K1 = vld1q_u8(skey + 1*16);
   const uint8x16_t K2 = vld1q_u8(skey + 2*16);
   const uint8x16_t K3 = vld1q_u8(skey + 3*16);
   const uint8x16_t K4 = vld1q_u8(skey + 4*16);
   const uint8x16_t K5 = vld1q_u8(skey + 5*16);
   const uint8x16_t K6 = vld1q_u8(skey + 6*16);
   const uint8x16_t K7 = vld1q_u8(skey + 7*16);
   const uint8x16_t K8 = vld1q_u8(skey + 8*16);
   const uint8x16_t K9 = vld1q_u8(skey + 9*16);
   const uint8x16_t K10 = vld1q_u8(skey + 10*16);

   while(blocks >= 4)
      {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in+16);
      uint8x16_t B2 = vld1q_u8(in+32);
      uint8x16_t B3 = vld1q_u8(in+48);

      AES_ENC_4_ROUNDS(K0);
      AES_ENC_4_ROUNDS(K1);
      AES_ENC_4_ROUNDS(K2);
      AES_ENC_4_ROUNDS(K3);
      AES_ENC_4_ROUNDS(K4);
      AES_ENC_4_ROUNDS(K5);
      AES_ENC_4_ROUNDS(K6);
      AES_ENC_4_ROUNDS(K7);
      AES_ENC_4_ROUNDS(K8);
      AES_ENC_4_LAST_ROUNDS(K9, K10);

      vst1q_u8(out, B0);
      vst1q_u8(out+16, B1);
      vst1q_u8(out+32, B2);
      vst1q_u8(out+48, B3);

      in += 16*4;
      out += 16*4;
      blocks -= 4;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t B = vld1q_u8(in+16*i);
      B = vaesmcq_u8(vaeseq_u8(B, K0));
      B = vaesmcq_u8(vaeseq_u8(B, K1));
      B = vaesmcq_u8(vaeseq_u8(B, K2));
      B = vaesmcq_u8(vaeseq_u8(B, K3));
      B = vaesmcq_u8(vaeseq_u8(B, K4));
      B = vaesmcq_u8(vaeseq_u8(B, K5));
      B = vaesmcq_u8(vaeseq_u8(B, K6));
      B = vaesmcq_u8(vaeseq_u8(B, K7));
      B = vaesmcq_u8(vaeseq_u8(B, K8));
      B = veorq_u8(vaeseq_u8(B, K9), K10);
      vst1q_u8(out+16*i, B);
      }
   }

/*
* AES-128 Decryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_128::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_DK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0*16);
   const uint8x16_t K1 = vld1q_u8(skey + 1*16);
   const uint8x16_t K2 = vld1q_u8(skey + 2*16);
   const uint8x16_t K3 = vld1q_u8(skey + 3*16);
   const uint8x16_t K4 = vld1q_u8(skey + 4*16);
   const uint8x16_t K5 = vld1q_u8(skey + 5*16);
   const uint8x16_t K6 = vld1q_u8(skey + 6*16);
   const uint8x16_t K7 = vld1q_u8(skey + 7*16);
   const uint8x16_t K8 = vld1q_u8(skey + 8*16);
   const uint8x16_t K9 = vld1q_u8(skey + 9*16);
   const uint8x16_t K10 = vld1q_u8(skey + 10*16);

   while(blocks >= 4)
      {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in+16);
      uint8x16_t B2 = vld1q_u8(in+32);
      uint8x16_t B3 = vld1q_u8(in+48);

      AES_DEC_4_ROUNDS(K0);
      AES_DEC_4_ROUNDS(K1);
      AES_DEC_4_ROUNDS(K2);
      AES_DEC_4_ROUNDS(K3);
      AES_DEC_4_ROUNDS(K4);
      AES_DEC_4_ROUNDS(K5);
      AES_DEC_4_ROUNDS(K6);
      AES_DEC_4_ROUNDS(K7);
      AES_DEC_4_ROUNDS(K8);
      AES_DEC_4_LAST_ROUNDS(K9, K10);

      vst1q_u8(out, B0);
      vst1q_u8(out+16, B1);
      vst1q_u8(out+32, B2);
      vst1q_u8(out+48, B3);

      in += 16*4;
      out += 16*4;
      blocks -= 4;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t B = vld1q_u8(in+16*i);
      B = vaesimcq_u8(vaesdq_u8(B, K0));
      B = vaesimcq_u8(vaesdq_u8(B, K1));
      B = vaesimcq_u8(vaesdq_u8(B, K2));
      B = vaesimcq_u8(vaesdq_u8(B, K3));
      B = vaesimcq_u8(vaesdq_u8(B, K4));
      B = vaesimcq_u8(vaesdq_u8(B, K5));
      B = vaesimcq_u8(vaesdq_u8(B, K6));
      B = vaesimcq_u8(vaesdq_u8(B, K7));
      B = vaesimcq_u8(vaesdq_u8(B, K8));
      B = veorq_u8(vaesdq_u8(B, K9), K10);
      vst1q_u8(out+16*i, B);
      }
   }

/*
* AES-192 Encryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_192::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_EK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0*16);
   const uint8x16_t K1 = vld1q_u8(skey + 1*16);
   const uint8x16_t K2 = vld1q_u8(skey + 2*16);
   const uint8x16_t K3 = vld1q_u8(skey + 3*16);
   const uint8x16_t K4 = vld1q_u8(skey + 4*16);
   const uint8x16_t K5 = vld1q_u8(skey + 5*16);
   const uint8x16_t K6 = vld1q_u8(skey + 6*16);
   const uint8x16_t K7 = vld1q_u8(skey + 7*16);
   const uint8x16_t K8 = vld1q_u8(skey + 8*16);
   const uint8x16_t K9 = vld1q_u8(skey + 9*16);
   const uint8x16_t K10 = vld1q_u8(skey + 10*16);
   const uint8x16_t K11 = vld1q_u8(skey + 11*16);
   const uint8x16_t K12 = vld1q_u8(skey + 12*16);

   while(blocks >= 4)
      {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in+16);
      uint8x16_t B2 = vld1q_u8(in+32);
      uint8x16_t B3 = vld1q_u8(in+48);

      AES_ENC_4_ROUNDS(K0);
      AES_ENC_4_ROUNDS(K1);
      AES_ENC_4_ROUNDS(K2);
      AES_ENC_4_ROUNDS(K3);
      AES_ENC_4_ROUNDS(K4);
      AES_ENC_4_ROUNDS(K5);
      AES_ENC_4_ROUNDS(K6);
      AES_ENC_4_ROUNDS(K7);
      AES_ENC_4_ROUNDS(K8);
      AES_ENC_4_ROUNDS(K9);
      AES_ENC_4_ROUNDS(K10);
      AES_ENC_4_LAST_ROUNDS(K11, K12);

      vst1q_u8(out, B0);
      vst1q_u8(out+16, B1);
      vst1q_u8(out+32, B2);
      vst1q_u8(out+48, B3);

      in += 16*4;
      out += 16*4;
      blocks -= 4;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t B = vld1q_u8(in+16*i);
      B = vaesmcq_u8(vaeseq_u8(B, K0));
      B = vaesmcq_u8(vaeseq_u8(B, K1));
      B = vaesmcq_u8(vaeseq_u8(B, K2));
      B = vaesmcq_u8(vaeseq_u8(B, K3));
      B = vaesmcq_u8(vaeseq_u8(B, K4));
      B = vaesmcq_u8(vaeseq_u8(B, K5));
      B = vaesmcq_u8(vaeseq_u8(B, K6));
      B = vaesmcq_u8(vaeseq_u8(B, K7));
      B = vaesmcq_u8(vaeseq_u8(B, K8));
      B = vaesmcq_u8(vaeseq_u8(B, K9));
      B = vaesmcq_u8(vaeseq_u8(B, K10));
      B = veorq_u8(vaeseq_u8(B, K11), K12);
      vst1q_u8(out+16*i, B);
      }
   }

/*
* AES-192 Decryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_192::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_DK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0*16);
   const uint8x16_t K1 = vld1q_u8(skey + 1*16);
   const uint8x16_t K2 = vld1q_u8(skey + 2*16);
   const uint8x16_t K3 = vld1q_u8(skey + 3*16);
   const uint8x16_t K4 = vld1q_u8(skey + 4*16);
   const uint8x16_t K5 = vld1q_u8(skey + 5*16);
   const uint8x16_t K6 = vld1q_u8(skey + 6*16);
   const uint8x16_t K7 = vld1q_u8(skey + 7*16);
   const uint8x16_t K8 = vld1q_u8(skey + 8*16);
   const uint8x16_t K9 = vld1q_u8(skey + 9*16);
   const uint8x16_t K10 = vld1q_u8(skey + 10*16);
   const uint8x16_t K11 = vld1q_u8(skey + 11*16);
   const uint8x16_t K12 = vld1q_u8(skey + 12*16);

   while(blocks >= 4)
      {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in+16);
      uint8x16_t B2 = vld1q_u8(in+32);
      uint8x16_t B3 = vld1q_u8(in+48);

      AES_DEC_4_ROUNDS(K0);
      AES_DEC_4_ROUNDS(K1);
      AES_DEC_4_ROUNDS(K2);
      AES_DEC_4_ROUNDS(K3);
      AES_DEC_4_ROUNDS(K4);
      AES_DEC_4_ROUNDS(K5);
      AES_DEC_4_ROUNDS(K6);
      AES_DEC_4_ROUNDS(K7);
      AES_DEC_4_ROUNDS(K8);
      AES_DEC_4_ROUNDS(K9);
      AES_DEC_4_ROUNDS(K10);
      AES_DEC_4_LAST_ROUNDS(K11, K12);

      vst1q_u8(out, B0);
      vst1q_u8(out+16, B1);
      vst1q_u8(out+32, B2);
      vst1q_u8(out+48, B3);

      in += 16*4;
      out += 16*4;
      blocks -= 4;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t B = vld1q_u8(in+16*i);
      B = vaesimcq_u8(vaesdq_u8(B, K0));
      B = vaesimcq_u8(vaesdq_u8(B, K1));
      B = vaesimcq_u8(vaesdq_u8(B, K2));
      B = vaesimcq_u8(vaesdq_u8(B, K3));
      B = vaesimcq_u8(vaesdq_u8(B, K4));
      B = vaesimcq_u8(vaesdq_u8(B, K5));
      B = vaesimcq_u8(vaesdq_u8(B, K6));
      B = vaesimcq_u8(vaesdq_u8(B, K7));
      B = vaesimcq_u8(vaesdq_u8(B, K8));
      B = vaesimcq_u8(vaesdq_u8(B, K9));
      B = vaesimcq_u8(vaesdq_u8(B, K10));
      B = veorq_u8(vaesdq_u8(B, K11), K12);
      vst1q_u8(out+16*i, B);
      }
   }

/*
* AES-256 Encryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_256::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_EK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0*16);
   const uint8x16_t K1 = vld1q_u8(skey + 1*16);
   const uint8x16_t K2 = vld1q_u8(skey + 2*16);
   const uint8x16_t K3 = vld1q_u8(skey + 3*16);
   const uint8x16_t K4 = vld1q_u8(skey + 4*16);
   const uint8x16_t K5 = vld1q_u8(skey + 5*16);
   const uint8x16_t K6 = vld1q_u8(skey + 6*16);
   const uint8x16_t K7 = vld1q_u8(skey + 7*16);
   const uint8x16_t K8 = vld1q_u8(skey + 8*16);
   const uint8x16_t K9 = vld1q_u8(skey + 9*16);
   const uint8x16_t K10 = vld1q_u8(skey + 10*16);
   const uint8x16_t K11 = vld1q_u8(skey + 11*16);
   const uint8x16_t K12 = vld1q_u8(skey + 12*16);
   const uint8x16_t K13 = vld1q_u8(skey + 13*16);
   const uint8x16_t K14 = vld1q_u8(skey + 14*16);

   while(blocks >= 4)
      {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in+16);
      uint8x16_t B2 = vld1q_u8(in+32);
      uint8x16_t B3 = vld1q_u8(in+48);

      AES_ENC_4_ROUNDS(K0);
      AES_ENC_4_ROUNDS(K1);
      AES_ENC_4_ROUNDS(K2);
      AES_ENC_4_ROUNDS(K3);
      AES_ENC_4_ROUNDS(K4);
      AES_ENC_4_ROUNDS(K5);
      AES_ENC_4_ROUNDS(K6);
      AES_ENC_4_ROUNDS(K7);
      AES_ENC_4_ROUNDS(K8);
      AES_ENC_4_ROUNDS(K9);
      AES_ENC_4_ROUNDS(K10);
      AES_ENC_4_ROUNDS(K11);
      AES_ENC_4_ROUNDS(K12);
      AES_ENC_4_LAST_ROUNDS(K13, K14);

      vst1q_u8(out, B0);
      vst1q_u8(out+16, B1);
      vst1q_u8(out+32, B2);
      vst1q_u8(out+48, B3);

      in += 16*4;
      out += 16*4;
      blocks -= 4;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t B = vld1q_u8(in+16*i);
      B = vaesmcq_u8(vaeseq_u8(B, K0));
      B = vaesmcq_u8(vaeseq_u8(B, K1));
      B = vaesmcq_u8(vaeseq_u8(B, K2));
      B = vaesmcq_u8(vaeseq_u8(B, K3));
      B = vaesmcq_u8(vaeseq_u8(B, K4));
      B = vaesmcq_u8(vaeseq_u8(B, K5));
      B = vaesmcq_u8(vaeseq_u8(B, K6));
      B = vaesmcq_u8(vaeseq_u8(B, K7));
      B = vaesmcq_u8(vaeseq_u8(B, K8));
      B = vaesmcq_u8(vaeseq_u8(B, K9));
      B = vaesmcq_u8(vaeseq_u8(B, K10));
      B = vaesmcq_u8(vaeseq_u8(B, K11));
      B = vaesmcq_u8(vaeseq_u8(B, K12));
      B = veorq_u8(vaeseq_u8(B, K13), K14);
      vst1q_u8(out+16*i, B);
      }
   }

/*
* AES-256 Decryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_256::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_DK.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0*16);
   const uint8x16_t K1 = vld1q_u8(skey + 1*16);
   const uint8x16_t K2 = vld1q_u8(skey + 2*16);
   const uint8x16_t K3 = vld1q_u8(skey + 3*16);
   const uint8x16_t K4 = vld1q_u8(skey + 4*16);
   const uint8x16_t K5 = vld1q_u8(skey + 5*16);
   const uint8x16_t K6 = vld1q_u8(skey + 6*16);
   const uint8x16_t K7 = vld1q_u8(skey + 7*16);
   const uint8x16_t K8 = vld1q_u8(skey + 8*16);
   const uint8x16_t K9 = vld1q_u8(skey + 9*16);
   const uint8x16_t K10 = vld1q_u8(skey + 10*16);
   const uint8x16_t K11 = vld1q_u8(skey + 11*16);
   const uint8x16_t K12 = vld1q_u8(skey + 12*16);
   const uint8x16_t K13 = vld1q_u8(skey + 13*16);
   const uint8x16_t K14 = vld1q_u8(skey + 14*16);

   while(blocks >= 4)
      {
      uint8x16_t B0 = vld1q_u8(in);
      uint8x16_t B1 = vld1q_u8(in+16);
      uint8x16_t B2 = vld1q_u8(in+32);
      uint8x16_t B3 = vld1q_u8(in+48);

      AES_DEC_4_ROUNDS(K0);
      AES_DEC_4_ROUNDS(K1);
      AES_DEC_4_ROUNDS(K2);
      AES_DEC_4_ROUNDS(K3);
      AES_DEC_4_ROUNDS(K4);
      AES_DEC_4_ROUNDS(K5);
      AES_DEC_4_ROUNDS(K6);
      AES_DEC_4_ROUNDS(K7);
      AES_DEC_4_ROUNDS(K8);
      AES_DEC_4_ROUNDS(K9);
      AES_DEC_4_ROUNDS(K10);
      AES_DEC_4_ROUNDS(K11);
      AES_DEC_4_ROUNDS(K12);
      AES_DEC_4_LAST_ROUNDS(K13, K14);

      vst1q_u8(out, B0);
      vst1q_u8(out+16, B1);
      vst1q_u8(out+32, B2);
      vst1q_u8(out+48, B3);

      in += 16*4;
      out += 16*4;
      blocks -= 4;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t B = vld1q_u8(in+16*i);
      B = vaesimcq_u8(vaesdq_u8(B, K0));
      B = vaesimcq_u8(vaesdq_u8(B, K1));
      B = vaesimcq_u8(vaesdq_u8(B, K2));
      B = vaesimcq_u8(vaesdq_u8(B, K3));
      B = vaesimcq_u8(vaesdq_u8(B, K4));
      B = vaesimcq_u8(vaesdq_u8(B, K5));
      B = vaesimcq_u8(vaesdq_u8(B, K6));
      B = vaesimcq_u8(vaesdq_u8(B, K7));
      B = vaesimcq_u8(vaesdq_u8(B, K8));
      B = vaesimcq_u8(vaesdq_u8(B, K9));
      B = vaesimcq_u8(vaesdq_u8(B, K10));
      B = vaesimcq_u8(vaesdq_u8(B, K11));
      B = vaesimcq_u8(vaesdq_u8(B, K12));
      B = veorq_u8(vaesdq_u8(B, K13), K14);
      vst1q_u8(out+16*i, B);
      }
   }

#undef AES_ENC_4_ROUNDS
#undef AES_ENC_4_LAST_ROUNDS
#undef AES_DEC_4_ROUNDS
#undef AES_DEC_4_LAST_ROUNDS

}

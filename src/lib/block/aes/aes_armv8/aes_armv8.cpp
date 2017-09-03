/*
* AES using ARMv8
* Contributed by Jeffrey Walton
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aes.h>
#include <botan/loadstor.h>
#include <arm_neon.h>

namespace Botan {

/*
* AES-128 Encryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_128::armv8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_EK.data());
   const uint8_t *mkey = reinterpret_cast<const uint8_t*>(m_ME.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0);
   const uint8x16_t K1 = vld1q_u8(skey + 16);
   const uint8x16_t K2 = vld1q_u8(skey + 32);
   const uint8x16_t K3 = vld1q_u8(skey + 48);
   const uint8x16_t K4 = vld1q_u8(skey + 64);
   const uint8x16_t K5 = vld1q_u8(skey + 80);
   const uint8x16_t K6 = vld1q_u8(skey + 96);
   const uint8x16_t K7 = vld1q_u8(skey + 112);
   const uint8x16_t K8 = vld1q_u8(skey + 128);
   const uint8x16_t K9 = vld1q_u8(skey + 144);
   const uint8x16_t K10 = vld1q_u8(mkey);

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t data = vld1q_u8(in+16*i);
      data = vaesmcq_u8(vaeseq_u8(data, K0));
      data = vaesmcq_u8(vaeseq_u8(data, K1));
      data = vaesmcq_u8(vaeseq_u8(data, K2));
      data = vaesmcq_u8(vaeseq_u8(data, K3));
      data = vaesmcq_u8(vaeseq_u8(data, K4));
      data = vaesmcq_u8(vaeseq_u8(data, K5));
      data = vaesmcq_u8(vaeseq_u8(data, K6));
      data = vaesmcq_u8(vaeseq_u8(data, K7));
      data = vaesmcq_u8(vaeseq_u8(data, K8));
      data = veorq_u8(vaeseq_u8(data, K9), K10);
      vst1q_u8(out+16*i, data);
      }
   }

/*
* AES-128 Decryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_128::armv8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_DK.empty() == false, "Key was set");

   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_DK.data());
   const uint8_t *mkey = reinterpret_cast<const uint8_t*>(m_MD.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0);
   const uint8x16_t K1 = vld1q_u8(skey + 16);
   const uint8x16_t K2 = vld1q_u8(skey + 32);
   const uint8x16_t K3 = vld1q_u8(skey + 48);
   const uint8x16_t K4 = vld1q_u8(skey + 64);
   const uint8x16_t K5 = vld1q_u8(skey + 80);
   const uint8x16_t K6 = vld1q_u8(skey + 96);
   const uint8x16_t K7 = vld1q_u8(skey + 112);
   const uint8x16_t K8 = vld1q_u8(skey + 128);
   const uint8x16_t K9 = vld1q_u8(skey + 144);
   const uint8x16_t K10 = vld1q_u8(mkey);

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t data = vld1q_u8(in+16*i);
      data = vaesimcq_u8(vaesdq_u8(data, K0));
      data = vaesimcq_u8(vaesdq_u8(data, K1));
      data = vaesimcq_u8(vaesdq_u8(data, K2));
      data = vaesimcq_u8(vaesdq_u8(data, K3));
      data = vaesimcq_u8(vaesdq_u8(data, K4));
      data = vaesimcq_u8(vaesdq_u8(data, K5));
      data = vaesimcq_u8(vaesdq_u8(data, K6));
      data = vaesimcq_u8(vaesdq_u8(data, K7));
      data = vaesimcq_u8(vaesdq_u8(data, K8));
      data = veorq_u8(vaesdq_u8(data, K9), K10);
      vst1q_u8(out+16*i, data);
      }
   }

/*
* AES-192 Encryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_192::armv8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_EK.data());
   const uint8_t *mkey = reinterpret_cast<const uint8_t*>(m_ME.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0);
   const uint8x16_t K1 = vld1q_u8(skey + 16);
   const uint8x16_t K2 = vld1q_u8(skey + 32);
   const uint8x16_t K3 = vld1q_u8(skey + 48);
   const uint8x16_t K4 = vld1q_u8(skey + 64);
   const uint8x16_t K5 = vld1q_u8(skey + 80);
   const uint8x16_t K6 = vld1q_u8(skey + 96);
   const uint8x16_t K7 = vld1q_u8(skey + 112);
   const uint8x16_t K8 = vld1q_u8(skey + 128);
   const uint8x16_t K9 = vld1q_u8(skey + 144);
   const uint8x16_t K10 = vld1q_u8(skey + 160);
   const uint8x16_t K11 = vld1q_u8(skey + 176);
   const uint8x16_t K12 = vld1q_u8(mkey);

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t data = vld1q_u8(in+16*i);
      data = vaesmcq_u8(vaeseq_u8(data, K0));
      data = vaesmcq_u8(vaeseq_u8(data, K1));
      data = vaesmcq_u8(vaeseq_u8(data, K2));
      data = vaesmcq_u8(vaeseq_u8(data, K3));
      data = vaesmcq_u8(vaeseq_u8(data, K4));
      data = vaesmcq_u8(vaeseq_u8(data, K5));
      data = vaesmcq_u8(vaeseq_u8(data, K6));
      data = vaesmcq_u8(vaeseq_u8(data, K7));
      data = vaesmcq_u8(vaeseq_u8(data, K8));
      data = vaesmcq_u8(vaeseq_u8(data, K9));
      data = vaesmcq_u8(vaeseq_u8(data, K10));
      data = veorq_u8(vaeseq_u8(data, K11), K12);
      vst1q_u8(out+16*i, data);
      }
   }

/*
* AES-192 Decryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_192::armv8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_DK.empty() == false, "Key was set");
   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_DK.data());
   const uint8_t *mkey = reinterpret_cast<const uint8_t*>(m_MD.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0);
   const uint8x16_t K1 = vld1q_u8(skey + 16);
   const uint8x16_t K2 = vld1q_u8(skey + 32);
   const uint8x16_t K3 = vld1q_u8(skey + 48);
   const uint8x16_t K4 = vld1q_u8(skey + 64);
   const uint8x16_t K5 = vld1q_u8(skey + 80);
   const uint8x16_t K6 = vld1q_u8(skey + 96);
   const uint8x16_t K7 = vld1q_u8(skey + 112);
   const uint8x16_t K8 = vld1q_u8(skey + 128);
   const uint8x16_t K9 = vld1q_u8(skey + 144);
   const uint8x16_t K10 = vld1q_u8(skey + 160);
   const uint8x16_t K11 = vld1q_u8(skey + 176);
   const uint8x16_t K12 = vld1q_u8(mkey);

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t data = vld1q_u8(in+16*i);
      data = vaesimcq_u8(vaesdq_u8(data, K0));
      data = vaesimcq_u8(vaesdq_u8(data, K1));
      data = vaesimcq_u8(vaesdq_u8(data, K2));
      data = vaesimcq_u8(vaesdq_u8(data, K3));
      data = vaesimcq_u8(vaesdq_u8(data, K4));
      data = vaesimcq_u8(vaesdq_u8(data, K5));
      data = vaesimcq_u8(vaesdq_u8(data, K6));
      data = vaesimcq_u8(vaesdq_u8(data, K7));
      data = vaesimcq_u8(vaesdq_u8(data, K8));
      data = vaesimcq_u8(vaesdq_u8(data, K9));
      data = vaesimcq_u8(vaesdq_u8(data, K10));
      data = veorq_u8(vaesdq_u8(data, K11), K12);
      vst1q_u8(out+16*i, data);
      }
   }

/*
* AES-256 Encryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_256::armv8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_EK.data());
   const uint8_t *mkey = reinterpret_cast<const uint8_t*>(m_ME.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0);
   const uint8x16_t K1 = vld1q_u8(skey + 16);
   const uint8x16_t K2 = vld1q_u8(skey + 32);
   const uint8x16_t K3 = vld1q_u8(skey + 48);
   const uint8x16_t K4 = vld1q_u8(skey + 64);
   const uint8x16_t K5 = vld1q_u8(skey + 80);
   const uint8x16_t K6 = vld1q_u8(skey + 96);
   const uint8x16_t K7 = vld1q_u8(skey + 112);
   const uint8x16_t K8 = vld1q_u8(skey + 128);
   const uint8x16_t K9 = vld1q_u8(skey + 144);
   const uint8x16_t K10 = vld1q_u8(skey + 160);
   const uint8x16_t K11 = vld1q_u8(skey + 176);
   const uint8x16_t K12 = vld1q_u8(skey + 192);
   const uint8x16_t K13 = vld1q_u8(skey + 208);
   const uint8x16_t K14 = vld1q_u8(mkey);

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t data = vld1q_u8(in+16*i);
      data = vaesmcq_u8(vaeseq_u8(data, K0));
      data = vaesmcq_u8(vaeseq_u8(data, K1));
      data = vaesmcq_u8(vaeseq_u8(data, K2));
      data = vaesmcq_u8(vaeseq_u8(data, K3));
      data = vaesmcq_u8(vaeseq_u8(data, K4));
      data = vaesmcq_u8(vaeseq_u8(data, K5));
      data = vaesmcq_u8(vaeseq_u8(data, K6));
      data = vaesmcq_u8(vaeseq_u8(data, K7));
      data = vaesmcq_u8(vaeseq_u8(data, K8));
      data = vaesmcq_u8(vaeseq_u8(data, K9));
      data = vaesmcq_u8(vaeseq_u8(data, K10));
      data = vaesmcq_u8(vaeseq_u8(data, K11));
      data = vaesmcq_u8(vaeseq_u8(data, K12));
      data = veorq_u8(vaeseq_u8(data, K13), K14);
      vst1q_u8(out+16*i, data);
      }
   }

/*
* AES-256 Decryption
*/
BOTAN_FUNC_ISA("+crypto")
void AES_256::armv8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_DK.empty() == false, "Key was set");

   const uint8_t *skey = reinterpret_cast<const uint8_t*>(m_DK.data());
   const uint8_t *mkey = reinterpret_cast<const uint8_t*>(m_MD.data());

   const uint8x16_t K0 = vld1q_u8(skey + 0);
   const uint8x16_t K1 = vld1q_u8(skey + 16);
   const uint8x16_t K2 = vld1q_u8(skey + 32);
   const uint8x16_t K3 = vld1q_u8(skey + 48);
   const uint8x16_t K4 = vld1q_u8(skey + 64);
   const uint8x16_t K5 = vld1q_u8(skey + 80);
   const uint8x16_t K6 = vld1q_u8(skey + 96);
   const uint8x16_t K7 = vld1q_u8(skey + 112);
   const uint8x16_t K8 = vld1q_u8(skey + 128);
   const uint8x16_t K9 = vld1q_u8(skey + 144);
   const uint8x16_t K10 = vld1q_u8(skey + 160);
   const uint8x16_t K11 = vld1q_u8(skey + 176);
   const uint8x16_t K12 = vld1q_u8(skey + 192);
   const uint8x16_t K13 = vld1q_u8(skey + 208);
   const uint8x16_t K14 = vld1q_u8(mkey);

   for(size_t i = 0; i != blocks; ++i)
      {
      uint8x16_t data = vld1q_u8(in+16*i);
      data = vaesimcq_u8(vaesdq_u8(data, K0));
      data = vaesimcq_u8(vaesdq_u8(data, K1));
      data = vaesimcq_u8(vaesdq_u8(data, K2));
      data = vaesimcq_u8(vaesdq_u8(data, K3));
      data = vaesimcq_u8(vaesdq_u8(data, K4));
      data = vaesimcq_u8(vaesdq_u8(data, K5));
      data = vaesimcq_u8(vaesdq_u8(data, K6));
      data = vaesimcq_u8(vaesdq_u8(data, K7));
      data = vaesimcq_u8(vaesdq_u8(data, K8));
      data = vaesimcq_u8(vaesdq_u8(data, K9));
      data = vaesimcq_u8(vaesdq_u8(data, K10));
      data = vaesimcq_u8(vaesdq_u8(data, K11));
      data = vaesimcq_u8(vaesdq_u8(data, K12));
      data = veorq_u8(vaesdq_u8(data, K13), K14);
      vst1q_u8(out+16*i, data);
      }
   }


}

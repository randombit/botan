/*
* AES using POWER8 crypto extensions
*
* Contributed by Jeffrey Walton
*
* Further changes
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aes.h>
#include <botan/cpuid.h>

#include <altivec.h>
#undef vector
#undef bool

namespace Botan {

namespace {

__vector unsigned long long LoadKey(const uint32_t* src)
   {
   __vector unsigned int vec = vec_vsx_ld(0, src);

   if(CPUID::is_little_endian())
      {
      const __vector unsigned char mask = {12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3};
      const __vector unsigned char zero = {0};
      return (__vector unsigned long long)vec_perm((__vector unsigned char)vec, zero, mask);
      }
   else
      {
      return (__vector unsigned long long)vec;
      }
   }

__vector unsigned char Reverse8x16(const __vector unsigned char src)
   {
   if(CPUID::is_little_endian())
      {
      const __vector unsigned char mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
      const __vector unsigned char zero = {0};
      return vec_perm(src, zero, mask);
      }
   else
      {
      return src;
      }
   }

__vector unsigned long long LoadBlock(const uint8_t* src)
   {
   return (__vector unsigned long long)Reverse8x16(vec_vsx_ld(0, src));
   }

void StoreBlock(const __vector unsigned long long src, uint8_t* dest)
   {
   vec_vsx_st(Reverse8x16((__vector unsigned char)src), 0, dest);
   }

}

BOTAN_FUNC_ISA("crypto")
void AES_128::power8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadKey(&m_EK[0]);
   const __vector unsigned long long K1  = LoadKey(&m_EK[4]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[8]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K10 = LoadBlock(m_ME.data());

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vcipher(B, K1);
      B = __builtin_crypto_vcipher(B, K2);
      B = __builtin_crypto_vcipher(B, K3);
      B = __builtin_crypto_vcipher(B, K4);
      B = __builtin_crypto_vcipher(B, K5);
      B = __builtin_crypto_vcipher(B, K6);
      B = __builtin_crypto_vcipher(B, K7);
      B = __builtin_crypto_vcipher(B, K8);
      B = __builtin_crypto_vcipher(B, K9);
      B = __builtin_crypto_vcipherlast(B, K10);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_128::power8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadBlock(m_ME.data());
   const __vector unsigned long long K1  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[8]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[4]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[0]);

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vncipher(B, K1);
      B = __builtin_crypto_vncipher(B, K2);
      B = __builtin_crypto_vncipher(B, K3);
      B = __builtin_crypto_vncipher(B, K4);
      B = __builtin_crypto_vncipher(B, K5);
      B = __builtin_crypto_vncipher(B, K6);
      B = __builtin_crypto_vncipher(B, K7);
      B = __builtin_crypto_vncipher(B, K8);
      B = __builtin_crypto_vncipher(B, K9);
      B = __builtin_crypto_vncipherlast(B, K10);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_192::power8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadKey(&m_EK[0]);
   const __vector unsigned long long K1  = LoadKey(&m_EK[4]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[8]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[40]);
   const __vector unsigned long long K11 = LoadKey(&m_EK[44]);
   const __vector unsigned long long K12 = LoadBlock(m_ME.data());

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vcipher(B, K1);
      B = __builtin_crypto_vcipher(B, K2);
      B = __builtin_crypto_vcipher(B, K3);
      B = __builtin_crypto_vcipher(B, K4);
      B = __builtin_crypto_vcipher(B, K5);
      B = __builtin_crypto_vcipher(B, K6);
      B = __builtin_crypto_vcipher(B, K7);
      B = __builtin_crypto_vcipher(B, K8);
      B = __builtin_crypto_vcipher(B, K9);
      B = __builtin_crypto_vcipher(B, K10);
      B = __builtin_crypto_vcipher(B, K11);
      B = __builtin_crypto_vcipherlast(B, K12);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_192::power8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadBlock(m_ME.data());
   const __vector unsigned long long K1  = LoadKey(&m_EK[44]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[40]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[8]);
   const __vector unsigned long long K11 = LoadKey(&m_EK[4]);
   const __vector unsigned long long K12 = LoadKey(&m_EK[0]);

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vncipher(B, K1);
      B = __builtin_crypto_vncipher(B, K2);
      B = __builtin_crypto_vncipher(B, K3);
      B = __builtin_crypto_vncipher(B, K4);
      B = __builtin_crypto_vncipher(B, K5);
      B = __builtin_crypto_vncipher(B, K6);
      B = __builtin_crypto_vncipher(B, K7);
      B = __builtin_crypto_vncipher(B, K8);
      B = __builtin_crypto_vncipher(B, K9);
      B = __builtin_crypto_vncipher(B, K10);
      B = __builtin_crypto_vncipher(B, K11);
      B = __builtin_crypto_vncipherlast(B, K12);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_256::power8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");
   const __vector unsigned long long K0  = LoadKey(&m_EK[0]);
   const __vector unsigned long long K1  = LoadKey(&m_EK[4]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[8]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[40]);
   const __vector unsigned long long K11 = LoadKey(&m_EK[44]);
   const __vector unsigned long long K12 = LoadKey(&m_EK[48]);
   const __vector unsigned long long K13 = LoadKey(&m_EK[52]);
   const __vector unsigned long long K14 = LoadBlock(m_ME.data());

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vcipher(B, K1);
      B = __builtin_crypto_vcipher(B, K2);
      B = __builtin_crypto_vcipher(B, K3);
      B = __builtin_crypto_vcipher(B, K4);
      B = __builtin_crypto_vcipher(B, K5);
      B = __builtin_crypto_vcipher(B, K6);
      B = __builtin_crypto_vcipher(B, K7);
      B = __builtin_crypto_vcipher(B, K8);
      B = __builtin_crypto_vcipher(B, K9);
      B = __builtin_crypto_vcipher(B, K10);
      B = __builtin_crypto_vcipher(B, K11);
      B = __builtin_crypto_vcipher(B, K12);
      B = __builtin_crypto_vcipher(B, K13);
      B = __builtin_crypto_vcipherlast(B, K14);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_256::power8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadBlock(m_ME.data());
   const __vector unsigned long long K1  = LoadKey(&m_EK[52]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[48]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[44]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[40]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[16]);
   const __vector unsigned long long K11 = LoadKey(&m_EK[12]);
   const __vector unsigned long long K12 = LoadKey(&m_EK[8]);
   const __vector unsigned long long K13 = LoadKey(&m_EK[4]);
   const __vector unsigned long long K14 = LoadKey(&m_EK[0]);

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vncipher(B, K1);
      B = __builtin_crypto_vncipher(B, K2);
      B = __builtin_crypto_vncipher(B, K3);
      B = __builtin_crypto_vncipher(B, K4);
      B = __builtin_crypto_vncipher(B, K5);
      B = __builtin_crypto_vncipher(B, K6);
      B = __builtin_crypto_vncipher(B, K7);
      B = __builtin_crypto_vncipher(B, K8);
      B = __builtin_crypto_vncipher(B, K9);
      B = __builtin_crypto_vncipher(B, K10);
      B = __builtin_crypto_vncipher(B, K11);
      B = __builtin_crypto_vncipher(B, K12);
      B = __builtin_crypto_vncipher(B, K13);
      B = __builtin_crypto_vncipherlast(B, K14);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

}

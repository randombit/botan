/*
* AES using POWER8/POWER9 crypto extensions
*
* Contributed by Jeffrey Walton
*
* Further changes
* (C) 2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes.h>

#include <botan/compiler.h>
#include <botan/internal/cpuid.h>

#include <altivec.h>
#undef vector
#undef bool

namespace Botan {

typedef __vector unsigned long long Altivec64x2;
typedef __vector unsigned int Altivec32x4;
typedef __vector unsigned char Altivec8x16;

namespace {

inline Altivec8x16 reverse_vec(Altivec8x16 src) {
   if(CPUID::is_little_endian()) {
      const Altivec8x16 mask = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
      const Altivec8x16 zero = {0};
      return vec_perm(src, zero, mask);
   } else {
      return src;
   }
}

BOTAN_FUNC_ISA("vsx") inline Altivec64x2 load_key(const uint32_t key[]) {
   return reinterpret_cast<Altivec64x2>(reverse_vec(reinterpret_cast<Altivec8x16>(vec_vsx_ld(0, key))));
}

BOTAN_FUNC_ISA("vsx") inline Altivec64x2 load_block(const uint8_t src[]) {
   return reinterpret_cast<Altivec64x2>(reverse_vec(vec_vsx_ld(0, src)));
}

BOTAN_FUNC_ISA("vsx") inline void store_block(Altivec64x2 src, uint8_t dest[]) {
   vec_vsx_st(reverse_vec(reinterpret_cast<Altivec8x16>(src)), 0, dest);
}

inline void store_blocks(Altivec64x2 B0, Altivec64x2 B1, Altivec64x2 B2, Altivec64x2 B3, uint8_t out[]) {
   store_block(B0, out);
   store_block(B1, out + 16);
   store_block(B2, out + 16 * 2);
   store_block(B3, out + 16 * 3);
}

#define AES_XOR_4(B0, B1, B2, B3, K) \
   do {                              \
      B0 = vec_xor(B0, K);           \
      B1 = vec_xor(B1, K);           \
      B2 = vec_xor(B2, K);           \
      B3 = vec_xor(B3, K);           \
   } while(0)

#define AES_ENCRYPT_4(B0, B1, B2, B3, K)    \
   do {                                     \
      B0 = __builtin_crypto_vcipher(B0, K); \
      B1 = __builtin_crypto_vcipher(B1, K); \
      B2 = __builtin_crypto_vcipher(B2, K); \
      B3 = __builtin_crypto_vcipher(B3, K); \
   } while(0)

#define AES_ENCRYPT_4_LAST(B0, B1, B2, B3, K)   \
   do {                                         \
      B0 = __builtin_crypto_vcipherlast(B0, K); \
      B1 = __builtin_crypto_vcipherlast(B1, K); \
      B2 = __builtin_crypto_vcipherlast(B2, K); \
      B3 = __builtin_crypto_vcipherlast(B3, K); \
   } while(0)

#define AES_DECRYPT_4(B0, B1, B2, B3, K)     \
   do {                                      \
      B0 = __builtin_crypto_vncipher(B0, K); \
      B1 = __builtin_crypto_vncipher(B1, K); \
      B2 = __builtin_crypto_vncipher(B2, K); \
      B3 = __builtin_crypto_vncipher(B3, K); \
   } while(0)

#define AES_DECRYPT_4_LAST(B0, B1, B2, B3, K)    \
   do {                                          \
      B0 = __builtin_crypto_vncipherlast(B0, K); \
      B1 = __builtin_crypto_vncipherlast(B1, K); \
      B2 = __builtin_crypto_vncipherlast(B2, K); \
      B3 = __builtin_crypto_vncipherlast(B3, K); \
   } while(0)

}  // namespace

BOTAN_FUNC_ISA("crypto,vsx") void AES_128::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const Altivec64x2 K0 = load_key(&m_EK[0]);
   const Altivec64x2 K1 = load_key(&m_EK[4]);
   const Altivec64x2 K2 = load_key(&m_EK[8]);
   const Altivec64x2 K3 = load_key(&m_EK[12]);
   const Altivec64x2 K4 = load_key(&m_EK[16]);
   const Altivec64x2 K5 = load_key(&m_EK[20]);
   const Altivec64x2 K6 = load_key(&m_EK[24]);
   const Altivec64x2 K7 = load_key(&m_EK[28]);
   const Altivec64x2 K8 = load_key(&m_EK[32]);
   const Altivec64x2 K9 = load_key(&m_EK[36]);
   const Altivec64x2 K10 = load_key(&m_EK[40]);

   while(blocks >= 4) {
      Altivec64x2 B0 = load_block(in);
      Altivec64x2 B1 = load_block(in + 16);
      Altivec64x2 B2 = load_block(in + 16 * 2);
      Altivec64x2 B3 = load_block(in + 16 * 3);

      AES_XOR_4(B0, B1, B2, B3, K0);
      AES_ENCRYPT_4(B0, B1, B2, B3, K1);
      AES_ENCRYPT_4(B0, B1, B2, B3, K2);
      AES_ENCRYPT_4(B0, B1, B2, B3, K3);
      AES_ENCRYPT_4(B0, B1, B2, B3, K4);
      AES_ENCRYPT_4(B0, B1, B2, B3, K5);
      AES_ENCRYPT_4(B0, B1, B2, B3, K6);
      AES_ENCRYPT_4(B0, B1, B2, B3, K7);
      AES_ENCRYPT_4(B0, B1, B2, B3, K8);
      AES_ENCRYPT_4(B0, B1, B2, B3, K9);
      AES_ENCRYPT_4_LAST(B0, B1, B2, B3, K10);

      store_blocks(B0, B1, B2, B3, out);

      out += 4 * 16;
      in += 4 * 16;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      Altivec64x2 B = load_block(in);

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

      store_block(B, out);

      out += 16;
      in += 16;
   }
}

BOTAN_FUNC_ISA("crypto,vsx") void AES_128::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const Altivec64x2 K0 = load_key(&m_EK[40]);
   const Altivec64x2 K1 = load_key(&m_EK[36]);
   const Altivec64x2 K2 = load_key(&m_EK[32]);
   const Altivec64x2 K3 = load_key(&m_EK[28]);
   const Altivec64x2 K4 = load_key(&m_EK[24]);
   const Altivec64x2 K5 = load_key(&m_EK[20]);
   const Altivec64x2 K6 = load_key(&m_EK[16]);
   const Altivec64x2 K7 = load_key(&m_EK[12]);
   const Altivec64x2 K8 = load_key(&m_EK[8]);
   const Altivec64x2 K9 = load_key(&m_EK[4]);
   const Altivec64x2 K10 = load_key(&m_EK[0]);

   while(blocks >= 4) {
      Altivec64x2 B0 = load_block(in);
      Altivec64x2 B1 = load_block(in + 16);
      Altivec64x2 B2 = load_block(in + 16 * 2);
      Altivec64x2 B3 = load_block(in + 16 * 3);

      AES_XOR_4(B0, B1, B2, B3, K0);
      AES_DECRYPT_4(B0, B1, B2, B3, K1);
      AES_DECRYPT_4(B0, B1, B2, B3, K2);
      AES_DECRYPT_4(B0, B1, B2, B3, K3);
      AES_DECRYPT_4(B0, B1, B2, B3, K4);
      AES_DECRYPT_4(B0, B1, B2, B3, K5);
      AES_DECRYPT_4(B0, B1, B2, B3, K6);
      AES_DECRYPT_4(B0, B1, B2, B3, K7);
      AES_DECRYPT_4(B0, B1, B2, B3, K8);
      AES_DECRYPT_4(B0, B1, B2, B3, K9);
      AES_DECRYPT_4_LAST(B0, B1, B2, B3, K10);

      store_blocks(B0, B1, B2, B3, out);

      out += 4 * 16;
      in += 4 * 16;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      Altivec64x2 B = load_block(in);

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

      store_block(B, out);

      out += 16;
      in += 16;
   }
}

BOTAN_FUNC_ISA("crypto,vsx") void AES_192::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const Altivec64x2 K0 = load_key(&m_EK[0]);
   const Altivec64x2 K1 = load_key(&m_EK[4]);
   const Altivec64x2 K2 = load_key(&m_EK[8]);
   const Altivec64x2 K3 = load_key(&m_EK[12]);
   const Altivec64x2 K4 = load_key(&m_EK[16]);
   const Altivec64x2 K5 = load_key(&m_EK[20]);
   const Altivec64x2 K6 = load_key(&m_EK[24]);
   const Altivec64x2 K7 = load_key(&m_EK[28]);
   const Altivec64x2 K8 = load_key(&m_EK[32]);
   const Altivec64x2 K9 = load_key(&m_EK[36]);
   const Altivec64x2 K10 = load_key(&m_EK[40]);
   const Altivec64x2 K11 = load_key(&m_EK[44]);
   const Altivec64x2 K12 = load_key(&m_EK[48]);

   while(blocks >= 4) {
      Altivec64x2 B0 = load_block(in);
      Altivec64x2 B1 = load_block(in + 16);
      Altivec64x2 B2 = load_block(in + 16 * 2);
      Altivec64x2 B3 = load_block(in + 16 * 3);

      AES_XOR_4(B0, B1, B2, B3, K0);
      AES_ENCRYPT_4(B0, B1, B2, B3, K1);
      AES_ENCRYPT_4(B0, B1, B2, B3, K2);
      AES_ENCRYPT_4(B0, B1, B2, B3, K3);
      AES_ENCRYPT_4(B0, B1, B2, B3, K4);
      AES_ENCRYPT_4(B0, B1, B2, B3, K5);
      AES_ENCRYPT_4(B0, B1, B2, B3, K6);
      AES_ENCRYPT_4(B0, B1, B2, B3, K7);
      AES_ENCRYPT_4(B0, B1, B2, B3, K8);
      AES_ENCRYPT_4(B0, B1, B2, B3, K9);
      AES_ENCRYPT_4(B0, B1, B2, B3, K10);
      AES_ENCRYPT_4(B0, B1, B2, B3, K11);
      AES_ENCRYPT_4_LAST(B0, B1, B2, B3, K12);

      store_blocks(B0, B1, B2, B3, out);

      out += 4 * 16;
      in += 4 * 16;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      Altivec64x2 B = load_block(in);

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

      store_block(B, out);

      out += 16;
      in += 16;
   }
}

BOTAN_FUNC_ISA("crypto,vsx") void AES_192::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const Altivec64x2 K0 = load_key(&m_EK[48]);
   const Altivec64x2 K1 = load_key(&m_EK[44]);
   const Altivec64x2 K2 = load_key(&m_EK[40]);
   const Altivec64x2 K3 = load_key(&m_EK[36]);
   const Altivec64x2 K4 = load_key(&m_EK[32]);
   const Altivec64x2 K5 = load_key(&m_EK[28]);
   const Altivec64x2 K6 = load_key(&m_EK[24]);
   const Altivec64x2 K7 = load_key(&m_EK[20]);
   const Altivec64x2 K8 = load_key(&m_EK[16]);
   const Altivec64x2 K9 = load_key(&m_EK[12]);
   const Altivec64x2 K10 = load_key(&m_EK[8]);
   const Altivec64x2 K11 = load_key(&m_EK[4]);
   const Altivec64x2 K12 = load_key(&m_EK[0]);

   while(blocks >= 4) {
      Altivec64x2 B0 = load_block(in);
      Altivec64x2 B1 = load_block(in + 16);
      Altivec64x2 B2 = load_block(in + 16 * 2);
      Altivec64x2 B3 = load_block(in + 16 * 3);

      AES_XOR_4(B0, B1, B2, B3, K0);
      AES_DECRYPT_4(B0, B1, B2, B3, K1);
      AES_DECRYPT_4(B0, B1, B2, B3, K2);
      AES_DECRYPT_4(B0, B1, B2, B3, K3);
      AES_DECRYPT_4(B0, B1, B2, B3, K4);
      AES_DECRYPT_4(B0, B1, B2, B3, K5);
      AES_DECRYPT_4(B0, B1, B2, B3, K6);
      AES_DECRYPT_4(B0, B1, B2, B3, K7);
      AES_DECRYPT_4(B0, B1, B2, B3, K8);
      AES_DECRYPT_4(B0, B1, B2, B3, K9);
      AES_DECRYPT_4(B0, B1, B2, B3, K10);
      AES_DECRYPT_4(B0, B1, B2, B3, K11);
      AES_DECRYPT_4_LAST(B0, B1, B2, B3, K12);

      store_blocks(B0, B1, B2, B3, out);

      out += 4 * 16;
      in += 4 * 16;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      Altivec64x2 B = load_block(in);

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

      store_block(B, out);

      out += 16;
      in += 16;
   }
}

BOTAN_FUNC_ISA("crypto,vsx") void AES_256::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const Altivec64x2 K0 = load_key(&m_EK[0]);
   const Altivec64x2 K1 = load_key(&m_EK[4]);
   const Altivec64x2 K2 = load_key(&m_EK[8]);
   const Altivec64x2 K3 = load_key(&m_EK[12]);
   const Altivec64x2 K4 = load_key(&m_EK[16]);
   const Altivec64x2 K5 = load_key(&m_EK[20]);
   const Altivec64x2 K6 = load_key(&m_EK[24]);
   const Altivec64x2 K7 = load_key(&m_EK[28]);
   const Altivec64x2 K8 = load_key(&m_EK[32]);
   const Altivec64x2 K9 = load_key(&m_EK[36]);
   const Altivec64x2 K10 = load_key(&m_EK[40]);
   const Altivec64x2 K11 = load_key(&m_EK[44]);
   const Altivec64x2 K12 = load_key(&m_EK[48]);
   const Altivec64x2 K13 = load_key(&m_EK[52]);
   const Altivec64x2 K14 = load_key(&m_EK[56]);

   while(blocks >= 4) {
      Altivec64x2 B0 = load_block(in);
      Altivec64x2 B1 = load_block(in + 16);
      Altivec64x2 B2 = load_block(in + 16 * 2);
      Altivec64x2 B3 = load_block(in + 16 * 3);

      AES_XOR_4(B0, B1, B2, B3, K0);
      AES_ENCRYPT_4(B0, B1, B2, B3, K1);
      AES_ENCRYPT_4(B0, B1, B2, B3, K2);
      AES_ENCRYPT_4(B0, B1, B2, B3, K3);
      AES_ENCRYPT_4(B0, B1, B2, B3, K4);
      AES_ENCRYPT_4(B0, B1, B2, B3, K5);
      AES_ENCRYPT_4(B0, B1, B2, B3, K6);
      AES_ENCRYPT_4(B0, B1, B2, B3, K7);
      AES_ENCRYPT_4(B0, B1, B2, B3, K8);
      AES_ENCRYPT_4(B0, B1, B2, B3, K9);
      AES_ENCRYPT_4(B0, B1, B2, B3, K10);
      AES_ENCRYPT_4(B0, B1, B2, B3, K11);
      AES_ENCRYPT_4(B0, B1, B2, B3, K12);
      AES_ENCRYPT_4(B0, B1, B2, B3, K13);
      AES_ENCRYPT_4_LAST(B0, B1, B2, B3, K14);

      store_blocks(B0, B1, B2, B3, out);

      out += 4 * 16;
      in += 4 * 16;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      Altivec64x2 B = load_block(in);

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

      store_block(B, out);

      out += 16;
      in += 16;
   }
}

BOTAN_FUNC_ISA("crypto,vsx") void AES_256::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const Altivec64x2 K0 = load_key(&m_EK[56]);
   const Altivec64x2 K1 = load_key(&m_EK[52]);
   const Altivec64x2 K2 = load_key(&m_EK[48]);
   const Altivec64x2 K3 = load_key(&m_EK[44]);
   const Altivec64x2 K4 = load_key(&m_EK[40]);
   const Altivec64x2 K5 = load_key(&m_EK[36]);
   const Altivec64x2 K6 = load_key(&m_EK[32]);
   const Altivec64x2 K7 = load_key(&m_EK[28]);
   const Altivec64x2 K8 = load_key(&m_EK[24]);
   const Altivec64x2 K9 = load_key(&m_EK[20]);
   const Altivec64x2 K10 = load_key(&m_EK[16]);
   const Altivec64x2 K11 = load_key(&m_EK[12]);
   const Altivec64x2 K12 = load_key(&m_EK[8]);
   const Altivec64x2 K13 = load_key(&m_EK[4]);
   const Altivec64x2 K14 = load_key(&m_EK[0]);

   while(blocks >= 4) {
      Altivec64x2 B0 = load_block(in);
      Altivec64x2 B1 = load_block(in + 16);
      Altivec64x2 B2 = load_block(in + 16 * 2);
      Altivec64x2 B3 = load_block(in + 16 * 3);

      AES_XOR_4(B0, B1, B2, B3, K0);
      AES_DECRYPT_4(B0, B1, B2, B3, K1);
      AES_DECRYPT_4(B0, B1, B2, B3, K2);
      AES_DECRYPT_4(B0, B1, B2, B3, K3);
      AES_DECRYPT_4(B0, B1, B2, B3, K4);
      AES_DECRYPT_4(B0, B1, B2, B3, K5);
      AES_DECRYPT_4(B0, B1, B2, B3, K6);
      AES_DECRYPT_4(B0, B1, B2, B3, K7);
      AES_DECRYPT_4(B0, B1, B2, B3, K8);
      AES_DECRYPT_4(B0, B1, B2, B3, K9);
      AES_DECRYPT_4(B0, B1, B2, B3, K10);
      AES_DECRYPT_4(B0, B1, B2, B3, K11);
      AES_DECRYPT_4(B0, B1, B2, B3, K12);
      AES_DECRYPT_4(B0, B1, B2, B3, K13);
      AES_DECRYPT_4_LAST(B0, B1, B2, B3, K14);

      store_blocks(B0, B1, B2, B3, out);

      out += 4 * 16;
      in += 4 * 16;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      Altivec64x2 B = load_block(in);

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

      store_block(B, out);

      out += 16;
      in += 16;
   }
}

#undef AES_XOR_4
#undef AES_ENCRYPT_4
#undef AES_ENCRYPT_4_LAST
#undef AES_DECRYPT_4
#undef AES_DECRYPT_4_LAST

}  // namespace Botan

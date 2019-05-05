/*
* DES
* (C) 1999-2008,2018 Jack Lloyd
*
* Based on a public domain implemenation by Phil Karn (who in turn
* credited Richard Outerbridge and Jim Gillogly)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/des.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace {

/*
* DES Key Schedule
*/
void des_key_schedule(uint32_t round_key[32], const uint8_t key[8])
   {
   static const uint8_t ROT[16] = { 1, 1, 2, 2, 2, 2, 2, 2,
                                 1, 2, 2, 2, 2, 2, 2, 1 };

   uint32_t C = ((key[7] & 0x80) << 20) | ((key[6] & 0x80) << 19) |
                ((key[5] & 0x80) << 18) | ((key[4] & 0x80) << 17) |
                ((key[3] & 0x80) << 16) | ((key[2] & 0x80) << 15) |
                ((key[1] & 0x80) << 14) | ((key[0] & 0x80) << 13) |
                ((key[7] & 0x40) << 13) | ((key[6] & 0x40) << 12) |
                ((key[5] & 0x40) << 11) | ((key[4] & 0x40) << 10) |
                ((key[3] & 0x40) <<  9) | ((key[2] & 0x40) <<  8) |
                ((key[1] & 0x40) <<  7) | ((key[0] & 0x40) <<  6) |
                ((key[7] & 0x20) <<  6) | ((key[6] & 0x20) <<  5) |
                ((key[5] & 0x20) <<  4) | ((key[4] & 0x20) <<  3) |
                ((key[3] & 0x20) <<  2) | ((key[2] & 0x20) <<  1) |
                ((key[1] & 0x20)      ) | ((key[0] & 0x20) >>  1) |
                ((key[7] & 0x10) >>  1) | ((key[6] & 0x10) >>  2) |
                ((key[5] & 0x10) >>  3) | ((key[4] & 0x10) >>  4);
   uint32_t D = ((key[7] & 0x02) << 26) | ((key[6] & 0x02) << 25) |
                ((key[5] & 0x02) << 24) | ((key[4] & 0x02) << 23) |
                ((key[3] & 0x02) << 22) | ((key[2] & 0x02) << 21) |
                ((key[1] & 0x02) << 20) | ((key[0] & 0x02) << 19) |
                ((key[7] & 0x04) << 17) | ((key[6] & 0x04) << 16) |
                ((key[5] & 0x04) << 15) | ((key[4] & 0x04) << 14) |
                ((key[3] & 0x04) << 13) | ((key[2] & 0x04) << 12) |
                ((key[1] & 0x04) << 11) | ((key[0] & 0x04) << 10) |
                ((key[7] & 0x08) <<  8) | ((key[6] & 0x08) <<  7) |
                ((key[5] & 0x08) <<  6) | ((key[4] & 0x08) <<  5) |
                ((key[3] & 0x08) <<  4) | ((key[2] & 0x08) <<  3) |
                ((key[1] & 0x08) <<  2) | ((key[0] & 0x08) <<  1) |
                ((key[3] & 0x10) >>  1) | ((key[2] & 0x10) >>  2) |
                ((key[1] & 0x10) >>  3) | ((key[0] & 0x10) >>  4);

   for(size_t i = 0; i != 16; ++i)
      {
      C = ((C << ROT[i]) | (C >> (28-ROT[i]))) & 0x0FFFFFFF;
      D = ((D << ROT[i]) | (D >> (28-ROT[i]))) & 0x0FFFFFFF;
      round_key[2*i  ] = ((C & 0x00000010) << 22) | ((C & 0x00000800) << 17) |
                         ((C & 0x00000020) << 16) | ((C & 0x00004004) << 15) |
                         ((C & 0x00000200) << 11) | ((C & 0x00020000) << 10) |
                         ((C & 0x01000000) >>  6) | ((C & 0x00100000) >>  4) |
                         ((C & 0x00010000) <<  3) | ((C & 0x08000000) >>  2) |
                         ((C & 0x00800000) <<  1) | ((D & 0x00000010) <<  8) |
                         ((D & 0x00000002) <<  7) | ((D & 0x00000001) <<  2) |
                         ((D & 0x00000200)      ) | ((D & 0x00008000) >>  2) |
                         ((D & 0x00000088) >>  3) | ((D & 0x00001000) >>  7) |
                         ((D & 0x00080000) >>  9) | ((D & 0x02020000) >> 14) |
                         ((D & 0x00400000) >> 21);
      round_key[2*i+1] = ((C & 0x00000001) << 28) | ((C & 0x00000082) << 18) |
                         ((C & 0x00002000) << 14) | ((C & 0x00000100) << 10) |
                         ((C & 0x00001000) <<  9) | ((C & 0x00040000) <<  6) |
                         ((C & 0x02400000) <<  4) | ((C & 0x00008000) <<  2) |
                         ((C & 0x00200000) >>  1) | ((C & 0x04000000) >> 10) |
                         ((D & 0x00000020) <<  6) | ((D & 0x00000100)      ) |
                         ((D & 0x00000800) >>  1) | ((D & 0x00000040) >>  3) |
                         ((D & 0x00010000) >>  4) | ((D & 0x00000400) >>  5) |
                         ((D & 0x00004000) >> 10) | ((D & 0x04000000) >> 13) |
                         ((D & 0x00800000) >> 14) | ((D & 0x00100000) >> 18) |
                         ((D & 0x01000000) >> 24) | ((D & 0x08000000) >> 26);
      }
   }

inline uint32_t spbox(uint32_t T0, uint32_t T1)
   {
   return DES_SPBOX1[get_byte(0, T0)] ^ DES_SPBOX2[get_byte(0, T1)] ^
          DES_SPBOX3[get_byte(1, T0)] ^ DES_SPBOX4[get_byte(1, T1)] ^
          DES_SPBOX5[get_byte(2, T0)] ^ DES_SPBOX6[get_byte(2, T1)] ^
          DES_SPBOX7[get_byte(3, T0)] ^ DES_SPBOX8[get_byte(3, T1)];
   }

/*
* DES Encryption
*/
inline void des_encrypt(uint32_t& Lr, uint32_t& Rr,
                        const uint32_t round_key[32])
   {
   uint32_t L = Lr;
   uint32_t R = Rr;
   for(size_t i = 0; i != 16; i += 2)
      {
      L ^= spbox(rotr<4>(R) ^ round_key[2*i  ], R ^ round_key[2*i+1]);
      R ^= spbox(rotr<4>(L) ^ round_key[2*i+2], L ^ round_key[2*i+3]);
      }

   Lr = L;
   Rr = R;
   }

inline void des_encrypt_x2(uint32_t& L0r, uint32_t& R0r,
                           uint32_t& L1r, uint32_t& R1r,
                           const uint32_t round_key[32])
   {
   uint32_t L0 = L0r;
   uint32_t R0 = R0r;
   uint32_t L1 = L1r;
   uint32_t R1 = R1r;

   for(size_t i = 0; i != 16; i += 2)
      {
      L0 ^= spbox(rotr<4>(R0) ^ round_key[2*i  ], R0 ^ round_key[2*i+1]);
      L1 ^= spbox(rotr<4>(R1) ^ round_key[2*i  ], R1 ^ round_key[2*i+1]);

      R0 ^= spbox(rotr<4>(L0) ^ round_key[2*i+2], L0 ^ round_key[2*i+3]);
      R1 ^= spbox(rotr<4>(L1) ^ round_key[2*i+2], L1 ^ round_key[2*i+3]);
      }

   L0r = L0;
   R0r = R0;
   L1r = L1;
   R1r = R1;
   }

/*
* DES Decryption
*/
inline void des_decrypt(uint32_t& Lr, uint32_t& Rr,
                        const uint32_t round_key[32])
   {
   uint32_t L = Lr;
   uint32_t R = Rr;
   for(size_t i = 16; i != 0; i -= 2)
      {
      L ^= spbox(rotr<4>(R) ^ round_key[2*i - 2], R  ^ round_key[2*i - 1]);
      R ^= spbox(rotr<4>(L) ^ round_key[2*i - 4], L  ^ round_key[2*i - 3]);
      }
   Lr = L;
   Rr = R;
   }

inline void des_decrypt_x2(uint32_t& L0r, uint32_t& R0r,
                           uint32_t& L1r, uint32_t& R1r,
                           const uint32_t round_key[32])
   {
   uint32_t L0 = L0r;
   uint32_t R0 = R0r;
   uint32_t L1 = L1r;
   uint32_t R1 = R1r;

   for(size_t i = 16; i != 0; i -= 2)
      {
      L0 ^= spbox(rotr<4>(R0) ^ round_key[2*i - 2], R0  ^ round_key[2*i - 1]);
      L1 ^= spbox(rotr<4>(R1) ^ round_key[2*i - 2], R1  ^ round_key[2*i - 1]);

      R0 ^= spbox(rotr<4>(L0) ^ round_key[2*i - 4], L0  ^ round_key[2*i - 3]);
      R1 ^= spbox(rotr<4>(L1) ^ round_key[2*i - 4], L1  ^ round_key[2*i - 3]);
      }

   L0r = L0;
   R0r = R0;
   L1r = L1;
   R1r = R1;
   }

inline void des_IP(uint32_t& L, uint32_t& R, const uint8_t block[])
   {
   // IP sequence by Wei Dai, taken from public domain Crypto++
   L = load_be<uint32_t>(block, 0);
   R = load_be<uint32_t>(block, 1);

   uint32_t T;
   R = rotl<4>(R);
   T = (L ^ R) & 0xF0F0F0F0;
   L ^= T;
   R = rotr<20>(R ^ T);
   T = (L ^ R) & 0xFFFF0000;
   L ^= T;
   R = rotr<18>(R ^ T);
   T = (L ^ R) & 0x33333333;
   L ^= T;
   R = rotr<6>(R ^ T);
   T = (L ^ R) & 0x00FF00FF;
   L ^= T;
   R = rotl<9>(R ^ T);
   T = (L ^ R) & 0xAAAAAAAA;
   L = rotl<1>(L ^ T);
   R ^= T;
   }

inline void des_FP(uint32_t L, uint32_t R, uint8_t out[])
   {
   // FP sequence by Wei Dai, taken from public domain Crypto++
   uint32_t T;

   R = rotr<1>(R);
   T = (L ^ R) & 0xAAAAAAAA;
   R ^= T;
   L = rotr<9>(L ^ T);
   T = (L ^ R) & 0x00FF00FF;
   R ^= T;
   L = rotl<6>(L ^ T);
   T = (L ^ R) & 0x33333333;
   R ^= T;
   L = rotl<18>(L ^ T);
   T = (L ^ R) & 0xFFFF0000;
   R ^= T;
   L = rotl<20>(L ^ T);
   T = (L ^ R) & 0xF0F0F0F0;
   R ^= T;
   L = rotr<4>(L ^ T);

   store_be(out, R, L);
   }

}

/*
* DES Encryption
*/
void DES::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_round_key.empty() == false);

   while(blocks >= 2)
      {
      uint32_t L0, R0;
      uint32_t L1, R1;

      des_IP(L0, R0, in);
      des_IP(L1, R1, in + BLOCK_SIZE);

      des_encrypt_x2(L0, R0, L1, R1, m_round_key.data());

      des_FP(L0, R0, out);
      des_FP(L1, R1, out + BLOCK_SIZE);

      in += 2*BLOCK_SIZE;
      out += 2*BLOCK_SIZE;
      blocks -= 2;
      }

   for(size_t i = 0; i < blocks; ++i)
      {
      uint32_t L, R;
      des_IP(L, R, in + BLOCK_SIZE*i);
      des_encrypt(L, R, m_round_key.data());
      des_FP(L, R, out + BLOCK_SIZE*i);
      }
   }

/*
* DES Decryption
*/
void DES::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_round_key.empty() == false);

   while(blocks >= 2)
      {
      uint32_t L0, R0;
      uint32_t L1, R1;

      des_IP(L0, R0, in);
      des_IP(L1, R1, in + BLOCK_SIZE);

      des_decrypt_x2(L0, R0, L1, R1, m_round_key.data());

      des_FP(L0, R0, out);
      des_FP(L1, R1, out + BLOCK_SIZE);

      in += 2*BLOCK_SIZE;
      out += 2*BLOCK_SIZE;
      blocks -= 2;
      }

   for(size_t i = 0; i < blocks; ++i)
      {
      uint32_t L, R;
      des_IP(L, R, in + BLOCK_SIZE*i);
      des_decrypt(L, R, m_round_key.data());
      des_FP(L, R, out + BLOCK_SIZE*i);
      }
   }

/*
* DES Key Schedule
*/
void DES::key_schedule(const uint8_t key[], size_t)
   {
   m_round_key.resize(32);
   des_key_schedule(m_round_key.data(), key);
   }

void DES::clear()
   {
   zap(m_round_key);
   }

/*
* TripleDES Encryption
*/
void TripleDES::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_round_key.empty() == false);

   while(blocks >= 2)
      {
      uint32_t L0, R0;
      uint32_t L1, R1;

      des_IP(L0, R0, in);
      des_IP(L1, R1, in + BLOCK_SIZE);

      des_encrypt_x2(L0, R0, L1, R1, &m_round_key[0]);
      des_decrypt_x2(R0, L0, R1, L1, &m_round_key[32]);
      des_encrypt_x2(L0, R0, L1, R1, &m_round_key[64]);

      des_FP(L0, R0, out);
      des_FP(L1, R1, out + BLOCK_SIZE);

      in += 2*BLOCK_SIZE;
      out += 2*BLOCK_SIZE;
      blocks -= 2;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t L, R;
      des_IP(L, R, in + BLOCK_SIZE*i);

      des_encrypt(L, R, &m_round_key[0]);
      des_decrypt(R, L, &m_round_key[32]);
      des_encrypt(L, R, &m_round_key[64]);

      des_FP(L, R, out + BLOCK_SIZE*i);
      }
   }

/*
* TripleDES Decryption
*/
void TripleDES::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_round_key.empty() == false);

   while(blocks >= 2)
      {
      uint32_t L0, R0;
      uint32_t L1, R1;

      des_IP(L0, R0, in);
      des_IP(L1, R1, in + BLOCK_SIZE);

      des_decrypt_x2(L0, R0, L1, R1, &m_round_key[64]);
      des_encrypt_x2(R0, L0, R1, L1, &m_round_key[32]);
      des_decrypt_x2(L0, R0, L1, R1, &m_round_key[0]);

      des_FP(L0, R0, out);
      des_FP(L1, R1, out + BLOCK_SIZE);

      in += 2*BLOCK_SIZE;
      out += 2*BLOCK_SIZE;
      blocks -= 2;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t L, R;
      des_IP(L, R, in + BLOCK_SIZE*i);

      des_decrypt(L, R, &m_round_key[64]);
      des_encrypt(R, L, &m_round_key[32]);
      des_decrypt(L, R, &m_round_key[0]);

      des_FP(L, R, out + BLOCK_SIZE*i);
      }
   }

/*
* TripleDES Key Schedule
*/
void TripleDES::key_schedule(const uint8_t key[], size_t length)
   {
   m_round_key.resize(3*32);
   des_key_schedule(&m_round_key[0], key);
   des_key_schedule(&m_round_key[32], key + 8);

   if(length == 24)
      des_key_schedule(&m_round_key[64], key + 16);
   else
      copy_mem(&m_round_key[64], &m_round_key[0], 32);
   }

void TripleDES::clear()
   {
   zap(m_round_key);
   }

}

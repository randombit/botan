/*
* DES
* (C) 1999-2008,2018,2020 Jack Lloyd
*
* Based on a public domain implemenation by Phil Karn (who in turn
* credited Richard Outerbridge and Jim Gillogly)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/des.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

namespace Botan {

namespace {

alignas(256) const uint8_t SPBOX_CATS[64 * 8] = {
   0x54, 0x00, 0x10, 0x55, 0x51, 0x15, 0x01, 0x10, 0x04, 0x54, 0x55, 0x04, 0x45, 0x51, 0x40, 0x01,
   0x05, 0x44, 0x44, 0x14, 0x14, 0x50, 0x50, 0x45, 0x11, 0x41, 0x41, 0x11, 0x00, 0x05, 0x15, 0x40,
   0x10, 0x55, 0x01, 0x50, 0x54, 0x40, 0x40, 0x04, 0x51, 0x10, 0x14, 0x41, 0x04, 0x01, 0x45, 0x15,
   0x55, 0x11, 0x50, 0x45, 0x41, 0x05, 0x15, 0x54, 0x05, 0x44, 0x44, 0x00, 0x11, 0x14, 0x00, 0x51,

   0x55, 0x44, 0x04, 0x15, 0x10, 0x01, 0x51, 0x45, 0x41, 0x55, 0x54, 0x40, 0x44, 0x10, 0x01, 0x51,
   0x14, 0x11, 0x45, 0x00, 0x40, 0x04, 0x15, 0x50, 0x11, 0x41, 0x00, 0x14, 0x05, 0x54, 0x50, 0x05,
   0x00, 0x15, 0x51, 0x10, 0x45, 0x50, 0x54, 0x04, 0x50, 0x44, 0x01, 0x55, 0x15, 0x01, 0x04, 0x40,
   0x05, 0x54, 0x10, 0x41, 0x11, 0x45, 0x41, 0x11, 0x14, 0x00, 0x44, 0x05, 0x40, 0x51, 0x55, 0x14,

   0x09, 0xA8, 0x00, 0xA1, 0x88, 0x00, 0x29, 0x88, 0x21, 0x81, 0x81, 0x20, 0xA9, 0x21, 0xA0, 0x09,
   0x80, 0x01, 0xA8, 0x08, 0x28, 0xA0, 0xA1, 0x29, 0x89, 0x28, 0x20, 0x89, 0x01, 0xA9, 0x08, 0x80,
   0xA8, 0x80, 0x21, 0x09, 0x20, 0xA8, 0x88, 0x00, 0x08, 0x21, 0xA9, 0x88, 0x81, 0x08, 0x00, 0xA1,
   0x89, 0x20, 0x80, 0xA9, 0x01, 0x29, 0x28, 0x81, 0xA0, 0x89, 0x09, 0xA0, 0x29, 0x01, 0xA1, 0x28,

   0x51, 0x15, 0x15, 0x04, 0x54, 0x45, 0x41, 0x11, 0x00, 0x50, 0x50, 0x55, 0x05, 0x00, 0x44, 0x41,
   0x01, 0x10, 0x40, 0x51, 0x04, 0x40, 0x11, 0x14, 0x45, 0x01, 0x14, 0x44, 0x10, 0x54, 0x55, 0x05,
   0x44, 0x41, 0x50, 0x55, 0x05, 0x00, 0x00, 0x50, 0x14, 0x44, 0x45, 0x01, 0x51, 0x15, 0x15, 0x04,
   0x55, 0x05, 0x01, 0x10, 0x41, 0x11, 0x54, 0x45, 0x11, 0x14, 0x40, 0x51, 0x04, 0x40, 0x10, 0x54,

   0x01, 0x29, 0x28, 0xA1, 0x08, 0x01, 0x80, 0x28, 0x89, 0x08, 0x21, 0x89, 0xA1, 0xA8, 0x09, 0x80,
   0x20, 0x88, 0x88, 0x00, 0x81, 0xA9, 0xA9, 0x21, 0xA8, 0x81, 0x00, 0xA0, 0x29, 0x20, 0xA0, 0x09,
   0x08, 0xA1, 0x01, 0x20, 0x80, 0x28, 0xA1, 0x89, 0x21, 0x80, 0xA8, 0x29, 0x89, 0x01, 0x20, 0xA8,
   0xA9, 0x09, 0xA0, 0xA9, 0x28, 0x00, 0x88, 0xA0, 0x09, 0x21, 0x81, 0x08, 0x00, 0x88, 0x29, 0x81,

   0x41, 0x50, 0x04, 0x55, 0x50, 0x01, 0x55, 0x10, 0x44, 0x15, 0x10, 0x41, 0x11, 0x44, 0x40, 0x05,
   0x00, 0x11, 0x45, 0x04, 0x14, 0x45, 0x01, 0x51, 0x51, 0x00, 0x15, 0x54, 0x05, 0x14, 0x54, 0x40,
   0x44, 0x01, 0x51, 0x14, 0x55, 0x10, 0x05, 0x41, 0x10, 0x44, 0x40, 0x05, 0x41, 0x55, 0x14, 0x50,
   0x15, 0x54, 0x00, 0x51, 0x01, 0x04, 0x50, 0x15, 0x04, 0x11, 0x45, 0x00, 0x54, 0x40, 0x11, 0x45,

   0x10, 0x51, 0x45, 0x00, 0x04, 0x45, 0x15, 0x54, 0x55, 0x10, 0x00, 0x41, 0x01, 0x40, 0x51, 0x05,
   0x44, 0x15, 0x11, 0x44, 0x41, 0x50, 0x54, 0x11, 0x50, 0x04, 0x05, 0x55, 0x14, 0x01, 0x40, 0x14,
   0x40, 0x14, 0x10, 0x45, 0x45, 0x51, 0x51, 0x01, 0x11, 0x40, 0x44, 0x10, 0x54, 0x05, 0x15, 0x54,
   0x05, 0x41, 0x55, 0x50, 0x14, 0x00, 0x01, 0x55, 0x00, 0x15, 0x50, 0x04, 0x41, 0x44, 0x04, 0x11,

   0x89, 0x08, 0x20, 0xA9, 0x80, 0x89, 0x01, 0x80, 0x21, 0xA0, 0xA9, 0x28, 0xA8, 0x29, 0x08, 0x01,
   0xA0, 0x81, 0x88, 0x09, 0x28, 0x21, 0xA1, 0xA8, 0x09, 0x00, 0x00, 0xA1, 0x81, 0x88, 0x29, 0x20,
   0x29, 0x20, 0xa8, 0x08, 0x01, 0xA1, 0x08, 0x29, 0x88, 0x01, 0x81, 0xA0, 0xA1, 0x80, 0x20, 0x89,
   0x00, 0xA9, 0x21, 0x81, 0xA0, 0x88, 0x89, 0x00, 0xA9, 0x28, 0x28, 0x09, 0x09, 0x21, 0x80, 0xA8,
};

const uint32_t SPBOX_CAT_0_MUL = 0x70041106;
const uint32_t SPBOX_CAT_1_MUL = 0x02012020;
const uint32_t SPBOX_CAT_2_MUL = 0x00901048;
const uint32_t SPBOX_CAT_3_MUL = 0x8e060221;
const uint32_t SPBOX_CAT_4_MUL = 0x00912140;
const uint32_t SPBOX_CAT_5_MUL = 0x80841018;
const uint32_t SPBOX_CAT_6_MUL = 0xe0120202;
const uint32_t SPBOX_CAT_7_MUL = 0x00212240;

const uint32_t SPBOX_CAT_0_MASK = 0x01010404;
const uint32_t SPBOX_CAT_1_MASK = 0x80108020;
const uint32_t SPBOX_CAT_2_MASK = 0x08020208;
const uint32_t SPBOX_CAT_3_MASK = 0x00802081;
const uint32_t SPBOX_CAT_4_MASK = 0x42080100;
const uint32_t SPBOX_CAT_5_MASK = 0x20404010;
const uint32_t SPBOX_CAT_6_MASK = 0x04200802;
const uint32_t SPBOX_CAT_7_MASK = 0x10041040;

/*
* DES Key Schedule
*/
void des_key_schedule(uint32_t round_key[32], const uint8_t key[8]) {
   static const uint8_t ROT[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

   uint32_t C = ((key[7] & 0x80) << 20) | ((key[6] & 0x80) << 19) | ((key[5] & 0x80) << 18) | ((key[4] & 0x80) << 17) |
                ((key[3] & 0x80) << 16) | ((key[2] & 0x80) << 15) | ((key[1] & 0x80) << 14) | ((key[0] & 0x80) << 13) |
                ((key[7] & 0x40) << 13) | ((key[6] & 0x40) << 12) | ((key[5] & 0x40) << 11) | ((key[4] & 0x40) << 10) |
                ((key[3] & 0x40) << 9) | ((key[2] & 0x40) << 8) | ((key[1] & 0x40) << 7) | ((key[0] & 0x40) << 6) |
                ((key[7] & 0x20) << 6) | ((key[6] & 0x20) << 5) | ((key[5] & 0x20) << 4) | ((key[4] & 0x20) << 3) |
                ((key[3] & 0x20) << 2) | ((key[2] & 0x20) << 1) | ((key[1] & 0x20)) | ((key[0] & 0x20) >> 1) |
                ((key[7] & 0x10) >> 1) | ((key[6] & 0x10) >> 2) | ((key[5] & 0x10) >> 3) | ((key[4] & 0x10) >> 4);
   uint32_t D = ((key[7] & 0x02) << 26) | ((key[6] & 0x02) << 25) | ((key[5] & 0x02) << 24) | ((key[4] & 0x02) << 23) |
                ((key[3] & 0x02) << 22) | ((key[2] & 0x02) << 21) | ((key[1] & 0x02) << 20) | ((key[0] & 0x02) << 19) |
                ((key[7] & 0x04) << 17) | ((key[6] & 0x04) << 16) | ((key[5] & 0x04) << 15) | ((key[4] & 0x04) << 14) |
                ((key[3] & 0x04) << 13) | ((key[2] & 0x04) << 12) | ((key[1] & 0x04) << 11) | ((key[0] & 0x04) << 10) |
                ((key[7] & 0x08) << 8) | ((key[6] & 0x08) << 7) | ((key[5] & 0x08) << 6) | ((key[4] & 0x08) << 5) |
                ((key[3] & 0x08) << 4) | ((key[2] & 0x08) << 3) | ((key[1] & 0x08) << 2) | ((key[0] & 0x08) << 1) |
                ((key[3] & 0x10) >> 1) | ((key[2] & 0x10) >> 2) | ((key[1] & 0x10) >> 3) | ((key[0] & 0x10) >> 4);

   for(size_t i = 0; i != 16; ++i) {
      C = ((C << ROT[i]) | (C >> (28 - ROT[i]))) & 0x0FFFFFFF;
      D = ((D << ROT[i]) | (D >> (28 - ROT[i]))) & 0x0FFFFFFF;
      round_key[2 * i] = ((C & 0x00000010) << 22) | ((C & 0x00000800) << 17) | ((C & 0x00000020) << 16) |
                         ((C & 0x00004004) << 15) | ((C & 0x00000200) << 11) | ((C & 0x00020000) << 10) |
                         ((C & 0x01000000) >> 6) | ((C & 0x00100000) >> 4) | ((C & 0x00010000) << 3) |
                         ((C & 0x08000000) >> 2) | ((C & 0x00800000) << 1) | ((D & 0x00000010) << 8) |
                         ((D & 0x00000002) << 7) | ((D & 0x00000001) << 2) | ((D & 0x00000200)) |
                         ((D & 0x00008000) >> 2) | ((D & 0x00000088) >> 3) | ((D & 0x00001000) >> 7) |
                         ((D & 0x00080000) >> 9) | ((D & 0x02020000) >> 14) | ((D & 0x00400000) >> 21);
      round_key[2 * i + 1] =
         ((C & 0x00000001) << 28) | ((C & 0x00000082) << 18) | ((C & 0x00002000) << 14) | ((C & 0x00000100) << 10) |
         ((C & 0x00001000) << 9) | ((C & 0x00040000) << 6) | ((C & 0x02400000) << 4) | ((C & 0x00008000) << 2) |
         ((C & 0x00200000) >> 1) | ((C & 0x04000000) >> 10) | ((D & 0x00000020) << 6) | ((D & 0x00000100)) |
         ((D & 0x00000800) >> 1) | ((D & 0x00000040) >> 3) | ((D & 0x00010000) >> 4) | ((D & 0x00000400) >> 5) |
         ((D & 0x00004000) >> 10) | ((D & 0x04000000) >> 13) | ((D & 0x00800000) >> 14) | ((D & 0x00100000) >> 18) |
         ((D & 0x01000000) >> 24) | ((D & 0x08000000) >> 26);
   }
}

inline uint32_t spbox(uint32_t T0, uint32_t T1) {
   return ((SPBOX_CATS[0 * 64 + ((T0 >> 24) & 0x3F)] * SPBOX_CAT_0_MUL) & SPBOX_CAT_0_MASK) ^
          ((SPBOX_CATS[1 * 64 + ((T1 >> 24) & 0x3F)] * SPBOX_CAT_1_MUL) & SPBOX_CAT_1_MASK) ^
          ((SPBOX_CATS[2 * 64 + ((T0 >> 16) & 0x3F)] * SPBOX_CAT_2_MUL) & SPBOX_CAT_2_MASK) ^
          ((SPBOX_CATS[3 * 64 + ((T1 >> 16) & 0x3F)] * SPBOX_CAT_3_MUL) & SPBOX_CAT_3_MASK) ^
          ((SPBOX_CATS[4 * 64 + ((T0 >> 8) & 0x3F)] * SPBOX_CAT_4_MUL) & SPBOX_CAT_4_MASK) ^
          ((SPBOX_CATS[5 * 64 + ((T1 >> 8) & 0x3F)] * SPBOX_CAT_5_MUL) & SPBOX_CAT_5_MASK) ^
          ((SPBOX_CATS[6 * 64 + ((T0 >> 0) & 0x3F)] * SPBOX_CAT_6_MUL) & SPBOX_CAT_6_MASK) ^
          ((SPBOX_CATS[7 * 64 + ((T1 >> 0) & 0x3F)] * SPBOX_CAT_7_MUL) & SPBOX_CAT_7_MASK);
}

/*
* DES Encryption
*/
inline void des_encrypt(uint32_t& Lr, uint32_t& Rr, const uint32_t round_key[32]) {
   uint32_t L = Lr;
   uint32_t R = Rr;
   for(size_t i = 0; i != 16; i += 2) {
      L ^= spbox(rotr<4>(R) ^ round_key[2 * i], R ^ round_key[2 * i + 1]);
      R ^= spbox(rotr<4>(L) ^ round_key[2 * i + 2], L ^ round_key[2 * i + 3]);
   }

   Lr = L;
   Rr = R;
}

inline void des_encrypt_x2(uint32_t& L0r, uint32_t& R0r, uint32_t& L1r, uint32_t& R1r, const uint32_t round_key[32]) {
   uint32_t L0 = L0r;
   uint32_t R0 = R0r;
   uint32_t L1 = L1r;
   uint32_t R1 = R1r;

   for(size_t i = 0; i != 16; i += 2) {
      L0 ^= spbox(rotr<4>(R0) ^ round_key[2 * i], R0 ^ round_key[2 * i + 1]);
      L1 ^= spbox(rotr<4>(R1) ^ round_key[2 * i], R1 ^ round_key[2 * i + 1]);

      R0 ^= spbox(rotr<4>(L0) ^ round_key[2 * i + 2], L0 ^ round_key[2 * i + 3]);
      R1 ^= spbox(rotr<4>(L1) ^ round_key[2 * i + 2], L1 ^ round_key[2 * i + 3]);
   }

   L0r = L0;
   R0r = R0;
   L1r = L1;
   R1r = R1;
}

/*
* DES Decryption
*/
inline void des_decrypt(uint32_t& Lr, uint32_t& Rr, const uint32_t round_key[32]) {
   uint32_t L = Lr;
   uint32_t R = Rr;
   for(size_t i = 16; i != 0; i -= 2) {
      L ^= spbox(rotr<4>(R) ^ round_key[2 * i - 2], R ^ round_key[2 * i - 1]);
      R ^= spbox(rotr<4>(L) ^ round_key[2 * i - 4], L ^ round_key[2 * i - 3]);
   }
   Lr = L;
   Rr = R;
}

inline void des_decrypt_x2(uint32_t& L0r, uint32_t& R0r, uint32_t& L1r, uint32_t& R1r, const uint32_t round_key[32]) {
   uint32_t L0 = L0r;
   uint32_t R0 = R0r;
   uint32_t L1 = L1r;
   uint32_t R1 = R1r;

   for(size_t i = 16; i != 0; i -= 2) {
      L0 ^= spbox(rotr<4>(R0) ^ round_key[2 * i - 2], R0 ^ round_key[2 * i - 1]);
      L1 ^= spbox(rotr<4>(R1) ^ round_key[2 * i - 2], R1 ^ round_key[2 * i - 1]);

      R0 ^= spbox(rotr<4>(L0) ^ round_key[2 * i - 4], L0 ^ round_key[2 * i - 3]);
      R1 ^= spbox(rotr<4>(L1) ^ round_key[2 * i - 4], L1 ^ round_key[2 * i - 3]);
   }

   L0r = L0;
   R0r = R0;
   L1r = L1;
   R1r = R1;
}

inline void des_IP(uint32_t& L, uint32_t& R) {
   // IP sequence by Wei Dai, taken from public domain Crypto++
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

inline void des_FP(uint32_t& L, uint32_t& R) {
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
}

}  // namespace

/*
* DES Encryption
*/
void DES::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   while(blocks >= 2) {
      uint32_t L0 = load_be<uint32_t>(in, 0);
      uint32_t R0 = load_be<uint32_t>(in, 1);
      uint32_t L1 = load_be<uint32_t>(in, 2);
      uint32_t R1 = load_be<uint32_t>(in, 3);

      des_IP(L0, R0);
      des_IP(L1, R1);

      des_encrypt_x2(L0, R0, L1, R1, m_round_key.data());

      des_FP(L0, R0);
      des_FP(L1, R1);

      store_be(out, R0, L0, R1, L1);

      in += 2 * BLOCK_SIZE;
      out += 2 * BLOCK_SIZE;
      blocks -= 2;
   }

   while(blocks > 0) {
      uint32_t L0 = load_be<uint32_t>(in, 0);
      uint32_t R0 = load_be<uint32_t>(in, 1);
      des_IP(L0, R0);
      des_encrypt(L0, R0, m_round_key.data());
      des_FP(L0, R0);
      store_be(out, R0, L0);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      blocks -= 1;
   }
}

/*
* DES Decryption
*/
void DES::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   while(blocks >= 2) {
      uint32_t L0 = load_be<uint32_t>(in, 0);
      uint32_t R0 = load_be<uint32_t>(in, 1);
      uint32_t L1 = load_be<uint32_t>(in, 2);
      uint32_t R1 = load_be<uint32_t>(in, 3);

      des_IP(L0, R0);
      des_IP(L1, R1);

      des_decrypt_x2(L0, R0, L1, R1, m_round_key.data());

      des_FP(L0, R0);
      des_FP(L1, R1);

      store_be(out, R0, L0, R1, L1);

      in += 2 * BLOCK_SIZE;
      out += 2 * BLOCK_SIZE;
      blocks -= 2;
   }

   while(blocks > 0) {
      uint32_t L0 = load_be<uint32_t>(in, 0);
      uint32_t R0 = load_be<uint32_t>(in, 1);
      des_IP(L0, R0);
      des_decrypt(L0, R0, m_round_key.data());
      des_FP(L0, R0);
      store_be(out, R0, L0);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      blocks -= 1;
   }
}

bool DES::has_keying_material() const {
   return !m_round_key.empty();
}

/*
* DES Key Schedule
*/
void DES::key_schedule(std::span<const uint8_t> key) {
   m_round_key.resize(32);
   des_key_schedule(m_round_key.data(), key.data());
}

void DES::clear() {
   zap(m_round_key);
}

/*
* TripleDES Encryption
*/
void TripleDES::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   while(blocks >= 2) {
      uint32_t L0 = load_be<uint32_t>(in, 0);
      uint32_t R0 = load_be<uint32_t>(in, 1);
      uint32_t L1 = load_be<uint32_t>(in, 2);
      uint32_t R1 = load_be<uint32_t>(in, 3);

      des_IP(L0, R0);
      des_IP(L1, R1);

      des_encrypt_x2(L0, R0, L1, R1, &m_round_key[0]);
      des_decrypt_x2(R0, L0, R1, L1, &m_round_key[32]);
      des_encrypt_x2(L0, R0, L1, R1, &m_round_key[64]);

      des_FP(L0, R0);
      des_FP(L1, R1);

      store_be(out, R0, L0, R1, L1);

      in += 2 * BLOCK_SIZE;
      out += 2 * BLOCK_SIZE;
      blocks -= 2;
   }

   while(blocks > 0) {
      uint32_t L0 = load_be<uint32_t>(in, 0);
      uint32_t R0 = load_be<uint32_t>(in, 1);

      des_IP(L0, R0);
      des_encrypt(L0, R0, &m_round_key[0]);
      des_decrypt(R0, L0, &m_round_key[32]);
      des_encrypt(L0, R0, &m_round_key[64]);
      des_FP(L0, R0);

      store_be(out, R0, L0);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      blocks -= 1;
   }
}

/*
* TripleDES Decryption
*/
void TripleDES::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   while(blocks >= 2) {
      uint32_t L0 = load_be<uint32_t>(in, 0);
      uint32_t R0 = load_be<uint32_t>(in, 1);
      uint32_t L1 = load_be<uint32_t>(in, 2);
      uint32_t R1 = load_be<uint32_t>(in, 3);

      des_IP(L0, R0);
      des_IP(L1, R1);

      des_decrypt_x2(L0, R0, L1, R1, &m_round_key[64]);
      des_encrypt_x2(R0, L0, R1, L1, &m_round_key[32]);
      des_decrypt_x2(L0, R0, L1, R1, &m_round_key[0]);

      des_FP(L0, R0);
      des_FP(L1, R1);

      store_be(out, R0, L0, R1, L1);

      in += 2 * BLOCK_SIZE;
      out += 2 * BLOCK_SIZE;
      blocks -= 2;
   }

   while(blocks > 0) {
      uint32_t L0 = load_be<uint32_t>(in, 0);
      uint32_t R0 = load_be<uint32_t>(in, 1);

      des_IP(L0, R0);
      des_decrypt(L0, R0, &m_round_key[64]);
      des_encrypt(R0, L0, &m_round_key[32]);
      des_decrypt(L0, R0, &m_round_key[0]);
      des_FP(L0, R0);

      store_be(out, R0, L0);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      blocks -= 1;
   }
}

bool TripleDES::has_keying_material() const {
   return !m_round_key.empty();
}

/*
* TripleDES Key Schedule
*/
void TripleDES::key_schedule(std::span<const uint8_t> key) {
   m_round_key.resize(3 * 32);
   des_key_schedule(&m_round_key[0], key.first(8).data());
   des_key_schedule(&m_round_key[32], key.subspan(8, 8).data());

   if(key.size() == 24) {
      des_key_schedule(&m_round_key[64], key.last(8).data());
   } else {
      copy_mem(&m_round_key[64], &m_round_key[0], 32);
   }
}

void TripleDES::clear() {
   zap(m_round_key);
}

}  // namespace Botan

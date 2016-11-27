/*
* DES
* (C) 1999-2008 Jack Lloyd
*
* Based on a public domain implemenation by Phil Karn (who in turn
* credited Richard Outerbridge and Jim Gillogly)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/des.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

/*
* DES Key Schedule
*/
void des_key_schedule(u32bit round_key[32], const byte key[8])
   {
   static const byte ROT[16] = { 1, 1, 2, 2, 2, 2, 2, 2,
                                 1, 2, 2, 2, 2, 2, 2, 1 };

   u32bit C = ((key[7] & 0x80) << 20) | ((key[6] & 0x80) << 19) |
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
   u32bit D = ((key[7] & 0x02) << 26) | ((key[6] & 0x02) << 25) |
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

/*
* DES Encryption
*/
void des_encrypt(u32bit& L, u32bit& R,
                 const u32bit round_key[32])
   {
   for(size_t i = 0; i != 16; i += 2)
      {
      u32bit T0, T1;

      T0 = rotate_right(R, 4) ^ round_key[2*i];
      T1 =              R     ^ round_key[2*i + 1];

      L ^= DES_SPBOX1[get_byte(0, T0)] ^ DES_SPBOX2[get_byte(0, T1)] ^
           DES_SPBOX3[get_byte(1, T0)] ^ DES_SPBOX4[get_byte(1, T1)] ^
           DES_SPBOX5[get_byte(2, T0)] ^ DES_SPBOX6[get_byte(2, T1)] ^
           DES_SPBOX7[get_byte(3, T0)] ^ DES_SPBOX8[get_byte(3, T1)];

      T0 = rotate_right(L, 4) ^ round_key[2*i + 2];
      T1 =              L     ^ round_key[2*i + 3];

      R ^= DES_SPBOX1[get_byte(0, T0)] ^ DES_SPBOX2[get_byte(0, T1)] ^
           DES_SPBOX3[get_byte(1, T0)] ^ DES_SPBOX4[get_byte(1, T1)] ^
           DES_SPBOX5[get_byte(2, T0)] ^ DES_SPBOX6[get_byte(2, T1)] ^
           DES_SPBOX7[get_byte(3, T0)] ^ DES_SPBOX8[get_byte(3, T1)];
      }
   }

/*
* DES Decryption
*/
void des_decrypt(u32bit& L, u32bit& R,
                 const u32bit round_key[32])
   {
   for(size_t i = 16; i != 0; i -= 2)
      {
      u32bit T0, T1;

      T0 = rotate_right(R, 4) ^ round_key[2*i - 2];
      T1 =              R     ^ round_key[2*i - 1];

      L ^= DES_SPBOX1[get_byte(0, T0)] ^ DES_SPBOX2[get_byte(0, T1)] ^
           DES_SPBOX3[get_byte(1, T0)] ^ DES_SPBOX4[get_byte(1, T1)] ^
           DES_SPBOX5[get_byte(2, T0)] ^ DES_SPBOX6[get_byte(2, T1)] ^
           DES_SPBOX7[get_byte(3, T0)] ^ DES_SPBOX8[get_byte(3, T1)];

      T0 = rotate_right(L, 4) ^ round_key[2*i - 4];
      T1 =              L     ^ round_key[2*i - 3];

      R ^= DES_SPBOX1[get_byte(0, T0)] ^ DES_SPBOX2[get_byte(0, T1)] ^
           DES_SPBOX3[get_byte(1, T0)] ^ DES_SPBOX4[get_byte(1, T1)] ^
           DES_SPBOX5[get_byte(2, T0)] ^ DES_SPBOX6[get_byte(2, T1)] ^
           DES_SPBOX7[get_byte(3, T0)] ^ DES_SPBOX8[get_byte(3, T1)];
      }
   }

}

/*
* DES Encryption
*/
void DES::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i < blocks; ++i)
      {
      u64bit T = (DES_IPTAB1[in[8*i+0]]     ) | (DES_IPTAB1[in[8*i+1]] << 1) |
                 (DES_IPTAB1[in[8*i+2]] << 2) | (DES_IPTAB1[in[8*i+3]] << 3) |
                 (DES_IPTAB1[in[8*i+4]] << 4) | (DES_IPTAB1[in[8*i+5]] << 5) |
                 (DES_IPTAB1[in[8*i+6]] << 6) | (DES_IPTAB2[in[8*i+7]]     );

      u32bit L = static_cast<u32bit>(T >> 32);
      u32bit R = static_cast<u32bit>(T);

      des_encrypt(L, R, m_round_key.data());

      T = (DES_FPTAB1[get_byte(0, L)] << 5) | (DES_FPTAB1[get_byte(1, L)] << 3) |
          (DES_FPTAB1[get_byte(2, L)] << 1) | (DES_FPTAB2[get_byte(3, L)] << 1) |
          (DES_FPTAB1[get_byte(0, R)] << 4) | (DES_FPTAB1[get_byte(1, R)] << 2) |
          (DES_FPTAB1[get_byte(2, R)]     ) | (DES_FPTAB2[get_byte(3, R)]     );
      T = rotate_left(T, 32);

      store_be(T, out + 8*i);
      }
   }

/*
* DES Decryption
*/
void DES::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i < blocks; ++i)
      {
      u64bit T = (DES_IPTAB1[in[BLOCK_SIZE*i+0]]     ) | (DES_IPTAB1[in[BLOCK_SIZE*i+1]] << 1) |
                 (DES_IPTAB1[in[BLOCK_SIZE*i+2]] << 2) | (DES_IPTAB1[in[BLOCK_SIZE*i+3]] << 3) |
                 (DES_IPTAB1[in[BLOCK_SIZE*i+4]] << 4) | (DES_IPTAB1[in[BLOCK_SIZE*i+5]] << 5) |
                 (DES_IPTAB1[in[BLOCK_SIZE*i+6]] << 6) | (DES_IPTAB2[in[BLOCK_SIZE*i+7]]     );

      u32bit L = static_cast<u32bit>(T >> 32);
      u32bit R = static_cast<u32bit>(T);

      des_decrypt(L, R, m_round_key.data());

      T = (DES_FPTAB1[get_byte(0, L)] << 5) | (DES_FPTAB1[get_byte(1, L)] << 3) |
          (DES_FPTAB1[get_byte(2, L)] << 1) | (DES_FPTAB2[get_byte(3, L)] << 1) |
          (DES_FPTAB1[get_byte(0, R)] << 4) | (DES_FPTAB1[get_byte(1, R)] << 2) |
          (DES_FPTAB1[get_byte(2, R)]     ) | (DES_FPTAB2[get_byte(3, R)]     );

      T = rotate_left(T, 32);

      store_be(T, out + BLOCK_SIZE*i);
      }
   }

/*
* DES Key Schedule
*/
void DES::key_schedule(const byte key[], size_t)
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
void TripleDES::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u64bit T = (DES_IPTAB1[in[0]]     ) | (DES_IPTAB1[in[1]] << 1) |
                 (DES_IPTAB1[in[2]] << 2) | (DES_IPTAB1[in[3]] << 3) |
                 (DES_IPTAB1[in[4]] << 4) | (DES_IPTAB1[in[5]] << 5) |
                 (DES_IPTAB1[in[6]] << 6) | (DES_IPTAB2[in[7]]     );

      u32bit L = static_cast<u32bit>(T >> 32);
      u32bit R = static_cast<u32bit>(T);

      des_encrypt(L, R, &m_round_key[0]);
      des_decrypt(R, L, &m_round_key[32]);
      des_encrypt(L, R, &m_round_key[64]);

      T = (DES_FPTAB1[get_byte(0, L)] << 5) | (DES_FPTAB1[get_byte(1, L)] << 3) |
          (DES_FPTAB1[get_byte(2, L)] << 1) | (DES_FPTAB2[get_byte(3, L)] << 1) |
          (DES_FPTAB1[get_byte(0, R)] << 4) | (DES_FPTAB1[get_byte(1, R)] << 2) |
          (DES_FPTAB1[get_byte(2, R)]     ) | (DES_FPTAB2[get_byte(3, R)]     );

      T = rotate_left(T, 32);

      store_be(T, out);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* TripleDES Decryption
*/
void TripleDES::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u64bit T = (DES_IPTAB1[in[0]]     ) | (DES_IPTAB1[in[1]] << 1) |
                 (DES_IPTAB1[in[2]] << 2) | (DES_IPTAB1[in[3]] << 3) |
                 (DES_IPTAB1[in[4]] << 4) | (DES_IPTAB1[in[5]] << 5) |
                 (DES_IPTAB1[in[6]] << 6) | (DES_IPTAB2[in[7]]     );

      u32bit L = static_cast<u32bit>(T >> 32);
      u32bit R = static_cast<u32bit>(T);

      des_decrypt(L, R, &m_round_key[64]);
      des_encrypt(R, L, &m_round_key[32]);
      des_decrypt(L, R, &m_round_key[0]);

      T = (DES_FPTAB1[get_byte(0, L)] << 5) | (DES_FPTAB1[get_byte(1, L)] << 3) |
          (DES_FPTAB1[get_byte(2, L)] << 1) | (DES_FPTAB2[get_byte(3, L)] << 1) |
          (DES_FPTAB1[get_byte(0, R)] << 4) | (DES_FPTAB1[get_byte(1, R)] << 2) |
          (DES_FPTAB1[get_byte(2, R)]     ) | (DES_FPTAB2[get_byte(3, R)]     );

      T = rotate_left(T, 32);

      store_be(T, out);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* TripleDES Key Schedule
*/
void TripleDES::key_schedule(const byte key[], size_t length)
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

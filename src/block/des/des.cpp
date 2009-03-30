/*
* DES
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
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

   for(u32bit j = 0; j != 16; ++j)
      {
      C = ((C << ROT[j]) | (C >> (28-ROT[j]))) & 0x0FFFFFFF;
      D = ((D << ROT[j]) | (D >> (28-ROT[j]))) & 0x0FFFFFFF;
      round_key[2*j  ] = ((C & 0x00000010) << 22) | ((C & 0x00000800) << 17) |
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
      round_key[2*j+1] = ((C & 0x00000001) << 28) | ((C & 0x00000082) << 18) |
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
   for(u32bit j = 0; j != 16; j += 2)
      {
      u32bit T0, T1;

      T0 = rotate_right(R, 4) ^ round_key[2*j];
      T1 =              R     ^ round_key[2*j + 1];

      L ^= DES_SPBOX1[get_byte(0, T0)] ^ DES_SPBOX2[get_byte(0, T1)] ^
           DES_SPBOX3[get_byte(1, T0)] ^ DES_SPBOX4[get_byte(1, T1)] ^
           DES_SPBOX5[get_byte(2, T0)] ^ DES_SPBOX6[get_byte(2, T1)] ^
           DES_SPBOX7[get_byte(3, T0)] ^ DES_SPBOX8[get_byte(3, T1)];

      T0 = rotate_right(L, 4) ^ round_key[2*j + 2];
      T1 =              L     ^ round_key[2*j + 3];

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
   for(u32bit j = 16; j != 0; j -= 2)
      {
      u32bit T0, T1;

      T0 = rotate_right(R, 4) ^ round_key[2*j - 2];
      T1 =              R     ^ round_key[2*j - 1];

      L ^= DES_SPBOX1[get_byte(0, T0)] ^ DES_SPBOX2[get_byte(0, T1)] ^
           DES_SPBOX3[get_byte(1, T0)] ^ DES_SPBOX4[get_byte(1, T1)] ^
           DES_SPBOX5[get_byte(2, T0)] ^ DES_SPBOX6[get_byte(2, T1)] ^
           DES_SPBOX7[get_byte(3, T0)] ^ DES_SPBOX8[get_byte(3, T1)];

      T0 = rotate_right(L, 4) ^ round_key[2*j - 4];
      T1 =              L     ^ round_key[2*j - 3];

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
void DES::enc(const byte in[], byte out[]) const
   {
   u64bit T = (DES_IPTAB1[in[0]]     ) | (DES_IPTAB1[in[1]] << 1) |
              (DES_IPTAB1[in[2]] << 2) | (DES_IPTAB1[in[3]] << 3) |
              (DES_IPTAB1[in[4]] << 4) | (DES_IPTAB1[in[5]] << 5) |
              (DES_IPTAB1[in[6]] << 6) | (DES_IPTAB2[in[7]]     );

   u32bit L = static_cast<u32bit>(T >> 32);
   u32bit R = static_cast<u32bit>(T);

   des_encrypt(L, R, round_key);

   T = (DES_FPTAB1[get_byte(0, L)] << 5) | (DES_FPTAB1[get_byte(1, L)] << 3) |
       (DES_FPTAB1[get_byte(2, L)] << 1) | (DES_FPTAB2[get_byte(3, L)] << 1) |
       (DES_FPTAB1[get_byte(0, R)] << 4) | (DES_FPTAB1[get_byte(1, R)] << 2) |
       (DES_FPTAB1[get_byte(2, R)]     ) | (DES_FPTAB2[get_byte(3, R)]     );

   T = rotate_left(T, 32);

   store_be(T, out);
   }

/*
* DES Decryption
*/
void DES::dec(const byte in[], byte out[]) const
   {
   u64bit T = (DES_IPTAB1[in[0]]     ) | (DES_IPTAB1[in[1]] << 1) |
              (DES_IPTAB1[in[2]] << 2) | (DES_IPTAB1[in[3]] << 3) |
              (DES_IPTAB1[in[4]] << 4) | (DES_IPTAB1[in[5]] << 5) |
              (DES_IPTAB1[in[6]] << 6) | (DES_IPTAB2[in[7]]     );

   u32bit L = static_cast<u32bit>(T >> 32);
   u32bit R = static_cast<u32bit>(T);

   des_decrypt(L, R, round_key);

   T = (DES_FPTAB1[get_byte(0, L)] << 5) | (DES_FPTAB1[get_byte(1, L)] << 3) |
       (DES_FPTAB1[get_byte(2, L)] << 1) | (DES_FPTAB2[get_byte(3, L)] << 1) |
       (DES_FPTAB1[get_byte(0, R)] << 4) | (DES_FPTAB1[get_byte(1, R)] << 2) |
       (DES_FPTAB1[get_byte(2, R)]     ) | (DES_FPTAB2[get_byte(3, R)]     );

   T = rotate_left(T, 32);

   store_be(T, out);
   }

/*
* DES Key Schedule
*/
void DES::key_schedule(const byte key[], u32bit)
   {
   des_key_schedule(round_key.begin(), key);
   }

/*
* TripleDES Encryption
*/
void TripleDES::enc(const byte in[], byte out[]) const
   {
   u64bit T = (DES_IPTAB1[in[0]]     ) | (DES_IPTAB1[in[1]] << 1) |
              (DES_IPTAB1[in[2]] << 2) | (DES_IPTAB1[in[3]] << 3) |
              (DES_IPTAB1[in[4]] << 4) | (DES_IPTAB1[in[5]] << 5) |
              (DES_IPTAB1[in[6]] << 6) | (DES_IPTAB2[in[7]]     );

   u32bit L = static_cast<u32bit>(T >> 32);
   u32bit R = static_cast<u32bit>(T);

   des_encrypt(L, R, round_key);
   des_decrypt(R, L, round_key + 32);
   des_encrypt(L, R, round_key + 64);

   T = (DES_FPTAB1[get_byte(0, L)] << 5) | (DES_FPTAB1[get_byte(1, L)] << 3) |
       (DES_FPTAB1[get_byte(2, L)] << 1) | (DES_FPTAB2[get_byte(3, L)] << 1) |
       (DES_FPTAB1[get_byte(0, R)] << 4) | (DES_FPTAB1[get_byte(1, R)] << 2) |
       (DES_FPTAB1[get_byte(2, R)]     ) | (DES_FPTAB2[get_byte(3, R)]     );

   T = rotate_left(T, 32);

   store_be(T, out);
   }

/*
* TripleDES Decryption
*/
void TripleDES::dec(const byte in[], byte out[]) const
   {
   u64bit T = (DES_IPTAB1[in[0]]     ) | (DES_IPTAB1[in[1]] << 1) |
              (DES_IPTAB1[in[2]] << 2) | (DES_IPTAB1[in[3]] << 3) |
              (DES_IPTAB1[in[4]] << 4) | (DES_IPTAB1[in[5]] << 5) |
              (DES_IPTAB1[in[6]] << 6) | (DES_IPTAB2[in[7]]     );

   u32bit L = static_cast<u32bit>(T >> 32);
   u32bit R = static_cast<u32bit>(T);

   des_decrypt(L, R, round_key + 64);
   des_encrypt(R, L, round_key + 32);
   des_decrypt(L, R, round_key);

   T = (DES_FPTAB1[get_byte(0, L)] << 5) | (DES_FPTAB1[get_byte(1, L)] << 3) |
       (DES_FPTAB1[get_byte(2, L)] << 1) | (DES_FPTAB2[get_byte(3, L)] << 1) |
       (DES_FPTAB1[get_byte(0, R)] << 4) | (DES_FPTAB1[get_byte(1, R)] << 2) |
       (DES_FPTAB1[get_byte(2, R)]     ) | (DES_FPTAB2[get_byte(3, R)]     );

   T = rotate_left(T, 32);

   store_be(T, out);
   }

/*
* TripleDES Key Schedule
*/
void TripleDES::key_schedule(const byte key[], u32bit length)
   {
   des_key_schedule(&round_key[0], key);
   des_key_schedule(&round_key[32], key + 8);

   if(length == 24)
      des_key_schedule(&round_key[64], key + 16);
   else
      copy_mem(&round_key[64], round_key.begin(), 32);
   }

}

/*************************************************
* DES Source File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/des.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* DES Encryption                                 *
*************************************************/
void DES::enc(const byte in[], byte out[]) const
   {
   u32bit L = make_u32bit(in[0], in[1], in[2], in[3]),
          R = make_u32bit(in[4], in[5], in[6], in[7]);

   IP(L, R);
   raw_encrypt(L, R);
   FP(L, R);

   out[0] = get_byte(0, R); out[1] = get_byte(1, R);
   out[2] = get_byte(2, R); out[3] = get_byte(3, R);
   out[4] = get_byte(0, L); out[5] = get_byte(1, L);
   out[6] = get_byte(2, L); out[7] = get_byte(3, L);
   }

/*************************************************
* DES Decryption                                 *
*************************************************/
void DES::dec(const byte in[], byte out[]) const
   {
   u32bit L = make_u32bit(in[0], in[1], in[2], in[3]),
          R = make_u32bit(in[4], in[5], in[6], in[7]);

   IP(L, R);
   raw_decrypt(L, R);
   FP(L, R);

   out[0] = get_byte(0, R); out[1] = get_byte(1, R);
   out[2] = get_byte(2, R); out[3] = get_byte(3, R);
   out[4] = get_byte(0, L); out[5] = get_byte(1, L);
   out[6] = get_byte(2, L); out[7] = get_byte(3, L);
   }

/*************************************************
* DES Initial Permutation                        *
*************************************************/
void DES::IP(u32bit& L, u32bit& R)
   {
   u64bit T = (IPTAB1[get_byte(0, L)]     ) | (IPTAB1[get_byte(1, L)] << 1) |
              (IPTAB1[get_byte(2, L)] << 2) | (IPTAB1[get_byte(3, L)] << 3) |
              (IPTAB1[get_byte(0, R)] << 4) | (IPTAB1[get_byte(1, R)] << 5) |
              (IPTAB1[get_byte(2, R)] << 6) | (IPTAB2[get_byte(3, R)]     );
   L = (u32bit)((T >> 32) & 0xFFFFFFFF);
   R = (u32bit)((T      ) & 0xFFFFFFFF);
   }

/*************************************************
* DES Final Permutation                          *
*************************************************/
void DES::FP(u32bit& L, u32bit& R)
   {
   u64bit T = (FPTAB1[get_byte(0, L)] << 5) | (FPTAB1[get_byte(1, L)] << 3) |
              (FPTAB1[get_byte(2, L)] << 1) | (FPTAB2[get_byte(3, L)] << 1) |
              (FPTAB1[get_byte(0, R)] << 4) | (FPTAB1[get_byte(1, R)] << 2) |
              (FPTAB1[get_byte(2, R)]     ) | (FPTAB2[get_byte(3, R)]     );
   L = (u32bit)((T >> 32) & 0xFFFFFFFF);
   R = (u32bit)((T      ) & 0xFFFFFFFF);
   }

/*************************************************
* DES Raw Encryption                             *
*************************************************/
void DES::raw_encrypt(u32bit& L, u32bit& R) const
   {
   for(u32bit j = 0; j != 16; j += 2)
      {
      u32bit T0, T1;

      T0 = rotate_right(R, 4) ^ round_key[2*j];
      T1 =              R     ^ round_key[2*j + 1];

      L ^= SPBOX1[get_byte(0, T0)] ^ SPBOX2[get_byte(0, T1)] ^
           SPBOX3[get_byte(1, T0)] ^ SPBOX4[get_byte(1, T1)] ^
           SPBOX5[get_byte(2, T0)] ^ SPBOX6[get_byte(2, T1)] ^
           SPBOX7[get_byte(3, T0)] ^ SPBOX8[get_byte(3, T1)];

      T0 = rotate_right(L, 4) ^ round_key[2*j + 2];
      T1 =              L     ^ round_key[2*j + 3];

      R ^= SPBOX1[get_byte(0, T0)] ^ SPBOX2[get_byte(0, T1)] ^
           SPBOX3[get_byte(1, T0)] ^ SPBOX4[get_byte(1, T1)] ^
           SPBOX5[get_byte(2, T0)] ^ SPBOX6[get_byte(2, T1)] ^
           SPBOX7[get_byte(3, T0)] ^ SPBOX8[get_byte(3, T1)];
      }
   }

/*************************************************
* DES Raw Decryption                             *
*************************************************/
void DES::raw_decrypt(u32bit& L, u32bit& R) const
   {
   for(u32bit j = 16; j != 0; j -= 2)
      {
      u32bit T0, T1;

      T0 = rotate_right(R, 4) ^ round_key[2*j - 2];
      T1 =              R     ^ round_key[2*j - 1];

      L ^= SPBOX1[get_byte(0, T0)] ^ SPBOX2[get_byte(0, T1)] ^
           SPBOX3[get_byte(1, T0)] ^ SPBOX4[get_byte(1, T1)] ^
           SPBOX5[get_byte(2, T0)] ^ SPBOX6[get_byte(2, T1)] ^
           SPBOX7[get_byte(3, T0)] ^ SPBOX8[get_byte(3, T1)];

      T0 = rotate_right(L, 4) ^ round_key[2*j - 4];
      T1 =              L     ^ round_key[2*j - 3];

      R ^= SPBOX1[get_byte(0, T0)] ^ SPBOX2[get_byte(0, T1)] ^
           SPBOX3[get_byte(1, T0)] ^ SPBOX4[get_byte(1, T1)] ^
           SPBOX5[get_byte(2, T0)] ^ SPBOX6[get_byte(2, T1)] ^
           SPBOX7[get_byte(3, T0)] ^ SPBOX8[get_byte(3, T1)];
      }
   }

/*************************************************
* DES Key Schedule                               *
*************************************************/
void DES::key(const byte key[], u32bit)
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

/*************************************************
* TripleDES Encryption                           *
*************************************************/
void TripleDES::enc(const byte in[], byte out[]) const
   {
   u32bit L = make_u32bit(in[0], in[1], in[2], in[3]),
          R = make_u32bit(in[4], in[5], in[6], in[7]);

   DES::IP(L, R);
   des1.raw_encrypt(L, R);
   des2.raw_decrypt(R, L);
   des3.raw_encrypt(L, R);
   DES::FP(L, R);

   out[0] = get_byte(0, R); out[1] = get_byte(1, R);
   out[2] = get_byte(2, R); out[3] = get_byte(3, R);
   out[4] = get_byte(0, L); out[5] = get_byte(1, L);
   out[6] = get_byte(2, L); out[7] = get_byte(3, L);
   }

/*************************************************
* TripleDES Decryption                           *
*************************************************/
void TripleDES::dec(const byte in[], byte out[]) const
   {
   u32bit L = make_u32bit(in[0], in[1], in[2], in[3]),
          R = make_u32bit(in[4], in[5], in[6], in[7]);

   DES::IP(L, R);
   des3.raw_decrypt(L, R);
   des2.raw_encrypt(R, L);
   des1.raw_decrypt(L, R);
   DES::FP(L, R);

   out[0] = get_byte(0, R); out[1] = get_byte(1, R);
   out[2] = get_byte(2, R); out[3] = get_byte(3, R);
   out[4] = get_byte(0, L); out[5] = get_byte(1, L);
   out[6] = get_byte(2, L); out[7] = get_byte(3, L);
   }

/*************************************************
* TripleDES Key Schedule                         *
*************************************************/
void TripleDES::key(const byte key[], u32bit length)
   {
   des1.set_key(key, 8);
   des2.set_key(key + 8, 8);
   if(length == 24)
      des3.set_key(key + 16, 8);
   else
      des3.set_key(key, 8);
   }

/*************************************************
* DESX Encryption                                *
*************************************************/
void DESX::enc(const byte in[], byte out[]) const
   {
   xor_buf(out, in, K1.begin(), BLOCK_SIZE);
   des.encrypt(out);
   xor_buf(out, K2.begin(), BLOCK_SIZE);
   }

/*************************************************
* DESX Decryption                                *
*************************************************/
void DESX::dec(const byte in[], byte out[]) const
   {
   xor_buf(out, in, K2.begin(), BLOCK_SIZE);
   des.decrypt(out);
   xor_buf(out, K1.begin(), BLOCK_SIZE);
   }

/*************************************************
* DESX Key Schedule                              *
*************************************************/
void DESX::key(const byte key[], u32bit)
   {
   K1.copy(key, 8);
   des.set_key(key + 8, 8);
   K2.copy(key + 16, 8);
   }

}

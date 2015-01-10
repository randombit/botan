/*
* Twofish
* (C) 1999-2007 Jack Lloyd
*
* The key schedule implemenation is based on a public domain
* implementation by Matthew Skala
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/twofish.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

/*
* Twofish Encryption
*/
void Twofish::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit A = load_le<u32bit>(in, 0) ^ RK[0];
      u32bit B = load_le<u32bit>(in, 1) ^ RK[1];
      u32bit C = load_le<u32bit>(in, 2) ^ RK[2];
      u32bit D = load_le<u32bit>(in, 3) ^ RK[3];

      for(size_t j = 0; j != 16; j += 2)
         {
         u32bit X, Y;

         X = SB[    get_byte(3, A)] ^ SB[256+get_byte(2, A)] ^
             SB[512+get_byte(1, A)] ^ SB[768+get_byte(0, A)];
         Y = SB[    get_byte(0, B)] ^ SB[256+get_byte(3, B)] ^
             SB[512+get_byte(2, B)] ^ SB[768+get_byte(1, B)];
         X += Y;
         Y += X + RK[2*j + 9];
         X += RK[2*j + 8];

         C = rotate_right(C ^ X, 1);
         D = rotate_left(D, 1) ^ Y;

         X = SB[    get_byte(3, C)] ^ SB[256+get_byte(2, C)] ^
             SB[512+get_byte(1, C)] ^ SB[768+get_byte(0, C)];
         Y = SB[    get_byte(0, D)] ^ SB[256+get_byte(3, D)] ^
             SB[512+get_byte(2, D)] ^ SB[768+get_byte(1, D)];
         X += Y;
         Y += X + RK[2*j + 11];
         X += RK[2*j + 10];

         A = rotate_right(A ^ X, 1);
         B = rotate_left(B, 1) ^ Y;
         }

      C ^= RK[4];
      D ^= RK[5];
      A ^= RK[6];
      B ^= RK[7];

      store_le(out, C, D, A, B);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Twofish Decryption
*/
void Twofish::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit A = load_le<u32bit>(in, 0) ^ RK[4];
      u32bit B = load_le<u32bit>(in, 1) ^ RK[5];
      u32bit C = load_le<u32bit>(in, 2) ^ RK[6];
      u32bit D = load_le<u32bit>(in, 3) ^ RK[7];

      for(size_t j = 0; j != 16; j += 2)
         {
         u32bit X, Y;

         X = SB[    get_byte(3, A)] ^ SB[256+get_byte(2, A)] ^
             SB[512+get_byte(1, A)] ^ SB[768+get_byte(0, A)];
         Y = SB[    get_byte(0, B)] ^ SB[256+get_byte(3, B)] ^
             SB[512+get_byte(2, B)] ^ SB[768+get_byte(1, B)];
         X += Y;
         Y += X + RK[39 - 2*j];
         X += RK[38 - 2*j];

         C = rotate_left(C, 1) ^ X;
         D = rotate_right(D ^ Y, 1);

         X = SB[    get_byte(3, C)] ^ SB[256+get_byte(2, C)] ^
             SB[512+get_byte(1, C)] ^ SB[768+get_byte(0, C)];
         Y = SB[    get_byte(0, D)] ^ SB[256+get_byte(3, D)] ^
             SB[512+get_byte(2, D)] ^ SB[768+get_byte(1, D)];
         X += Y;
         Y += X + RK[37 - 2*j];
         X += RK[36 - 2*j];

         A = rotate_left(A, 1) ^ X;
         B = rotate_right(B ^ Y, 1);
         }

      C ^= RK[0];
      D ^= RK[1];
      A ^= RK[2];
      B ^= RK[3];

      store_le(out, C, D, A, B);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Twofish Key Schedule
*/
void Twofish::key_schedule(const byte key[], size_t length)
   {
   SB.resize(1024);
   RK.resize(40);

   secure_vector<byte> S(16);

   for(size_t i = 0; i != length; ++i)
      rs_mul(&S[4*(i/8)], key[i], i);

   if(length == 16)
      {
      for(size_t i = 0; i != 256; ++i)
         {
         SB[    i] = MDS0[Q0[Q0[i]^S[ 0]]^S[ 4]];
         SB[256+i] = MDS1[Q0[Q1[i]^S[ 1]]^S[ 5]];
         SB[512+i] = MDS2[Q1[Q0[i]^S[ 2]]^S[ 6]];
         SB[768+i] = MDS3[Q1[Q1[i]^S[ 3]]^S[ 7]];
         }

      for(size_t i = 0; i != 40; i += 2)
         {
         u32bit X = MDS0[Q0[Q0[i  ]^key[ 8]]^key[ 0]] ^
                    MDS1[Q0[Q1[i  ]^key[ 9]]^key[ 1]] ^
                    MDS2[Q1[Q0[i  ]^key[10]]^key[ 2]] ^
                    MDS3[Q1[Q1[i  ]^key[11]]^key[ 3]];
         u32bit Y = MDS0[Q0[Q0[i+1]^key[12]]^key[ 4]] ^
                    MDS1[Q0[Q1[i+1]^key[13]]^key[ 5]] ^
                    MDS2[Q1[Q0[i+1]^key[14]]^key[ 6]] ^
                    MDS3[Q1[Q1[i+1]^key[15]]^key[ 7]];
         Y = rotate_left(Y, 8);
         X += Y; Y += X;

         RK[i] = X;
         RK[i+1] = rotate_left(Y, 9);
         }
      }
   else if(length == 24)
      {
      for(size_t i = 0; i != 256; ++i)
         {
         SB[    i] = MDS0[Q0[Q0[Q1[i]^S[ 0]]^S[ 4]]^S[ 8]];
         SB[256+i] = MDS1[Q0[Q1[Q1[i]^S[ 1]]^S[ 5]]^S[ 9]];
         SB[512+i] = MDS2[Q1[Q0[Q0[i]^S[ 2]]^S[ 6]]^S[10]];
         SB[768+i] = MDS3[Q1[Q1[Q0[i]^S[ 3]]^S[ 7]]^S[11]];
         }

      for(size_t i = 0; i != 40; i += 2)
         {
         u32bit X = MDS0[Q0[Q0[Q1[i  ]^key[16]]^key[ 8]]^key[ 0]] ^
                    MDS1[Q0[Q1[Q1[i  ]^key[17]]^key[ 9]]^key[ 1]] ^
                    MDS2[Q1[Q0[Q0[i  ]^key[18]]^key[10]]^key[ 2]] ^
                    MDS3[Q1[Q1[Q0[i  ]^key[19]]^key[11]]^key[ 3]];
         u32bit Y = MDS0[Q0[Q0[Q1[i+1]^key[20]]^key[12]]^key[ 4]] ^
                    MDS1[Q0[Q1[Q1[i+1]^key[21]]^key[13]]^key[ 5]] ^
                    MDS2[Q1[Q0[Q0[i+1]^key[22]]^key[14]]^key[ 6]] ^
                    MDS3[Q1[Q1[Q0[i+1]^key[23]]^key[15]]^key[ 7]];
         Y = rotate_left(Y, 8);
         X += Y; Y += X;

         RK[i] = X;
         RK[i+1] = rotate_left(Y, 9);
         }
      }
   else if(length == 32)
      {
      for(size_t i = 0; i != 256; ++i)
         {
         SB[    i] = MDS0[Q0[Q0[Q1[Q1[i]^S[ 0]]^S[ 4]]^S[ 8]]^S[12]];
         SB[256+i] = MDS1[Q0[Q1[Q1[Q0[i]^S[ 1]]^S[ 5]]^S[ 9]]^S[13]];
         SB[512+i] = MDS2[Q1[Q0[Q0[Q0[i]^S[ 2]]^S[ 6]]^S[10]]^S[14]];
         SB[768+i] = MDS3[Q1[Q1[Q0[Q1[i]^S[ 3]]^S[ 7]]^S[11]]^S[15]];
         }

      for(size_t i = 0; i != 40; i += 2)
         {
         u32bit X = MDS0[Q0[Q0[Q1[Q1[i  ]^key[24]]^key[16]]^key[ 8]]^key[ 0]] ^
                    MDS1[Q0[Q1[Q1[Q0[i  ]^key[25]]^key[17]]^key[ 9]]^key[ 1]] ^
                    MDS2[Q1[Q0[Q0[Q0[i  ]^key[26]]^key[18]]^key[10]]^key[ 2]] ^
                    MDS3[Q1[Q1[Q0[Q1[i  ]^key[27]]^key[19]]^key[11]]^key[ 3]];
         u32bit Y = MDS0[Q0[Q0[Q1[Q1[i+1]^key[28]]^key[20]]^key[12]]^key[ 4]] ^
                    MDS1[Q0[Q1[Q1[Q0[i+1]^key[29]]^key[21]]^key[13]]^key[ 5]] ^
                    MDS2[Q1[Q0[Q0[Q0[i+1]^key[30]]^key[22]]^key[14]]^key[ 6]] ^
                    MDS3[Q1[Q1[Q0[Q1[i+1]^key[31]]^key[23]]^key[15]]^key[ 7]];
         Y = rotate_left(Y, 8);
         X += Y; Y += X;

         RK[i] = X;
         RK[i+1] = rotate_left(Y, 9);
         }
      }
   }

/*
* Do one column of the RS matrix multiplcation
*/
void Twofish::rs_mul(byte S[4], byte key, size_t offset)
   {
   if(key)
      {
      byte X = POLY_TO_EXP[key - 1];

      byte RS1 = RS[(4*offset  ) % 32];
      byte RS2 = RS[(4*offset+1) % 32];
      byte RS3 = RS[(4*offset+2) % 32];
      byte RS4 = RS[(4*offset+3) % 32];

      S[0] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS1 - 1]) % 255];
      S[1] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS2 - 1]) % 255];
      S[2] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS3 - 1]) % 255];
      S[3] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS4 - 1]) % 255];
      }
   }

/*
* Clear memory of sensitive data
*/
void Twofish::clear()
   {
   zap(SB);
   zap(RK);
   }

}

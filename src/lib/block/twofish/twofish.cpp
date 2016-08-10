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
   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks; ++i)
      {
      u32bit A, B, C, D;
      load_le(in + BLOCK_SIZE*i, A, B, C, D);

      A ^= m_RK[0];
      B ^= m_RK[1];
      C ^= m_RK[2];
      D ^= m_RK[3];

      for(size_t j = 0; j != 16; j += 2)
         {
         u32bit X, Y;

         X = m_SB[    get_byte(3, A)] ^ m_SB[256+get_byte(2, A)] ^
             m_SB[512+get_byte(1, A)] ^ m_SB[768+get_byte(0, A)];
         Y = m_SB[    get_byte(0, B)] ^ m_SB[256+get_byte(3, B)] ^
             m_SB[512+get_byte(2, B)] ^ m_SB[768+get_byte(1, B)];
         X += Y;
         Y += X + m_RK[2*j + 9];
         X += m_RK[2*j + 8];

         C = rotate_right(C ^ X, 1);
         D = rotate_left(D, 1) ^ Y;

         X = m_SB[    get_byte(3, C)] ^ m_SB[256+get_byte(2, C)] ^
             m_SB[512+get_byte(1, C)] ^ m_SB[768+get_byte(0, C)];
         Y = m_SB[    get_byte(0, D)] ^ m_SB[256+get_byte(3, D)] ^
             m_SB[512+get_byte(2, D)] ^ m_SB[768+get_byte(1, D)];
         X += Y;
         Y += X + m_RK[2*j + 11];
         X += m_RK[2*j + 10];

         A = rotate_right(A ^ X, 1);
         B = rotate_left(B, 1) ^ Y;
         }

      C ^= m_RK[4];
      D ^= m_RK[5];
      A ^= m_RK[6];
      B ^= m_RK[7];

      store_le(out + BLOCK_SIZE*i, C, D, A, B);
      }
   }

/*
* Twofish Decryption
*/
void Twofish::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks; ++i)
      {
      u32bit A, B, C, D;
      load_le(in + BLOCK_SIZE*i, A, B, C, D);

      A ^= m_RK[4];
      B ^= m_RK[5];
      C ^= m_RK[6];
      D ^= m_RK[7];

      for(size_t j = 0; j != 16; j += 2)
         {
         u32bit X, Y;

         X = m_SB[    get_byte(3, A)] ^ m_SB[256+get_byte(2, A)] ^
             m_SB[512+get_byte(1, A)] ^ m_SB[768+get_byte(0, A)];
         Y = m_SB[    get_byte(0, B)] ^ m_SB[256+get_byte(3, B)] ^
             m_SB[512+get_byte(2, B)] ^ m_SB[768+get_byte(1, B)];
         X += Y;
         Y += X + m_RK[39 - 2*j];
         X += m_RK[38 - 2*j];

         C = rotate_left(C, 1) ^ X;
         D = rotate_right(D ^ Y, 1);

         X = m_SB[    get_byte(3, C)] ^ m_SB[256+get_byte(2, C)] ^
             m_SB[512+get_byte(1, C)] ^ m_SB[768+get_byte(0, C)];
         Y = m_SB[    get_byte(0, D)] ^ m_SB[256+get_byte(3, D)] ^
             m_SB[512+get_byte(2, D)] ^ m_SB[768+get_byte(1, D)];
         X += Y;
         Y += X + m_RK[37 - 2*j];
         X += m_RK[36 - 2*j];

         A = rotate_left(A, 1) ^ X;
         B = rotate_right(B ^ Y, 1);
         }

      C ^= m_RK[0];
      D ^= m_RK[1];
      A ^= m_RK[2];
      B ^= m_RK[3];

      store_le(out + BLOCK_SIZE*i, C, D, A, B);
      }
   }

/*
* Twofish Key Schedule
*/
void Twofish::key_schedule(const byte key[], size_t length)
   {
   m_SB.resize(1024);
   m_RK.resize(40);

   secure_vector<byte> S(16);

   for(size_t i = 0; i != length; ++i)
      rs_mul(&S[4*(i/8)], key[i], i);

   if(length == 16)
      {
      for(size_t i = 0; i != 256; ++i)
         {
         m_SB[    i] = MDS0[Q0[Q0[i]^S[ 0]]^S[ 4]];
         m_SB[256+i] = MDS1[Q0[Q1[i]^S[ 1]]^S[ 5]];
         m_SB[512+i] = MDS2[Q1[Q0[i]^S[ 2]]^S[ 6]];
         m_SB[768+i] = MDS3[Q1[Q1[i]^S[ 3]]^S[ 7]];
         }

      BOTAN_PARALLEL_FOR(size_t i = 0; i < 40; i += 2)
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

         m_RK[i] = X;
         m_RK[i+1] = rotate_left(Y, 9);
         }
      }
   else if(length == 24)
      {
      for(size_t i = 0; i != 256; ++i)
         {
         m_SB[    i] = MDS0[Q0[Q0[Q1[i]^S[ 0]]^S[ 4]]^S[ 8]];
         m_SB[256+i] = MDS1[Q0[Q1[Q1[i]^S[ 1]]^S[ 5]]^S[ 9]];
         m_SB[512+i] = MDS2[Q1[Q0[Q0[i]^S[ 2]]^S[ 6]]^S[10]];
         m_SB[768+i] = MDS3[Q1[Q1[Q0[i]^S[ 3]]^S[ 7]]^S[11]];
         }

      BOTAN_PARALLEL_FOR(size_t i = 0; i < 40; i += 2)
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

         m_RK[i] = X;
         m_RK[i+1] = rotate_left(Y, 9);
         }
      }
   else if(length == 32)
      {
      for(size_t i = 0; i != 256; ++i)
         {
         m_SB[    i] = MDS0[Q0[Q0[Q1[Q1[i]^S[ 0]]^S[ 4]]^S[ 8]]^S[12]];
         m_SB[256+i] = MDS1[Q0[Q1[Q1[Q0[i]^S[ 1]]^S[ 5]]^S[ 9]]^S[13]];
         m_SB[512+i] = MDS2[Q1[Q0[Q0[Q0[i]^S[ 2]]^S[ 6]]^S[10]]^S[14]];
         m_SB[768+i] = MDS3[Q1[Q1[Q0[Q1[i]^S[ 3]]^S[ 7]]^S[11]]^S[15]];
         }

      BOTAN_PARALLEL_FOR(size_t i = 0; i < 40; i += 2)
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

         m_RK[i] = X;
         m_RK[i+1] = rotate_left(Y, 9);
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
   zap(m_SB);
   zap(m_RK);
   }

}

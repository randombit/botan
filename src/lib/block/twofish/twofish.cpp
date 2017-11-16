/*
* Twofish
* (C) 1999-2007,2017 Jack Lloyd
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

namespace {

inline void TF_E(uint32_t A, uint32_t B, uint32_t& C, uint32_t& D,
                 uint32_t RK1, uint32_t RK2,
                 const secure_vector<uint32_t>& SB)
   {
   uint32_t X = SB[    get_byte(3, A)] ^ SB[256+get_byte(2, A)] ^
                SB[512+get_byte(1, A)] ^ SB[768+get_byte(0, A)];
   uint32_t Y = SB[    get_byte(0, B)] ^ SB[256+get_byte(3, B)] ^
                SB[512+get_byte(2, B)] ^ SB[768+get_byte(1, B)];

   X += Y;
   Y += X;

   X += RK1;
   Y += RK2;

   C = rotr<1>(C ^ X);
   D = rotl<1>(D) ^ Y;
   }

inline void TF_D(uint32_t A, uint32_t B, uint32_t& C, uint32_t& D,
                 uint32_t RK1, uint32_t RK2,
                 const secure_vector<uint32_t>& SB)
   {
   uint32_t X = SB[    get_byte(3, A)] ^ SB[256+get_byte(2, A)] ^
                SB[512+get_byte(1, A)] ^ SB[768+get_byte(0, A)];
   uint32_t Y = SB[    get_byte(0, B)] ^ SB[256+get_byte(3, B)] ^
                SB[512+get_byte(2, B)] ^ SB[768+get_byte(1, B)];

   X += Y;
   Y += X;

   X += RK1;
   Y += RK2;

   C = rotl<1>(C) ^ X;
   D = rotr<1>(D ^ Y);
   }

}

/*
* Twofish Encryption
*/
void Twofish::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_SB.empty() == false);

   while(blocks >= 2)
      {
      uint32_t A0, B0, C0, D0;
      uint32_t A1, B1, C1, D1;
      load_le(in, A0, B0, C0, D0, A1, B1, C1, D1);

      A0 ^= m_RK[0];
      A1 ^= m_RK[0];
      B0 ^= m_RK[1];
      B1 ^= m_RK[1];
      C0 ^= m_RK[2];
      C1 ^= m_RK[2];
      D0 ^= m_RK[3];
      D1 ^= m_RK[3];

      for(size_t k = 8; k != 40; k += 4)
         {
         TF_E(A0, B0, C0, D0, m_RK[k+0], m_RK[k+1], m_SB);
         TF_E(A1, B1, C1, D1, m_RK[k+0], m_RK[k+1], m_SB);

         TF_E(C0, D0, A0, B0, m_RK[k+2], m_RK[k+3], m_SB);
         TF_E(C1, D1, A1, B1, m_RK[k+2], m_RK[k+3], m_SB);
         }

      C0 ^= m_RK[4];
      C1 ^= m_RK[4];
      D0 ^= m_RK[5];
      D1 ^= m_RK[5];
      A0 ^= m_RK[6];
      A1 ^= m_RK[6];
      B0 ^= m_RK[7];
      B1 ^= m_RK[7];

      store_le(out, C0, D0, A0, B0, C1, D1, A1, B1);

      blocks -= 2;
      out += 2*BLOCK_SIZE;
      in  += 2*BLOCK_SIZE;
      }

   if(blocks)
      {
      uint32_t A, B, C, D;
      load_le(in, A, B, C, D);

      A ^= m_RK[0];
      B ^= m_RK[1];
      C ^= m_RK[2];
      D ^= m_RK[3];

      for(size_t k = 8; k != 40; k += 4)
         {
         TF_E(A, B, C, D, m_RK[k  ], m_RK[k+1], m_SB);
         TF_E(C, D, A, B, m_RK[k+2], m_RK[k+3], m_SB);
         }

      C ^= m_RK[4];
      D ^= m_RK[5];
      A ^= m_RK[6];
      B ^= m_RK[7];

      store_le(out, C, D, A, B);
      }
   }

/*
* Twofish Decryption
*/
void Twofish::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_SB.empty() == false);

   while(blocks >= 2)
      {
      uint32_t A0, B0, C0, D0;
      uint32_t A1, B1, C1, D1;
      load_le(in, A0, B0, C0, D0, A1, B1, C1, D1);

      A0 ^= m_RK[4];
      A1 ^= m_RK[4];
      B0 ^= m_RK[5];
      B1 ^= m_RK[5];
      C0 ^= m_RK[6];
      C1 ^= m_RK[6];
      D0 ^= m_RK[7];
      D1 ^= m_RK[7];

      for(size_t k = 40; k != 8; k -= 4)
         {
         TF_D(A0, B0, C0, D0, m_RK[k-2], m_RK[k-1], m_SB);
         TF_D(A1, B1, C1, D1, m_RK[k-2], m_RK[k-1], m_SB);

         TF_D(C0, D0, A0, B0, m_RK[k-4], m_RK[k-3], m_SB);
         TF_D(C1, D1, A1, B1, m_RK[k-4], m_RK[k-3], m_SB);
         }

      C0 ^= m_RK[0];
      C1 ^= m_RK[0];
      D0 ^= m_RK[1];
      D1 ^= m_RK[1];
      A0 ^= m_RK[2];
      A1 ^= m_RK[2];
      B0 ^= m_RK[3];
      B1 ^= m_RK[3];

      store_le(out, C0, D0, A0, B0, C1, D1, A1, B1);

      blocks -= 2;
      out += 2*BLOCK_SIZE;
      in  += 2*BLOCK_SIZE;
      }

   if(blocks)
      {
      uint32_t A, B, C, D;
      load_le(in, A, B, C, D);

      A ^= m_RK[4];
      B ^= m_RK[5];
      C ^= m_RK[6];
      D ^= m_RK[7];

      for(size_t k = 40; k != 8; k -= 4)
         {
         TF_D(A, B, C, D, m_RK[k-2], m_RK[k-1], m_SB);
         TF_D(C, D, A, B, m_RK[k-4], m_RK[k-3], m_SB);
         }

      C ^= m_RK[0];
      D ^= m_RK[1];
      A ^= m_RK[2];
      B ^= m_RK[3];

      store_le(out, C, D, A, B);
      }
   }

/*
* Twofish Key Schedule
*/
void Twofish::key_schedule(const uint8_t key[], size_t length)
   {
   m_SB.resize(1024);
   m_RK.resize(40);

   secure_vector<uint8_t> S(16);

   for(size_t i = 0; i != length; ++i)
      {
      /*
      * Do one column of the RS matrix multiplcation
      */
      if(key[i])
         {
         uint8_t X = POLY_TO_EXP[key[i] - 1];

         uint8_t RS1 = RS[(4*i  ) % 32];
         uint8_t RS2 = RS[(4*i+1) % 32];
         uint8_t RS3 = RS[(4*i+2) % 32];
         uint8_t RS4 = RS[(4*i+3) % 32];

         S[4*(i/8)  ] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS1 - 1]) % 255];
         S[4*(i/8)+1] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS2 - 1]) % 255];
         S[4*(i/8)+2] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS3 - 1]) % 255];
         S[4*(i/8)+3] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS4 - 1]) % 255];
         }
      }

   if(length == 16)
      {
      for(size_t i = 0; i != 256; ++i)
         {
         m_SB[    i] = MDS0[Q0[Q0[i]^S[ 0]]^S[ 4]];
         m_SB[256+i] = MDS1[Q0[Q1[i]^S[ 1]]^S[ 5]];
         m_SB[512+i] = MDS2[Q1[Q0[i]^S[ 2]]^S[ 6]];
         m_SB[768+i] = MDS3[Q1[Q1[i]^S[ 3]]^S[ 7]];
         }

      for(size_t i = 0; i < 40; i += 2)
         {
         uint32_t X = MDS0[Q0[Q0[i  ]^key[ 8]]^key[ 0]] ^
                      MDS1[Q0[Q1[i  ]^key[ 9]]^key[ 1]] ^
                      MDS2[Q1[Q0[i  ]^key[10]]^key[ 2]] ^
                      MDS3[Q1[Q1[i  ]^key[11]]^key[ 3]];
         uint32_t Y = MDS0[Q0[Q0[i+1]^key[12]]^key[ 4]] ^
                      MDS1[Q0[Q1[i+1]^key[13]]^key[ 5]] ^
                      MDS2[Q1[Q0[i+1]^key[14]]^key[ 6]] ^
                      MDS3[Q1[Q1[i+1]^key[15]]^key[ 7]];
         Y = rotl<8>(Y);
         X += Y; Y += X;

         m_RK[i] = X;
         m_RK[i+1] = rotl<9>(Y);
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

      for(size_t i = 0; i < 40; i += 2)
         {
         uint32_t X = MDS0[Q0[Q0[Q1[i  ]^key[16]]^key[ 8]]^key[ 0]] ^
                      MDS1[Q0[Q1[Q1[i  ]^key[17]]^key[ 9]]^key[ 1]] ^
                      MDS2[Q1[Q0[Q0[i  ]^key[18]]^key[10]]^key[ 2]] ^
                      MDS3[Q1[Q1[Q0[i  ]^key[19]]^key[11]]^key[ 3]];
         uint32_t Y = MDS0[Q0[Q0[Q1[i+1]^key[20]]^key[12]]^key[ 4]] ^
                      MDS1[Q0[Q1[Q1[i+1]^key[21]]^key[13]]^key[ 5]] ^
                      MDS2[Q1[Q0[Q0[i+1]^key[22]]^key[14]]^key[ 6]] ^
                      MDS3[Q1[Q1[Q0[i+1]^key[23]]^key[15]]^key[ 7]];
         Y = rotl<8>(Y);
         X += Y; Y += X;

         m_RK[i] = X;
         m_RK[i+1] = rotl<9>(Y);
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

      for(size_t i = 0; i < 40; i += 2)
         {
         uint32_t X = MDS0[Q0[Q0[Q1[Q1[i  ]^key[24]]^key[16]]^key[ 8]]^key[ 0]] ^
                      MDS1[Q0[Q1[Q1[Q0[i  ]^key[25]]^key[17]]^key[ 9]]^key[ 1]] ^
                      MDS2[Q1[Q0[Q0[Q0[i  ]^key[26]]^key[18]]^key[10]]^key[ 2]] ^
                      MDS3[Q1[Q1[Q0[Q1[i  ]^key[27]]^key[19]]^key[11]]^key[ 3]];
         uint32_t Y = MDS0[Q0[Q0[Q1[Q1[i+1]^key[28]]^key[20]]^key[12]]^key[ 4]] ^
                      MDS1[Q0[Q1[Q1[Q0[i+1]^key[29]]^key[21]]^key[13]]^key[ 5]] ^
                      MDS2[Q1[Q0[Q0[Q0[i+1]^key[30]]^key[22]]^key[14]]^key[ 6]] ^
                      MDS3[Q1[Q1[Q0[Q1[i+1]^key[31]]^key[23]]^key[15]]^key[ 7]];
         Y = rotl<8>(Y);
         X += Y; Y += X;

         m_RK[i] = X;
         m_RK[i+1] = rotl<9>(Y);
         }
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

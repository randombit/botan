/*
* CAST-128
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cast128.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace {

/*
* CAST-128 Round Type 1
*/
inline void R1(u32bit& L, u32bit R, u32bit MK, u32bit RK)
   {
   u32bit T = rotate_left(MK + R, RK);
   L ^= (CAST_SBOX1[get_byte(0, T)] ^ CAST_SBOX2[get_byte(1, T)]) -
         CAST_SBOX3[get_byte(2, T)] + CAST_SBOX4[get_byte(3, T)];
   }

/*
* CAST-128 Round Type 2
*/
inline void R2(u32bit& L, u32bit R, u32bit MK, u32bit RK)
   {
   u32bit T = rotate_left(MK ^ R, RK);
   L ^= (CAST_SBOX1[get_byte(0, T)]  - CAST_SBOX2[get_byte(1, T)] +
         CAST_SBOX3[get_byte(2, T)]) ^ CAST_SBOX4[get_byte(3, T)];
   }

/*
* CAST-128 Round Type 3
*/
inline void R3(u32bit& L, u32bit R, u32bit MK, u32bit RK)
   {
   u32bit T = rotate_left(MK - R, RK);
   L ^= ((CAST_SBOX1[get_byte(0, T)]  + CAST_SBOX2[get_byte(1, T)]) ^
          CAST_SBOX3[get_byte(2, T)]) - CAST_SBOX4[get_byte(3, T)];
   }

}

/*
* CAST-128 Encryption
*/
void CAST_128::enc(const byte in[], byte out[]) const
   {
   u32bit L = load_be<u32bit>(in, 0);
   u32bit R = load_be<u32bit>(in, 1);

   R1(L, R, MK[ 0], RK[ 0]);
   R2(R, L, MK[ 1], RK[ 1]);
   R3(L, R, MK[ 2], RK[ 2]);
   R1(R, L, MK[ 3], RK[ 3]);
   R2(L, R, MK[ 4], RK[ 4]);
   R3(R, L, MK[ 5], RK[ 5]);
   R1(L, R, MK[ 6], RK[ 6]);
   R2(R, L, MK[ 7], RK[ 7]);
   R3(L, R, MK[ 8], RK[ 8]);
   R1(R, L, MK[ 9], RK[ 9]);
   R2(L, R, MK[10], RK[10]);
   R3(R, L, MK[11], RK[11]);
   R1(L, R, MK[12], RK[12]);
   R2(R, L, MK[13], RK[13]);
   R3(L, R, MK[14], RK[14]);
   R1(R, L, MK[15], RK[15]);

   store_be(out, R, L);
   }

/*
* CAST-128 Decryption
*/
void CAST_128::dec(const byte in[], byte out[]) const
   {
   u32bit L = load_be<u32bit>(in, 0);
   u32bit R = load_be<u32bit>(in, 1);

   R1(L, R, MK[15], RK[15]);
   R3(R, L, MK[14], RK[14]);
   R2(L, R, MK[13], RK[13]);
   R1(R, L, MK[12], RK[12]);
   R3(L, R, MK[11], RK[11]);
   R2(R, L, MK[10], RK[10]);
   R1(L, R, MK[ 9], RK[ 9]);
   R3(R, L, MK[ 8], RK[ 8]);
   R2(L, R, MK[ 7], RK[ 7]);
   R1(R, L, MK[ 6], RK[ 6]);
   R3(L, R, MK[ 5], RK[ 5]);
   R2(R, L, MK[ 4], RK[ 4]);
   R1(L, R, MK[ 3], RK[ 3]);
   R3(R, L, MK[ 2], RK[ 2]);
   R2(L, R, MK[ 1], RK[ 1]);
   R1(R, L, MK[ 0], RK[ 0]);

   store_be(out, R, L);
   }

/*
* CAST-128 Key Schedule
*/
void CAST_128::key_schedule(const byte key[], u32bit length)
   {
   clear();
   SecureBuffer<u32bit, 4> X;
   for(u32bit j = 0; j != length; ++j)
      X[j/4] = (X[j/4] << 8) + key[j];

   key_schedule(MK, X);
   key_schedule(RK, X);

   for(u32bit j = 0; j != 16; ++j)
      RK[j] %= 32;
   }

/*
* S-Box Based Key Expansion
*/
void CAST_128::key_schedule(u32bit K[16], u32bit X[4])
   {
   class ByteReader
      {
      public:
         byte operator()(u32bit i) { return (X[i/4] >> (8*(3 - (i%4)))); }
         ByteReader(const u32bit* x) : X(x) {}
      private:
         const u32bit* X;
      };

   SecureBuffer<u32bit, 4> Z;
   ByteReader x(X), z(Z);

   Z[0]  = X[0] ^ S5[x(13)] ^ S6[x(15)] ^ S7[x(12)] ^ S8[x(14)] ^ S7[x( 8)];
   Z[1]  = X[2] ^ S5[z( 0)] ^ S6[z( 2)] ^ S7[z( 1)] ^ S8[z( 3)] ^ S8[x(10)];
   Z[2]  = X[3] ^ S5[z( 7)] ^ S6[z( 6)] ^ S7[z( 5)] ^ S8[z( 4)] ^ S5[x( 9)];
   Z[3]  = X[1] ^ S5[z(10)] ^ S6[z( 9)] ^ S7[z(11)] ^ S8[z( 8)] ^ S6[x(11)];
   K[ 0] = S5[z( 8)] ^ S6[z( 9)] ^ S7[z( 7)] ^ S8[z( 6)] ^ S5[z( 2)];
   K[ 1] = S5[z(10)] ^ S6[z(11)] ^ S7[z( 5)] ^ S8[z( 4)] ^ S6[z( 6)];
   K[ 2] = S5[z(12)] ^ S6[z(13)] ^ S7[z( 3)] ^ S8[z( 2)] ^ S7[z( 9)];
   K[ 3] = S5[z(14)] ^ S6[z(15)] ^ S7[z( 1)] ^ S8[z( 0)] ^ S8[z(12)];
   X[0]  = Z[2] ^ S5[z( 5)] ^ S6[z( 7)] ^ S7[z( 4)] ^ S8[z( 6)] ^ S7[z( 0)];
   X[1]  = Z[0] ^ S5[x( 0)] ^ S6[x( 2)] ^ S7[x( 1)] ^ S8[x( 3)] ^ S8[z( 2)];
   X[2]  = Z[1] ^ S5[x( 7)] ^ S6[x( 6)] ^ S7[x( 5)] ^ S8[x( 4)] ^ S5[z( 1)];
   X[3]  = Z[3] ^ S5[x(10)] ^ S6[x( 9)] ^ S7[x(11)] ^ S8[x( 8)] ^ S6[z( 3)];
   K[ 4] = S5[x( 3)] ^ S6[x( 2)] ^ S7[x(12)] ^ S8[x(13)] ^ S5[x( 8)];
   K[ 5] = S5[x( 1)] ^ S6[x( 0)] ^ S7[x(14)] ^ S8[x(15)] ^ S6[x(13)];
   K[ 6] = S5[x( 7)] ^ S6[x( 6)] ^ S7[x( 8)] ^ S8[x( 9)] ^ S7[x( 3)];
   K[ 7] = S5[x( 5)] ^ S6[x( 4)] ^ S7[x(10)] ^ S8[x(11)] ^ S8[x( 7)];
   Z[0]  = X[0] ^ S5[x(13)] ^ S6[x(15)] ^ S7[x(12)] ^ S8[x(14)] ^ S7[x( 8)];
   Z[1]  = X[2] ^ S5[z( 0)] ^ S6[z( 2)] ^ S7[z( 1)] ^ S8[z( 3)] ^ S8[x(10)];
   Z[2]  = X[3] ^ S5[z( 7)] ^ S6[z( 6)] ^ S7[z( 5)] ^ S8[z( 4)] ^ S5[x( 9)];
   Z[3]  = X[1] ^ S5[z(10)] ^ S6[z( 9)] ^ S7[z(11)] ^ S8[z( 8)] ^ S6[x(11)];
   K[ 8] = S5[z( 3)] ^ S6[z( 2)] ^ S7[z(12)] ^ S8[z(13)] ^ S5[z( 9)];
   K[ 9] = S5[z( 1)] ^ S6[z( 0)] ^ S7[z(14)] ^ S8[z(15)] ^ S6[z(12)];
   K[10] = S5[z( 7)] ^ S6[z( 6)] ^ S7[z( 8)] ^ S8[z( 9)] ^ S7[z( 2)];
   K[11] = S5[z( 5)] ^ S6[z( 4)] ^ S7[z(10)] ^ S8[z(11)] ^ S8[z( 6)];
   X[0]  = Z[2] ^ S5[z( 5)] ^ S6[z( 7)] ^ S7[z( 4)] ^ S8[z( 6)] ^ S7[z( 0)];
   X[1]  = Z[0] ^ S5[x( 0)] ^ S6[x( 2)] ^ S7[x( 1)] ^ S8[x( 3)] ^ S8[z( 2)];
   X[2]  = Z[1] ^ S5[x( 7)] ^ S6[x( 6)] ^ S7[x( 5)] ^ S8[x( 4)] ^ S5[z( 1)];
   X[3]  = Z[3] ^ S5[x(10)] ^ S6[x( 9)] ^ S7[x(11)] ^ S8[x( 8)] ^ S6[z( 3)];
   K[12] = S5[x( 8)] ^ S6[x( 9)] ^ S7[x( 7)] ^ S8[x( 6)] ^ S5[x( 3)];
   K[13] = S5[x(10)] ^ S6[x(11)] ^ S7[x( 5)] ^ S8[x( 4)] ^ S6[x( 7)];
   K[14] = S5[x(12)] ^ S6[x(13)] ^ S7[x( 3)] ^ S8[x( 2)] ^ S7[x( 8)];
   K[15] = S5[x(14)] ^ S6[x(15)] ^ S7[x( 1)] ^ S8[x( 0)] ^ S8[x(13)];
   }

}

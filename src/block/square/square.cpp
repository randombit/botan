/*
* Square
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/square.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

/*
* Square Encryption
*/
void Square::enc(const byte in[], byte out[]) const
   {
   u32bit T0, T1, T2, T3, B0, B1, B2, B3;
   B0 = TE0[in[ 0] ^ ME[ 0]] ^ TE1[in[ 4] ^ ME[ 4]] ^
        TE2[in[ 8] ^ ME[ 8]] ^ TE3[in[12] ^ ME[12]] ^ EK[0];
   B1 = TE0[in[ 1] ^ ME[ 1]] ^ TE1[in[ 5] ^ ME[ 5]] ^
        TE2[in[ 9] ^ ME[ 9]] ^ TE3[in[13] ^ ME[13]] ^ EK[1];
   B2 = TE0[in[ 2] ^ ME[ 2]] ^ TE1[in[ 6] ^ ME[ 6]] ^
        TE2[in[10] ^ ME[10]] ^ TE3[in[14] ^ ME[14]] ^ EK[2];
   B3 = TE0[in[ 3] ^ ME[ 3]] ^ TE1[in[ 7] ^ ME[ 7]] ^
        TE2[in[11] ^ ME[11]] ^ TE3[in[15] ^ ME[15]] ^ EK[3];
   for(u32bit j = 1; j != 7; j += 2)
      {
      T0 = TE0[get_byte(0, B0)] ^ TE1[get_byte(0, B1)] ^
           TE2[get_byte(0, B2)] ^ TE3[get_byte(0, B3)] ^ EK[4*j+0];
      T1 = TE0[get_byte(1, B0)] ^ TE1[get_byte(1, B1)] ^
           TE2[get_byte(1, B2)] ^ TE3[get_byte(1, B3)] ^ EK[4*j+1];
      T2 = TE0[get_byte(2, B0)] ^ TE1[get_byte(2, B1)] ^
           TE2[get_byte(2, B2)] ^ TE3[get_byte(2, B3)] ^ EK[4*j+2];
      T3 = TE0[get_byte(3, B0)] ^ TE1[get_byte(3, B1)] ^
           TE2[get_byte(3, B2)] ^ TE3[get_byte(3, B3)] ^ EK[4*j+3];
      B0 = TE0[get_byte(0, T0)] ^ TE1[get_byte(0, T1)] ^
           TE2[get_byte(0, T2)] ^ TE3[get_byte(0, T3)] ^ EK[4*j+4];
      B1 = TE0[get_byte(1, T0)] ^ TE1[get_byte(1, T1)] ^
           TE2[get_byte(1, T2)] ^ TE3[get_byte(1, T3)] ^ EK[4*j+5];
      B2 = TE0[get_byte(2, T0)] ^ TE1[get_byte(2, T1)] ^
           TE2[get_byte(2, T2)] ^ TE3[get_byte(2, T3)] ^ EK[4*j+6];
      B3 = TE0[get_byte(3, T0)] ^ TE1[get_byte(3, T1)] ^
           TE2[get_byte(3, T2)] ^ TE3[get_byte(3, T3)] ^ EK[4*j+7];
      }
   out[ 0] = SE[get_byte(0, B0)] ^ ME[16];
   out[ 1] = SE[get_byte(0, B1)] ^ ME[17];
   out[ 2] = SE[get_byte(0, B2)] ^ ME[18];
   out[ 3] = SE[get_byte(0, B3)] ^ ME[19];
   out[ 4] = SE[get_byte(1, B0)] ^ ME[20];
   out[ 5] = SE[get_byte(1, B1)] ^ ME[21];
   out[ 6] = SE[get_byte(1, B2)] ^ ME[22];
   out[ 7] = SE[get_byte(1, B3)] ^ ME[23];
   out[ 8] = SE[get_byte(2, B0)] ^ ME[24];
   out[ 9] = SE[get_byte(2, B1)] ^ ME[25];
   out[10] = SE[get_byte(2, B2)] ^ ME[26];
   out[11] = SE[get_byte(2, B3)] ^ ME[27];
   out[12] = SE[get_byte(3, B0)] ^ ME[28];
   out[13] = SE[get_byte(3, B1)] ^ ME[29];
   out[14] = SE[get_byte(3, B2)] ^ ME[30];
   out[15] = SE[get_byte(3, B3)] ^ ME[31];
   }

/*
* Square Decryption
*/
void Square::dec(const byte in[], byte out[]) const
   {
   u32bit T0, T1, T2, T3, B0, B1, B2, B3;
   B0 = TD0[in[ 0] ^ MD[ 0]] ^ TD1[in[ 4] ^ MD[ 4]] ^
        TD2[in[ 8] ^ MD[ 8]] ^ TD3[in[12] ^ MD[12]] ^ DK[0];
   B1 = TD0[in[ 1] ^ MD[ 1]] ^ TD1[in[ 5] ^ MD[ 5]] ^
        TD2[in[ 9] ^ MD[ 9]] ^ TD3[in[13] ^ MD[13]] ^ DK[1];
   B2 = TD0[in[ 2] ^ MD[ 2]] ^ TD1[in[ 6] ^ MD[ 6]] ^
        TD2[in[10] ^ MD[10]] ^ TD3[in[14] ^ MD[14]] ^ DK[2];
   B3 = TD0[in[ 3] ^ MD[ 3]] ^ TD1[in[ 7] ^ MD[ 7]] ^
        TD2[in[11] ^ MD[11]] ^ TD3[in[15] ^ MD[15]] ^ DK[3];
   for(u32bit j = 1; j != 7; j += 2)
      {
      T0 = TD0[get_byte(0, B0)] ^ TD1[get_byte(0, B1)] ^
           TD2[get_byte(0, B2)] ^ TD3[get_byte(0, B3)] ^ DK[4*j+0];
      T1 = TD0[get_byte(1, B0)] ^ TD1[get_byte(1, B1)] ^
           TD2[get_byte(1, B2)] ^ TD3[get_byte(1, B3)] ^ DK[4*j+1];
      T2 = TD0[get_byte(2, B0)] ^ TD1[get_byte(2, B1)] ^
           TD2[get_byte(2, B2)] ^ TD3[get_byte(2, B3)] ^ DK[4*j+2];
      T3 = TD0[get_byte(3, B0)] ^ TD1[get_byte(3, B1)] ^
           TD2[get_byte(3, B2)] ^ TD3[get_byte(3, B3)] ^ DK[4*j+3];
      B0 = TD0[get_byte(0, T0)] ^ TD1[get_byte(0, T1)] ^
           TD2[get_byte(0, T2)] ^ TD3[get_byte(0, T3)] ^ DK[4*j+4];
      B1 = TD0[get_byte(1, T0)] ^ TD1[get_byte(1, T1)] ^
           TD2[get_byte(1, T2)] ^ TD3[get_byte(1, T3)] ^ DK[4*j+5];
      B2 = TD0[get_byte(2, T0)] ^ TD1[get_byte(2, T1)] ^
           TD2[get_byte(2, T2)] ^ TD3[get_byte(2, T3)] ^ DK[4*j+6];
      B3 = TD0[get_byte(3, T0)] ^ TD1[get_byte(3, T1)] ^
           TD2[get_byte(3, T2)] ^ TD3[get_byte(3, T3)] ^ DK[4*j+7];
      }
   out[ 0] = SD[get_byte(0, B0)] ^ MD[16];
   out[ 1] = SD[get_byte(0, B1)] ^ MD[17];
   out[ 2] = SD[get_byte(0, B2)] ^ MD[18];
   out[ 3] = SD[get_byte(0, B3)] ^ MD[19];
   out[ 4] = SD[get_byte(1, B0)] ^ MD[20];
   out[ 5] = SD[get_byte(1, B1)] ^ MD[21];
   out[ 6] = SD[get_byte(1, B2)] ^ MD[22];
   out[ 7] = SD[get_byte(1, B3)] ^ MD[23];
   out[ 8] = SD[get_byte(2, B0)] ^ MD[24];
   out[ 9] = SD[get_byte(2, B1)] ^ MD[25];
   out[10] = SD[get_byte(2, B2)] ^ MD[26];
   out[11] = SD[get_byte(2, B3)] ^ MD[27];
   out[12] = SD[get_byte(3, B0)] ^ MD[28];
   out[13] = SD[get_byte(3, B1)] ^ MD[29];
   out[14] = SD[get_byte(3, B2)] ^ MD[30];
   out[15] = SD[get_byte(3, B3)] ^ MD[31];
   }

/*
* Square Key Schedule
*/
void Square::key_schedule(const byte key[], u32bit)
   {
   SecureBuffer<u32bit, 36> XEK, XDK;
   for(u32bit j = 0; j != 4; ++j)
      XEK[j] = load_be<u32bit>(key, j);
   for(u32bit j = 0; j != 8; ++j)
      {
      XEK[4*j+4] = XEK[4*j  ] ^ rotate_left(XEK[4*j+3], 8) ^ (0x01000000 << j);
      XEK[4*j+5] = XEK[4*j+1] ^ XEK[4*j+4];
      XEK[4*j+6] = XEK[4*j+2] ^ XEK[4*j+5];
      XEK[4*j+7] = XEK[4*j+3] ^ XEK[4*j+6];
      XDK.copy(28 - 4*j, XEK + 4*(j+1), 4);
      transform(XEK + 4*j);
      }
   for(u32bit j = 0; j != 4; ++j)
      for(u32bit k = 0; k != 4; ++k)
         {
         ME[4*j+k   ] = get_byte(k, XEK[j   ]);
         ME[4*j+k+16] = get_byte(k, XEK[j+32]);
         MD[4*j+k   ] = get_byte(k, XDK[j   ]);
         MD[4*j+k+16] = get_byte(k, XEK[j   ]);
         }
   EK.copy(XEK + 4, 28);
   DK.copy(XDK + 4, 28);
   }

/*
* Square's Inverse Linear Transformation
*/
void Square::transform(u32bit round_key[4])
   {
   static const byte G[4][4] = {
      { 0x02, 0x01, 0x01, 0x03 },
      { 0x03, 0x02, 0x01, 0x01 },
      { 0x01, 0x03, 0x02, 0x01 },
      { 0x01, 0x01, 0x03, 0x02 } };

   for(u32bit j = 0; j != 4; ++j)
      {
      SecureBuffer<byte, 4> A, B;

      store_be(round_key[j], A);

      for(u32bit k = 0; k != 4; ++k)
         for(u32bit l = 0; l != 4; ++l)
            {
            const byte a = A[l];
            const byte b = G[l][k];

            if(a && b)
               B[k] ^= ALog[(Log[a] + Log[b]) % 255];
            }

      round_key[j] = load_be<u32bit>(B.begin(), 0);
      }
   }

/*
* Clear memory of sensitive data
*/
void Square::clear() throw()
   {
   EK.clear();
   DK.clear();
   ME.clear();
   MD.clear();
   }

}

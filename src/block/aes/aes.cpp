/**
* AES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/aes.h>
#include <botan/loadstor.h>

namespace Botan {

/**
* AES Encryption
*/
void AES::enc(const byte in[], byte out[]) const
   {
   const u32bit* TE0 = TE;
   const u32bit* TE1 = TE + 256;
   const u32bit* TE2 = TE + 512;
   const u32bit* TE3 = TE + 768;

   u32bit T0 = load_be<u32bit>(in, 0) ^ EK[0];
   u32bit T1 = load_be<u32bit>(in, 1) ^ EK[1];
   u32bit T2 = load_be<u32bit>(in, 2) ^ EK[2];
   u32bit T3 = load_be<u32bit>(in, 3) ^ EK[3];

   u32bit B0 = TE[get_byte(0, T0)] ^
               rotate_right(TE[get_byte(1, T1)],  8) ^
               rotate_right(TE[get_byte(2, T2)], 16) ^
               rotate_right(TE[get_byte(3, T3)], 24) ^ EK[4];

   u32bit B1 = TE[get_byte(0, T1)] ^
               rotate_right(TE[get_byte(1, T2)],  8) ^
               rotate_right(TE[get_byte(2, T3)], 16) ^
               rotate_right(TE[get_byte(3, T0)], 24) ^ EK[5];

   u32bit B2 = TE[get_byte(0, T2)] ^
               rotate_right(TE[get_byte(1, T3)],  8) ^
               rotate_right(TE[get_byte(2, T0)], 16) ^
               rotate_right(TE[get_byte(3, T1)], 24) ^ EK[6];

   u32bit B3 = TE[get_byte(0, T3)] ^
               rotate_right(TE[get_byte(1, T0)],  8) ^
               rotate_right(TE[get_byte(2, T1)], 16) ^
               rotate_right(TE[get_byte(3, T2)], 24) ^ EK[7];

   for(u32bit j = 2; j != ROUNDS; j += 2)
      {
      const u32bit K0 = EK[4*j];
      const u32bit K1 = EK[4*j+1];
      const u32bit K2 = EK[4*j+2];
      const u32bit K3 = EK[4*j+3];

      T0 = TE0[get_byte(0, B0)] ^ TE1[get_byte(1, B1)] ^
           TE2[get_byte(2, B2)] ^ TE3[get_byte(3, B3)] ^ K0;
      T1 = TE0[get_byte(0, B1)] ^ TE1[get_byte(1, B2)] ^
           TE2[get_byte(2, B3)] ^ TE3[get_byte(3, B0)] ^ K1;
      T2 = TE0[get_byte(0, B2)] ^ TE1[get_byte(1, B3)] ^
           TE2[get_byte(2, B0)] ^ TE3[get_byte(3, B1)] ^ K2;
      T3 = TE0[get_byte(0, B3)] ^ TE1[get_byte(1, B0)] ^
           TE2[get_byte(2, B1)] ^ TE3[get_byte(3, B2)] ^ K3;

      const u32bit K4 = EK[4*(j+1)+0];
      const u32bit K5 = EK[4*(j+1)+1];
      const u32bit K6 = EK[4*(j+1)+2];
      const u32bit K7 = EK[4*(j+1)+3];

      B0 = TE0[get_byte(0, T0)] ^ TE1[get_byte(1, T1)] ^
           TE2[get_byte(2, T2)] ^ TE3[get_byte(3, T3)] ^ K4;
      B1 = TE0[get_byte(0, T1)] ^ TE1[get_byte(1, T2)] ^
           TE2[get_byte(2, T3)] ^ TE3[get_byte(3, T0)] ^ K5;
      B2 = TE0[get_byte(0, T2)] ^ TE1[get_byte(1, T3)] ^
           TE2[get_byte(2, T0)] ^ TE3[get_byte(3, T1)] ^ K6;
      B3 = TE0[get_byte(0, T3)] ^ TE1[get_byte(1, T0)] ^
           TE2[get_byte(2, T1)] ^ TE3[get_byte(3, T2)] ^ K7;
      }

   /*
   Joseph Bonneau and Ilya Mironov's paper
   <a href = "http://icme2007.org/users/mironov/papers/aes-timing.pdf">
   Cache-Collision Timing Attacks Against AES</a> describes an attack
   that can recover AES keys with as few as 2<sup>13</sup> samples.

   """In addition to OpenSSL v. 0.9.8.(a), which was used in our
   experiments, the AES implementations of Crypto++ 5.2.1 and
   LibTomCrypt 1.09 use the original Rijndael C implementation with
   very few changes and are highly vulnerable. The AES implementations
   in libgcrypt v. 1.2.2 and Botan v. 1.4.2 are also vulnerable, but
   use a smaller byte-wide final table which lessens the effectiveness
   of the attacks."""
   */
   out[ 0] = SE[get_byte(0, B0)] ^ ME[0];
   out[ 1] = SE[get_byte(1, B1)] ^ ME[1];
   out[ 2] = SE[get_byte(2, B2)] ^ ME[2];
   out[ 3] = SE[get_byte(3, B3)] ^ ME[3];
   out[ 4] = SE[get_byte(0, B1)] ^ ME[4];
   out[ 5] = SE[get_byte(1, B2)] ^ ME[5];
   out[ 6] = SE[get_byte(2, B3)] ^ ME[6];
   out[ 7] = SE[get_byte(3, B0)] ^ ME[7];
   out[ 8] = SE[get_byte(0, B2)] ^ ME[8];
   out[ 9] = SE[get_byte(1, B3)] ^ ME[9];
   out[10] = SE[get_byte(2, B0)] ^ ME[10];
   out[11] = SE[get_byte(3, B1)] ^ ME[11];
   out[12] = SE[get_byte(0, B3)] ^ ME[12];
   out[13] = SE[get_byte(1, B0)] ^ ME[13];
   out[14] = SE[get_byte(2, B1)] ^ ME[14];
   out[15] = SE[get_byte(3, B2)] ^ ME[15];
   }

/**
* AES Decryption
*/
void AES::dec(const byte in[], byte out[]) const
   {
   const u32bit* TD0 = TD;
   const u32bit* TD1 = TD + 256;
   const u32bit* TD2 = TD + 512;
   const u32bit* TD3 = TD + 768;

   u32bit T0 = load_be<u32bit>(in, 0) ^ DK[0];
   u32bit T1 = load_be<u32bit>(in, 1) ^ DK[1];
   u32bit T2 = load_be<u32bit>(in, 2) ^ DK[2];
   u32bit T3 = load_be<u32bit>(in, 3) ^ DK[3];

   u32bit B0 = TD[get_byte(0, T0)] ^
               rotate_right(TD[get_byte(1, T3)],  8) ^
               rotate_right(TD[get_byte(2, T2)], 16) ^
               rotate_right(TD[get_byte(3, T1)], 24) ^ DK[4];

   u32bit B1 = TD[get_byte(0, T1)] ^
               rotate_right(TD[get_byte(1, T0)],  8) ^
               rotate_right(TD[get_byte(2, T3)], 16) ^
               rotate_right(TD[get_byte(3, T2)], 24) ^ DK[5];

   u32bit B2 = TD[get_byte(0, T2)] ^
               rotate_right(TD[get_byte(1, T1)],  8) ^
               rotate_right(TD[get_byte(2, T0)], 16) ^
               rotate_right(TD[get_byte(3, T3)], 24) ^ DK[6];

   u32bit B3 = TD[get_byte(0, T3)] ^
               rotate_right(TD[get_byte(1, T2)],  8) ^
               rotate_right(TD[get_byte(2, T1)], 16) ^
               rotate_right(TD[get_byte(3, T0)], 24) ^ DK[7];

   for(u32bit j = 2; j != ROUNDS; j += 2)
      {
      const u32bit K0 = DK[4*j+0];
      const u32bit K1 = DK[4*j+1];
      const u32bit K2 = DK[4*j+2];
      const u32bit K3 = DK[4*j+3];

      T0 = TD0[get_byte(0, B0)] ^ TD1[get_byte(1, B3)] ^
           TD2[get_byte(2, B2)] ^ TD3[get_byte(3, B1)] ^ K0;
      T1 = TD0[get_byte(0, B1)] ^ TD1[get_byte(1, B0)] ^
           TD2[get_byte(2, B3)] ^ TD3[get_byte(3, B2)] ^ K1;
      T2 = TD0[get_byte(0, B2)] ^ TD1[get_byte(1, B1)] ^
           TD2[get_byte(2, B0)] ^ TD3[get_byte(3, B3)] ^ K2;
      T3 = TD0[get_byte(0, B3)] ^ TD1[get_byte(1, B2)] ^
           TD2[get_byte(2, B1)] ^ TD3[get_byte(3, B0)] ^ K3;

      const u32bit K4 = DK[4*(j+1)+0];
      const u32bit K5 = DK[4*(j+1)+1];
      const u32bit K6 = DK[4*(j+1)+2];
      const u32bit K7 = DK[4*(j+1)+3];

      B0 = TD0[get_byte(0, T0)] ^ TD1[get_byte(1, T3)] ^
           TD2[get_byte(2, T2)] ^ TD3[get_byte(3, T1)] ^ K4;
      B1 = TD0[get_byte(0, T1)] ^ TD1[get_byte(1, T0)] ^
           TD2[get_byte(2, T3)] ^ TD3[get_byte(3, T2)] ^ K5;
      B2 = TD0[get_byte(0, T2)] ^ TD1[get_byte(1, T1)] ^
           TD2[get_byte(2, T0)] ^ TD3[get_byte(3, T3)] ^ K6;
      B3 = TD0[get_byte(0, T3)] ^ TD1[get_byte(1, T2)] ^
           TD2[get_byte(2, T1)] ^ TD3[get_byte(3, T0)] ^ K7;
      }

   out[ 0] = SD[get_byte(0, B0)] ^ MD[0];
   out[ 1] = SD[get_byte(1, B3)] ^ MD[1];
   out[ 2] = SD[get_byte(2, B2)] ^ MD[2];
   out[ 3] = SD[get_byte(3, B1)] ^ MD[3];
   out[ 4] = SD[get_byte(0, B1)] ^ MD[4];
   out[ 5] = SD[get_byte(1, B0)] ^ MD[5];
   out[ 6] = SD[get_byte(2, B3)] ^ MD[6];
   out[ 7] = SD[get_byte(3, B2)] ^ MD[7];
   out[ 8] = SD[get_byte(0, B2)] ^ MD[8];
   out[ 9] = SD[get_byte(1, B1)] ^ MD[9];
   out[10] = SD[get_byte(2, B0)] ^ MD[10];
   out[11] = SD[get_byte(3, B3)] ^ MD[11];
   out[12] = SD[get_byte(0, B3)] ^ MD[12];
   out[13] = SD[get_byte(1, B2)] ^ MD[13];
   out[14] = SD[get_byte(2, B1)] ^ MD[14];
   out[15] = SD[get_byte(3, B0)] ^ MD[15];
   }

/**
* AES Key Schedule
*/
void AES::key_schedule(const byte key[], u32bit length)
   {
   static const u32bit RC[10] = {
      0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000,
      0x40000000, 0x80000000, 0x1B000000, 0x36000000 };
   ROUNDS = (length / 4) + 6;

   SecureBuffer<u32bit, 64> XEK, XDK;

   const u32bit X = length / 4;
   for(u32bit j = 0; j != X; ++j)
      XEK[j] = load_be<u32bit>(key, j);

   for(u32bit j = X; j < 4*(ROUNDS+1); j += X)
      {
      XEK[j] = XEK[j-X] ^ S(rotate_left(XEK[j-1], 8)) ^ RC[(j-X)/X];
      for(u32bit k = 1; k != X; ++k)
         {
         if(X == 8 && k == 4)
            XEK[j+k] = XEK[j+k-X] ^ S(XEK[j+k-1]);
         else
            XEK[j+k] = XEK[j+k-X] ^ XEK[j+k-1];
         }
      }

   for(u32bit j = 0; j != 4*(ROUNDS+1); j += 4)
      {
      XDK[j  ] = XEK[4*ROUNDS-j  ];
      XDK[j+1] = XEK[4*ROUNDS-j+1];
      XDK[j+2] = XEK[4*ROUNDS-j+2];
      XDK[j+3] = XEK[4*ROUNDS-j+3];
      }

   for(u32bit j = 4; j != length + 24; ++j)
      XDK[j] = TD[SE[get_byte(0, XDK[j])] +   0] ^
               TD[SE[get_byte(1, XDK[j])] + 256] ^
               TD[SE[get_byte(2, XDK[j])] + 512] ^
               TD[SE[get_byte(3, XDK[j])] + 768];

   for(u32bit j = 0; j != 4; ++j)
      {
      store_be(XEK[j+4*ROUNDS], ME + 4*j);
      store_be(XEK[j], MD + 4*j);
      }

   EK.copy(XEK, length + 24);
   DK.copy(XDK, length + 24);
   }

/**
* AES Byte Substitution
*/
u32bit AES::S(u32bit input)
   {
   return make_u32bit(SE[get_byte(0, input)], SE[get_byte(1, input)],
                      SE[get_byte(2, input)], SE[get_byte(3, input)]);
   }

/**
* AES Constructor
*/
AES::AES(u32bit key_size) : BlockCipher(16, key_size)
   {
   if(key_size != 16 && key_size != 24 && key_size != 32)
      throw Invalid_Key_Length(name(), key_size);
   ROUNDS = (key_size / 4) + 6;
   }

/**
* Clear memory of sensitive data
*/
void AES::clear() throw()
   {
   EK.clear();
   DK.clear();
   ME.clear();
   MD.clear();
   }

}

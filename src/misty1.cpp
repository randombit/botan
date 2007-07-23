/*************************************************
* MISTY1 Source File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/misty1.h>
#include <botan/bit_ops.h>
#include <botan/parsing.h>

namespace Botan {

namespace {

/*************************************************
* MISTY1 FI Function                             *
*************************************************/
u16bit FI(u16bit input, u16bit key7, u16bit key9)
   {
   u16bit D9 = input >> 7, D7 = input & 0x7F;
   D9 = MISTY1_SBOX_S9[D9] ^ D7;
   D7 = (MISTY1_SBOX_S7[D7] ^ key7 ^ D9) & 0x7F;
   D9 = MISTY1_SBOX_S9[D9 ^ key9] ^ D7;
   return static_cast<u16bit>((D7 << 9) | D9);
   }

}

/*************************************************
* MISTY1 Encryption                              *
*************************************************/
void MISTY1::enc(const byte in[], byte out[]) const
   {
   u16bit B0 = load_be<u16bit>(in, 0);
   u16bit B1 = load_be<u16bit>(in, 1);
   u16bit B2 = load_be<u16bit>(in, 2);
   u16bit B3 = load_be<u16bit>(in, 3);

   for(u32bit j = 0; j != 12; j += 3)
      {
      const u16bit* RK = EK + 8 * j;

      B1 ^= B0 & RK[0];
      B0 ^= B1 | RK[1];
      B3 ^= B2 & RK[2];
      B2 ^= B3 | RK[3];

      u32bit T0, T1;

      T0  = FI(B0 ^ RK[ 4], RK[ 5], RK[ 6]) ^ B1;
      T1  = FI(B1 ^ RK[ 7], RK[ 8], RK[ 9]) ^ T0;
      T0  = FI(T0 ^ RK[10], RK[11], RK[12]) ^ T1;

      B2 ^= T1 ^ RK[13];
      B3 ^= T0;

      T0  = FI(B2 ^ RK[14], RK[15], RK[16]) ^ B3;
      T1  = FI(B3 ^ RK[17], RK[18], RK[19]) ^ T0;
      T0  = FI(T0 ^ RK[20], RK[21], RK[22]) ^ T1;

      B0 ^= T1 ^ RK[23];
      B1 ^= T0;
      }

   B1 ^= B0 & EK[96];
   B0 ^= B1 | EK[97];
   B3 ^= B2 & EK[98];
   B2 ^= B3 | EK[99];

   store_be(out, B2, B3, B0, B1);
   }

/*************************************************
* MISTY1 Decryption                              *
*************************************************/
void MISTY1::dec(const byte in[], byte out[]) const
   {
   u16bit B0 = load_be<u16bit>(in, 2);
   u16bit B1 = load_be<u16bit>(in, 3);
   u16bit B2 = load_be<u16bit>(in, 0);
   u16bit B3 = load_be<u16bit>(in, 1);

   for(u32bit j = 0; j != 12; j += 3)
      {
      const u16bit* RK = DK + 8 * j;

      B2 ^= B3 | RK[0];
      B3 ^= B2 & RK[1];
      B0 ^= B1 | RK[2];
      B1 ^= B0 & RK[3];

      u32bit T0, T1;

      T0  = FI(B2 ^ RK[ 4], RK[ 5], RK[ 6]) ^ B3;
      T1  = FI(B3 ^ RK[ 7], RK[ 8], RK[ 9]) ^ T0;
      T0  = FI(T0 ^ RK[10], RK[11], RK[12]) ^ T1;

      B0 ^= T1 ^ RK[13];
      B1 ^= T0;

      T0  = FI(B0 ^ RK[14], RK[15], RK[16]) ^ B1;
      T1  = FI(B1 ^ RK[17], RK[18], RK[19]) ^ T0;
      T0  = FI(T0 ^ RK[20], RK[21], RK[22]) ^ T1;

      B2 ^= T1 ^ RK[23];
      B3 ^= T0;
      }

   B2 ^= B3 | DK[96];
   B3 ^= B2 & DK[97];
   B0 ^= B1 | DK[98];
   B1 ^= B0 & DK[99];

   store_be(out, B0, B1, B2, B3);
   }

/*************************************************
* MISTY1 Key Schedule                            *
*************************************************/
void MISTY1::key(const byte key[], u32bit length)
   {
   SecureBuffer<u16bit, 32> KS;
   for(u32bit j = 0; j != length / 2; ++j)
      KS[j] = load_be<u16bit>(key, j);

   for(u32bit j = 0; j != 8; ++j)
      {
      KS[j+ 8] = FI(KS[j], KS[(j+1) % 8] >> 9, KS[(j+1) % 8] & 0x1FF);
      KS[j+16] = KS[j+8] >> 9;
      KS[j+24] = KS[j+8] & 0x1FF;
      }
   for(u32bit j = 0; j != 100; ++j)
      {
      EK[j] = KS[EK_ORDER[j]];
      DK[j] = KS[DK_ORDER[j]];
      }
   }

/*************************************************
* MISTY1 Constructor                             *
*************************************************/
MISTY1::MISTY1(u32bit rounds) : BlockCipher(8, 16)
   {
   if(rounds != 8)
      throw Invalid_Argument("MISTY1: Invalid number of rounds: "
                             + to_string(rounds));
   }

}

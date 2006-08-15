/*************************************************
* Serpent Source File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/serpent.h>
#include <botan/bit_ops.h>

namespace Botan {

namespace {

/*************************************************
* Serpent Encryption S-Box 1                     *
*************************************************/
inline void SBoxE1(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   u32bit T0 = B0, T1 = B1, T2 = B2, T3 = B3, T4;
   T3 ^= T0; T4  = T1; T1 &= T3; T4 ^= T2; T1 ^= T0; T0 |= T3; T0 ^= T4;
   T4 ^= T3; T3 ^= T2; T2 |= T1; T2 ^= T4; T4 = ~T4; T4 |= T1; T1 ^= T3;
   T1 ^= T4; T3 |= T0; T1 ^= T3; T4 ^= T3;
   B0 = T1; B1 = T4; B2 = T2; B3 = T0;
   }

/*************************************************
* Serpent Encryption S-Box 2                     *
*************************************************/
inline void SBoxE2(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   u32bit T0 = B0, T1 = B1, T2 = B2, T3 = B3, T4;
   T0 = ~T0; T2 = ~T2; T4  = T0; T0 &= T1; T2 ^= T0; T0 |= T3; T3 ^= T2;
   T1 ^= T0; T0 ^= T4; T4 |= T1; T1 ^= T3; T2 |= T0; T2 &= T4; T0 ^= T1;
   T1 &= T2; T1 ^= T0; T0 &= T2; T0 ^= T4;
   B0 = T2; B1 = T0; B2 = T3; B3 = T1;
   }

/*************************************************
* Serpent Encryption S-Box 3                     *
*************************************************/
inline void SBoxE3(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   u32bit T0 = B0, T1 = B1, T2 = B2, T3 = B3, T4;
   T4  = T0; T0 &= T2; T0 ^= T3; T2 ^= T1; T2 ^= T0; T3 |= T4; T3 ^= T1;
   T4 ^= T2; T1  = T3; T3 |= T4; T3 ^= T0; T0 &= T1; T4 ^= T0; T1 ^= T3;
   T1 ^= T4; T4 = ~T4;
   B0 = T2; B1 = T3; B2 = T1; B3 = T4;
   }

/*************************************************
* Serpent Encryption S-Box 4                     *
*************************************************/
inline void SBoxE4(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   u32bit T0 = B0, T1 = B1, T2 = B2, T3 = B3, T4;
   T4  = T0; T0 |= T3; T3 ^= T1; T1 &= T4; T4 ^= T2; T2 ^= T3; T3 &= T0;
   T4 |= T1; T3 ^= T4; T0 ^= T1; T4 &= T0; T1 ^= T3; T4 ^= T2; T1 |= T0;
   T1 ^= T2; T0 ^= T3; T2  = T1; T1 |= T3; T1 ^= T0;
   B0 = T1; B1 = T2; B2 = T3; B3 = T4;
   }

/*************************************************
* Serpent Encryption S-Box 5                     *
*************************************************/
inline void SBoxE5(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   u32bit T0 = B0, T1 = B1, T2 = B2, T3 = B3, T4;
   T1 ^= T3; T3 = ~T3; T2 ^= T3; T3 ^= T0; T4  = T1; T1 &= T3; T1 ^= T2;
   T4 ^= T3; T0 ^= T4; T2 &= T4; T2 ^= T0; T0 &= T1; T3 ^= T0; T4 |= T1;
   T4 ^= T0; T0 |= T3; T0 ^= T2; T2 &= T3; T0 = ~T0; T4 ^= T2;
   B0 = T1; B1 = T4; B2 = T0; B3 = T3;
   }
/*************************************************
* Serpent Encryption S-Box 6                     *
*************************************************/
inline void SBoxE6(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   u32bit T0 = B0, T1 = B1, T2 = B2, T3 = B3, T4;
   T0 ^= T1; T1 ^= T3; T3 = ~T3; T4  = T1; T1 &= T0; T2 ^= T3; T1 ^= T2;
   T2 |= T4; T4 ^= T3; T3 &= T1; T3 ^= T0; T4 ^= T1; T4 ^= T2; T2 ^= T0;
   T0 &= T3; T2 = ~T2; T0 ^= T4; T4 |= T3; T2 ^= T4;
   B0 = T1; B1 = T3; B2 = T0; B3 = T2;
   }

/*************************************************
* Serpent Encryption S-Box 7                     *
*************************************************/
inline void SBoxE7(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   u32bit T0 = B0, T1 = B1, T2 = B2, T3 = B3, T4;
   T2 = ~T2; T4  = T3; T3 &= T0; T0 ^= T4; T3 ^= T2; T2 |= T4; T1 ^= T3;
   T2 ^= T0; T0 |= T1; T2 ^= T1; T4 ^= T0; T0 |= T3; T0 ^= T2; T4 ^= T3;
   T4 ^= T0; T3 = ~T3; T2 &= T4; T2 ^= T3;
   B0 = T0; B1 = T1; B2 = T4; B3 = T2;
   }

/*************************************************
* Serpent Encryption S-Box 8                     *
*************************************************/
inline void SBoxE8(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   u32bit T0 = B0, T1 = B1, T2 = B2, T3 = B3, T4;
   T4  = T1; T1 |= T2; T1 ^= T3; T4 ^= T2; T2 ^= T1; T3 |= T4; T3 &= T0;
   T4 ^= T2; T3 ^= T1; T1 |= T4; T1 ^= T0; T0 |= T4; T0 ^= T2; T1 ^= T4;
   T2 ^= T1; T1 &= T0; T1 ^= T4; T2 = ~T2; T2 |= T0; T4 ^= T2;
   B0 = T4; B1 = T3; B2 = T1; B3 = T0;
   }

}

extern "C" void serpent_encrypt(const byte[16], byte[16], const u32bit[132]);
extern "C" void serpent_decrypt(const byte[16], byte[16], const u32bit[132]);

/*************************************************
* Serpent Encryption                             *
*************************************************/
void Serpent::enc(const byte in[], byte out[]) const
   {
   serpent_encrypt(in, out, round_key);
   }

/*************************************************
* Serpent Decryption                             *
*************************************************/
void Serpent::dec(const byte in[], byte out[]) const
   {
   serpent_decrypt(in, out, round_key);
   }

/*************************************************
* Serpent Key Schedule                           *
*************************************************/
void Serpent::key(const byte key[], u32bit length)
   {
   const u32bit PHI = 0x9E3779B9;

   SecureBuffer<u32bit, 140> W;
   for(u32bit j = 0; j != length / 4; ++j)
      W[j] = make_u32bit(key[4*j+3], key[4*j+2], key[4*j+1], key[4*j]);
   W[length / 4] |= u32bit(1) << ((length%4)*8);
   for(u32bit j = 8; j != 140; ++j)
      W[j] = rotate_left(W[j-8] ^ W[j-5] ^ W[j-3] ^ W[j-1] ^ PHI ^ (j-8), 11);
   SBoxE4(W[  8],W[  9],W[ 10],W[ 11]); SBoxE3(W[ 12],W[ 13],W[ 14],W[ 15]);
   SBoxE2(W[ 16],W[ 17],W[ 18],W[ 19]); SBoxE1(W[ 20],W[ 21],W[ 22],W[ 23]);
   SBoxE8(W[ 24],W[ 25],W[ 26],W[ 27]); SBoxE7(W[ 28],W[ 29],W[ 30],W[ 31]);
   SBoxE6(W[ 32],W[ 33],W[ 34],W[ 35]); SBoxE5(W[ 36],W[ 37],W[ 38],W[ 39]);
   SBoxE4(W[ 40],W[ 41],W[ 42],W[ 43]); SBoxE3(W[ 44],W[ 45],W[ 46],W[ 47]);
   SBoxE2(W[ 48],W[ 49],W[ 50],W[ 51]); SBoxE1(W[ 52],W[ 53],W[ 54],W[ 55]);
   SBoxE8(W[ 56],W[ 57],W[ 58],W[ 59]); SBoxE7(W[ 60],W[ 61],W[ 62],W[ 63]);
   SBoxE6(W[ 64],W[ 65],W[ 66],W[ 67]); SBoxE5(W[ 68],W[ 69],W[ 70],W[ 71]);
   SBoxE4(W[ 72],W[ 73],W[ 74],W[ 75]); SBoxE3(W[ 76],W[ 77],W[ 78],W[ 79]);
   SBoxE2(W[ 80],W[ 81],W[ 82],W[ 83]); SBoxE1(W[ 84],W[ 85],W[ 86],W[ 87]);
   SBoxE8(W[ 88],W[ 89],W[ 90],W[ 91]); SBoxE7(W[ 92],W[ 93],W[ 94],W[ 95]);
   SBoxE6(W[ 96],W[ 97],W[ 98],W[ 99]); SBoxE5(W[100],W[101],W[102],W[103]);
   SBoxE4(W[104],W[105],W[106],W[107]); SBoxE3(W[108],W[109],W[110],W[111]);
   SBoxE2(W[112],W[113],W[114],W[115]); SBoxE1(W[116],W[117],W[118],W[119]);
   SBoxE8(W[120],W[121],W[122],W[123]); SBoxE7(W[124],W[125],W[126],W[127]);
   SBoxE6(W[128],W[129],W[130],W[131]); SBoxE5(W[132],W[133],W[134],W[135]);
   SBoxE4(W[136],W[137],W[138],W[139]);
   round_key.copy(W + 8, 132);
   }

}

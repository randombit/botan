/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/block_utils.h>
#include <botan/serpent.h>
#include <botan/internal/serpent_sbox.h>

namespace Botan {

BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(Serpent);

namespace {

/*
* Serpent's Linear Transform
*/
inline void transform(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   B0  = rotate_left(B0, 13);   B2  = rotate_left(B2, 3);
   B1 ^= B0 ^ B2;               B3 ^= B2 ^ (B0 << 3);
   B1  = rotate_left(B1, 1);    B3  = rotate_left(B3, 7);
   B0 ^= B1 ^ B3;               B2 ^= B3 ^ (B1 << 7);
   B0  = rotate_left(B0, 5);    B2  = rotate_left(B2, 22);
   }

/*
* Serpent's Inverse Linear Transform
*/
inline void i_transform(u32bit& B0, u32bit& B1, u32bit& B2, u32bit& B3)
   {
   B2  = rotate_right(B2, 22);  B0  = rotate_right(B0, 5);
   B2 ^= B3 ^ (B1 << 7);        B0 ^= B1 ^ B3;
   B3  = rotate_right(B3, 7);   B1  = rotate_right(B1, 1);
   B3 ^= B2 ^ (B0 << 3);        B1 ^= B0 ^ B2;
   B2  = rotate_right(B2, 3);   B0  = rotate_right(B0, 13);
   }

}

/*
* XOR a key block with a data block
*/
#define key_xor(round, B0, B1, B2, B3) \
   B0 ^= round_key[4*round  ]; \
   B1 ^= round_key[4*round+1]; \
   B2 ^= round_key[4*round+2]; \
   B3 ^= round_key[4*round+3];

/*
* Serpent Encryption
*/
void Serpent::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit B0 = load_le<u32bit>(in, 0);
      u32bit B1 = load_le<u32bit>(in, 1);
      u32bit B2 = load_le<u32bit>(in, 2);
      u32bit B3 = load_le<u32bit>(in, 3);

      key_xor( 0,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 1,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 2,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 3,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 4,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 5,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 6,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 7,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 8,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 9,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(10,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(11,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(12,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(13,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(14,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(15,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(16,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(17,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(18,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(19,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(20,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(21,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(22,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(23,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(24,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(25,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(26,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(27,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(28,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(29,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(30,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(31,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); key_xor(32,B0,B1,B2,B3);

      store_le(out, B0, B1, B2, B3);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Serpent Decryption
*/
void Serpent::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit B0 = load_le<u32bit>(in, 0);
      u32bit B1 = load_le<u32bit>(in, 1);
      u32bit B2 = load_le<u32bit>(in, 2);
      u32bit B3 = load_le<u32bit>(in, 3);

      key_xor(32,B0,B1,B2,B3);  SBoxD8(B0,B1,B2,B3); key_xor(31,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(30,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(29,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(28,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(27,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(26,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(25,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(24,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor(23,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(22,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(21,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(20,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(19,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(18,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(17,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(16,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor(15,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(14,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(13,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(12,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(11,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(10,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 9,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 8,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor( 7,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor( 6,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor( 5,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor( 4,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor( 3,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor( 2,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 1,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 0,B0,B1,B2,B3);

      store_le(out, B0, B1, B2, B3);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

#undef key_xor
#undef transform
#undef i_transform

/*
* Serpent Key Schedule
*/
void Serpent::key_schedule(const byte key[], size_t length)
   {
   const u32bit PHI = 0x9E3779B9;

   secure_vector<u32bit> W(140);
   for(size_t i = 0; i != length / 4; ++i)
      W[i] = load_le<u32bit>(key, i);

   W[length / 4] |= u32bit(1) << ((length%4)*8);

   for(size_t i = 8; i != 140; ++i)
      {
      u32bit wi = W[i-8] ^ W[i-5] ^ W[i-3] ^ W[i-1] ^ PHI ^ u32bit(i-8);
      W[i] = rotate_left(wi, 11);
      }

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

   round_key.assign(&W[8], &W[140]);
   }

void Serpent::clear()
   {
   zap(round_key);
   }

}

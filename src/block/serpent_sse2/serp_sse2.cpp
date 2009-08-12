/*
* Serpent (SSE2)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/serp_sse2.h>
#include <botan/serp_sse2_sbox.h>
#include <botan/loadstor.h>
#include <emmintrin.h>

namespace Botan {

namespace {

#define rotate_left_m128(vec, rot)              \
   _mm_or_si128(_mm_slli_epi32(vec, rot), _mm_srli_epi32(vec, 32-rot))

#define key_xor(round, b0, b1, b2, b3)                                      \
   do {                                                                     \
      __m128i key = _mm_loadu_si128(keys + round);                          \
      b0 = _mm_xor_si128(b0, _mm_shuffle_epi32(key, _MM_SHUFFLE(0,0,0,0))); \
      b1 = _mm_xor_si128(b1, _mm_shuffle_epi32(key, _MM_SHUFFLE(1,1,1,1))); \
      b2 = _mm_xor_si128(b2, _mm_shuffle_epi32(key, _MM_SHUFFLE(2,2,2,2))); \
      b3 = _mm_xor_si128(b3, _mm_shuffle_epi32(key, _MM_SHUFFLE(3,3,3,3))); \
      } while(0);

#define transform(b0, b1, b2, b3)                                       \
   do                                                                   \
      {                                                                 \
      b0 = rotate_left_m128(b0, 13);                                    \
      b2 = rotate_left_m128(b2, 3);                                     \
      b1 = _mm_xor_si128(b1, _mm_xor_si128(b0, b2));                    \
      b3 = _mm_xor_si128(b3, _mm_xor_si128(b2, _mm_slli_epi32(b0, 3))); \
      b1 = rotate_left_m128(b1, 1);                                     \
      b3 = rotate_left_m128(b3, 7);                                     \
      b0 = _mm_xor_si128(b0, _mm_xor_si128(b1, b3));                    \
      b2 = _mm_xor_si128(b2, _mm_xor_si128(b3, _mm_slli_epi32(b1, 7))); \
      b0 = rotate_left_m128(b0, 5);                                     \
      b2 = rotate_left_m128(b2, 22);                                    \
      } while(0);

void print_simd(const char* name, __m128i vec)
   {
   union { __m128i v; int32_t ints[4]; } u = { vec };

   printf("%s: ", name);
   for(u32bit i = 0; i != 4; ++i)
      printf("%08X ", u.ints[i]);
   printf("\n");
   }

void serpent_encrypt_4(const byte in[64],
                       byte out[64],
                       const u32bit keys_32[132])
   {
   const __m128i* keys = (const __m128i*)(keys_32);

   /*
   FIXME: figure out a fast way to do this with 4 loads with
   _mm_loadu_si128 plus shuffle/interleave ops
   */
   union { __m128i v; u32bit u32[4]; } convert;

   convert.u32[0] = load_le<u32bit>(in, 0);
   convert.u32[1] = load_le<u32bit>(in, 4);
   convert.u32[2] = load_le<u32bit>(in, 8);
   convert.u32[3] = load_le<u32bit>(in, 12);
   __m128i B0 = convert.v;

   convert.u32[0] = load_le<u32bit>(in, 1);
   convert.u32[1] = load_le<u32bit>(in, 5);
   convert.u32[2] = load_le<u32bit>(in, 9);
   convert.u32[3] = load_le<u32bit>(in, 13);
   __m128i B1 = convert.v;

   convert.u32[0] = load_le<u32bit>(in, 2);
   convert.u32[1] = load_le<u32bit>(in, 6);
   convert.u32[2] = load_le<u32bit>(in, 10);
   convert.u32[3] = load_le<u32bit>(in, 14);
   __m128i B2 = convert.v;

   convert.u32[0] = load_le<u32bit>(in, 3);
   convert.u32[1] = load_le<u32bit>(in, 7);
   convert.u32[2] = load_le<u32bit>(in, 11);
   convert.u32[3] = load_le<u32bit>(in, 15);
   __m128i B3 = convert.v;

   key_xor(0,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(1,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(2,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(3,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(4,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(5,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(6,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(7,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);

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

   // FIXME: figure out how to do this fast
   union { __m128i v; u32bit u32[4]; } convert_B0;
   union { __m128i v; u32bit u32[4]; } convert_B1;
   union { __m128i v; u32bit u32[4]; } convert_B2;
   union { __m128i v; u32bit u32[4]; } convert_B3;
   convert_B0.v = B0;
   convert_B1.v = B1;
   convert_B2.v = B2;
   convert_B3.v = B3;
   store_le(out,
            convert_B0.u32[0], convert_B1.u32[0],
            convert_B2.u32[0], convert_B3.u32[0]);

   store_le(out + 16,
            convert_B0.u32[1], convert_B1.u32[1],
            convert_B2.u32[1], convert_B3.u32[1]);

   store_le(out + 32,
            convert_B0.u32[2], convert_B1.u32[2],
            convert_B2.u32[2], convert_B3.u32[2]);

   store_le(out + 48,
            convert_B0.u32[3], convert_B1.u32[3],
            convert_B2.u32[3], convert_B3.u32[3]);
   }

}

/*
* Serpent Encryption
*/
void Serpent_SSE2::encrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   while(blocks >= 4)
      {
      serpent_encrypt_4(in, out, this->round_key);
      //Serpent::encrypt_n(in, out, 4);
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
      }

   for(u32bit i = 0; i != blocks; ++i)
      {
      Serpent::encrypt_n(in, out, 1);
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Serpent Decryption
*/
void Serpent_SSE2::decrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      Serpent::decrypt_n(in, out, 1);
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

}

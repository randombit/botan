/*
* Serpent (SSE2)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/serp_sse2.h>
#include <botan/loadstor.h>
#include <emmintrin.h>

namespace Botan {

namespace {

#define SBoxE1(b0, b1, b2, b3, b4)              \
   do {                                         \
      b3 = _mm_xor_si128(b3, b0);               \
      b4 = b1;                                  \
      b1 = _mm_and_si128(b1, b3);               \
      b4 = _mm_xor_si128(b4, b2);               \
      b1 = _mm_xor_si128(b1, b0);               \
      b0 = _mm_or_si128(b0, b3);                \
      b0 = _mm_xor_si128(b0, b4);               \
      b4 = _mm_xor_si128(b4, b3);               \
      b3 = _mm_xor_si128(b3, b2);               \
      b2 = _mm_or_si128(b2, b1);                \
      b2 = _mm_xor_si128(b2, b4);               \
      b4 = _mm_andnot_si128(b4, all_ones);      \
      b4 = _mm_or_si128(b4, b1);                \
      b1 = _mm_xor_si128(b1, b3);               \
      b1 = _mm_xor_si128(b1, b4);               \
      b3 = _mm_or_si128(b3, b0);                \
      b1 = _mm_xor_si128(b1, b3);               \
      b4 = _mm_xor_si128(b4, b3);               \
      b3 = b0; b0 = b1; b1 = b4;                \
   } while(0);

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

   __m128i b0 = convert.v;

   convert.u32[0] = load_le<u32bit>(in, 1);
   convert.u32[1] = load_le<u32bit>(in, 5);
   convert.u32[2] = load_le<u32bit>(in, 9);
   convert.u32[3] = load_le<u32bit>(in, 13);

   __m128i b1 = convert.v;

   convert.u32[0] = load_le<u32bit>(in, 2);
   convert.u32[1] = load_le<u32bit>(in, 6);
   convert.u32[2] = load_le<u32bit>(in, 10);
   convert.u32[3] = load_le<u32bit>(in, 14);

   __m128i b2 = convert.v;

   convert.u32[0] = load_le<u32bit>(in, 3);
   convert.u32[1] = load_le<u32bit>(in, 7);
   convert.u32[2] = load_le<u32bit>(in, 11);
   convert.u32[3] = load_le<u32bit>(in, 15);


   __m128i b3 = convert.v;

   __m128i b4; // temp

   const __m128i all_ones = _mm_set1_epi8(0xFF);

   key_xor(0, b0, b1, b2, b3);
   SBoxE1(b0, b1, b2, b3, b4);
   transform(b0, b1, b2, b3);

   key_xor(b0, b1, b2, b3, 1);

   print_simd("b0", b0);
   print_simd("b1", b1);
   print_simd("b2", b2);
   print_simd("b3", b3);
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

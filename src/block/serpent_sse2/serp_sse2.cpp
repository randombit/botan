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

#define key_xor(round, B0, B1, B2, B3)                                      \
   do {                                                                     \
      __m128i key = _mm_loadu_si128(keys + round);                          \
      B0 = _mm_xor_si128(B0, _mm_shuffle_epi32(key, _MM_SHUFFLE(0,0,0,0))); \
      B1 = _mm_xor_si128(B1, _mm_shuffle_epi32(key, _MM_SHUFFLE(1,1,1,1))); \
      B2 = _mm_xor_si128(B2, _mm_shuffle_epi32(key, _MM_SHUFFLE(2,2,2,2))); \
      B3 = _mm_xor_si128(B3, _mm_shuffle_epi32(key, _MM_SHUFFLE(3,3,3,3))); \
   } while(0);

/*
* Serpent's linear transformations
*/
#define rotate_left_m128(vec, rot)              \
   _mm_or_si128(_mm_slli_epi32(vec, rot), _mm_srli_epi32(vec, 32-rot))

#define rotate_right_m128(vec, rot)              \
   _mm_or_si128(_mm_srli_epi32(vec, rot), _mm_slli_epi32(vec, 32-rot))

#define transform(B0, B1, B2, B3)                                       \
   do {                                                                 \
      B0 = rotate_left_m128(B0, 13);                                    \
      B2 = rotate_left_m128(B2, 3);                                     \
      B1 = _mm_xor_si128(B1, _mm_xor_si128(B0, B2));                    \
      B3 = _mm_xor_si128(B3, _mm_xor_si128(B2, _mm_slli_epi32(B0, 3))); \
      B1 = rotate_left_m128(B1, 1);                                     \
      B3 = rotate_left_m128(B3, 7);                                     \
      B0 = _mm_xor_si128(B0, _mm_xor_si128(B1, B3));                    \
      B2 = _mm_xor_si128(B2, _mm_xor_si128(B3, _mm_slli_epi32(B1, 7))); \
      B0 = rotate_left_m128(B0, 5);                                     \
      B2 = rotate_left_m128(B2, 22);                                    \
   } while(0);

#define i_transform(B0, B1, B2, B3)                                     \
   do {                                                                 \
      B2 = rotate_right_m128(B2, 22);                                   \
      B0 = rotate_right_m128(B0, 5);                                    \
      B2 = _mm_xor_si128(B2, _mm_xor_si128(B3, _mm_slli_epi32(B1, 7))); \
      B0 = _mm_xor_si128(B0, _mm_xor_si128(B1, B3));                    \
      B3 = rotate_right_m128(B3, 7);                                    \
      B1 = rotate_right_m128(B1, 1);                                    \
      B3 = _mm_xor_si128(B3, _mm_xor_si128(B2, _mm_slli_epi32(B0, 3))); \
      B1 = _mm_xor_si128(B1, _mm_xor_si128(B0, B2));                    \
      B2 = rotate_right_m128(B2, 3);                                    \
      B0 = rotate_right_m128(B0, 13);                                   \
   } while(0);

/*
* 4x4 SSE2 integer matrix transpose
*/
#define transpose(B0, B1, B2, B3)               \
   do {                                         \
      __m128i T0 = _mm_unpacklo_epi32(B0, B1);  \
      __m128i T1 = _mm_unpacklo_epi32(B2, B3);  \
      __m128i T2 = _mm_unpackhi_epi32(B0, B1);  \
      __m128i T3 = _mm_unpackhi_epi32(B2, B3);  \
      B0 = _mm_unpacklo_epi64(T0, T1);          \
      B1 = _mm_unpackhi_epi64(T0, T1);          \
      B2 = _mm_unpacklo_epi64(T2, T3);          \
      B3 = _mm_unpackhi_epi64(T2, T3);          \
   } while(0);

/*
* SSE2 Serpent Encryption of 4 blocks in parallel
*/
void serpent_encrypt_4(const byte in[64],
                       byte out[64],
                       const u32bit keys_32[132])
   {
   const __m128i all_ones = _mm_set1_epi8(0xFF);

   const __m128i* keys = (const __m128i*)(keys_32);
   __m128i* out_mm = (__m128i*)(out);
   __m128i* in_mm = (__m128i*)(in);

   __m128i B0 = _mm_loadu_si128(in_mm);
   __m128i B1 = _mm_loadu_si128(in_mm + 1);
   __m128i B2 = _mm_loadu_si128(in_mm + 2);
   __m128i B3 = _mm_loadu_si128(in_mm + 3);

   transpose(B0, B1, B2, B3);

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

   transpose(B0, B1, B2, B3);

   _mm_storeu_si128(out_mm    , B0);
   _mm_storeu_si128(out_mm + 1, B1);
   _mm_storeu_si128(out_mm + 2, B2);
   _mm_storeu_si128(out_mm + 3, B3);
   }

/*
* SSE2 Serpent Decryption of 4 blocks in parallel
*/
void serpent_decrypt_4(const byte in[64],
                       byte out[64],
                       const u32bit keys_32[132])
   {
   const __m128i all_ones = _mm_set1_epi8(0xFF);

   const __m128i* keys = (const __m128i*)(keys_32);
   __m128i* out_mm = (__m128i*)(out);
   __m128i* in_mm = (__m128i*)(in);

   __m128i B0 = _mm_loadu_si128(in_mm);
   __m128i B1 = _mm_loadu_si128(in_mm + 1);
   __m128i B2 = _mm_loadu_si128(in_mm + 2);
   __m128i B3 = _mm_loadu_si128(in_mm + 3);

   transpose(B0, B1, B2, B3);

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

   transpose(B0, B1, B2, B3);

   _mm_storeu_si128(out_mm    , B0);
   _mm_storeu_si128(out_mm + 1, B1);
   _mm_storeu_si128(out_mm + 2, B2);
   _mm_storeu_si128(out_mm + 3, B3);
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
   while(blocks >= 4)
      {
      serpent_decrypt_4(in, out, this->round_key);
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
      }

   for(u32bit i = 0; i != blocks; ++i)
      {
      Serpent::decrypt_n(in, out, 1);
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

}

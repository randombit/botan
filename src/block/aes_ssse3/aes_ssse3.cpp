/*
* AES using SSSE3
* (C) 2010 Jack Lloyd
*
* This is more or less a direct translation of public domain x86-64
* assembly written by Mike Hamburg, described in "Accelerating AES
* with Vector Permute Instructions" (CHES 2009). His original code is
* available at http://crypto.stanford.edu/vpaes/
*
* Distributed under the terms of the Botan license
*/

#include <botan/aes_ssse3.h>
#include <tmmintrin.h>

namespace Botan {

namespace {

const __m128i low_nibs = _mm_set1_epi8(0x0F);

const __m128i k_ipt1 = _mm_set_epi64x(
  0xCABAE09052227808, 0xC2B2E8985A2A7000);
const __m128i k_ipt2 = _mm_set_epi64x(
  0xCD80B1FCB0FDCC81, 0x4C01307D317C4D00);

const __m128i k_inv1 = _mm_set_epi64x(
  0x040703090A0B0C02, 0x0E05060F0D080180);
const __m128i k_inv2 = _mm_set_epi64x(
  0x030D0E0C02050809, 0x01040A060F0B0780);

const __m128i sb1u = _mm_set_epi64x(
  0xA5DF7A6E142AF544, 0xB19BE18FCB503E00);
const __m128i sb1t = _mm_set_epi64x(
  0x3BF7CCC10D2ED9EF, 0x3618D415FAE22300);

const __m128i mc_forward[4] = {
  _mm_set_epi64x(0x0C0F0E0D080B0A09, 0x0407060500030201),
  _mm_set_epi64x(0x000302010C0F0E0D, 0x080B0A0904070605),
  _mm_set_epi64x(0x0407060500030201, 0x0C0F0E0D080B0A09),
  _mm_set_epi64x(0x080B0A0904070605, 0x000302010C0F0E0D)
};

const __m128i sr[4] = {
  _mm_set_epi64x(0x0F0E0D0C0B0A0908, 0x0706050403020100),
  _mm_set_epi64x(0x0B06010C07020D08, 0x030E09040F0A0500),
  _mm_set_epi64x(0x070E050C030A0108, 0x0F060D040B020900),
  _mm_set_epi64x(0x0306090C0F020508, 0x0B0E0104070A0D00),
};

#define mm_xor3(x, y, z) _mm_xor_si128(x, _mm_xor_si128(y, z))

__m128i aes_schedule_transform(__m128i input,
                               __m128i table_1,
                               __m128i table_2)
   {
   __m128i i_1 = _mm_and_si128(low_nibs, input);
   __m128i i_2 = _mm_srli_epi32(_mm_andnot_si128(low_nibs, input), 4);

   input = _mm_and_si128(low_nibs, input);

   return _mm_xor_si128(
      _mm_shuffle_epi8(table_1, i_1),
      _mm_shuffle_epi8(table_2, i_2));
   }

__m128i aes_schedule_mangle(__m128i k, byte round_no)
   {
   __m128i t = _mm_shuffle_epi8(_mm_xor_si128(k, _mm_set1_epi8(0x5B)),
                                mc_forward[0]);

   __m128i t2 = t;

   t = _mm_shuffle_epi8(t, mc_forward[0]);

   t2 = mm_xor3(t2, t, _mm_shuffle_epi8(t, mc_forward[0]));

   return _mm_shuffle_epi8(t2, sr[round_no % 4]);
   }

__m128i aes_schedule_mangle_dec(__m128i k, byte round_no)
   {
   const __m128i dsk[8] = {
      _mm_set_epi64x(0x4AED933482255BFC, 0xB6116FC87ED9A700),
      _mm_set_epi64x(0x8BB89FACE9DAFDCE, 0x4576516227143300),
      _mm_set_epi64x(0x4622EE8AADC90561, 0x27438FEBCCA86400),
      _mm_set_epi64x(0x73AEE13CBD602FF2, 0x815C13CE4F92DD00),
      _mm_set_epi64x(0xF83F3EF9FA3D3CFB, 0x03C4C50201C6C700),
      _mm_set_epi64x(0xA5526A9D7384BC4B, 0xEE1921D638CFF700),
      _mm_set_epi64x(0xA080D3F310306343, 0xE3C390B053732000),
      _mm_set_epi64x(0x2F45AEC48CE60D67, 0xA0CA214B036982E8)
   };

   __m128i t = aes_schedule_transform(k, dsk[0], dsk[1]);
   __m128i output = _mm_shuffle_epi8(t, mc_forward[0]);

   t = aes_schedule_transform(t, dsk[2], dsk[3]);
   output = _mm_shuffle_epi8(_mm_xor_si128(t, output), mc_forward[0]);

   t = aes_schedule_transform(t, dsk[4], dsk[5]);
   output = _mm_shuffle_epi8(_mm_xor_si128(t, output), mc_forward[0]);

   t = aes_schedule_transform(t, dsk[6], dsk[7]);
   output = _mm_shuffle_epi8(_mm_xor_si128(t, output), mc_forward[0]);

   return _mm_shuffle_epi8(output, sr[round_no % 4]);
   }

__m128i aes_schedule_mangle_last(__m128i k, byte round_no)
   {
   const __m128i out_tr1 = _mm_set_epi64x(
      0xF7974121DEBE6808, 0xFF9F4929D6B66000);
   const __m128i out_tr2 = _mm_set_epi64x(
      0xE10D5DB1B05C0CE0, 0x01EDBD5150BCEC00);

   k = _mm_shuffle_epi8(k, sr[round_no % 4]);
   k = _mm_xor_si128(k, _mm_set1_epi8(0x5B));
   return aes_schedule_transform(k, out_tr1, out_tr2);
   }

__m128i aes_schedule_mangle_last_dec(__m128i k)
   {
   const __m128i deskew1 = _mm_set_epi64x(
      0x1DFEB95A5DBEF91A, 0x07E4A34047A4E300);
   const __m128i deskew2 = _mm_set_epi64x(
      0x2841C2ABF49D1E77, 0x5F36B5DC83EA6900);

   k = _mm_xor_si128(k, _mm_set1_epi8(0x5B));
   return aes_schedule_transform(k, deskew1, deskew2);
   }

__m128i aes_schedule_round(__m128i* rcon, __m128i input1, __m128i input2)
   {
   if(rcon)
      {
      input2 = _mm_xor_si128(_mm_alignr_epi8(_mm_setzero_si128(), *rcon, 15),
                             input2);

      *rcon = _mm_alignr_epi8(*rcon, *rcon, 15); // next rcon

      input1 = _mm_shuffle_epi32(input1, 0xFF); // rotate
      input1 = _mm_alignr_epi8(input1, input1, 1);
      }

   __m128i smeared = _mm_xor_si128(input2, _mm_slli_si128(input2, 4));
   smeared = mm_xor3(smeared, _mm_slli_si128(smeared, 8), _mm_set1_epi8(0x5B));

   __m128i t = _mm_srli_epi32(_mm_andnot_si128(low_nibs, input1), 4);

   input1 = _mm_and_si128(low_nibs, input1);

   __m128i t2 = _mm_shuffle_epi8(k_inv2, input1);

   input1 = _mm_xor_si128(input1, t);

   __m128i t3 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, t));
   __m128i t4 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, input1));

   __m128i t5 = _mm_xor_si128(input1, _mm_shuffle_epi8(k_inv1, t3));
   __m128i t6 = _mm_xor_si128(t, _mm_shuffle_epi8(k_inv1, t4));

   return mm_xor3(_mm_shuffle_epi8(sb1u, t5),
                  _mm_shuffle_epi8(sb1t, t6),
                  smeared);
   }

__m128i aes_ssse3_encrypt(__m128i B, const __m128i* keys, u32bit rounds)
   {
   const __m128i sb2u = _mm_set_epi64x(
      0x5EB7E955BC982FCD, 0xE27A93C60B712400);
   const __m128i sb2t = _mm_set_epi64x(
      0xC2A163C8AB82234A, 0x69EB88400AE12900);

   const __m128i sbou = _mm_set_epi64x(
      0x15AABF7AC502A878, 0xD0D26D176FBDC700);
   const __m128i sbot = _mm_set_epi64x(
      0x8E1E90D1412B35FA, 0xCFE474A55FBB6A00);

   const __m128i mc_backward[4] = {
      _mm_set_epi64x(0x0E0D0C0F0A09080B, 0x0605040702010003),
      _mm_set_epi64x(0x0A09080B06050407, 0x020100030E0D0C0F),
      _mm_set_epi64x(0x0605040702010003, 0x0E0D0C0F0A09080B),
      _mm_set_epi64x(0x020100030E0D0C0F, 0x0A09080B06050407),
   };

   B = mm_xor3(_mm_shuffle_epi8(k_ipt1, _mm_and_si128(low_nibs, B)),
               _mm_shuffle_epi8(k_ipt2,
                                _mm_srli_epi32(
                                   _mm_andnot_si128(low_nibs, B),
                                   4)),
               _mm_loadu_si128(keys));

   for(u32bit r = 1; ; ++r)
      {
      const __m128i K = _mm_loadu_si128(keys + r);

      __m128i t = _mm_srli_epi32(_mm_andnot_si128(low_nibs, B), 4);

      B = _mm_and_si128(low_nibs, B);

      __m128i t2 = _mm_shuffle_epi8(k_inv2, B);

      B = _mm_xor_si128(B, t);

      __m128i t3 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, t));
      __m128i t4 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, B));

      __m128i t5 = _mm_xor_si128(B, _mm_shuffle_epi8(k_inv1, t3));
      __m128i t6 = _mm_xor_si128(t, _mm_shuffle_epi8(k_inv1, t4));

      if(r == rounds)
         {
         B = _mm_shuffle_epi8(
            mm_xor3(_mm_shuffle_epi8(sbou, t5),
                    _mm_shuffle_epi8(sbot, t6),
                    K),
            sr[r % 4]);

         return B;
         }

      __m128i t7 = mm_xor3(_mm_shuffle_epi8(sb1t, t6),
                           _mm_shuffle_epi8(sb1u, t5),
                           K);

      __m128i t8 = mm_xor3(_mm_shuffle_epi8(sb2t, t6),
                           _mm_shuffle_epi8(sb2u, t5),
                           _mm_shuffle_epi8(t7, mc_forward[r % 4]));

      B = mm_xor3(_mm_shuffle_epi8(t8, mc_forward[r % 4]),
                  _mm_shuffle_epi8(t7, mc_backward[r % 4]),
                  t8);
      }
   }

__m128i aes_ssse3_decrypt(__m128i B, const __m128i* keys, u32bit rounds)
   {
   const __m128i k_dipt1 = _mm_set_epi64x(
      0x154A411E114E451A, 0x0F505B040B545F00);
   const __m128i k_dipt2 = _mm_set_epi64x(
      0x12771772F491F194, 0x86E383E660056500);

   const __m128i sb9u = _mm_set_epi64x(
      0xCAD51F504F994CC9, 0x851C03539A86D600);
   const __m128i sb9t = _mm_set_epi64x(
      0x725E2C9EB2FBA565, 0xC03B1789ECD74900);

   const __m128i sbeu = _mm_set_epi64x(
      0x2242600464B4F6B0, 0x46F2929626D4D000);
   const __m128i sbet = _mm_set_epi64x(
      0x9467F36B98593E32, 0x0C55A6CDFFAAC100);

   const __m128i sbdu = _mm_set_epi64x(
      0xF56E9B13882A4439, 0x7D57CCDFE6B1A200);
   const __m128i sbdt = _mm_set_epi64x(
      0x2931180D15DEEFD3, 0x3CE2FAF724C6CB00);

   const __m128i sbbu = _mm_set_epi64x(
      0x602646F6B0F2D404, 0xD022649296B44200);
   const __m128i sbbt = _mm_set_epi64x(
      0xF3FF0C3E3255AA6B, 0xC19498A6CD596700);

   __m128i mc = mc_forward[3];

   __m128i t =
      _mm_shuffle_epi8(k_dipt2,
                       _mm_srli_epi32(
                          _mm_andnot_si128(low_nibs, B),
                          4));

   B = mm_xor3(t, _mm_loadu_si128(keys),
               _mm_shuffle_epi8(k_dipt1, _mm_and_si128(B, low_nibs)));

   for(u32bit r = 1; ; ++r)
      {
      const __m128i K = _mm_loadu_si128(keys + r);

      t = _mm_srli_epi32(_mm_andnot_si128(low_nibs, B), 4);

      B = _mm_and_si128(low_nibs, B);

      __m128i t2 = _mm_shuffle_epi8(k_inv2, B);

      B = _mm_xor_si128(B, t);

      __m128i t3 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, t));
      __m128i t4 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, B));
      __m128i t5 = _mm_xor_si128(B, _mm_shuffle_epi8(k_inv1, t3));
      __m128i t6 = _mm_xor_si128(t, _mm_shuffle_epi8(k_inv1, t4));

      if(r == rounds)
         {
         const __m128i sbou = _mm_set_epi64x(
            0xC7AA6DB9D4943E2D, 0x1387EA537EF94000);
         const __m128i sbot = _mm_set_epi64x(
            0xCA4B8159D8C58E9C, 0x12D7560F93441D00);

         __m128i x = _mm_shuffle_epi8(sbou, t5);
         __m128i y = _mm_shuffle_epi8(sbot, t6);
         x = _mm_xor_si128(x, K);
         x = _mm_xor_si128(x, y);

         const u32bit which_sr = ((((rounds - 1) << 4) ^ 48) & 48) / 16;
         return _mm_shuffle_epi8(x, sr[which_sr]);
         }

      __m128i t8 = _mm_xor_si128(_mm_shuffle_epi8(sb9t, t6),
                                 _mm_xor_si128(_mm_shuffle_epi8(sb9u, t5), K));

      __m128i t9 = mm_xor3(_mm_shuffle_epi8(t8, mc),
                           _mm_shuffle_epi8(sbdu, t5),
                           _mm_shuffle_epi8(sbdt, t6));

      __m128i t12 = _mm_xor_si128(
         _mm_xor_si128(
            _mm_shuffle_epi8(t9, mc),
            _mm_shuffle_epi8(sbbu, t5)),
         _mm_shuffle_epi8(sbbt, t6));

      B = _mm_xor_si128(_mm_xor_si128(_mm_shuffle_epi8(t12, mc),
                                      _mm_shuffle_epi8(sbeu, t5)),
                        _mm_shuffle_epi8(sbet, t6));

      mc = _mm_alignr_epi8(mc, mc, 12);
      }
   }

}

/*
* AES-128 Encryption
*/
void AES_128_SSSE3::encrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   const __m128i* in_mm = (const __m128i*)in;
   __m128i* out_mm = (__m128i*)out;

   const __m128i* keys = (const __m128i*)&EK[0];

   for(u32bit i = 0; i != blocks; ++i)
      {
      __m128i B = _mm_loadu_si128(in_mm + i);
      _mm_storeu_si128(out_mm + i, aes_ssse3_encrypt(B, keys, 10));
      }
   }

/*
* AES-128 Decryption
*/
void AES_128_SSSE3::decrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   const __m128i* in_mm = (const __m128i*)in;
   __m128i* out_mm = (__m128i*)out;

   const __m128i* keys = (const __m128i*)&DK[0];

   for(u32bit i = 0; i != blocks; ++i)
      {
      __m128i B = _mm_loadu_si128(in_mm + i);
      _mm_storeu_si128(out_mm + i, aes_ssse3_decrypt(B, keys, 10));
      }
   }

/*
* AES-128 Key Schedule
*/
void AES_128_SSSE3::key_schedule(const byte keyb[], u32bit)
   {
   __m128i rcon = _mm_set_epi64x(0x702A98084D7C7D81,
                                 0x1F8391B9AF9DEEB6);

   __m128i key = _mm_loadu_si128((const __m128i*)keyb);

   __m128i* EK_out = (__m128i*)&EK[0];
   __m128i* DK_out = (__m128i*)&DK[0];

   _mm_storeu_si128(DK_out + 10, _mm_shuffle_epi8(key, sr[2]));

   key = aes_schedule_transform(key, k_ipt1, k_ipt2);

   _mm_storeu_si128(EK_out, key);

   for(u32bit r = 1; r != 10; ++r)
      {
      key = aes_schedule_round(&rcon, key, key);

      _mm_storeu_si128(EK_out + r,
                       aes_schedule_mangle(key, (12 - r) % 4));

      _mm_storeu_si128(DK_out + (10-r),
                       aes_schedule_mangle_dec(key, (10 - r) % 4));
      }

   key = aes_schedule_round(&rcon, key, key);
   _mm_storeu_si128(EK_out + 10, aes_schedule_mangle_last(key, 2));
   _mm_storeu_si128(DK_out, aes_schedule_mangle_last_dec(key));
   }

/*
* Clear memory of sensitive data
*/
void AES_128_SSSE3::clear()
   {
   EK.clear();
   DK.clear();
   }

}

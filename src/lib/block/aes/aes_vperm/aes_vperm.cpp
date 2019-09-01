/*
* AES using vector permutes (SSSE3, NEON)
* (C) 2010,2016,2019 Jack Lloyd
*
* This is more or less a direct translation of public domain x86-64
* assembly written by Mike Hamburg, described in "Accelerating AES
* with Vector Permute Instructions" (CHES 2009). His original code is
* available at https://crypto.stanford.edu/vpaes/
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aes.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/simd_32.h>

#if defined(BOTAN_SIMD_USE_SSE2)
  #include <tmmintrin.h>
#elif defined(BOTAN_SIMD_USE_NEON)
  #include <arm_neon.h>
#endif

namespace Botan {

namespace {

inline SIMD_4x32 shuffle(SIMD_4x32 a, SIMD_4x32 b)
   {
#if defined(BOTAN_SIMD_USE_SSE2)
   return SIMD_4x32(_mm_shuffle_epi8(a.raw(), b.raw()));
#elif defined(BOTAN_SIMD_USE_NEON)
   const uint8x16_t tbl = vreinterpretq_u8_u32(a.raw());
   const uint8x16_t idx = vreinterpretq_u8_u32(b.raw());

#if defined(BOTAN_TARGET_ARCH_IS_ARM32)
   uint8x8x2_t tbl2 = { vget_low_u8(tbl), vget_high_u8(tbl) };

   return SIMD_4x32(vreinterpretq_u32_u8(
                       vcombine_u8(vtbl2_u8(tbl2, vget_low_u8(idx)),
                                   vtbl2_u8(tbl2, vget_high_u8(idx)))));

#else
   return SIMD_4x32(vreinterpretq_u32_u8(vqtbl1q_u8(tbl, idx)));
#endif

#else
   #error "No shuffle implementation available"
#endif
   }

template<size_t I>
inline SIMD_4x32 slli(SIMD_4x32 x)
   {
#if defined(BOTAN_SIMD_USE_SSE2)
   return SIMD_4x32(_mm_slli_si128(x.raw(), 4*I));
#elif defined(BOTAN_SIMD_USE_NEON)
   return SIMD_4x32(vreinterpretq_u32_u8(vextq_u8(vdupq_n_u8(0), vreinterpretq_u8_u32(x.raw()), 16 - 4*I)));
#endif
   }

inline SIMD_4x32 zero_top_half(SIMD_4x32 x)
   {
#if defined(BOTAN_SIMD_USE_SSE2)
   return SIMD_4x32(_mm_slli_si128(_mm_srli_si128(x.raw(), 8), 8));
#elif defined(BOTAN_SIMD_USE_NEON)
   // fixme do better ?
   SIMD_4x32 mask(0, 0, ~0, ~0);
   return x & mask;
#endif
   }

template<int C>
inline SIMD_4x32 alignr(SIMD_4x32 a, SIMD_4x32 b)
   {
#if defined(BOTAN_SIMD_USE_SSE2)
   return SIMD_4x32(_mm_alignr_epi8(a.raw(), b.raw(), C));
#elif defined(BOTAN_SIMD_USE_NEON)
   return SIMD_4x32(vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(b.raw()), vreinterpretq_u8_u32(a.raw()), C)));
#endif
   }

const SIMD_4x32 k_ipt1 = SIMD_4x32(0x5A2A7000, 0xC2B2E898, 0x52227808, 0xCABAE090);
const SIMD_4x32 k_ipt2 = SIMD_4x32(0x317C4D00, 0x4C01307D, 0xB0FDCC81, 0xCD80B1FC);

const SIMD_4x32 k_inv1 = SIMD_4x32(0x0D080180, 0x0E05060F, 0x0A0B0C02, 0x04070309);
const SIMD_4x32 k_inv2 = SIMD_4x32(0x0F0B0780, 0x01040A06, 0x02050809, 0x030D0E0C);

const SIMD_4x32 sb1u = SIMD_4x32(0xCB503E00, 0xB19BE18F, 0x142AF544, 0xA5DF7A6E);
const SIMD_4x32 sb1t = SIMD_4x32(0xFAE22300, 0x3618D415, 0x0D2ED9EF, 0x3BF7CCC1);

const SIMD_4x32 mc_forward[4] = {
   SIMD_4x32(0x00030201, 0x04070605, 0x080B0A09, 0x0C0F0E0D),
   SIMD_4x32(0x04070605, 0x080B0A09, 0x0C0F0E0D, 0x00030201),
   SIMD_4x32(0x080B0A09, 0x0C0F0E0D, 0x00030201, 0x04070605),
   SIMD_4x32(0x0C0F0E0D, 0x00030201, 0x04070605, 0x080B0A09)
};

const SIMD_4x32 sr[4] = {
   SIMD_4x32(0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C),
   SIMD_4x32(0x0F0A0500, 0x030E0904, 0x07020D08, 0x0B06010C),
   SIMD_4x32(0x0B020900, 0x0F060D04, 0x030A0108, 0x070E050C),
   SIMD_4x32(0x070A0D00, 0x0B0E0104, 0x0F020508, 0x0306090C),
};

const SIMD_4x32 lo_nibs_mask = SIMD_4x32::splat_u8(0x0F);
const SIMD_4x32 hi_nibs_mask = SIMD_4x32::splat_u8(0xF0);

const SIMD_4x32 shuffle3333 = SIMD_4x32::splat(0x0F0E0D0C);

inline SIMD_4x32 low_nibs(SIMD_4x32 x)
   {
   return lo_nibs_mask & x;
   }

inline SIMD_4x32 high_nibs(SIMD_4x32 x)
   {
   return (hi_nibs_mask & x).shr<4>();
   }

SIMD_4x32 aes_vperm_encrypt(SIMD_4x32 B, const uint32_t* keys, size_t rounds)
   {
   const SIMD_4x32 sb2u = SIMD_4x32(0x0B712400, 0xE27A93C6, 0xBC982FCD, 0x5EB7E955);
   const SIMD_4x32 sb2t = SIMD_4x32(0x0AE12900, 0x69EB8840, 0xAB82234A, 0xC2A163C8);

   const SIMD_4x32 sbou = SIMD_4x32(0x6FBDC700, 0xD0D26D17, 0xC502A878, 0x15AABF7A);
   const SIMD_4x32 sbot = SIMD_4x32(0x5FBB6A00, 0xCFE474A5, 0x412B35FA, 0x8E1E90D1);

   const SIMD_4x32 mc_backward[4] = {
      SIMD_4x32(0x02010003, 0x06050407, 0x0A09080B, 0x0E0D0C0F),
      SIMD_4x32(0x0E0D0C0F, 0x02010003, 0x06050407, 0x0A09080B),
      SIMD_4x32(0x0A09080B, 0x0E0D0C0F, 0x02010003, 0x06050407),
      SIMD_4x32(0x06050407, 0x0A09080B, 0x0E0D0C0F, 0x02010003),
   };

   B = shuffle(k_ipt1, low_nibs(B)) ^ shuffle(k_ipt2, high_nibs(B)) ^ SIMD_4x32(&keys[0]);

   for(size_t r = 1; ; ++r)
      {
      const SIMD_4x32 K(&keys[4*r]);

      SIMD_4x32 t = high_nibs(B);
      B = low_nibs(B);

      SIMD_4x32 t2 = shuffle(k_inv2, B);

      B ^= t;

      SIMD_4x32 t3 = t2 ^ shuffle(k_inv1, t);
      SIMD_4x32 t4 = t2 ^ shuffle(k_inv1, B);

      SIMD_4x32 t5 = B ^ shuffle(k_inv1, t3);
      SIMD_4x32 t6 = t ^ shuffle(k_inv1, t4);

      if(r == rounds)
         {
         return shuffle(shuffle(sbou, t5) ^ shuffle(sbot, t6) ^ K, sr[r % 4]);
         }

      SIMD_4x32 t7 = shuffle(sb1t, t6) ^ shuffle(sb1u, t5) ^ K;

      SIMD_4x32 t8 = shuffle(sb2t, t6) ^ shuffle(sb2u, t5) ^ shuffle(t7, mc_forward[r % 4]);

      B = shuffle(t8, mc_forward[r % 4]) ^ shuffle(t7, mc_backward[r % 4]) ^ t8;
      }
   }

SIMD_4x32 aes_vperm_decrypt(SIMD_4x32 B, const uint32_t keys[], size_t rounds)
   {
   const SIMD_4x32 k_dipt1 = SIMD_4x32(0x0B545F00, 0x0F505B04, 0x114E451A, 0x154A411E);
   const SIMD_4x32 k_dipt2 = SIMD_4x32(0x60056500, 0x86E383E6, 0xF491F194, 0x12771772);

   const SIMD_4x32 sb9u = SIMD_4x32(0x9A86D600, 0x851C0353, 0x4F994CC9, 0xCAD51F50);
   const SIMD_4x32 sb9t = SIMD_4x32(0xECD74900, 0xC03B1789, 0xB2FBA565, 0x725E2C9E);

   const SIMD_4x32 sbeu = SIMD_4x32(0x26D4D000, 0x46F29296, 0x64B4F6B0, 0x22426004);
   const SIMD_4x32 sbet = SIMD_4x32(0xFFAAC100, 0x0C55A6CD, 0x98593E32, 0x9467F36B);

   const SIMD_4x32 sbdu = SIMD_4x32(0xE6B1A200, 0x7D57CCDF, 0x882A4439, 0xF56E9B13);
   const SIMD_4x32 sbdt = SIMD_4x32(0x24C6CB00, 0x3CE2FAF7, 0x15DEEFD3, 0x2931180D);

   const SIMD_4x32 sbbu = SIMD_4x32(0x96B44200, 0xD0226492, 0xB0F2D404, 0x602646F6);
   const SIMD_4x32 sbbt = SIMD_4x32(0xCD596700, 0xC19498A6, 0x3255AA6B, 0xF3FF0C3E);

   const SIMD_4x32 sbou = SIMD_4x32(0x7EF94000, 0x1387EA53, 0xD4943E2D, 0xC7AA6DB9);
   const SIMD_4x32 sbot = SIMD_4x32(0x93441D00, 0x12D7560F, 0xD8C58E9C, 0xCA4B8159);

   SIMD_4x32 mc(mc_forward[3]);

   B = shuffle(k_dipt1, low_nibs(B)) ^ shuffle(k_dipt2, high_nibs(B)) ^ SIMD_4x32(&keys[0]);

   for(size_t r = 1; ; ++r)
      {
      const SIMD_4x32 K(&keys[4*r]);

      SIMD_4x32 t = high_nibs(B);
      B = low_nibs(B);

      SIMD_4x32 t2 = shuffle(k_inv2, B);

      B ^= t;

      const SIMD_4x32 t3 = t2 ^ shuffle(k_inv1, t);
      const SIMD_4x32 t4 = t2 ^ shuffle(k_inv1, B);
      const SIMD_4x32 t5 = B ^ shuffle(k_inv1, t3);
      const SIMD_4x32 t6 = t ^ shuffle(k_inv1, t4);

      if(r == rounds)
         {
         const SIMD_4x32 x = shuffle(sbou, t5) ^ shuffle(sbot, t6) ^ K;
         const uint32_t which_sr = ((((rounds - 1) << 4) ^ 48) & 48) / 16;
         return shuffle(x, sr[which_sr]);
         }

      const SIMD_4x32 t8 = shuffle(sb9t, t6) ^ shuffle(sb9u, t5) ^ K;
      const SIMD_4x32 t9 = shuffle(t8, mc) ^ shuffle(sbdu, t5) ^ shuffle(sbdt, t6);
      const SIMD_4x32 t12 = shuffle(t9, mc) ^ shuffle(sbbu, t5) ^ shuffle(sbbt, t6);

      B = shuffle(t12, mc) ^ shuffle(sbeu, t5) ^ shuffle(sbet, t6);

      mc = alignr<12>(mc, mc);
      }
   }

void vperm_encrypt_blocks(const uint8_t in[], uint8_t out[], size_t blocks,
                          const uint32_t keys[], size_t rounds)
   {
   CT::poison(in, blocks * 16);

   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks; ++i)
      {
      SIMD_4x32 B = SIMD_4x32::load_le(in + i*16); // ???
      B = aes_vperm_encrypt(B, keys, rounds);
      B.store_le(out + i*16);
      }

   CT::unpoison(in,  blocks * 16);
   CT::unpoison(out, blocks * 16);
   }

void vperm_decrypt_blocks(const uint8_t in[], uint8_t out[], size_t blocks,
                          const uint32_t keys[], size_t rounds)
   {
   CT::poison(in, blocks * 16);

   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks; ++i)
      {
      SIMD_4x32 B = SIMD_4x32::load_le(in + i*16); // ???
      B = aes_vperm_decrypt(B, keys, rounds);
      B.store_le(out + i*16);
      }

   CT::unpoison(in,  blocks * 16);
   CT::unpoison(out, blocks * 16);
   }

}

void AES_128::vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   vperm_encrypt_blocks(in, out, blocks, m_EK.data(), 10);
   }

void AES_128::vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   vperm_decrypt_blocks(in, out, blocks, m_DK.data(), 10);
   }

void AES_192::vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   vperm_encrypt_blocks(in, out, blocks, m_EK.data(), 12);
   }

void AES_192::vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   vperm_decrypt_blocks(in, out, blocks, m_DK.data(), 12);
   }

void AES_256::vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   vperm_encrypt_blocks(in, out, blocks, m_EK.data(), 14);
   }

void AES_256::vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   vperm_decrypt_blocks(in, out, blocks, m_DK.data(), 14);
   }

namespace {

SIMD_4x32 aes_schedule_transform(SIMD_4x32 input,
                                 SIMD_4x32 table_1,
                                 SIMD_4x32 table_2)
   {
   return shuffle(table_1, low_nibs(input)) ^ shuffle(table_2, high_nibs(input));
   }

SIMD_4x32 aes_schedule_mangle(SIMD_4x32 k, uint8_t round_no)
   {
   const SIMD_4x32 mc_forward0(0x00030201, 0x04070605, 0x080B0A09, 0x0C0F0E0D);
   const SIMD_4x32 srx(sr[round_no % 4]);

   SIMD_4x32 t = shuffle(k ^ SIMD_4x32::splat_u8(0x5B), mc_forward0);
   SIMD_4x32 t2 = t;
   t = shuffle(t, mc_forward0);
   t2 = t ^ t2 ^ shuffle(t, mc_forward0);
   return shuffle(t2, srx);
   }

SIMD_4x32 aes_schedule_mangle_dec(SIMD_4x32 k, uint8_t round_no)
   {
   const SIMD_4x32 mc_forward0(0x00030201, 0x04070605, 0x080B0A09, 0x0C0F0E0D);

   const SIMD_4x32 dsk[8] = {
      SIMD_4x32(0x7ED9A700, 0xB6116FC8, 0x82255BFC, 0x4AED9334),
      SIMD_4x32(0x27143300, 0x45765162, 0xE9DAFDCE, 0x8BB89FAC),
      SIMD_4x32(0xCCA86400, 0x27438FEB, 0xADC90561, 0x4622EE8A),
      SIMD_4x32(0x4F92DD00, 0x815C13CE, 0xBD602FF2, 0x73AEE13C),
      SIMD_4x32(0x01C6C700, 0x03C4C502, 0xFA3D3CFB, 0xF83F3EF9),
      SIMD_4x32(0x38CFF700, 0xEE1921D6, 0x7384BC4B, 0xA5526A9D),
      SIMD_4x32(0x53732000, 0xE3C390B0, 0x10306343, 0xA080D3F3),
      SIMD_4x32(0x036982E8, 0xA0CA214B, 0x8CE60D67, 0x2F45AEC4),
   };

   SIMD_4x32 t = aes_schedule_transform(k, dsk[0], dsk[1]);
   SIMD_4x32 output = shuffle(t, mc_forward0);

   t = aes_schedule_transform(t, dsk[2], dsk[3]);
   output = shuffle(t ^ output, mc_forward0);

   t = aes_schedule_transform(t, dsk[4], dsk[5]);
   output = shuffle(t ^ output, mc_forward0);

   t = aes_schedule_transform(t, dsk[6], dsk[7]);
   output = shuffle(t ^ output, mc_forward0);

   return shuffle(output, sr[round_no % 4]);
   }

SIMD_4x32 aes_schedule_mangle_last(SIMD_4x32 k, uint8_t round_no)
   {
   const SIMD_4x32 out_tr1(0xD6B66000, 0xFF9F4929, 0xDEBE6808, 0xF7974121);
   const SIMD_4x32 out_tr2(0x50BCEC00, 0x01EDBD51, 0xB05C0CE0, 0xE10D5DB1);

   k = shuffle(k, sr[round_no % 4]);
   k ^= SIMD_4x32::splat_u8(0x5B);
   return aes_schedule_transform(k, out_tr1, out_tr2);
   }

SIMD_4x32 aes_schedule_mangle_last_dec(SIMD_4x32 k)
   {
   const SIMD_4x32 deskew1(0x47A4E300, 0x07E4A340, 0x5DBEF91A, 0x1DFEB95A);
   const SIMD_4x32 deskew2(0x83EA6900, 0x5F36B5DC, 0xF49D1E77, 0x2841C2AB);

   k ^= SIMD_4x32::splat_u8(0x5B);
   return aes_schedule_transform(k, deskew1, deskew2);
   }

SIMD_4x32 aes_schedule_round(SIMD_4x32 input1, SIMD_4x32 input2)
   {
   SIMD_4x32 smeared = input2 ^ slli<1>(input2);
   smeared ^= slli<2>(smeared);
   smeared ^= SIMD_4x32::splat_u8(0x5B);

   SIMD_4x32 t = high_nibs(input1);
   input1 = low_nibs(input1);

   SIMD_4x32 t2 = shuffle(k_inv2, input1);

   input1 ^= t;

   SIMD_4x32 t3 = t2 ^ shuffle(k_inv1, t);
   SIMD_4x32 t4 = t2 ^ shuffle(k_inv1, input1);

   SIMD_4x32 t5 = input1 ^ shuffle(k_inv1, t3);
   SIMD_4x32 t6 = t ^ shuffle(k_inv1, t4);

   return smeared ^ shuffle(sb1u, t5) ^ shuffle(sb1t, t6);
   }

SIMD_4x32 aes_schedule_round(SIMD_4x32& rcon, SIMD_4x32 input1, SIMD_4x32 input2)
   {
   input2 ^= alignr<15>(SIMD_4x32(), rcon);
   rcon = alignr<15>(rcon, rcon);
   input1 = shuffle(input1, shuffle3333);
   input1 = alignr<1>(input1, input1);

   return aes_schedule_round(input1, input2);
   }

SIMD_4x32 aes_schedule_192_smear(SIMD_4x32 x, SIMD_4x32 y)
   {
   const SIMD_4x32 shuffle3332 =
      SIMD_4x32(0x0B0A0908, 0x0F0E0D0C, 0x0F0E0D0C, 0x0F0E0D0C);
   const SIMD_4x32 shuffle2000 =
      SIMD_4x32(0x03020100, 0x03020100, 0x03020100, 0x0B0A0908);
   return y ^ shuffle(x, shuffle3332) ^ shuffle(y, shuffle2000);
   }

}

void AES_128::vperm_key_schedule(const uint8_t keyb[], size_t)
   {
   m_EK.resize(11*4);
   m_DK.resize(11*4);

   SIMD_4x32 rcon(0xAF9DEEB6, 0x1F8391B9, 0x4D7C7D81, 0x702A9808);

   SIMD_4x32 key = SIMD_4x32::load_le(keyb);

   shuffle(key, sr[2]).store_le(&m_DK[4*10]);

   key = aes_schedule_transform(key, k_ipt1, k_ipt2);
   key.store_le(&m_EK[0]);

   for(size_t i = 1; i != 10; ++i)
      {
      key = aes_schedule_round(rcon, key, key);

      aes_schedule_mangle(key, (12-i) % 4).store_le(&m_EK[4*i]);

      aes_schedule_mangle_dec(key, (10-i)%4).store_le(&m_DK[4*(10-i)]);
      }

   key = aes_schedule_round(rcon, key, key);
   aes_schedule_mangle_last(key, 2).store_le(&m_EK[4*10]);
   aes_schedule_mangle_last_dec(key).store_le(&m_DK[0]);
   }

void AES_192::vperm_key_schedule(const uint8_t keyb[], size_t)
   {
   m_EK.resize(13*4);
   m_DK.resize(13*4);

   SIMD_4x32 rcon(0xAF9DEEB6, 0x1F8391B9, 0x4D7C7D81, 0x702A9808);

   SIMD_4x32 key1 = SIMD_4x32::load_le(keyb);
   SIMD_4x32 key2 = SIMD_4x32::load_le(keyb + 8);

   shuffle(key1, sr[0]).store_le(&m_DK[12*4]);

   key1 = aes_schedule_transform(key1, k_ipt1, k_ipt2);
   key2 = aes_schedule_transform(key2, k_ipt1, k_ipt2);

   key1.store_le(&m_EK[0]);

   for(size_t i = 0; i != 4; ++i)
      {
      // key2 with 8 high bytes masked off
      SIMD_4x32 t = zero_top_half(key2);
      key2 = aes_schedule_round(rcon, key2, key1);

      // fixme cse
      aes_schedule_mangle(alignr<8>(key2, t), (i+3)%4).store_le(&m_EK[4*(3*i+1)]);
      aes_schedule_mangle_dec(alignr<8>(key2, t), (i+3)%4).store_le(&m_DK[4*(11-3*i)]);

      t = aes_schedule_192_smear(key2, t);

      aes_schedule_mangle(t, (i+2)%4).store_le(&m_EK[4*(3*i+2)]);
      aes_schedule_mangle_dec(t, (i+2)%4).store_le(&m_DK[4*(10-3*i)]);

      key2 = aes_schedule_round(rcon, t, key2);

      if(i == 3)
         {
         aes_schedule_mangle_last(key2, (i+1)%4).store_le(&m_EK[4*(3*i+3)]);
         aes_schedule_mangle_last_dec(key2).store_le(&m_DK[4*(9-3*i)]);
         }
      else
         {
         aes_schedule_mangle(key2, (i+1)%4).store_le(&m_EK[4*(3*i+3)]);
         aes_schedule_mangle_dec(key2, (i+1)%4).store_le(&m_DK[4*(9-3*i)]);
         }

      key1 = key2;
      key2 = aes_schedule_192_smear(key2, zero_top_half(t));
      }
   }

void AES_256::vperm_key_schedule(const uint8_t keyb[], size_t)
   {
   m_EK.resize(15*4);
   m_DK.resize(15*4);

   SIMD_4x32 rcon(0xAF9DEEB6, 0x1F8391B9, 0x4D7C7D81, 0x702A9808);

   SIMD_4x32 key1 = SIMD_4x32::load_le(keyb);
   SIMD_4x32 key2 = SIMD_4x32::load_le(keyb + 16);

   shuffle(key1, sr[2]).store_le(&m_DK[4*14]);

   key1 = aes_schedule_transform(key1, k_ipt1, k_ipt2);
   key2 = aes_schedule_transform(key2, k_ipt1, k_ipt2);

   key1.store_le(&m_EK[0]);
   aes_schedule_mangle(key2, 3).store_le(&m_EK[4]);

   aes_schedule_mangle_dec(key2, 1).store_le(&m_DK[4*13]);

   for(size_t i = 2; i != 14; i += 2)
      {
      const SIMD_4x32 k_t = key2;
      key1 = key2 = aes_schedule_round(rcon, key2, key1);

      aes_schedule_mangle(key2, i % 4).store_le(&m_EK[4*i]);
      aes_schedule_mangle_dec(key2, (i+2)%4).store_le(&m_DK[4*(14-i)]);

      key2 = aes_schedule_round(shuffle(key2, shuffle3333), k_t);

      aes_schedule_mangle(key2, (i-1)%4).store_le(&m_EK[4*(i+1)]);
      aes_schedule_mangle_dec(key2, (i+1)%4).store_le(&m_DK[4*(13-i)]);
      }

   key2 = aes_schedule_round(rcon, key2, key1);

   aes_schedule_mangle_last(key2, 2).store_le(&m_EK[4*14]);
   aes_schedule_mangle_last_dec(key2).store_le(&m_DK[0]);
   }

}

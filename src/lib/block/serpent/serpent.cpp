/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/serpent.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/serpent_sbox.h>

#if defined(BOTAN_HAS_SERPENT_SIMD) || defined(BOTAN_HAS_SERPENT_AVX2) || defined(BOTAN_HAS_SERPENT_AVX512)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

/*
* Serpent Encryption
*/
void Serpent::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   using namespace Botan::Serpent_F;

   assert_key_material_set();

#if defined(BOTAN_HAS_SERPENT_AVX512)
   if(CPUID::has_avx512()) {
      while(blocks >= 16) {
         avx512_encrypt_16(in, out);
         in += 16 * BLOCK_SIZE;
         out += 16 * BLOCK_SIZE;
         blocks -= 16;
      }
   }
#endif

#if defined(BOTAN_HAS_SERPENT_AVX2)
   if(CPUID::has_avx2()) {
      while(blocks >= 8) {
         avx2_encrypt_8(in, out);
         in += 8 * BLOCK_SIZE;
         out += 8 * BLOCK_SIZE;
         blocks -= 8;
      }
   }
#endif

#if defined(BOTAN_HAS_SERPENT_SIMD)
   if(CPUID::has_simd_32()) {
      while(blocks >= 4) {
         simd_encrypt_4(in, out);
         in += 4 * BLOCK_SIZE;
         out += 4 * BLOCK_SIZE;
         blocks -= 4;
      }
   }
#endif

   const Key_Inserter key_xor(m_round_key.data());

   for(size_t i = 0; i < blocks; ++i) {
      uint32_t B0, B1, B2, B3;
      load_le(in + 16 * i, B0, B1, B2, B3);

      key_xor(0, B0, B1, B2, B3);
      SBoxE0(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(1, B0, B1, B2, B3);
      SBoxE1(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(2, B0, B1, B2, B3);
      SBoxE2(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(3, B0, B1, B2, B3);
      SBoxE3(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(4, B0, B1, B2, B3);
      SBoxE4(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(5, B0, B1, B2, B3);
      SBoxE5(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(6, B0, B1, B2, B3);
      SBoxE6(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(7, B0, B1, B2, B3);
      SBoxE7(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(8, B0, B1, B2, B3);
      SBoxE0(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(9, B0, B1, B2, B3);
      SBoxE1(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(10, B0, B1, B2, B3);
      SBoxE2(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(11, B0, B1, B2, B3);
      SBoxE3(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(12, B0, B1, B2, B3);
      SBoxE4(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(13, B0, B1, B2, B3);
      SBoxE5(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(14, B0, B1, B2, B3);
      SBoxE6(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(15, B0, B1, B2, B3);
      SBoxE7(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(16, B0, B1, B2, B3);
      SBoxE0(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(17, B0, B1, B2, B3);
      SBoxE1(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(18, B0, B1, B2, B3);
      SBoxE2(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(19, B0, B1, B2, B3);
      SBoxE3(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(20, B0, B1, B2, B3);
      SBoxE4(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(21, B0, B1, B2, B3);
      SBoxE5(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(22, B0, B1, B2, B3);
      SBoxE6(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(23, B0, B1, B2, B3);
      SBoxE7(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(24, B0, B1, B2, B3);
      SBoxE0(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(25, B0, B1, B2, B3);
      SBoxE1(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(26, B0, B1, B2, B3);
      SBoxE2(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(27, B0, B1, B2, B3);
      SBoxE3(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(28, B0, B1, B2, B3);
      SBoxE4(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(29, B0, B1, B2, B3);
      SBoxE5(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(30, B0, B1, B2, B3);
      SBoxE6(B0, B1, B2, B3);
      transform(B0, B1, B2, B3);
      key_xor(31, B0, B1, B2, B3);
      SBoxE7(B0, B1, B2, B3);
      key_xor(32, B0, B1, B2, B3);

      store_le(out + 16 * i, B0, B1, B2, B3);
   }
}

/*
* Serpent Decryption
*/
void Serpent::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   using namespace Botan::Serpent_F;

   assert_key_material_set();

#if defined(BOTAN_HAS_SERPENT_AVX512)
   if(CPUID::has_avx512()) {
      while(blocks >= 16) {
         avx512_decrypt_16(in, out);
         in += 16 * BLOCK_SIZE;
         out += 16 * BLOCK_SIZE;
         blocks -= 16;
      }
   }
#endif

#if defined(BOTAN_HAS_SERPENT_AVX2)
   if(CPUID::has_avx2()) {
      while(blocks >= 8) {
         avx2_decrypt_8(in, out);
         in += 8 * BLOCK_SIZE;
         out += 8 * BLOCK_SIZE;
         blocks -= 8;
      }
   }
#endif

#if defined(BOTAN_HAS_SERPENT_SIMD)
   if(CPUID::has_simd_32()) {
      while(blocks >= 4) {
         simd_decrypt_4(in, out);
         in += 4 * BLOCK_SIZE;
         out += 4 * BLOCK_SIZE;
         blocks -= 4;
      }
   }
#endif

   const Key_Inserter key_xor(m_round_key.data());

   for(size_t i = 0; i < blocks; ++i) {
      uint32_t B0, B1, B2, B3;
      load_le(in + 16 * i, B0, B1, B2, B3);

      key_xor(32, B0, B1, B2, B3);
      SBoxD7(B0, B1, B2, B3);
      key_xor(31, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD6(B0, B1, B2, B3);
      key_xor(30, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD5(B0, B1, B2, B3);
      key_xor(29, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD4(B0, B1, B2, B3);
      key_xor(28, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD3(B0, B1, B2, B3);
      key_xor(27, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD2(B0, B1, B2, B3);
      key_xor(26, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD1(B0, B1, B2, B3);
      key_xor(25, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD0(B0, B1, B2, B3);
      key_xor(24, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD7(B0, B1, B2, B3);
      key_xor(23, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD6(B0, B1, B2, B3);
      key_xor(22, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD5(B0, B1, B2, B3);
      key_xor(21, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD4(B0, B1, B2, B3);
      key_xor(20, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD3(B0, B1, B2, B3);
      key_xor(19, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD2(B0, B1, B2, B3);
      key_xor(18, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD1(B0, B1, B2, B3);
      key_xor(17, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD0(B0, B1, B2, B3);
      key_xor(16, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD7(B0, B1, B2, B3);
      key_xor(15, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD6(B0, B1, B2, B3);
      key_xor(14, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD5(B0, B1, B2, B3);
      key_xor(13, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD4(B0, B1, B2, B3);
      key_xor(12, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD3(B0, B1, B2, B3);
      key_xor(11, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD2(B0, B1, B2, B3);
      key_xor(10, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD1(B0, B1, B2, B3);
      key_xor(9, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD0(B0, B1, B2, B3);
      key_xor(8, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD7(B0, B1, B2, B3);
      key_xor(7, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD6(B0, B1, B2, B3);
      key_xor(6, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD5(B0, B1, B2, B3);
      key_xor(5, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD4(B0, B1, B2, B3);
      key_xor(4, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD3(B0, B1, B2, B3);
      key_xor(3, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD2(B0, B1, B2, B3);
      key_xor(2, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD1(B0, B1, B2, B3);
      key_xor(1, B0, B1, B2, B3);
      i_transform(B0, B1, B2, B3);
      SBoxD0(B0, B1, B2, B3);
      key_xor(0, B0, B1, B2, B3);

      store_le(out + 16 * i, B0, B1, B2, B3);
   }
}

bool Serpent::has_keying_material() const {
   return !m_round_key.empty();
}

/*
* Serpent Key Schedule
*/
void Serpent::key_schedule(std::span<const uint8_t> key) {
   using namespace Botan::Serpent_F;

   const uint32_t PHI = 0x9E3779B9;

   secure_vector<uint32_t> W(140);
   for(size_t i = 0; i != key.size() / 4; ++i) {
      W[i] = load_le<uint32_t>(key.data(), i);
   }

   W[key.size() / 4] |= uint32_t(1) << ((key.size() % 4) * 8);

   for(size_t i = 8; i != 140; ++i) {
      uint32_t wi = W[i - 8] ^ W[i - 5] ^ W[i - 3] ^ W[i - 1] ^ PHI ^ uint32_t(i - 8);
      W[i] = rotl<11>(wi);
   }

   SBoxE0(W[20], W[21], W[22], W[23]);
   SBoxE0(W[52], W[53], W[54], W[55]);
   SBoxE0(W[84], W[85], W[86], W[87]);
   SBoxE0(W[116], W[117], W[118], W[119]);

   SBoxE1(W[16], W[17], W[18], W[19]);
   SBoxE1(W[48], W[49], W[50], W[51]);
   SBoxE1(W[80], W[81], W[82], W[83]);
   SBoxE1(W[112], W[113], W[114], W[115]);

   SBoxE2(W[12], W[13], W[14], W[15]);
   SBoxE2(W[44], W[45], W[46], W[47]);
   SBoxE2(W[76], W[77], W[78], W[79]);
   SBoxE2(W[108], W[109], W[110], W[111]);

   SBoxE3(W[8], W[9], W[10], W[11]);
   SBoxE3(W[40], W[41], W[42], W[43]);
   SBoxE3(W[72], W[73], W[74], W[75]);
   SBoxE3(W[104], W[105], W[106], W[107]);
   SBoxE3(W[136], W[137], W[138], W[139]);

   SBoxE4(W[36], W[37], W[38], W[39]);
   SBoxE4(W[68], W[69], W[70], W[71]);
   SBoxE4(W[100], W[101], W[102], W[103]);
   SBoxE4(W[132], W[133], W[134], W[135]);

   SBoxE5(W[32], W[33], W[34], W[35]);
   SBoxE5(W[64], W[65], W[66], W[67]);
   SBoxE5(W[96], W[97], W[98], W[99]);
   SBoxE5(W[128], W[129], W[130], W[131]);

   SBoxE6(W[28], W[29], W[30], W[31]);
   SBoxE6(W[60], W[61], W[62], W[63]);
   SBoxE6(W[92], W[93], W[94], W[95]);
   SBoxE6(W[124], W[125], W[126], W[127]);

   SBoxE7(W[24], W[25], W[26], W[27]);
   SBoxE7(W[56], W[57], W[58], W[59]);
   SBoxE7(W[88], W[89], W[90], W[91]);
   SBoxE7(W[120], W[121], W[122], W[123]);

   m_round_key.assign(W.begin() + 8, W.end());
}

void Serpent::clear() {
   zap(m_round_key);
}

std::string Serpent::provider() const {
#if defined(BOTAN_HAS_SERPENT_AVX512)
   if(CPUID::has_avx512()) {
      return "avx512";
   }
#endif

#if defined(BOTAN_HAS_SERPENT_AVX2)
   if(CPUID::has_avx2()) {
      return "avx2";
   }
#endif

#if defined(BOTAN_HAS_SERPENT_SIMD)
   if(CPUID::has_simd_32()) {
      return "simd";
   }
#endif

   return "base";
}

}  // namespace Botan

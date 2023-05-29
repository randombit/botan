/*
* Serpent (SIMD)
* (C) 2009,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/serpent.h>

#include <botan/internal/serpent_sbox.h>
#include <botan/internal/simd_32.h>

namespace Botan {

/*
* SIMD Serpent Encryption of 4 blocks in parallel
*/
void Serpent::simd_encrypt_4(const uint8_t in[64], uint8_t out[64]) const {
   using namespace Botan::Serpent_F;

   SIMD_4x32 B0 = SIMD_4x32::load_le(in);
   SIMD_4x32 B1 = SIMD_4x32::load_le(in + 16);
   SIMD_4x32 B2 = SIMD_4x32::load_le(in + 32);
   SIMD_4x32 B3 = SIMD_4x32::load_le(in + 48);

   SIMD_4x32::transpose(B0, B1, B2, B3);

   const Key_Inserter key_xor(m_round_key.data());

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

   SIMD_4x32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 16);
   B2.store_le(out + 32);
   B3.store_le(out + 48);
}

/*
* SIMD Serpent Decryption of 4 blocks in parallel
*/
void Serpent::simd_decrypt_4(const uint8_t in[64], uint8_t out[64]) const {
   using namespace Botan::Serpent_F;

   SIMD_4x32 B0 = SIMD_4x32::load_le(in);
   SIMD_4x32 B1 = SIMD_4x32::load_le(in + 16);
   SIMD_4x32 B2 = SIMD_4x32::load_le(in + 32);
   SIMD_4x32 B3 = SIMD_4x32::load_le(in + 48);

   SIMD_4x32::transpose(B0, B1, B2, B3);

   const Key_Inserter key_xor(m_round_key.data());

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

   SIMD_4x32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 16);
   B2.store_le(out + 32);
   B3.store_le(out + 48);
}

}  // namespace Botan

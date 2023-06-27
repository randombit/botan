/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/serpent.h>
#include <botan/internal/serpent_sbox.h>
#include <botan/internal/simd_avx512.h>

namespace Botan {

BOTAN_FORCE_INLINE void SBoxE0(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0xb9>(b, d, c);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0xe2>(a, b, d);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0x36>(a, b, d);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x26>(t0, d, b);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t3);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x96>(t1, c, o0);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0xa9>(o0, o1, t2);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x3c>(t2, c, t0);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxE1(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0xe5>(d, b, c);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x26>(c, d, b);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xa6>(a, b, c);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x2b>(a, b, d);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x83>(t2, d, t0);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x69>(t3, c, o1);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0x65>(o3, o1, t2);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxE2(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x96>(c, b, d);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0xda>(a, b, c);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0x66>(d, t0, c);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x94>(a, b, t0);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0xa1>(a, d, t0);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t2);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0xd2>(t3, d, o0);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x2d>(t4, b, c);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x2d>(t1, d, t2);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxE3(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x92>(d, c, b);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x3b>(d, b, c);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xbc>(a, c, t0);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x68>(t2, d, t1);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x6e>(a, c, o2);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0xb9>(a, d, t3);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x6d>(t4, b, t2);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x38>(t3, b, t0);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxE4(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0xc2>(c, b, d);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x79>(b, c, d);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0x71>(a, b, d);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x6b>(a, b, d);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0xc2>(a, t0, t3);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0x3c>(t2, c, t0);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x49>(t3, c, t0);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0xd6>(t4, b, t1);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxE5(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0xa9>(b, d, c);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x93>(b, c, d);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xc3>(a, b, c);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x27>(a, b, d);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0x85>(a, c, t1);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x2d>(t2, d, o0);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x7a>(t4, b, t0);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x87>(t3, t0, o0);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxE6(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x61>(d, c, b);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x9c>(b, d, t0);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0x93>(a, b, d);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0xb5>(a, b, c);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x3c>(t2, c, t0);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0x7c>(a, b, o1);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x1e>(t4, d, t0);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x29>(t3, t0, t1);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxE7(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x9b>(b, c, d);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x61>(c, b, d);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xe3>(a, d, t1);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x83>(b, c, d);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0x49>(a, b, c);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0xe1>(t2, b, c);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0xd1>(t3, a, t1);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x87>(t4, d, t2);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxD0(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x67>(c, d, b);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x49>(b, d, c);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xa9>(a, b, c);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x3c>(t2, d, t0);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x4d>(a, b, d);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x69>(t3, c, o0);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x56>(o3, o0, t2);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxD1(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x73>(d, b, c);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x68>(c, d, b);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xc5>(a, b, d);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x2d>(a, b, d);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x96>(t2, c, o0);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0xd2>(t3, o0, o1);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x99>(o0, t3, c);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxD2(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0xc6>(d, b, c);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x9c>(d, c, b);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xe1>(a, b, c);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0x87>(t2, d, t0);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0xd1>(t0, a, t1);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x9b>(a, c, o2);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x5b>(t3, b, d);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxD3(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x94>(c, d, b);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x99>(b, d, t0);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0x97>(a, b, d);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x4b>(t2, c, o0);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x94>(c, d, t2);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x0e>(t3, b, t0);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0x1c>(a, b, t0);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0xb4>(t4, c, d);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxD4(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0xa9>(d, c, b);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0xa6>(d, b, c);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xb5>(a, b, d);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x5e>(a, b, d);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0x50>(a, b, t0);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x96>(t4, c, d);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x4b>(t3, c, t4);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x5a>(t2, c, t0);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxD5(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0xc9>(a, b, c);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x65>(a, b, c);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0x25>(a, b, d);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x63>(c, d, t0);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0x86>(a, b, t3);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0x87>(t2, c, t0);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0xc3>(t4, c, d);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x47>(t1, d, t0);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0xac>(a, t0, t3);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxD6(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x07>(d, b, c);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x9e>(c, d, b);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0xc6>(a, b, c);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x34>(a, b, d);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0x2b>(a, c, d);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t1);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0xcb>(t2, d, t0);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0x4b>(t3, c, t0);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x69>(t4, b, o0);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_FORCE_INLINE void SBoxD7(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d) {
   const SIMD_16x32 t0 = SIMD_16x32::ternary_fn<0x67>(b, d, c);
   const SIMD_16x32 t1 = SIMD_16x32::ternary_fn<0x3e>(a, c, d);
   const SIMD_16x32 t2 = SIMD_16x32::ternary_fn<0x1c>(a, b, d);
   const SIMD_16x32 t3 = SIMD_16x32::ternary_fn<0x87>(t0, d, b);
   const SIMD_16x32 t4 = SIMD_16x32::ternary_fn<0x7d>(a, b, t1);
   const SIMD_16x32 o0 = SIMD_16x32::ternary_fn<0xac>(a, t0, t3);
   const SIMD_16x32 o1 = SIMD_16x32::ternary_fn<0x96>(t1, b, t0);
   const SIMD_16x32 o2 = SIMD_16x32::ternary_fn<0xd2>(t2, c, t1);
   const SIMD_16x32 o3 = SIMD_16x32::ternary_fn<0x6d>(t4, c, d);
   a = o0;
   b = o1;
   c = o2;
   d = o3;
}

BOTAN_AVX512_FN
void Serpent::avx512_encrypt_16(const uint8_t in[16 * 16], uint8_t out[16 * 16]) const {
   using namespace Botan::Serpent_F;

   SIMD_16x32 B0 = SIMD_16x32::load_le(in);
   SIMD_16x32 B1 = SIMD_16x32::load_le(in + 64);
   SIMD_16x32 B2 = SIMD_16x32::load_le(in + 128);
   SIMD_16x32 B3 = SIMD_16x32::load_le(in + 192);

   SIMD_16x32::transpose(B0, B1, B2, B3);

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

   SIMD_16x32::transpose(B0, B1, B2, B3);
   B0.store_le(out);
   B1.store_le(out + 64);
   B2.store_le(out + 128);
   B3.store_le(out + 192);

   SIMD_16x32::zero_registers();
}

BOTAN_AVX512_FN
void Serpent::avx512_decrypt_16(const uint8_t in[16 * 16], uint8_t out[16 * 16]) const {
   using namespace Botan::Serpent_F;

   SIMD_16x32 B0 = SIMD_16x32::load_le(in);
   SIMD_16x32 B1 = SIMD_16x32::load_le(in + 64);
   SIMD_16x32 B2 = SIMD_16x32::load_le(in + 128);
   SIMD_16x32 B3 = SIMD_16x32::load_le(in + 192);

   SIMD_16x32::transpose(B0, B1, B2, B3);

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

   SIMD_16x32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 64);
   B2.store_le(out + 128);
   B3.store_le(out + 192);

   SIMD_16x32::zero_registers();
}

}  // namespace Botan

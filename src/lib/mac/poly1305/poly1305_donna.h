/*
* Derived from poly1305-donna-64.h by Andrew Moon <liquidsun@gmail.com>
* in https://github.com/floodyberry/poly1305-donna
*
* (C) 2014 Andrew Moon
* (C) 2014 Jack Lloyd
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_POLY1305_DONNA_H__
#define BOTAN_POLY1305_DONNA_H__

#include <botan/loadstor.h>
#include <botan/mul128.h>

#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
  #include <botan/internal/donna128.h>
#endif

namespace Botan {

namespace {

#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
typedef donna128 uint128_t;
#else
inline u64bit carry_shift(const uint128_t a, size_t shift)
   {
   return static_cast<u64bit>(a >> shift);
   }
#endif

void poly1305_init(secure_vector<u64bit>& X, const byte key[32])
   {
   /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
   const u64bit t0 = load_le<u64bit>(key, 0);
   const u64bit t1 = load_le<u64bit>(key, 1);

   X[0] = ( t0                    ) & 0xffc0fffffff;
   X[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
   X[2] = ((t1 >> 24)             ) & 0x00ffffffc0f;

   /* h = 0 */
   X[3] = 0;
   X[4] = 0;
   X[5] = 0;

   /* save pad for later */
   X[6] = load_le<u64bit>(key, 2);
   X[7] = load_le<u64bit>(key, 3);
   }

void poly1305_blocks(secure_vector<u64bit>& X, const byte *m, size_t blocks, bool is_final = false)
   {
   const u64bit hibit = is_final ? 0 : (static_cast<u64bit>(1) << 40); /* 1 << 128 */
   //u64bit c;

   const u64bit r0 = X[0];
   const u64bit r1 = X[1];
   const u64bit r2 = X[2];

   u64bit h0 = X[3+0];
   u64bit h1 = X[3+1];
   u64bit h2 = X[3+2];

   const u64bit s1 = r1 * (5 << 2);
   const u64bit s2 = r2 * (5 << 2);

   while(blocks--)
      {
      /* h += m[i] */
      const u64bit t0 = load_le<u64bit>(m, 0);
      const u64bit t1 = load_le<u64bit>(m, 1);

      h0 += (( t0                    ) & 0xfffffffffff);
      h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
      h2 += (((t1 >> 24)             ) & 0x3ffffffffff) | hibit;

      /* h *= r */
      uint128_t d0 = uint128_t(h0) * r0 + uint128_t(h1) * s2 + uint128_t(h2) * s1;
      uint128_t d1 = uint128_t(h0) * r1 + uint128_t(h1) * r0 + uint128_t(h2) * s2;
      uint128_t d2 = uint128_t(h0) * r2 + uint128_t(h1) * r1 + uint128_t(h2) * r0;

      /* (partial) h %= p */
      u64bit        c = carry_shift(d0, 44); h0 = d0 & 0xfffffffffff;
      d1 += c;      c = carry_shift(d1, 44); h1 = d1 & 0xfffffffffff;
      d2 += c;      c = carry_shift(d2, 42); h2 = d2 & 0x3ffffffffff;
      h0  += c * 5; c = carry_shift(h0, 44); h0 = h0 & 0xfffffffffff;
      h1  += c;

      m += 16;
      }

   X[3+0] = h0;
   X[3+1] = h1;
   X[3+2] = h2;
   }

void poly1305_finish(secure_vector<u64bit>& X, byte mac[16])
   {
   /* fully carry h */
   u64bit h0 = X[3+0];
   u64bit h1 = X[3+1];
   u64bit h2 = X[3+2];

   u64bit c;
                c = (h1 >> 44); h1 &= 0xfffffffffff;
   h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
   h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
   h1 += c;     c = (h1 >> 44); h1 &= 0xfffffffffff;
   h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
   h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
   h1 += c;

   /* compute h + -p */
   u64bit g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
   u64bit g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
   u64bit g2 = h2 + c - ((u64bit)1 << 42);

   /* select h if h < p, or h + -p if h >= p */
   c = (g2 >> ((sizeof(u64bit) * 8) - 1)) - 1;
   g0 &= c;
   g1 &= c;
   g2 &= c;
   c = ~c;
   h0 = (h0 & c) | g0;
   h1 = (h1 & c) | g1;
   h2 = (h2 & c) | g2;

   /* h = (h + pad) */
   const u64bit t0 = X[6];
   const u64bit t1 = X[7];

   h0 += (( t0                    ) & 0xfffffffffff)    ; c = (h0 >> 44); h0 &= 0xfffffffffff;
   h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h1 >> 44); h1 &= 0xfffffffffff;
   h2 += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                 h2 &= 0x3ffffffffff;

   /* mac = h % (2^128) */
   h0 = ((h0      ) | (h1 << 44));
   h1 = ((h1 >> 20) | (h2 << 24));

   store_le(&mac[0], h0, h1);

   /* zero out the state */
   zero_mem(&X[0], X.size());
   }

}

}

#endif

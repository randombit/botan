/*
* Based on curve25519-donna-c64.c from github.com/agl/curve25519-donna
* revision 80ad9b9930c9baef5829dd2a235b6b7646d32a8e
*
* Further changes
* (C) 2014,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/* Copyright 2008, Google Inc.
* All rights reserved.
*
* Code released into the public domain.
*
* curve25519-donna: Curve25519 elliptic curve, public key function
*
* https://code.google.com/p/curve25519-donna/
*
* Adam Langley <agl@imperialviolet.org>
*
* Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
*
* More information about curve25519 can be found here
*   https://cr.yp.to/ecdh.html
*
* djb's sample implementation of curve25519 is written in a special assembly
* language called qhasm and uses the floating point registers.
*
* This is, almost, a clean room reimplementation from the curve25519 paper. It
* uses many of the tricks described therein. Only the crecip function is taken
* from the sample implementation.
*/

#include <botan/curve25519.h>
#include <botan/mul128.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/donna128.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
typedef donna128 uint128_t;
#endif

/* Sum two numbers: output += in */
inline void fsum(uint64_t out[5], const uint64_t in[5])
   {
   out[0] += in[0];
   out[1] += in[1];
   out[2] += in[2];
   out[3] += in[3];
   out[4] += in[4];
   }

/* Find the difference of two numbers: out = in - out
* (note the order of the arguments!)
*
* Assumes that out[i] < 2**52
* On return, out[i] < 2**55
*/
inline void fdifference_backwards(uint64_t out[5], const uint64_t in[5])
   {
   /* 152 is 19 << 3 */
   const uint64_t two54m152 = (static_cast<uint64_t>(1) << 54) - 152;
   const uint64_t two54m8   = (static_cast<uint64_t>(1) << 54) - 8;

   out[0] = in[0] + two54m152 - out[0];
   out[1] = in[1] + two54m8 - out[1];
   out[2] = in[2] + two54m8 - out[2];
   out[3] = in[3] + two54m8 - out[3];
   out[4] = in[4] + two54m8 - out[4];
   }

inline void fadd_sub(uint64_t x[5],
                     uint64_t y[5])
   {
   // TODO merge these and avoid the tmp array
   uint64_t tmp[5];
   copy_mem(tmp, y, 5);
   fsum(y, x);
   fdifference_backwards(x, tmp);  // does x - z
   }

/* Multiply a number by a scalar: out = in * scalar */
inline void fscalar_product(uint64_t out[5], const uint64_t in[5], const uint64_t scalar)
   {
   uint128_t a = uint128_t(in[0]) * scalar;
   out[0] = a & 0x7ffffffffffff;

   a = uint128_t(in[1]) * scalar + carry_shift(a, 51);
   out[1] = a & 0x7ffffffffffff;

   a = uint128_t(in[2]) * scalar + carry_shift(a, 51);
   out[2] = a & 0x7ffffffffffff;

   a = uint128_t(in[3]) * scalar + carry_shift(a, 51);
   out[3] = a & 0x7ffffffffffff;

   a = uint128_t(in[4]) * scalar + carry_shift(a, 51);
   out[4] = a & 0x7ffffffffffff;

   out[0] += carry_shift(a, 51) * 19;
   }

/* Multiply two numbers: out = in2 * in
*
* out must be distinct to both inputs. The inputs are reduced coefficient
* form, the output is not.
*
* Assumes that in[i] < 2**55 and likewise for in2.
* On return, out[i] < 2**52
*/
inline void fmul(uint64_t out[5], const uint64_t in[5], const uint64_t in2[5])
   {
   const uint128_t s0 = in2[0];
   const uint128_t s1 = in2[1];
   const uint128_t s2 = in2[2];
   const uint128_t s3 = in2[3];
   const uint128_t s4 = in2[4];

   uint64_t r0 = in[0];
   uint64_t r1 = in[1];
   uint64_t r2 = in[2];
   uint64_t r3 = in[3];
   uint64_t r4 = in[4];

   uint128_t t0 = r0 * s0;
   uint128_t t1 = r0 * s1 + r1 * s0;
   uint128_t t2 = r0 * s2 + r2 * s0 + r1 * s1;
   uint128_t t3 = r0 * s3 + r3 * s0 + r1 * s2 + r2 * s1;
   uint128_t t4 = r0 * s4 + r4 * s0 + r3 * s1 + r1 * s3 + r2 * s2;

   r4 *= 19;
   r1 *= 19;
   r2 *= 19;
   r3 *= 19;

   t0 += r4 * s1 + r1 * s4 + r2 * s3 + r3 * s2;
   t1 += r4 * s2 + r2 * s4 + r3 * s3;
   t2 += r4 * s3 + r3 * s4;
   t3 += r4 * s4;

   r0 = t0 & 0x7ffffffffffff; t1 += carry_shift(t0, 51);
   r1 = t1 & 0x7ffffffffffff; t2 += carry_shift(t1, 51);
   r2 = t2 & 0x7ffffffffffff; t3 += carry_shift(t2, 51);
   r3 = t3 & 0x7ffffffffffff; t4 += carry_shift(t3, 51);
   r4 = t4 & 0x7ffffffffffff; uint64_t c = carry_shift(t4, 51);

   r0 += c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
   r1 += c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
   r2 += c;

   out[0] = r0;
   out[1] = r1;
   out[2] = r2;
   out[3] = r3;
   out[4] = r4;
   }

inline void fsquare(uint64_t out[5], const uint64_t in[5], size_t count = 1)
   {
   uint64_t r0 = in[0];
   uint64_t r1 = in[1];
   uint64_t r2 = in[2];
   uint64_t r3 = in[3];
   uint64_t r4 = in[4];

   for(size_t i = 0; i != count; ++i)
      {
      const uint64_t d0 = r0 * 2;
      const uint64_t d1 = r1 * 2;
      const uint64_t d2 = r2 * 2 * 19;
      const uint64_t d419 = r4 * 19;
      const uint64_t d4 = d419 * 2;

      uint128_t t0 = uint128_t(r0) * r0 + uint128_t(d4) * r1 + uint128_t(d2) * (r3     );
      uint128_t t1 = uint128_t(d0) * r1 + uint128_t(d4) * r2 + uint128_t(r3) * (r3 * 19);
      uint128_t t2 = uint128_t(d0) * r2 + uint128_t(r1) * r1 + uint128_t(d4) * (r3     );
      uint128_t t3 = uint128_t(d0) * r3 + uint128_t(d1) * r2 + uint128_t(r4) * (d419   );
      uint128_t t4 = uint128_t(d0) * r4 + uint128_t(d1) * r3 + uint128_t(r2) * (r2     );

      r0 = t0 & 0x7ffffffffffff; t1 += carry_shift(t0, 51);
      r1 = t1 & 0x7ffffffffffff; t2 += carry_shift(t1, 51);
      r2 = t2 & 0x7ffffffffffff; t3 += carry_shift(t2, 51);
      r3 = t3 & 0x7ffffffffffff; t4 += carry_shift(t3, 51);
      r4 = t4 & 0x7ffffffffffff; uint64_t c = carry_shift(t4, 51);

      r0 += c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
      r1 += c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
      r2 += c;
      }

   out[0] = r0;
   out[1] = r1;
   out[2] = r2;
   out[3] = r3;
   out[4] = r4;
   }

/* Take a little-endian, 32-byte number and expand it into polynomial form */
inline void fexpand(uint64_t *out, const uint8_t *in)
   {
   out[0] = load_le<uint64_t>(in, 0) & 0x7ffffffffffff;
   out[1] = (load_le<uint64_t>(in+6, 0) >> 3) & 0x7ffffffffffff;
   out[2] = (load_le<uint64_t>(in+12, 0) >> 6) & 0x7ffffffffffff;
   out[3] = (load_le<uint64_t>(in+19, 0) >> 1) & 0x7ffffffffffff;
   out[4] = (load_le<uint64_t>(in+24, 0) >> 12) & 0x7ffffffffffff;
   }

/* Take a fully reduced polynomial form number and contract it into a
* little-endian, 32-byte array
*/
inline void fcontract(uint8_t *out, const uint64_t input[5])
   {
   uint128_t t0 = input[0];
   uint128_t t1 = input[1];
   uint128_t t2 = input[2];
   uint128_t t3 = input[3];
   uint128_t t4 = input[4];

   for(size_t i = 0; i != 2; ++i)
      {
      t1 += t0 >> 51;        t0 &= 0x7ffffffffffff;
      t2 += t1 >> 51;        t1 &= 0x7ffffffffffff;
      t3 += t2 >> 51;        t2 &= 0x7ffffffffffff;
      t4 += t3 >> 51;        t3 &= 0x7ffffffffffff;
      t0 += (t4 >> 51) * 19; t4 &= 0x7ffffffffffff;
      }

   /* now t is between 0 and 2^255-1, properly carried. */
   /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

   t0 += 19;

   t1 += t0 >> 51; t0 &= 0x7ffffffffffff;
   t2 += t1 >> 51; t1 &= 0x7ffffffffffff;
   t3 += t2 >> 51; t2 &= 0x7ffffffffffff;
   t4 += t3 >> 51; t3 &= 0x7ffffffffffff;
   t0 += (t4 >> 51) * 19; t4 &= 0x7ffffffffffff;

   /* now between 19 and 2^255-1 in both cases, and offset by 19. */

   t0 += 0x8000000000000 - 19;
   t1 += 0x8000000000000 - 1;
   t2 += 0x8000000000000 - 1;
   t3 += 0x8000000000000 - 1;
   t4 += 0x8000000000000 - 1;

   /* now between 2^255 and 2^256-20, and offset by 2^255. */

   t1 += t0 >> 51; t0 &= 0x7ffffffffffff;
   t2 += t1 >> 51; t1 &= 0x7ffffffffffff;
   t3 += t2 >> 51; t2 &= 0x7ffffffffffff;
   t4 += t3 >> 51; t3 &= 0x7ffffffffffff;
   t4 &= 0x7ffffffffffff;

   store_le(out,
            combine_lower(t0,  0, t1, 51),
            combine_lower(t1, 13, t2, 38),
            combine_lower(t2, 26, t3, 25),
            combine_lower(t3, 39, t4, 12));
   }

/* Input: Q, Q', Q-Q'
* Out: 2Q, Q+Q'
*
*   result.two_q (2*Q): long form
*   result.q_plus_q_dash (Q + Q): long form
*   in_q: short form, destroyed
*   in_q_dash: short form, destroyed
*   in_q_minus_q_dash: short form, preserved
*/
void fmonty(uint64_t result_two_q_x[5],
            uint64_t result_two_q_z[5],
            uint64_t result_q_plus_q_dash_x[5],
            uint64_t result_q_plus_q_dash_z[5],
            uint64_t in_q_x[5],
            uint64_t in_q_z[5],
            uint64_t in_q_dash_x[5],
            uint64_t in_q_dash_z[5],
            const uint64_t q_minus_q_dash[5])
   {
   uint64_t zzz[5];
   uint64_t xx[5];
   uint64_t zz[5];
   uint64_t xxprime[5];
   uint64_t zzprime[5];
   uint64_t zzzprime[5];

   fadd_sub(in_q_z, in_q_x);
   fadd_sub(in_q_dash_z, in_q_dash_x);

   fmul(xxprime, in_q_dash_x, in_q_z);
   fmul(zzprime, in_q_dash_z, in_q_x);

   fadd_sub(zzprime, xxprime);

   fsquare(result_q_plus_q_dash_x, xxprime);
   fsquare(zzzprime, zzprime);
   fmul(result_q_plus_q_dash_z, zzzprime, q_minus_q_dash);

   fsquare(xx, in_q_x);
   fsquare(zz, in_q_z);
   fmul(result_two_q_x, xx, zz);

   fdifference_backwards(zz, xx);  // does zz = xx - zz
   fscalar_product(zzz, zz, 121665);
   fsum(zzz, xx);

   fmul(result_two_q_z, zz, zzz);
   }

/*
* Maybe swap the contents of two uint64_t arrays (@a and @b),
* Param @iswap is assumed to be either 0 or 1
*
* This function performs the swap without leaking any side-channel
* information.
*/
inline void swap_conditional(uint64_t a[5], uint64_t b[5],
                             uint64_t c[5], uint64_t d[5],
                             uint64_t iswap)
   {
   const uint64_t swap = 0 - iswap;

   for(size_t i = 0; i < 5; ++i)
      {
      const uint64_t x0 = swap & (a[i] ^ b[i]);
      const uint64_t x1 = swap & (c[i] ^ d[i]);
      a[i] ^= x0;
      b[i] ^= x0;
      c[i] ^= x1;
      d[i] ^= x1;
      }
   }

/* Calculates nQ where Q is the x-coordinate of a point on the curve
*
*   resultx/resultz: the x/z coordinate of the resulting curve point (short form)
*   n: a little endian, 32-byte number
*   q: a point of the curve (short form)
*/
void cmult(uint64_t resultx[5], uint64_t resultz[5], const uint8_t n[32], const uint64_t q[5])
   {
   uint64_t a[5] = {0}; // nqpqx
   uint64_t b[5] = {1}; // npqpz
   uint64_t c[5] = {1}; // nqx
   uint64_t d[5] = {0}; // nqz
   uint64_t e[5] = {0}; // npqqx2
   uint64_t f[5] = {1}; // npqqz2
   uint64_t g[5] = {0}; // nqx2
   uint64_t h[5] = {1}; // nqz2

   copy_mem(a, q, 5);

   for(size_t i = 0; i < 32; ++i)
      {
      const uint64_t bit0 = (n[31 - i] >> 7) & 1;
      const uint64_t bit1 = (n[31 - i] >> 6) & 1;
      const uint64_t bit2 = (n[31 - i] >> 5) & 1;
      const uint64_t bit3 = (n[31 - i] >> 4) & 1;
      const uint64_t bit4 = (n[31 - i] >> 3) & 1;
      const uint64_t bit5 = (n[31 - i] >> 2) & 1;
      const uint64_t bit6 = (n[31 - i] >> 1) & 1;
      const uint64_t bit7 = (n[31 - i] >> 0) & 1;

      swap_conditional(c, a, d, b, bit0);
      fmonty(g, h, e, f, c, d, a, b, q);

      swap_conditional(g, e, h, f, bit0 ^ bit1);
      fmonty(c, d, a, b, g, h, e, f, q);

      swap_conditional(c, a, d, b, bit1 ^ bit2);
      fmonty(g, h, e, f, c, d, a, b, q);

      swap_conditional(g, e, h, f, bit2 ^ bit3);
      fmonty(c, d, a, b, g, h, e, f, q);

      swap_conditional(c, a, d, b, bit3 ^ bit4);
      fmonty(g, h, e, f, c, d, a, b, q);

      swap_conditional(g, e, h, f, bit4 ^ bit5);
      fmonty(c, d, a, b, g, h, e, f, q);

      swap_conditional(c, a, d, b, bit5 ^ bit6);
      fmonty(g, h, e, f, c, d, a, b, q);

      swap_conditional(g, e, h, f, bit6 ^ bit7);
      fmonty(c, d, a, b, g, h, e, f, q);

      swap_conditional(c, a, d, b, bit7);
      }

   copy_mem(resultx, c, 5);
   copy_mem(resultz, d, 5);
   }


// -----------------------------------------------------------------------------
// Shamelessly copied from djb's code, tightened a little
// -----------------------------------------------------------------------------
void crecip(uint64_t out[5], const uint64_t z[5])
   {
   uint64_t a[5];
   uint64_t b[5];
   uint64_t c[5];
   uint64_t t0[5];

   fsquare(a, z);       // 2
   fsquare(t0, a, 2);   // 8
   fmul(b, t0, z);      // 9
   fmul(a, b, a);       // 11
   fsquare(t0, a);      // 22
   fmul(b, t0, b);      // 2^5 - 2^0 = 31
   fsquare(t0, b, 5);   // 2^10 - 2^5
   fmul(b, t0, b);      // 2^10 - 2^0
   fsquare(t0, b, 10);  // 2^20 - 2^10
   fmul(c, t0, b);      // 2^20 - 2^0
   fsquare(t0, c, 20);  // 2^40 - 2^20
   fmul(t0, t0, c);     // 2^40 - 2^0
   fsquare(t0, t0, 10); // 2^50 - 2^10
   fmul(b, t0, b);      // 2^50 - 2^0
   fsquare(t0, b, 50);  // 2^100 - 2^50
   fmul(c, t0, b);      // 2^100 - 2^0
   fsquare(t0, c, 100); // 2^200 - 2^100
   fmul(t0, t0, c);     // 2^200 - 2^0
   fsquare(t0, t0, 50); // 2^250 - 2^50
   fmul(t0, t0, b);     // 2^250 - 2^0
   fsquare(t0, t0, 5);  // 2^255 - 2^5
   fmul(out, t0, a);    // 2^255 - 21
   }

}

void
curve25519_donna(uint8_t mypublic[32], const uint8_t secret[32], const uint8_t basepoint[32])
   {
   CT::poison(secret, 32);
   CT::poison(basepoint, 32);

   uint64_t bp[5], x[5], z[5], zmone[5];
   uint8_t e[32];

   copy_mem(e, secret, 32);
   e[ 0] &= 248;
   e[31] &= 127;
   e[31] |= 64;

   fexpand(bp, basepoint);
   cmult(x, z, e, bp);
   crecip(zmone, z);
   fmul(z, x, zmone);
   fcontract(mypublic, z);

   CT::unpoison(secret, 32);
   CT::unpoison(basepoint, 32);
   CT::unpoison(mypublic, 32);
   }

}

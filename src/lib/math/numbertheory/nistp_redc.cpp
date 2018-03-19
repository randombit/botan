/*
* NIST prime reductions
* (C) 2014,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/curve_nistp.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/mp_asmi.h>

namespace Botan {

const BigInt& prime_p521()
   {
   static const BigInt p521("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

   return p521;
   }

void redc_p521(BigInt& x, secure_vector<word>& ws)
   {
   const size_t p_full_words = 521 / BOTAN_MP_WORD_BITS;
   const size_t p_top_bits = 521 % BOTAN_MP_WORD_BITS;
   const size_t p_words = p_full_words + 1;

   const size_t x_sw = x.sig_words();

   if(x_sw < p_words)
      return; // already smaller

   if(ws.size() < p_words + 1)
      ws.resize(p_words + 1);

   clear_mem(ws.data(), ws.size());
   bigint_shr2(ws.data(), x.data(), x_sw, p_full_words, p_top_bits);

   x.mask_bits(521);

   // Word-level carry will be zero
   word carry = bigint_add3_nc(x.mutable_data(), x.data(), p_words, ws.data(), p_words);
   BOTAN_ASSERT_EQUAL(carry, 0, "Final carry in P-521 reduction");

   // Now find the actual carry in bit 522
   const uint8_t bit_522_set = x.word_at(p_full_words) >> (p_top_bits);

#if (BOTAN_MP_WORD_BITS == 64)
   static const word p521_words[9] = {
      0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
      0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
      0x1FF };
#endif

   /*
   * If bit 522 is set then we overflowed and must reduce. Otherwise, if the
   * top bit is set, it is possible we have x == 2**521 - 1 so check for that.
   */
   if(bit_522_set)
      {
#if (BOTAN_MP_WORD_BITS == 64)
      bigint_sub2(x.mutable_data(), x.size(), p521_words, 9);
#else
      x -= prime_p521();
#endif
      }
   else if(x.word_at(p_full_words) >> (p_top_bits - 1))
      {
      /*
      * Otherwise we must reduce if p is exactly 2^512-1
      */

      word possibly_521 = MP_WORD_MAX;
      for(size_t i = 0; i != p_full_words; ++i)
         possibly_521 &= x.word_at(i);

      if(possibly_521 == MP_WORD_MAX)
         x.reduce_below(prime_p521(), ws);
      }
   }

#if defined(BOTAN_HAS_NIST_PRIME_REDUCERS_W32)

namespace {

/**
* Treating this MPI as a sequence of 32-bit words in big-endian
* order, return word i (or 0 if out of range)
*/
inline uint32_t get_uint32_t(const BigInt& x, size_t i)
   {
#if (BOTAN_MP_WORD_BITS == 32)
   return x.word_at(i);
#elif (BOTAN_MP_WORD_BITS == 64)
   return static_cast<uint32_t>(x.word_at(i/2) >> ((i % 2)*32));
#else
  #error "Not implemented"
#endif
   }

/**
* Treating this MPI as a sequence of 32-bit words in big-endian
* order, set word i to the value x
*/
template<typename T>
inline void set_uint32_t(BigInt& x, size_t i, T v_in)
   {
   const uint32_t v = static_cast<uint32_t>(v_in);
#if (BOTAN_MP_WORD_BITS == 32)
   x.set_word_at(i, v);
#elif (BOTAN_MP_WORD_BITS == 64)
   const word shift_32 = (i % 2) * 32;
   const word w = (x.word_at(i/2) & (static_cast<word>(0xFFFFFFFF) << (32-shift_32))) | (static_cast<word>(v) << shift_32);
   x.set_word_at(i/2, w);
#else
  #error "Not implemented"
#endif
   }

}

const BigInt& prime_p192()
   {
   static const BigInt p192("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
   return p192;
   }

void redc_p192(BigInt& x, secure_vector<word>& ws)
   {
   const uint32_t X6 = get_uint32_t(x, 6);
   const uint32_t X7 = get_uint32_t(x, 7);
   const uint32_t X8 = get_uint32_t(x, 8);
   const uint32_t X9 = get_uint32_t(x, 9);
   const uint32_t X10 = get_uint32_t(x, 10);
   const uint32_t X11 = get_uint32_t(x, 11);

   x.mask_bits(192);

   uint64_t S = 0;

   S += get_uint32_t(x, 0);
   S += X6;
   S += X10;
   set_uint32_t(x, 0, S);
   S >>= 32;

   S += get_uint32_t(x, 1);
   S += X7;
   S += X11;
   set_uint32_t(x, 1, S);
   S >>= 32;

   S += get_uint32_t(x, 2);
   S += X6;
   S += X8;
   S += X10;
   set_uint32_t(x, 2, S);
   S >>= 32;

   S += get_uint32_t(x, 3);
   S += X7;
   S += X9;
   S += X11;
   set_uint32_t(x, 3, S);
   S >>= 32;

   S += get_uint32_t(x, 4);
   S += X8;
   S += X10;
   set_uint32_t(x, 4, S);
   S >>= 32;

   S += get_uint32_t(x, 5);
   S += X9;
   S += X11;
   set_uint32_t(x, 5, S);
   S >>= 32;

   set_uint32_t(x, 6, S);

   // No underflow possible

   x.reduce_below(prime_p192(), ws);
   }

const BigInt& prime_p224()
   {
   static const BigInt p224("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
   return p224;
   }

void redc_p224(BigInt& x, secure_vector<word>& ws)
   {
   const uint32_t X7 = get_uint32_t(x, 7);
   const uint32_t X8 = get_uint32_t(x, 8);
   const uint32_t X9 = get_uint32_t(x, 9);
   const uint32_t X10 = get_uint32_t(x, 10);
   const uint32_t X11 = get_uint32_t(x, 11);
   const uint32_t X12 = get_uint32_t(x, 12);
   const uint32_t X13 = get_uint32_t(x, 13);

   x.mask_bits(224);

   // One full copy of P224 is added, so the result is always positive

   int64_t S = 0;

   S += get_uint32_t(x, 0);
   S += 1;
   S -= X7;
   S -= X11;
   set_uint32_t(x, 0, S);
   S >>= 32;

   S += get_uint32_t(x, 1);
   S -= X8;
   S -= X12;
   set_uint32_t(x, 1, S);
   S >>= 32;

   S += get_uint32_t(x, 2);
   S -= X9;
   S -= X13;
   set_uint32_t(x, 2, S);
   S >>= 32;

   S += get_uint32_t(x, 3);
   S += 0xFFFFFFFF;
   S += X7;
   S += X11;
   S -= X10;
   set_uint32_t(x, 3, S);
   S >>= 32;

   S += get_uint32_t(x, 4);
   S += 0xFFFFFFFF;
   S += X8;
   S += X12;
   S -= X11;
   set_uint32_t(x, 4, S);
   S >>= 32;

   S += get_uint32_t(x, 5);
   S += 0xFFFFFFFF;
   S += X9;
   S += X13;
   S -= X12;
   set_uint32_t(x, 5, S);
   S >>= 32;

   S += get_uint32_t(x, 6);
   S += 0xFFFFFFFF;
   S += X10;
   S -= X13;
   set_uint32_t(x, 6, S);
   S >>= 32;
   set_uint32_t(x, 7, S);

   BOTAN_ASSERT_EQUAL(S >> 32, 0, "No underflow");

   x.reduce_below(prime_p224(), ws);
   }

const BigInt& prime_p256()
   {
   static const BigInt p256("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
   return p256;
   }

void redc_p256(BigInt& x, secure_vector<word>& ws)
   {
   static const size_t p256_limbs = (BOTAN_MP_WORD_BITS == 32) ? 8 : 4;

   BOTAN_UNUSED(ws);

   const uint32_t X8 = get_uint32_t(x, 8);
   const uint32_t X9 = get_uint32_t(x, 9);
   const uint32_t X10 = get_uint32_t(x, 10);
   const uint32_t X11 = get_uint32_t(x, 11);
   const uint32_t X12 = get_uint32_t(x, 12);
   const uint32_t X13 = get_uint32_t(x, 13);
   const uint32_t X14 = get_uint32_t(x, 14);
   const uint32_t X15 = get_uint32_t(x, 15);

   x.mask_bits(256);
   x.shrink_to_fit(p256_limbs + 1);

   int64_t S = 0;

   // Adds 6 * P-256 to prevent underflow

   S = get_uint32_t(x, 0);
   S += 0xFFFFFFFA;
   S += X8;
   S += X9;
   S -= X11;
   S -= X12;
   S -= X13;
   S -= X14;
   set_uint32_t(x, 0, S);
   S >>= 32;

   S += get_uint32_t(x, 1);
   S += 0xFFFFFFFF;
   S += X9;
   S += X10;
   S -= X12;
   S -= X13;
   S -= X14;
   S -= X15;
   set_uint32_t(x, 1, S);
   S >>= 32;

   S += get_uint32_t(x, 2);
   S += 0xFFFFFFFF;
   S += X10;
   S += X11;
   S -= X13;
   S -= X14;
   S -= X15;
   set_uint32_t(x, 2, S);
   S >>= 32;

   S += get_uint32_t(x, 3);
   S += 5;
   S += X11;
   S += X11;
   S += X12;
   S += X12;
   S += X13;
   S -= X15;
   S -= X8;
   S -= X9;
   set_uint32_t(x, 3, S);
   S >>= 32;

   S += get_uint32_t(x, 4);
   S += X12;
   S += X12;
   S += X13;
   S += X13;
   S += X14;
   S -= X9;
   S -= X10;
   set_uint32_t(x, 4, S);
   S >>= 32;

   S += get_uint32_t(x, 5);
   S += X13;
   S += X13;
   S += X14;
   S += X14;
   S += X15;
   S -= X10;
   S -= X11;
   set_uint32_t(x, 5, S);
   S >>= 32;

   S += get_uint32_t(x, 6);
   S += 6;
   S += X14;
   S += X14;
   S += X15;
   S += X15;
   S += X14;
   S += X13;
   S -= X8;
   S -= X9;
   set_uint32_t(x, 6, S);
   S >>= 32;

   S += get_uint32_t(x, 7);
   S += 0xFFFFFFFA;
   S += X15;
   S += X15;
   S += X15;
   S += X8;
   S -= X10;
   S -= X11;
   S -= X12;
   S -= X13;
   set_uint32_t(x, 7, S);
   S >>= 32;

   S += 5; // final carry of 6*P-256

   BOTAN_ASSERT(S >= 0 && S <= 10, "Expected overflow");

   /*
   This is a table of (i*P-256) % 2**256 for i in 1...10
   */
   static const word p256_mults[11][p256_limbs] = {
#if (BOTAN_MP_WORD_BITS == 64)
      {0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001},
      {0xFFFFFFFFFFFFFFFE, 0x00000001FFFFFFFF, 0x0000000000000000, 0xFFFFFFFE00000002},
      {0xFFFFFFFFFFFFFFFD, 0x00000002FFFFFFFF, 0x0000000000000000, 0xFFFFFFFD00000003},
      {0xFFFFFFFFFFFFFFFC, 0x00000003FFFFFFFF, 0x0000000000000000, 0xFFFFFFFC00000004},
      {0xFFFFFFFFFFFFFFFB, 0x00000004FFFFFFFF, 0x0000000000000000, 0xFFFFFFFB00000005},
      {0xFFFFFFFFFFFFFFFA, 0x00000005FFFFFFFF, 0x0000000000000000, 0xFFFFFFFA00000006},
      {0xFFFFFFFFFFFFFFF9, 0x00000006FFFFFFFF, 0x0000000000000000, 0xFFFFFFF900000007},
      {0xFFFFFFFFFFFFFFF8, 0x00000007FFFFFFFF, 0x0000000000000000, 0xFFFFFFF800000008},
      {0xFFFFFFFFFFFFFFF7, 0x00000008FFFFFFFF, 0x0000000000000000, 0xFFFFFFF700000009},
      {0xFFFFFFFFFFFFFFF6, 0x00000009FFFFFFFF, 0x0000000000000000, 0xFFFFFFF60000000A},
      {0xFFFFFFFFFFFFFFF5, 0x0000000AFFFFFFFF, 0x0000000000000000, 0xFFFFFFF50000000B},
#else
      {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
      {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000, 0x00000002, 0xFFFFFFFE},
      {0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000002, 0x00000000, 0x00000000, 0x00000003, 0xFFFFFFFD},
      {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000003, 0x00000000, 0x00000000, 0x00000004, 0xFFFFFFFC},
      {0xFFFFFFFB, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000004, 0x00000000, 0x00000000, 0x00000005, 0xFFFFFFFB},
      {0xFFFFFFFA, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000005, 0x00000000, 0x00000000, 0x00000006, 0xFFFFFFFA},
      {0xFFFFFFF9, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000006, 0x00000000, 0x00000000, 0x00000007, 0xFFFFFFF9},
      {0xFFFFFFF8, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000007, 0x00000000, 0x00000000, 0x00000008, 0xFFFFFFF8},
      {0xFFFFFFF7, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000008, 0x00000000, 0x00000000, 0x00000009, 0xFFFFFFF7},
      {0xFFFFFFF6, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000009, 0x00000000, 0x00000000, 0x0000000A, 0xFFFFFFF6},
      {0xFFFFFFF5, 0xFFFFFFFF, 0xFFFFFFFF, 0x0000000A, 0x00000000, 0x00000000, 0x0000000B, 0xFFFFFFF5},
#endif
   };

   word borrow = bigint_sub2(x.mutable_data(), x.size(), p256_mults[S], p256_limbs);

   BOTAN_ASSERT(borrow == 0 || borrow == 1, "Expected borrow during P-256 reduction");

   if(borrow)
      {
      bigint_add2(x.mutable_data(), x.size() - 1, p256_mults[0], p256_limbs);
      }
   }

const BigInt& prime_p384()
   {
   static const BigInt p384("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
   return p384;
   }

void redc_p384(BigInt& x, secure_vector<word>& ws)
   {
   BOTAN_UNUSED(ws);

   static const size_t p384_limbs = (BOTAN_MP_WORD_BITS == 32) ? 12 : 6;

   const uint32_t X12 = get_uint32_t(x, 12);
   const uint32_t X13 = get_uint32_t(x, 13);
   const uint32_t X14 = get_uint32_t(x, 14);
   const uint32_t X15 = get_uint32_t(x, 15);
   const uint32_t X16 = get_uint32_t(x, 16);
   const uint32_t X17 = get_uint32_t(x, 17);
   const uint32_t X18 = get_uint32_t(x, 18);
   const uint32_t X19 = get_uint32_t(x, 19);
   const uint32_t X20 = get_uint32_t(x, 20);
   const uint32_t X21 = get_uint32_t(x, 21);
   const uint32_t X22 = get_uint32_t(x, 22);
   const uint32_t X23 = get_uint32_t(x, 23);

   x.mask_bits(384);
   x.shrink_to_fit(p384_limbs + 1);

   int64_t S = 0;

   // One copy of P-384 is added to prevent underflow
   S = get_uint32_t(x, 0);
   S += 0xFFFFFFFF;
   S += X12;
   S += X21;
   S += X20;
   S -= X23;
   set_uint32_t(x, 0, S);
   S >>= 32;

   S += get_uint32_t(x, 1);
   S += X13;
   S += X22;
   S += X23;
   S -= X12;
   S -= X20;
   set_uint32_t(x, 1, S);
   S >>= 32;

   S += get_uint32_t(x, 2);
   S += X14;
   S += X23;
   S -= X13;
   S -= X21;
   set_uint32_t(x, 2, S);
   S >>= 32;

   S += get_uint32_t(x, 3);
   S += 0xFFFFFFFF;
   S += X15;
   S += X12;
   S += X20;
   S += X21;
   S -= X14;
   S -= X22;
   S -= X23;
   set_uint32_t(x, 3, S);
   S >>= 32;

   S += get_uint32_t(x, 4);
   S += 0xFFFFFFFE;
   S += X21;
   S += X21;
   S += X16;
   S += X13;
   S += X12;
   S += X20;
   S += X22;
   S -= X15;
   S -= X23;
   S -= X23;
   set_uint32_t(x, 4, S);
   S >>= 32;

   S += get_uint32_t(x, 5);
   S += 0xFFFFFFFF;
   S += X22;
   S += X22;
   S += X17;
   S += X14;
   S += X13;
   S += X21;
   S += X23;
   S -= X16;
   set_uint32_t(x, 5, S);
   S >>= 32;

   S += get_uint32_t(x, 6);
   S += 0xFFFFFFFF;
   S += X23;
   S += X23;
   S += X18;
   S += X15;
   S += X14;
   S += X22;
   S -= X17;
   set_uint32_t(x, 6, S);
   S >>= 32;

   S += get_uint32_t(x, 7);
   S += 0xFFFFFFFF;
   S += X19;
   S += X16;
   S += X15;
   S += X23;
   S -= X18;
   set_uint32_t(x, 7, S);
   S >>= 32;

   S += get_uint32_t(x, 8);
   S += 0xFFFFFFFF;
   S += X20;
   S += X17;
   S += X16;
   S -= X19;
   set_uint32_t(x, 8, S);
   S >>= 32;

   S += get_uint32_t(x, 9);
   S += 0xFFFFFFFF;
   S += X21;
   S += X18;
   S += X17;
   S -= X20;
   set_uint32_t(x, 9, S);
   S >>= 32;

   S += get_uint32_t(x, 10);
   S += 0xFFFFFFFF;
   S += X22;
   S += X19;
   S += X18;
   S -= X21;
   set_uint32_t(x, 10, S);
   S >>= 32;

   S += get_uint32_t(x, 11);
   S += 0xFFFFFFFF;
   S += X23;
   S += X20;
   S += X19;
   S -= X22;
   set_uint32_t(x, 11, S);
   S >>= 32;

   BOTAN_ASSERT(S >= 0 && S <= 4, "Expected overflow in P-384 reduction");

   /*
   This is a table of (i*P-384) % 2**384 for i in 1...4
   */
   static const word p384_mults[5][p384_limbs] = {
#if (BOTAN_MP_WORD_BITS == 64)
      {0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
      {0x00000001FFFFFFFE, 0xFFFFFFFE00000000, 0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
      {0x00000002FFFFFFFD, 0xFFFFFFFD00000000, 0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
      {0x00000003FFFFFFFC, 0xFFFFFFFC00000000, 0xFFFFFFFFFFFFFFFB, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
      {0x00000004FFFFFFFB, 0xFFFFFFFB00000000, 0xFFFFFFFFFFFFFFFA, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},

#else
      {0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF,
       0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
      {0xFFFFFFFE, 0x00000001, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF,
       0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
      {0xFFFFFFFD, 0x00000002, 0x00000000, 0xFFFFFFFD, 0xFFFFFFFC, 0xFFFFFFFF,
       0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
      {0xFFFFFFFC, 0x00000003, 0x00000000, 0xFFFFFFFC, 0xFFFFFFFB, 0xFFFFFFFF,
       0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
      {0xFFFFFFFB, 0x00000004, 0x00000000, 0xFFFFFFFB, 0xFFFFFFFA, 0xFFFFFFFF,
       0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
#endif
   };

   word borrow = bigint_sub2(x.mutable_data(), x.size(), p384_mults[S], p384_limbs);

   BOTAN_ASSERT(borrow == 0 || borrow == 1, "Expected borrow during P-384 reduction");

   if(borrow)
      {
      bigint_add2(x.mutable_data(), x.size() - 1, p384_mults[0], p384_limbs);
      }
   }

#endif


}

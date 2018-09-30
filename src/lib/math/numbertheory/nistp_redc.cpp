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
   const word bit_522_set = x.word_at(p_full_words) >> p_top_bits;

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
#else
   return static_cast<uint32_t>(x.word_at(i/2) >> ((i % 2)*32));
#endif
   }

inline void set_words(BigInt& x, size_t i, uint32_t R0, uint32_t R1)
   {
#if (BOTAN_MP_WORD_BITS == 32)
   x.set_word_at(i, R0);
   x.set_word_at(i+1, R1);
#else
   x.set_word_at(i/2, (static_cast<uint64_t>(R1) << 32) | R0);
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
   BOTAN_UNUSED(ws);

   static const size_t p192_limbs = 192 / BOTAN_MP_WORD_BITS;

   const uint64_t X00 = get_uint32_t(x,  0);
   const uint64_t X01 = get_uint32_t(x,  1);
   const uint64_t X02 = get_uint32_t(x,  2);
   const uint64_t X03 = get_uint32_t(x,  3);
   const uint64_t X04 = get_uint32_t(x,  4);
   const uint64_t X05 = get_uint32_t(x,  5);
   const uint64_t X06 = get_uint32_t(x,  6);
   const uint64_t X07 = get_uint32_t(x,  7);
   const uint64_t X08 = get_uint32_t(x,  8);
   const uint64_t X09 = get_uint32_t(x,  9);
   const uint64_t X10 = get_uint32_t(x, 10);
   const uint64_t X11 = get_uint32_t(x, 11);

   const uint64_t S0 = X00 + X06 + X10;
   const uint64_t S1 = X01 + X07 + X11;
   const uint64_t S2 = X02 + X06 + X08 + X10;
   const uint64_t S3 = X03 + X07 + X09 + X11;
   const uint64_t S4 = X04 + X08 + X10;
   const uint64_t S5 = X05 + X09 + X11;

   x.mask_bits(192);

   uint64_t S = 0;
   uint32_t R0 = 0, R1 = 0;

   S += S0;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S1;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 0, R0, R1);

   S += S2;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S3;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 2, R0, R1);

   S += S4;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S5;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 4, R0, R1);

   // No underflow possible

   BOTAN_ASSERT(S <= 2, "Expected overflow in P-192 reduce");

   /*
   This is a table of (i*P-192) % 2**192 for i in 1...3
   */
   static const word p192_mults[3][p192_limbs] = {
#if (BOTAN_MP_WORD_BITS == 64)
      {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF},
      {0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFF},
      {0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFF},
#else
      {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
      {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
      {0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
#endif
   };

   if(S == 0 && x.word_at(p192_limbs-1) < p192_mults[0][p192_limbs-1])
      {
      return;
      }

   word borrow = bigint_sub2(x.mutable_data(), x.size(), p192_mults[S], p192_limbs);

   BOTAN_ASSERT(borrow == 0 || borrow == 1, "Expected borrow during P-192 reduction");

   if(borrow)
      {
      bigint_add2(x.mutable_data(), x.size() - 1, p192_mults[0], p192_limbs);
      }
   }

const BigInt& prime_p224()
   {
   static const BigInt p224("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
   return p224;
   }

void redc_p224(BigInt& x, secure_vector<word>& ws)
   {
   static const size_t p224_limbs = (BOTAN_MP_WORD_BITS == 32) ? 7 : 4;

   BOTAN_UNUSED(ws);

   const int64_t X00 = get_uint32_t(x,  0);
   const int64_t X01 = get_uint32_t(x,  1);
   const int64_t X02 = get_uint32_t(x,  2);
   const int64_t X03 = get_uint32_t(x,  3);
   const int64_t X04 = get_uint32_t(x,  4);
   const int64_t X05 = get_uint32_t(x,  5);
   const int64_t X06 = get_uint32_t(x,  6);
   const int64_t X07 = get_uint32_t(x,  7);
   const int64_t X08 = get_uint32_t(x,  8);
   const int64_t X09 = get_uint32_t(x,  9);
   const int64_t X10 = get_uint32_t(x, 10);
   const int64_t X11 = get_uint32_t(x, 11);
   const int64_t X12 = get_uint32_t(x, 12);
   const int64_t X13 = get_uint32_t(x, 13);

   // One full copy of P224 is added, so the result is always positive

   const int64_t S0 = 0x00000001 + X00 - X07 - X11;
   const int64_t S1 = 0x00000000 + X01 - X08 - X12;
   const int64_t S2 = 0x00000000 + X02 - X09 - X13;
   const int64_t S3 = 0xFFFFFFFF + X03 + X07 + X11 - X10;
   const int64_t S4 = 0xFFFFFFFF + X04 + X08 + X12 - X11;
   const int64_t S5 = 0xFFFFFFFF + X05 + X09 + X13 - X12;
   const int64_t S6 = 0xFFFFFFFF + X06 + X10 - X13;

   x.mask_bits(224);
   x.shrink_to_fit(p224_limbs + 1);

   int64_t S = 0;
   uint32_t R0 = 0, R1 = 0;

   S += S0;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S1;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 0, R0, R1);

   S += S2;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S3;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 2, R0, R1);

   S += S4;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S5;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 4, R0, R1);

   S += S6;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 6, R0, 0);

   BOTAN_ASSERT(S >= 0 && S <= 2, "Expected overflow in P-224 reduce");

   static const word p224_mults[3][p224_limbs] = {
#if (BOTAN_MP_WORD_BITS == 64)
    {0x0000000000000001, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF},
    {0x0000000000000002, 0xFFFFFFFE00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF},
    {0x0000000000000003, 0xFFFFFFFD00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF},
#else
    {0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x00000002, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x00000003, 0x00000000, 0x00000000, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#endif

   };

   if(S == 0 && x.word_at(p224_limbs-1) < p224_mults[0][p224_limbs-1])
      {
      return;
      }

   word borrow = bigint_sub2(x.mutable_data(), x.size(), p224_mults[S], p224_limbs);

   BOTAN_ASSERT(borrow == 0 || borrow == 1, "Expected borrow during P-224 reduction");

   if(borrow)
      {
      bigint_add2(x.mutable_data(), x.size() - 1, p224_mults[0], p224_limbs);
      }
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

   const int64_t X00 = get_uint32_t(x,  0);
   const int64_t X01 = get_uint32_t(x,  1);
   const int64_t X02 = get_uint32_t(x,  2);
   const int64_t X03 = get_uint32_t(x,  3);
   const int64_t X04 = get_uint32_t(x,  4);
   const int64_t X05 = get_uint32_t(x,  5);
   const int64_t X06 = get_uint32_t(x,  6);
   const int64_t X07 = get_uint32_t(x,  7);
   const int64_t X08 = get_uint32_t(x,  8);
   const int64_t X09 = get_uint32_t(x,  9);
   const int64_t X10 = get_uint32_t(x, 10);
   const int64_t X11 = get_uint32_t(x, 11);
   const int64_t X12 = get_uint32_t(x, 12);
   const int64_t X13 = get_uint32_t(x, 13);
   const int64_t X14 = get_uint32_t(x, 14);
   const int64_t X15 = get_uint32_t(x, 15);

   // Adds 6 * P-256 to prevent underflow
   const int64_t S0 = 0xFFFFFFFA + X00 + X08 + X09 - X11 - X12 - X13 - X14;
   const int64_t S1 = 0xFFFFFFFF + X01 + X09 + X10 - X12 - X13 - X14 - X15;
   const int64_t S2 = 0xFFFFFFFF + X02 + X10 + X11 - X13 - X14 - X15;
   const int64_t S3 = 0x00000005 + X03 + (X11 + X12)*2 + X13 - X15 - X08 - X09;
   const int64_t S4 = 0x00000000 + X04 + (X12 + X13)*2 + X14 - X09 - X10;
   const int64_t S5 = 0x00000000 + X05 + (X13 + X14)*2 + X15 - X10 - X11;
   const int64_t S6 = 0x00000006 + X06 + X13 + X14*3 + X15*2 - X08 - X09;
   const int64_t S7 = 0xFFFFFFFA + X07 + X15*3 + X08 - X10 - X11 - X12 - X13;

   x.mask_bits(256);
   x.shrink_to_fit(p256_limbs + 1);

   int64_t S = 0;

   uint32_t R0 = 0, R1 = 0;

   S += S0;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S1;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 0, R0, R1);

   S += S2;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S3;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 2, R0, R1);

   S += S4;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S5;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 4, R0, R1);

   S += S6;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S7;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;
   set_words(x, 6, R0, R1);

   S += 5; // the top digits of 6*P-256

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

   if(S == 0 && x.word_at(p256_limbs-1) < p256_mults[0][p256_limbs-1])
      {
      return;
      }

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

   const int64_t X00 = get_uint32_t(x,  0);
   const int64_t X01 = get_uint32_t(x,  1);
   const int64_t X02 = get_uint32_t(x,  2);
   const int64_t X03 = get_uint32_t(x,  3);
   const int64_t X04 = get_uint32_t(x,  4);
   const int64_t X05 = get_uint32_t(x,  5);
   const int64_t X06 = get_uint32_t(x,  6);
   const int64_t X07 = get_uint32_t(x,  7);
   const int64_t X08 = get_uint32_t(x,  8);
   const int64_t X09 = get_uint32_t(x,  9);
   const int64_t X10 = get_uint32_t(x, 10);
   const int64_t X11 = get_uint32_t(x, 11);
   const int64_t X12 = get_uint32_t(x, 12);
   const int64_t X13 = get_uint32_t(x, 13);
   const int64_t X14 = get_uint32_t(x, 14);
   const int64_t X15 = get_uint32_t(x, 15);
   const int64_t X16 = get_uint32_t(x, 16);
   const int64_t X17 = get_uint32_t(x, 17);
   const int64_t X18 = get_uint32_t(x, 18);
   const int64_t X19 = get_uint32_t(x, 19);
   const int64_t X20 = get_uint32_t(x, 20);
   const int64_t X21 = get_uint32_t(x, 21);
   const int64_t X22 = get_uint32_t(x, 22);
   const int64_t X23 = get_uint32_t(x, 23);

   // One copy of P-384 is added to prevent underflow
   const int64_t S0 = 0xFFFFFFFF + X00 + X12 + X20 + X21 - X23;
   const int64_t S1 = 0x00000000 + X01 + X13 + X22 + X23 - X12 - X20;
   const int64_t S2 = 0x00000000 + X02 + X14 + X23 - X13 - X21;
   const int64_t S3 = 0xFFFFFFFF + X03 + X12 + X15 + X20 + X21 - X14 - X22 - X23;
   const int64_t S4 = 0xFFFFFFFE + X04 + X12 + X13 + X16 + X20 + X21*2 + X22 - X15 - X23*2;
   const int64_t S5 = 0xFFFFFFFF + X05 + X13 + X14 + X17 + X21 + X22*2 + X23 - X16;
   const int64_t S6 = 0xFFFFFFFF + X06 + X14 + X15 + X18 + X22 + X23*2 - X17;
   const int64_t S7 = 0xFFFFFFFF + X07 + X15 + X16 + X19 + X23 - X18;
   const int64_t S8 = 0xFFFFFFFF + X08 + X16 + X17 + X20 - X19;
   const int64_t S9 = 0xFFFFFFFF + X09 + X17 + X18 + X21 - X20;
   const int64_t SA = 0xFFFFFFFF + X10 + X18 + X19 + X22 - X21;
   const int64_t SB = 0xFFFFFFFF + X11 + X19 + X20 + X23 - X22;

   x.mask_bits(384);
   x.shrink_to_fit(p384_limbs + 1);

   int64_t S = 0;

   uint32_t R0 = 0, R1 = 0;

   S += S0;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S1;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 0, R0, R1);

   S += S2;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S3;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 2, R0, R1);

   S += S4;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S5;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 4, R0, R1);

   S += S6;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S7;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 6, R0, R1);

   S += S8;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S9;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 8, R0, R1);

   S += SA;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += SB;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(x, 10, R0, R1);

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

   if(S == 0 && x.word_at(p384_limbs-1) < p384_mults[0][p384_limbs-1])
      {
      return;
      }

   word borrow = bigint_sub2(x.mutable_data(), x.size(), p384_mults[S], p384_limbs);

   BOTAN_ASSERT(borrow == 0 || borrow == 1, "Expected borrow during P-384 reduction");

   if(borrow)
      {
      bigint_add2(x.mutable_data(), x.size() - 1, p384_mults[0], p384_limbs);
      }
   }

#endif


}

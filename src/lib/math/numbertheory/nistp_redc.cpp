/*
* NIST prime reductions
* (C) 2014,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/curve_nistp.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

namespace Botan {

const BigInt& prime_p521() {
   static const BigInt p521(
      "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

   return p521;
}

void redc_p521(BigInt& x, secure_vector<word>& ws) {
   BOTAN_DEBUG_ASSERT(x.is_positive());

   const size_t p_full_words = 521 / BOTAN_MP_WORD_BITS;
   const size_t p_top_bits = 521 % BOTAN_MP_WORD_BITS;
   const size_t p_words = p_full_words + 1;

   static const constinit auto p521_words = hex_to_words<word>(
      "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

   if(ws.size() < p_words + 1) {
      ws.resize(p_words + 1);
   }

   clear_mem(ws.data(), ws.size());
   bigint_shr2(ws.data(), x._data(), std::min(x.size(), 2 * p_words), 521);

   x.mask_bits(521);
   x.grow_to(p_words);

   // Word-level carry will be zero
   word carry = bigint_add3_nc(x.mutable_data(), x._data(), p_words, ws.data(), p_words);
   BOTAN_ASSERT_EQUAL(carry, 0, "Final carry in P-521 reduction");

   const word top_word = x.word_at(p_full_words);

   /*
   * Check if we need to reduce modulo P
   * There are two possible cases:
   * - The result overflowed past 521 bits, in which case bit 522 will be set
   * - The result is exactly 2**521 - 1
   */
   const auto bit_522_set = CT::Mask<word>::expand(top_word >> p_top_bits);

   const word max = WordInfo<word>::max;
   word and_512 = max;
   for(size_t i = 0; i != p_full_words; ++i) {
      and_512 &= x.word_at(i);
   }
   const auto all_512_low_bits_set = CT::Mask<word>::is_equal(and_512, max);
   const auto has_p521_top_word = CT::Mask<word>::is_equal(top_word, 0x1FF);
   const auto is_p521 = all_512_low_bits_set & has_p521_top_word;

   const auto needs_reduction = is_p521 | bit_522_set;

   bigint_cnd_sub(needs_reduction.value(), x.mutable_data(), p521_words.data(), p_words);
}

namespace {

/**
* Treating this MPI as a sequence of 32-bit words in big-endian
* order, return word i. The array is assumed to be large enough.
*/
inline uint32_t get_uint32(const word xw[], size_t i) {
#if(BOTAN_MP_WORD_BITS == 32)
   return xw[i];
#else
   return static_cast<uint32_t>(xw[i / 2] >> ((i % 2) * 32));
#endif
}

inline void set_words(word x[], size_t i, uint32_t R0, uint32_t R1) {
#if(BOTAN_MP_WORD_BITS == 32)
   x[i] = R0;
   x[i + 1] = R1;
#else
   x[i / 2] = (static_cast<uint64_t>(R1) << 32) | R0;
#endif
}

}  // namespace

const BigInt& prime_p192() {
   static const BigInt p192("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
   return p192;
}

void redc_p192(BigInt& x, secure_vector<word>& ws) {
   BOTAN_DEBUG_ASSERT(x.is_positive());

   BOTAN_UNUSED(ws);

   static const size_t p192_limbs = 192 / BOTAN_MP_WORD_BITS;

   x.grow_to(2 * p192_limbs);
   word* xw = x.mutable_data();

   const uint64_t X00 = get_uint32(xw, 0);
   const uint64_t X01 = get_uint32(xw, 1);
   const uint64_t X02 = get_uint32(xw, 2);
   const uint64_t X03 = get_uint32(xw, 3);
   const uint64_t X04 = get_uint32(xw, 4);
   const uint64_t X05 = get_uint32(xw, 5);
   const uint64_t X06 = get_uint32(xw, 6);
   const uint64_t X07 = get_uint32(xw, 7);
   const uint64_t X08 = get_uint32(xw, 8);
   const uint64_t X09 = get_uint32(xw, 9);
   const uint64_t X10 = get_uint32(xw, 10);
   const uint64_t X11 = get_uint32(xw, 11);

   const uint64_t S0 = X00 + X06 + X10;
   const uint64_t S1 = X01 + X07 + X11;
   const uint64_t S2 = X02 + X06 + X08 + X10;
   const uint64_t S3 = X03 + X07 + X09 + X11;
   const uint64_t S4 = X04 + X08 + X10;
   const uint64_t S5 = X05 + X09 + X11;

   uint64_t S = 0;
   uint32_t R0 = 0, R1 = 0;

   S += S0;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S1;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 0, R0, R1);

   S += S2;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S3;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 2, R0, R1);

   S += S4;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S5;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 4, R0, R1);

   // No underflow possible

   /*
   This is a table of (i*P-192) % 2**192 for i in 1...3
   */
   static const constinit std::array<word, p192_limbs> p192_mults[3] = {
      hex_to_words<word>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"),
      hex_to_words<word>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDFFFFFFFFFFFFFFFE"),
      hex_to_words<word>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCFFFFFFFFFFFFFFFD"),
   };

   CT::unpoison(S);
   BOTAN_ASSERT(S <= 2, "Expected overflow");

   BOTAN_ASSERT_NOMSG(x.size() >= p192_limbs + 1);
   x.mask_bits(192);
   word borrow = bigint_sub2(x.mutable_data(), p192_limbs + 1, p192_mults[S].data(), p192_limbs);
   BOTAN_DEBUG_ASSERT(borrow == 0 || borrow == 1);
   bigint_cnd_add(borrow, x.mutable_data(), p192_limbs + 1, p192_mults[0].data(), p192_limbs);
}

const BigInt& prime_p224() {
   static const BigInt p224("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
   return p224;
}

void redc_p224(BigInt& x, secure_vector<word>& ws) {
   BOTAN_DEBUG_ASSERT(x.is_positive());

   static const size_t p224_limbs = (BOTAN_MP_WORD_BITS == 32) ? 7 : 4;

   BOTAN_UNUSED(ws);

   x.grow_to(2 * p224_limbs);
   word* xw = x.mutable_data();

   const int64_t X00 = get_uint32(xw, 0);
   const int64_t X01 = get_uint32(xw, 1);
   const int64_t X02 = get_uint32(xw, 2);
   const int64_t X03 = get_uint32(xw, 3);
   const int64_t X04 = get_uint32(xw, 4);
   const int64_t X05 = get_uint32(xw, 5);
   const int64_t X06 = get_uint32(xw, 6);
   const int64_t X07 = get_uint32(xw, 7);
   const int64_t X08 = get_uint32(xw, 8);
   const int64_t X09 = get_uint32(xw, 9);
   const int64_t X10 = get_uint32(xw, 10);
   const int64_t X11 = get_uint32(xw, 11);
   const int64_t X12 = get_uint32(xw, 12);
   const int64_t X13 = get_uint32(xw, 13);

   // One full copy of P224 is added, so the result is always positive

   const int64_t S0 = 0x00000001 + X00 - X07 - X11;
   const int64_t S1 = 0x00000000 + X01 - X08 - X12;
   const int64_t S2 = 0x00000000 + X02 - X09 - X13;
   const int64_t S3 = 0xFFFFFFFF + X03 + X07 + X11 - X10;
   const int64_t S4 = 0xFFFFFFFF + X04 + X08 + X12 - X11;
   const int64_t S5 = 0xFFFFFFFF + X05 + X09 + X13 - X12;
   const int64_t S6 = 0xFFFFFFFF + X06 + X10 - X13;

   int64_t S = 0;
   uint32_t R0 = 0, R1 = 0;

   S += S0;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S1;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 0, R0, R1);

   S += S2;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S3;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 2, R0, R1);

   S += S4;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S5;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 4, R0, R1);

   S += S6;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 6, R0, 0);

   static const constinit std::array<word, p224_limbs> p224_mults[3] = {
      hex_to_words<word>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"),
      hex_to_words<word>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE000000000000000000000002"),
      hex_to_words<word>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD000000000000000000000003"),
   };

   CT::unpoison(S);
   BOTAN_ASSERT(S >= 0 && S <= 2, "Expected overflow");

   BOTAN_ASSERT_NOMSG(x.size() >= p224_limbs + 1);
   x.mask_bits(224);
   word borrow = bigint_sub2(x.mutable_data(), p224_limbs + 1, p224_mults[S].data(), p224_limbs);
   BOTAN_DEBUG_ASSERT(borrow == 0 || borrow == 1);
   bigint_cnd_add(borrow, x.mutable_data(), p224_limbs + 1, p224_mults[0].data(), p224_limbs);
}

const BigInt& prime_p256() {
   static const BigInt p256("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
   return p256;
}

void redc_p256(BigInt& x, secure_vector<word>& ws) {
   BOTAN_DEBUG_ASSERT(x.is_positive());

   static const size_t p256_limbs = (BOTAN_MP_WORD_BITS == 32) ? 8 : 4;

   BOTAN_UNUSED(ws);

   x.grow_to(2 * p256_limbs);
   word* xw = x.mutable_data();

   const int64_t X00 = get_uint32(xw, 0);
   const int64_t X01 = get_uint32(xw, 1);
   const int64_t X02 = get_uint32(xw, 2);
   const int64_t X03 = get_uint32(xw, 3);
   const int64_t X04 = get_uint32(xw, 4);
   const int64_t X05 = get_uint32(xw, 5);
   const int64_t X06 = get_uint32(xw, 6);
   const int64_t X07 = get_uint32(xw, 7);
   const int64_t X08 = get_uint32(xw, 8);
   const int64_t X09 = get_uint32(xw, 9);
   const int64_t X10 = get_uint32(xw, 10);
   const int64_t X11 = get_uint32(xw, 11);
   const int64_t X12 = get_uint32(xw, 12);
   const int64_t X13 = get_uint32(xw, 13);
   const int64_t X14 = get_uint32(xw, 14);
   const int64_t X15 = get_uint32(xw, 15);

   // Adds 6 * P-256 to prevent underflow
   const int64_t S0 = 0xFFFFFFFA + X00 + X08 + X09 - (X11 + X12 + X13) - X14;
   const int64_t S1 = 0xFFFFFFFF + X01 + X09 + X10 - X12 - (X13 + X14 + X15);
   const int64_t S2 = 0xFFFFFFFF + X02 + X10 + X11 - (X13 + X14 + X15);
   const int64_t S3 = 0x00000005 + X03 + (X11 + X12) * 2 + X13 - X15 - X08 - X09;
   const int64_t S4 = 0x00000000 + X04 + (X12 + X13) * 2 + X14 - X09 - X10;
   const int64_t S5 = 0x00000000 + X05 + (X13 + X14) * 2 + X15 - X10 - X11;
   const int64_t S6 = 0x00000006 + X06 + X13 + X14 * 3 + X15 * 2 - X08 - X09;
   const int64_t S7 = 0xFFFFFFFA + X07 + X15 * 3 + X08 - X10 - (X11 + X12 + X13);

   int64_t S = 0;

   uint32_t R0 = 0, R1 = 0;

   S += S0;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S1;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 0, R0, R1);

   S += S2;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S3;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 2, R0, R1);

   S += S4;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S5;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 4, R0, R1);

   S += S6;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S7;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;
   set_words(xw, 6, R0, R1);

   S += 5;  // the top digits of 6*P-256

   /*
   This is a table of (i*P-256) % 2**256 for i in 1...10
   */
   static const constinit std::array<word, p256_limbs> p256_mults[11] = {
      hex_to_words<word>("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
      hex_to_words<word>("FFFFFFFE00000002000000000000000000000001FFFFFFFFFFFFFFFFFFFFFFFE"),
      hex_to_words<word>("FFFFFFFD00000003000000000000000000000002FFFFFFFFFFFFFFFFFFFFFFFD"),
      hex_to_words<word>("FFFFFFFC00000004000000000000000000000003FFFFFFFFFFFFFFFFFFFFFFFC"),
      hex_to_words<word>("FFFFFFFB00000005000000000000000000000004FFFFFFFFFFFFFFFFFFFFFFFB"),
      hex_to_words<word>("FFFFFFFA00000006000000000000000000000005FFFFFFFFFFFFFFFFFFFFFFFA"),
      hex_to_words<word>("FFFFFFF900000007000000000000000000000006FFFFFFFFFFFFFFFFFFFFFFF9"),
      hex_to_words<word>("FFFFFFF800000008000000000000000000000007FFFFFFFFFFFFFFFFFFFFFFF8"),
      hex_to_words<word>("FFFFFFF700000009000000000000000000000008FFFFFFFFFFFFFFFFFFFFFFF7"),
      hex_to_words<word>("FFFFFFF60000000A000000000000000000000009FFFFFFFFFFFFFFFFFFFFFFF6"),
      hex_to_words<word>("FFFFFFF50000000B00000000000000000000000AFFFFFFFFFFFFFFFFFFFFFFF5"),
   };

   CT::unpoison(S);
   BOTAN_ASSERT(S >= 0 && S <= 10, "Expected overflow");

   BOTAN_ASSERT_NOMSG(x.size() >= p256_limbs + 1);
   x.mask_bits(256);
   word borrow = bigint_sub2(x.mutable_data(), p256_limbs + 1, p256_mults[S].data(), p256_limbs);
   BOTAN_DEBUG_ASSERT(borrow == 0 || borrow == 1);
   bigint_cnd_add(borrow, x.mutable_data(), p256_limbs + 1, p256_mults[0].data(), p256_limbs);
}

const BigInt& prime_p384() {
   static const BigInt p384(
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
   return p384;
}

void redc_p384(BigInt& x, secure_vector<word>& ws) {
   BOTAN_DEBUG_ASSERT(x.is_positive());

   BOTAN_UNUSED(ws);

   static const size_t p384_limbs = (BOTAN_MP_WORD_BITS == 32) ? 12 : 6;

   x.grow_to(2 * p384_limbs);
   word* xw = x.mutable_data();

   const int64_t X00 = get_uint32(xw, 0);
   const int64_t X01 = get_uint32(xw, 1);
   const int64_t X02 = get_uint32(xw, 2);
   const int64_t X03 = get_uint32(xw, 3);
   const int64_t X04 = get_uint32(xw, 4);
   const int64_t X05 = get_uint32(xw, 5);
   const int64_t X06 = get_uint32(xw, 6);
   const int64_t X07 = get_uint32(xw, 7);
   const int64_t X08 = get_uint32(xw, 8);
   const int64_t X09 = get_uint32(xw, 9);
   const int64_t X10 = get_uint32(xw, 10);
   const int64_t X11 = get_uint32(xw, 11);
   const int64_t X12 = get_uint32(xw, 12);
   const int64_t X13 = get_uint32(xw, 13);
   const int64_t X14 = get_uint32(xw, 14);
   const int64_t X15 = get_uint32(xw, 15);
   const int64_t X16 = get_uint32(xw, 16);
   const int64_t X17 = get_uint32(xw, 17);
   const int64_t X18 = get_uint32(xw, 18);
   const int64_t X19 = get_uint32(xw, 19);
   const int64_t X20 = get_uint32(xw, 20);
   const int64_t X21 = get_uint32(xw, 21);
   const int64_t X22 = get_uint32(xw, 22);
   const int64_t X23 = get_uint32(xw, 23);

   // One copy of P-384 is added to prevent underflow
   const int64_t S0 = 0xFFFFFFFF + X00 + X12 + X20 + X21 - X23;
   const int64_t S1 = 0x00000000 + X01 + X13 + X22 + X23 - X12 - X20;
   const int64_t S2 = 0x00000000 + X02 + X14 + X23 - X13 - X21;
   const int64_t S3 = 0xFFFFFFFF + X03 + X12 + X15 + X20 + X21 - X14 - X22 - X23;
   const int64_t S4 = 0xFFFFFFFE + X04 + X12 + X13 + X16 + X20 + X21 * 2 + X22 - X15 - X23 * 2;
   const int64_t S5 = 0xFFFFFFFF + X05 + X13 + X14 + X17 + X21 + X22 * 2 + X23 - X16;
   const int64_t S6 = 0xFFFFFFFF + X06 + X14 + X15 + X18 + X22 + X23 * 2 - X17;
   const int64_t S7 = 0xFFFFFFFF + X07 + X15 + X16 + X19 + X23 - X18;
   const int64_t S8 = 0xFFFFFFFF + X08 + X16 + X17 + X20 - X19;
   const int64_t S9 = 0xFFFFFFFF + X09 + X17 + X18 + X21 - X20;
   const int64_t SA = 0xFFFFFFFF + X10 + X18 + X19 + X22 - X21;
   const int64_t SB = 0xFFFFFFFF + X11 + X19 + X20 + X23 - X22;

   int64_t S = 0;

   uint32_t R0 = 0, R1 = 0;

   S += S0;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S1;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 0, R0, R1);

   S += S2;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S3;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 2, R0, R1);

   S += S4;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S5;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 4, R0, R1);

   S += S6;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S7;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 6, R0, R1);

   S += S8;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += S9;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 8, R0, R1);

   S += SA;
   R0 = static_cast<uint32_t>(S);
   S >>= 32;

   S += SB;
   R1 = static_cast<uint32_t>(S);
   S >>= 32;

   set_words(xw, 10, R0, R1);

   /*
   This is a table of (i*P-384) % 2**384 for i in 1...4
   */
   static const constinit std::array<word, p384_limbs> p384_mults[5] = {
      hex_to_words<word>(
         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
      hex_to_words<word>(
         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDFFFFFFFE0000000000000001FFFFFFFE"),
      hex_to_words<word>(
         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCFFFFFFFD0000000000000002FFFFFFFD"),
      hex_to_words<word>(
         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFFFFC0000000000000003FFFFFFFC"),
      hex_to_words<word>(
         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAFFFFFFFB0000000000000004FFFFFFFB"),
   };

   CT::unpoison(S);
   BOTAN_ASSERT(S >= 0 && S <= 4, "Expected overflow");

   BOTAN_ASSERT_NOMSG(x.size() >= p384_limbs + 1);
   x.mask_bits(384);
   word borrow = bigint_sub2(x.mutable_data(), p384_limbs + 1, p384_mults[S].data(), p384_limbs);
   BOTAN_DEBUG_ASSERT(borrow == 0 || borrow == 1);
   bigint_cnd_add(borrow, x.mutable_data(), p384_limbs + 1, p384_mults[0].data(), p384_limbs);
}

}  // namespace Botan

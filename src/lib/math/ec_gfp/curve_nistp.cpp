/*
* NIST prime reductions
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/curve_nistp.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/mp_asmi.h>

namespace Botan {

namespace {

void normalize(const BigInt& p, BigInt& x, secure_vector<word>& ws, size_t bound)
   {
   const word* prime = p.data();
   const size_t p_words = p.sig_words();

   while(x.is_negative())
      x += p;

   // TODO: provide a high level function for this compare-and-sub operation
   x.grow_to(p_words + 1);

   if(ws.size() < p_words + 1)
      ws.resize(p_words + 1);

   for(size_t i = 0; bound == 0 || i < bound; ++i)
      {
      const word* xd = x.data();
      word borrow = 0;

      for(size_t j = 0; j != p_words; ++j)
         {
         ws[j] = word_sub(xd[j], prime[j], &borrow);
         }

      ws[p_words] = word_sub(xd[p_words], 0, &borrow);

      if(borrow)
         break;

      x.swap_reg(ws);
      }
   }

}

const BigInt& prime_p521()
   {
   static const BigInt p521("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

   return p521;
   }

void redc_p521(BigInt& x, secure_vector<word>& ws)
   {
   const size_t p_full_words = 521 / MP_WORD_BITS;
   const size_t p_top_bits = 521 % MP_WORD_BITS;
   const size_t p_words = p_full_words + 1;

   const size_t x_sw = x.sig_words();

   if(x_sw < p_words)
      return; // already smaller

   if(ws.size() < p_words + 1)
      ws.resize(p_words + 1);

   clear_mem(ws.data(), ws.size());
   bigint_shr2(ws.data(), x.data(), x_sw, p_full_words, p_top_bits);

   x.mask_bits(521);

   word carry = bigint_add3_nc(x.mutable_data(), x.data(), p_words, ws.data(), p_words);
   BOTAN_ASSERT_EQUAL(carry, 0, "Final final carry in P-521 reduction");

   normalize(prime_p521(), x, ws, 1);
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

   normalize(prime_p192(), x, ws, 3);
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

   normalize(prime_p224(), x, ws, 3);
   }

const BigInt& prime_p256()
   {
   static const BigInt p256("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
   return p256;
   }

void redc_p256(BigInt& x, secure_vector<word>& ws)
   {
   const uint32_t X8 = get_uint32_t(x, 8);
   const uint32_t X9 = get_uint32_t(x, 9);
   const uint32_t X10 = get_uint32_t(x, 10);
   const uint32_t X11 = get_uint32_t(x, 11);
   const uint32_t X12 = get_uint32_t(x, 12);
   const uint32_t X13 = get_uint32_t(x, 13);
   const uint32_t X14 = get_uint32_t(x, 14);
   const uint32_t X15 = get_uint32_t(x, 15);

   x.mask_bits(256);

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

   S += 5;
   set_uint32_t(x, 8, S);

   BOTAN_ASSERT_EQUAL(S >> 32, 0, "No underflow");

   #if 0
   if(S >= 2)
      {
      BOTAN_ASSERT(S <= 10, "Expected overflow");
      static const BigInt P256_mults[9] = {
         2*CurveGFp_P256::prime(),
         3*CurveGFp_P256::prime(),
         4*CurveGFp_P256::prime(),
         5*CurveGFp_P256::prime(),
         6*CurveGFp_P256::prime(),
         7*CurveGFp_P256::prime(),
         8*CurveGFp_P256::prime(),
         9*CurveGFp_P256::prime(),
         10*CurveGFp_P256::prime()
      };
      x -= P256_mults[S - 2];
      }
   #endif

   normalize(prime_p256(), x, ws, 10);
   }

const BigInt& prime_p384()
   {
   static const BigInt p384("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
   return p384;
   }

void redc_p384(BigInt& x, secure_vector<word>& ws)
   {
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
   BOTAN_ASSERT_EQUAL(S >> 32, 0, "No underflow");
   set_uint32_t(x, 12, S);

   #if 0
   if(S >= 2)
      {
      BOTAN_ASSERT(S <= 4, "Expected overflow");

      static const BigInt P384_mults[3] = {
         2*CurveGFp_P384::prime(),
         3*CurveGFp_P384::prime(),
         4*CurveGFp_P384::prime()
      };

      x -= P384_mults[S - 2];
      }
   #endif

   normalize(prime_p384(), x, ws, 4);
   }

#endif


}

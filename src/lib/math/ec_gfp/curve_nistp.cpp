/*
* NIST curve reduction
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/curve_nistp.h>
#include <botan/internal/mp_core.h>

namespace Botan {

void CurveGFp_NIST::curve_mul(BigInt& z, const BigInt& x, const BigInt& y,
                              secure_vector<word>& ws) const
   {
   if(x.is_zero() || y.is_zero())
      {
      z = 0;
      return;
      }

   const size_t p_words = get_p_words();
   const size_t output_size = 2*p_words + 1;
   ws.resize(2*(p_words+2));

   z.grow_to(output_size);
   z.clear();

   bigint_mul(z.mutable_data(), output_size, ws.data(),
              x.data(), x.size(), x.sig_words(),
              y.data(), y.size(), y.sig_words());

   this->redc(z, ws);
   }

void CurveGFp_NIST::curve_sqr(BigInt& z, const BigInt& x,
                              secure_vector<word>& ws) const
   {
   if(x.is_zero())
      {
      z = 0;
      return;
      }

   const size_t p_words = get_p_words();
   const size_t output_size = 2*p_words + 1;

   ws.resize(2*(p_words+2));

   z.grow_to(output_size);
   z.clear();

   bigint_sqr(z.mutable_data(), output_size, ws.data(),
              x.data(), x.size(), x.sig_words());

   this->redc(z, ws);
   }

//static
const BigInt& CurveGFp_P521::prime()
   {
   static const BigInt p521("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

   return p521;
   }

void CurveGFp_P521::redc(BigInt& x, secure_vector<word>& ws) const
   {
   const size_t p_words = get_p_words();

   const size_t shift_words = 521 / MP_WORD_BITS,
                shift_bits  = 521 % MP_WORD_BITS;

   const size_t x_sw = x.sig_words();

   if(x_sw < p_words)
      return; // already smaller

   if(ws.size() < p_words + 1)
      ws.resize(p_words + 1);

   clear_mem(ws.data(), ws.size());
   bigint_shr2(ws.data(), x.data(), x_sw, shift_words, shift_bits);

   x.mask_bits(521);

   bigint_add3(x.mutable_data(), x.data(), p_words, ws.data(), p_words);

   normalize(x, ws, max_redc_subtractions());
   }

#if defined(BOTAN_HAS_CURVEGFP_NISTP_M32)

namespace {

/**
* Treating this MPI as a sequence of 32-bit words in big-endian
* order, return word i (or 0 if out of range)
*/
inline u32bit get_u32bit(const BigInt& x, size_t i)
   {
#if (BOTAN_MP_WORD_BITS == 32)
   return x.word_at(i);
#elif (BOTAN_MP_WORD_BITS == 64)
   return (x.word_at(i/2) >> ((i % 2)*32));
#else
  #error "Not implemented"
#endif
   }

/**
* Treating this MPI as a sequence of 32-bit words in big-endian
* order, set word i to the value x
*/
template<typename T>
inline void set_u32bit(BigInt& x, size_t i, T v_in)
   {
   const u32bit v = static_cast<u32bit>(v_in);
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

//static
const BigInt& CurveGFp_P192::prime()
   {
   static const BigInt p192("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
   return p192;
   }

void CurveGFp_P192::redc(BigInt& x, secure_vector<word>& ws) const
   {
   const u32bit X6 = get_u32bit(x, 6);
   const u32bit X7 = get_u32bit(x, 7);
   const u32bit X8 = get_u32bit(x, 8);
   const u32bit X9 = get_u32bit(x, 9);
   const u32bit X10 = get_u32bit(x, 10);
   const u32bit X11 = get_u32bit(x, 11);

   x.mask_bits(192);

   u64bit S = 0;

   S += get_u32bit(x, 0);
   S += X6;
   S += X10;
   set_u32bit(x, 0, S);
   S >>= 32;

   S += get_u32bit(x, 1);
   S += X7;
   S += X11;
   set_u32bit(x, 1, S);
   S >>= 32;

   S += get_u32bit(x, 2);
   S += X6;
   S += X8;
   S += X10;
   set_u32bit(x, 2, S);
   S >>= 32;

   S += get_u32bit(x, 3);
   S += X7;
   S += X9;
   S += X11;
   set_u32bit(x, 3, S);
   S >>= 32;

   S += get_u32bit(x, 4);
   S += X8;
   S += X10;
   set_u32bit(x, 4, S);
   S >>= 32;

   S += get_u32bit(x, 5);
   S += X9;
   S += X11;
   set_u32bit(x, 5, S);
   S >>= 32;

   set_u32bit(x, 6, S);

   // No underflow possible

   normalize(x, ws, max_redc_subtractions());
   }

//static
const BigInt& CurveGFp_P224::prime()
   {
   static const BigInt p224("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
   return p224;
   }

void CurveGFp_P224::redc(BigInt& x, secure_vector<word>& ws) const
   {
   const u32bit X7 = get_u32bit(x, 7);
   const u32bit X8 = get_u32bit(x, 8);
   const u32bit X9 = get_u32bit(x, 9);
   const u32bit X10 = get_u32bit(x, 10);
   const u32bit X11 = get_u32bit(x, 11);
   const u32bit X12 = get_u32bit(x, 12);
   const u32bit X13 = get_u32bit(x, 13);

   x.mask_bits(224);

   // One full copy of P224 is added, so the result is always positive

   int64_t S = 0;

   S += get_u32bit(x, 0);
   S += 1;
   S -= X7;
   S -= X11;
   set_u32bit(x, 0, S);
   S >>= 32;

   S += get_u32bit(x, 1);
   S -= X8;
   S -= X12;
   set_u32bit(x, 1, S);
   S >>= 32;

   S += get_u32bit(x, 2);
   S -= X9;
   S -= X13;
   set_u32bit(x, 2, S);
   S >>= 32;

   S += get_u32bit(x, 3);
   S += 0xFFFFFFFF;
   S += X7;
   S += X11;
   S -= X10;
   set_u32bit(x, 3, S);
   S >>= 32;

   S += get_u32bit(x, 4);
   S += 0xFFFFFFFF;
   S += X8;
   S += X12;
   S -= X11;
   set_u32bit(x, 4, S);
   S >>= 32;

   S += get_u32bit(x, 5);
   S += 0xFFFFFFFF;
   S += X9;
   S += X13;
   S -= X12;
   set_u32bit(x, 5, S);
   S >>= 32;

   S += get_u32bit(x, 6);
   S += 0xFFFFFFFF;
   S += X10;
   S -= X13;
   set_u32bit(x, 6, S);
   S >>= 32;
   set_u32bit(x, 7, S);

   BOTAN_ASSERT_EQUAL(S >> 32, 0, "No underflow");

   normalize(x, ws, max_redc_subtractions());
   }

//static
const BigInt& CurveGFp_P256::prime()
   {
   static const BigInt p256("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
   return p256;
   }

void CurveGFp_P256::redc(BigInt& x, secure_vector<word>& ws) const
   {
   const u32bit X8 = get_u32bit(x, 8);
   const u32bit X9 = get_u32bit(x, 9);
   const u32bit X10 = get_u32bit(x, 10);
   const u32bit X11 = get_u32bit(x, 11);
   const u32bit X12 = get_u32bit(x, 12);
   const u32bit X13 = get_u32bit(x, 13);
   const u32bit X14 = get_u32bit(x, 14);
   const u32bit X15 = get_u32bit(x, 15);

   x.mask_bits(256);

   int64_t S = 0;

   // Adds 6 * P-256 to prevent underflow

   S = get_u32bit(x, 0);
   S += 0xFFFFFFFA;
   S += X8;
   S += X9;
   S -= X11;
   S -= X12;
   S -= X13;
   S -= X14;
   set_u32bit(x, 0, S);
   S >>= 32;

   S += get_u32bit(x, 1);
   S += 0xFFFFFFFF;
   S += X9;
   S += X10;
   S -= X12;
   S -= X13;
   S -= X14;
   S -= X15;
   set_u32bit(x, 1, S);
   S >>= 32;

   S += get_u32bit(x, 2);
   S += 0xFFFFFFFF;
   S += X10;
   S += X11;
   S -= X13;
   S -= X14;
   S -= X15;
   set_u32bit(x, 2, S);
   S >>= 32;

   S += get_u32bit(x, 3);
   S += 5;
   S += X11;
   S += X11;
   S += X12;
   S += X12;
   S += X13;
   S -= X15;
   S -= X8;
   S -= X9;
   set_u32bit(x, 3, S);
   S >>= 32;

   S += get_u32bit(x, 4);
   S += X12;
   S += X12;
   S += X13;
   S += X13;
   S += X14;
   S -= X9;
   S -= X10;
   set_u32bit(x, 4, S);
   S >>= 32;

   S += get_u32bit(x, 5);
   S += X13;
   S += X13;
   S += X14;
   S += X14;
   S += X15;
   S -= X10;
   S -= X11;
   set_u32bit(x, 5, S);
   S >>= 32;

   S += get_u32bit(x, 6);
   S += 6;
   S += X14;
   S += X14;
   S += X15;
   S += X15;
   S += X14;
   S += X13;
   S -= X8;
   S -= X9;
   set_u32bit(x, 6, S);
   S >>= 32;

   S += get_u32bit(x, 7);
   S += 0xFFFFFFFA;
   S += X15;
   S += X15;
   S += X15;
   S += X8;
   S -= X10;
   S -= X11;
   S -= X12;
   S -= X13;
   set_u32bit(x, 7, S);
   S >>= 32;

   S += 5;
   set_u32bit(x, 8, S);

   BOTAN_ASSERT_EQUAL(S >> 32, 0, "No underflow");

   if(S >= 2)
      {
      BOTAN_ASSERT(S <= 10, "Expected overflow");
      static const BigInt P256_mults[9] = {
         2*get_p(),
         3*get_p(),
         4*get_p(),
         5*get_p(),
         6*get_p(),
         7*get_p(),
         8*get_p(),
         9*get_p(),
         10*get_p()
      };
      x -= P256_mults[S - 2];
      }

   normalize(x, ws, max_redc_subtractions());
   }

//static
const BigInt& CurveGFp_P384::prime()
   {
   static const BigInt p384("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
   return p384;
   }

void CurveGFp_P384::redc(BigInt& x, secure_vector<word>& ws) const
   {
   const u32bit X12 = get_u32bit(x, 12);
   const u32bit X13 = get_u32bit(x, 13);
   const u32bit X14 = get_u32bit(x, 14);
   const u32bit X15 = get_u32bit(x, 15);
   const u32bit X16 = get_u32bit(x, 16);
   const u32bit X17 = get_u32bit(x, 17);
   const u32bit X18 = get_u32bit(x, 18);
   const u32bit X19 = get_u32bit(x, 19);
   const u32bit X20 = get_u32bit(x, 20);
   const u32bit X21 = get_u32bit(x, 21);
   const u32bit X22 = get_u32bit(x, 22);
   const u32bit X23 = get_u32bit(x, 23);

   x.mask_bits(384);

   int64_t S = 0;

   // One copy of P-384 is added to prevent underflow
   S = get_u32bit(x, 0);
   S += 0xFFFFFFFF;
   S += X12;
   S += X21;
   S += X20;
   S -= X23;
   set_u32bit(x, 0, S);
   S >>= 32;

   S += get_u32bit(x, 1);
   S += X13;
   S += X22;
   S += X23;
   S -= X12;
   S -= X20;
   set_u32bit(x, 1, S);
   S >>= 32;

   S += get_u32bit(x, 2);
   S += X14;
   S += X23;
   S -= X13;
   S -= X21;
   set_u32bit(x, 2, S);
   S >>= 32;

   S += get_u32bit(x, 3);
   S += 0xFFFFFFFF;
   S += X15;
   S += X12;
   S += X20;
   S += X21;
   S -= X14;
   S -= X22;
   S -= X23;
   set_u32bit(x, 3, S);
   S >>= 32;

   S += get_u32bit(x, 4);
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
   set_u32bit(x, 4, S);
   S >>= 32;

   S += get_u32bit(x, 5);
   S += 0xFFFFFFFF;
   S += X22;
   S += X22;
   S += X17;
   S += X14;
   S += X13;
   S += X21;
   S += X23;
   S -= X16;
   set_u32bit(x, 5, S);
   S >>= 32;

   S += get_u32bit(x, 6);
   S += 0xFFFFFFFF;
   S += X23;
   S += X23;
   S += X18;
   S += X15;
   S += X14;
   S += X22;
   S -= X17;
   set_u32bit(x, 6, S);
   S >>= 32;

   S += get_u32bit(x, 7);
   S += 0xFFFFFFFF;
   S += X19;
   S += X16;
   S += X15;
   S += X23;
   S -= X18;
   set_u32bit(x, 7, S);
   S >>= 32;

   S += get_u32bit(x, 8);
   S += 0xFFFFFFFF;
   S += X20;
   S += X17;
   S += X16;
   S -= X19;
   set_u32bit(x, 8, S);
   S >>= 32;

   S += get_u32bit(x, 9);
   S += 0xFFFFFFFF;
   S += X21;
   S += X18;
   S += X17;
   S -= X20;
   set_u32bit(x, 9, S);
   S >>= 32;

   S += get_u32bit(x, 10);
   S += 0xFFFFFFFF;
   S += X22;
   S += X19;
   S += X18;
   S -= X21;
   set_u32bit(x, 10, S);
   S >>= 32;

   S += get_u32bit(x, 11);
   S += 0xFFFFFFFF;
   S += X23;
   S += X20;
   S += X19;
   S -= X22;
   set_u32bit(x, 11, S);
   S >>= 32;
   BOTAN_ASSERT_EQUAL(S >> 32, 0, "No underflow");
   set_u32bit(x, 12, S);

   if(S >= 2)
      {
      BOTAN_ASSERT(S <= 4, "Expected overflow");

      static const BigInt P384_mults[3] = {
         2*get_p(),
         3*get_p(),
         4*get_p()
      };

      x -= P384_mults[S - 2];
      }

   normalize(x, ws, max_redc_subtractions());
   }

#endif


}

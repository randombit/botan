/*
* NIST curve reduction
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/curve_nistp.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/rounding.h>
#include <botan/hex.h>

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

   bigint_mul(z.mutable_data(), output_size, &ws[0],
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

   bigint_sqr(z.mutable_data(), output_size, &ws[0],
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

   clear_mem(&ws[0], ws.size());
   bigint_shr2(&ws[0], x.data(), x_sw, shift_words, shift_bits);

   x.mask_bits(521);

   bigint_add3(x.mutable_data(), x.data(), p_words, &ws[0], p_words);

   normalize(x, ws, max_redc_subtractions());
   }

}

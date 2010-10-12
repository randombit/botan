/*
* Division Algorithm
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/divide.h>
#include <botan/internal/mp_core.h>

namespace Botan {

namespace {

/*
* Handle signed operands, if necessary
*/
void sign_fixup(const BigInt& x, const BigInt& y, BigInt& q, BigInt& r)
   {
   if(x.sign() == BigInt::Negative)
      {
      q.flip_sign();
      if(r.is_nonzero()) { --q; r = y.abs() - r; }
      }
   if(y.sign() == BigInt::Negative)
      q.flip_sign();
   }

}

/*
* Solve x = q * y + r
*/
void divide(const BigInt& x, const BigInt& y_arg, BigInt& q, BigInt& r)
   {
   if(y_arg.is_zero())
      throw BigInt::DivideByZero();

   BigInt y = y_arg;
   const size_t y_words = y.sig_words();

   r = x;
   q = 0;

   r.set_sign(BigInt::Positive);
   y.set_sign(BigInt::Positive);

   s32bit compare = r.cmp(y);

   if(compare == 0)
      {
      q = 1;
      r = 0;
      }
   else if(compare > 0)
      {
      size_t shifts = 0;
      word y_top = y[y.sig_words()-1];
      while(y_top < MP_WORD_TOP_BIT) { y_top <<= 1; ++shifts; }
      y <<= shifts;
      r <<= shifts;

      const size_t n = r.sig_words() - 1, t = y_words - 1;

      if(n < t)
         throw Internal_Error("BigInt division word sizes");

      q.get_reg().resize(n - t + 1);
      if(n <= t)
         {
         while(r > y) { r -= y; ++q; }
         r >>= shifts;
         sign_fixup(x, y_arg, q, r);
         return;
         }

      BigInt temp = y << (MP_WORD_BITS * (n-t));

      while(r >= temp) { r -= temp; ++q[n-t]; }

      for(size_t j = n; j != t; --j)
         {
         const word x_j0  = r.word_at(j);
         const word x_j1 = r.word_at(j-1);
         const word y_t  = y.word_at(t);

         if(x_j0 == y_t)
            q[j-t-1] = MP_WORD_MAX;
         else
            q[j-t-1] = bigint_divop(x_j0, x_j1, y_t);

         while(bigint_divcore(q[j-t-1], y_t, y.word_at(t-1),
                              x_j0, x_j1, r.word_at(j-2)))
            --q[j-t-1];

         r -= (q[j-t-1] * y) << (MP_WORD_BITS * (j-t-1));
         if(r.is_negative())
            {
            r += y << (MP_WORD_BITS * (j-t-1));
            --q[j-t-1];
            }
         }
      r >>= shifts;
      }

   sign_fixup(x, y_arg, q, r);
   }

}

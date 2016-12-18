/*
* BigInt Binary Operators
* (C) 1999-2007 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>
#include <botan/divide.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

namespace Botan {

/*
* Addition Operator
*/
BigInt operator+(const BigInt& x, const BigInt& y)
   {
   const size_t x_sw = x.sig_words(), y_sw = y.sig_words();

   BigInt z(x.sign(), std::max(x_sw, y_sw) + 1);

   if((x.sign() == y.sign()))
      bigint_add3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
   else
      {
      int32_t relative_size = bigint_cmp(x.data(), x_sw, y.data(), y_sw);

      if(relative_size < 0)
         {
         bigint_sub3(z.mutable_data(), y.data(), y_sw, x.data(), x_sw);
         z.set_sign(y.sign());
         }
      else if(relative_size == 0)
         z.set_sign(BigInt::Positive);
      else if(relative_size > 0)
         bigint_sub3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
      }

   return z;
   }

/*
* Subtraction Operator
*/
BigInt operator-(const BigInt& x, const BigInt& y)
   {
   const size_t x_sw = x.sig_words(), y_sw = y.sig_words();

   int32_t relative_size = bigint_cmp(x.data(), x_sw, y.data(), y_sw);

   BigInt z(BigInt::Positive, std::max(x_sw, y_sw) + 1);

   if(relative_size < 0)
      {
      if(x.sign() == y.sign())
         bigint_sub3(z.mutable_data(), y.data(), y_sw, x.data(), x_sw);
      else
         bigint_add3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
      z.set_sign(y.reverse_sign());
      }
   else if(relative_size == 0)
      {
      if(x.sign() != y.sign())
         bigint_shl2(z.mutable_data(), x.data(), x_sw, 0, 1);
      }
   else if(relative_size > 0)
      {
      if(x.sign() == y.sign())
         bigint_sub3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
      else
         bigint_add3(z.mutable_data(), x.data(), x_sw, y.data(), y_sw);
      z.set_sign(x.sign());
      }
   return z;
   }

/*
* Multiplication Operator
*/
BigInt operator*(const BigInt& x, const BigInt& y)
   {
   const size_t x_sw = x.sig_words(), y_sw = y.sig_words();

   BigInt z(BigInt::Positive, x.size() + y.size());

   if(x_sw == 1 && y_sw)
      bigint_linmul3(z.mutable_data(), y.data(), y_sw, x.word_at(0));
   else if(y_sw == 1 && x_sw)
      bigint_linmul3(z.mutable_data(), x.data(), x_sw, y.word_at(0));
   else if(x_sw && y_sw)
      {
      secure_vector<word> workspace(z.size());
      bigint_mul(z, x, y, workspace.data());
      }

   if(x_sw && y_sw && x.sign() != y.sign())
      z.flip_sign();
   return z;
   }

/*
* Division Operator
*/
BigInt operator/(const BigInt& x, const BigInt& y)
   {
   BigInt q, r;
   divide(x, y, q, r);
   return q;
   }

/*
* Modulo Operator
*/
BigInt operator%(const BigInt& n, const BigInt& mod)
   {
   if(mod.is_zero())
      throw BigInt::DivideByZero();
   if(mod.is_negative())
      throw Invalid_Argument("BigInt::operator%: modulus must be > 0");
   if(n.is_positive() && mod.is_positive() && n < mod)
      return n;

   BigInt q, r;
   divide(n, mod, q, r);
   return r;
   }

/*
* Modulo Operator
*/
word operator%(const BigInt& n, word mod)
   {
   if(mod == 0)
      throw BigInt::DivideByZero();

   if(is_power_of_2(mod))
      return (n.word_at(0) & (mod - 1));

   word remainder = 0;

   for(size_t j = n.sig_words(); j > 0; --j)
      remainder = bigint_modop(remainder, n.word_at(j-1), mod);

   if(remainder && n.sign() == BigInt::Negative)
      return mod - remainder;
   return remainder;
   }

/*
* Left Shift Operator
*/
BigInt operator<<(const BigInt& x, size_t shift)
   {
   if(shift == 0)
      return x;

   const size_t shift_words = shift / MP_WORD_BITS,
                shift_bits  = shift % MP_WORD_BITS;

   const size_t x_sw = x.sig_words();

   BigInt y(x.sign(), x_sw + shift_words + (shift_bits ? 1 : 0));
   bigint_shl2(y.mutable_data(), x.data(), x_sw, shift_words, shift_bits);
   return y;
   }

/*
* Right Shift Operator
*/
BigInt operator>>(const BigInt& x, size_t shift)
   {
   if(shift == 0)
      return x;
   if(x.bits() <= shift)
      return 0;

   const size_t shift_words = shift / MP_WORD_BITS,
                shift_bits  = shift % MP_WORD_BITS,
                x_sw = x.sig_words();

   BigInt y(x.sign(), x_sw - shift_words);
   bigint_shr2(y.mutable_data(), x.data(), x_sw, shift_words, shift_bits);
   return y;
   }

}

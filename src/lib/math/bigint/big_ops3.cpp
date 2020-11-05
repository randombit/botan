/*
* BigInt Binary Operators
* (C) 1999-2007,2018 Jack Lloyd
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

//static
BigInt BigInt::add2(const BigInt& x, const word y[], size_t y_words, BigInt::Sign y_sign)
   {
   const size_t x_sw = x.sig_words();

   BigInt z(x.sign(), std::max(x_sw, y_words) + 1);

   if(x.sign() == y_sign)
      {
      bigint_add3(z.mutable_data(), x.data(), x_sw, y, y_words);
      }
   else
      {
      const int32_t relative_size = bigint_sub_abs(z.mutable_data(), x.data(), x_sw, y, y_words);

      //z.sign_fixup(relative_size, y_sign);
      if(relative_size < 0)
         z.set_sign(y_sign);
      else if(relative_size == 0)
         z.set_sign(BigInt::Positive);
      }

   return z;
   }

/*
* Multiplication Operator
*/
BigInt operator*(const BigInt& x, const BigInt& y)
   {
   const size_t x_sw = x.sig_words();
   const size_t y_sw = y.sig_words();

   BigInt z(BigInt::Positive, x.size() + y.size());

   if(x_sw == 1 && y_sw)
      bigint_linmul3(z.mutable_data(), y.data(), y_sw, x.word_at(0));
   else if(y_sw == 1 && x_sw)
      bigint_linmul3(z.mutable_data(), x.data(), x_sw, y.word_at(0));
   else if(x_sw && y_sw)
      {
      secure_vector<word> workspace(z.size());

      bigint_mul(z.mutable_data(), z.size(),
                 x.data(), x.size(), x_sw,
                 y.data(), y.size(), y_sw,
                 workspace.data(), workspace.size());
      }

   z.cond_flip_sign(x_sw > 0 && y_sw > 0 && x.sign() != y.sign());

   return z;
   }

/*
* Multiplication Operator
*/
BigInt operator*(const BigInt& x, word y)
   {
   const size_t x_sw = x.sig_words();

   BigInt z(BigInt::Positive, x_sw + 1);

   if(x_sw && y)
      {
      bigint_linmul3(z.mutable_data(), x.data(), x_sw, y);
      z.set_sign(x.sign());
      }

   return z;
   }

/*
* Division Operator
*/
BigInt operator/(const BigInt& x, const BigInt& y)
   {
   if(y.sig_words() == 1)
      {
      return x / y.word_at(0);
      }

   BigInt q, r;
   vartime_divide(x, y, q, r);
   return q;
   }

/*
* Division Operator
*/
BigInt operator/(const BigInt& x, word y)
   {
   if(y == 0)
      throw BigInt::DivideByZero();
   else if(y == 1)
      return x;
   else if(y == 2)
      return (x >> 1);
   else if(y <= 255)
      {
      BigInt q;
      uint8_t r;
      ct_divide_u8(x, static_cast<uint8_t>(y), q, r);
      return q;
      }

   BigInt q, r;
   vartime_divide(x, y, q, r);
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

   if(mod.sig_words() == 1)
      {
      return n % mod.word_at(0);
      }

   BigInt q, r;
   vartime_divide(n, mod, q, r);
   return r;
   }

/*
* Modulo Operator
*/
word operator%(const BigInt& n, word mod)
   {
   if(mod == 0)
      throw BigInt::DivideByZero();

   if(mod == 1)
      return 0;

   word remainder = 0;

   if(is_power_of_2(mod))
      {
      remainder = (n.word_at(0) & (mod - 1));
      }
   else
      {
      const size_t sw = n.sig_words();
      for(size_t i = sw; i > 0; --i)
         {
         remainder = bigint_modop(remainder, n.word_at(i-1), mod);
         }
      }

   if(remainder && n.sign() == BigInt::Negative)
      return mod - remainder;
   return remainder;
   }

/*
* Left Shift Operator
*/
BigInt operator<<(const BigInt& x, size_t shift)
   {
   const size_t shift_words = shift / BOTAN_MP_WORD_BITS,
                shift_bits  = shift % BOTAN_MP_WORD_BITS;

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
   const size_t shift_words = shift / BOTAN_MP_WORD_BITS;
   const size_t shift_bits  = shift % BOTAN_MP_WORD_BITS;
   const size_t x_sw = x.sig_words();

   BigInt y(x.sign(), x_sw - shift_words);
   bigint_shr2(y.mutable_data(), x.data(), x_sw, shift_words, shift_bits);

   if(x.is_negative() && y.is_zero())
      y.set_sign(BigInt::Positive);

   return y;
   }

}

/*
* BigInt Assignment Operators
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/bigint.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

namespace Botan {

/*
* Addition Operator
*/
BigInt& BigInt::operator+=(const BigInt& y)
   {
   const size_t x_sw = sig_words(), y_sw = y.sig_words();

   const size_t reg_size = std::max(x_sw, y_sw) + 1;
   grow_to(reg_size);

   if(sign() == y.sign())
      bigint_add2(get_reg(), reg_size - 1, y.data(), y_sw);
   else
      {
      s32bit relative_size = bigint_cmp(data(), x_sw, y.data(), y_sw);

      if(relative_size < 0)
         {
         SecureVector<word> z(reg_size - 1);
         bigint_sub3(z, y.data(), reg_size - 1, data(), x_sw);
         copy_mem(&reg[0], &z[0], z.size());
         set_sign(y.sign());
         }
      else if(relative_size == 0)
         {
         zeroise(reg);
         set_sign(Positive);
         }
      else if(relative_size > 0)
         bigint_sub2(get_reg(), x_sw, y.data(), y_sw);
      }

   return (*this);
   }

/*
* Subtraction Operator
*/
BigInt& BigInt::operator-=(const BigInt& y)
   {
   const size_t x_sw = sig_words(), y_sw = y.sig_words();

   s32bit relative_size = bigint_cmp(data(), x_sw, y.data(), y_sw);

   const size_t reg_size = std::max(x_sw, y_sw) + 1;
   grow_to(reg_size);

   if(relative_size < 0)
      {
      if(sign() == y.sign())
         bigint_sub2_rev(get_reg(), y.data(), y_sw);
      else
         bigint_add2(get_reg(), reg_size - 1, y.data(), y_sw);

      set_sign(y.reverse_sign());
      }
   else if(relative_size == 0)
      {
      if(sign() == y.sign())
         {
         clear();
         set_sign(Positive);
         }
      else
         bigint_shl1(get_reg(), x_sw, 0, 1);
      }
   else if(relative_size > 0)
      {
      if(sign() == y.sign())
         bigint_sub2(get_reg(), x_sw, y.data(), y_sw);
      else
         bigint_add2(get_reg(), reg_size - 1, y.data(), y_sw);
      }

   return (*this);
   }

/*
* Multiplication Operator
*/
BigInt& BigInt::operator*=(const BigInt& y)
   {
   const size_t x_sw = sig_words(), y_sw = y.sig_words();
   set_sign((sign() == y.sign()) ? Positive : Negative);

   if(x_sw == 0 || y_sw == 0)
      {
      clear();
      set_sign(Positive);
      }
   else if(x_sw == 1 && y_sw)
      {
      grow_to(y_sw + 2);
      bigint_linmul3(get_reg(), y.data(), y_sw, word_at(0));
      }
   else if(y_sw == 1 && x_sw)
      {
      grow_to(x_sw + 2);
      bigint_linmul2(get_reg(), x_sw, y.word_at(0));
      }
   else
      {
      grow_to(size() + y.size());

      SecureVector<word> z(data(), x_sw);
      SecureVector<word> workspace(size());

      bigint_mul(get_reg(), size(), workspace,
                 z, z.size(), x_sw,
                 y.data(), y.size(), y_sw);
      }

   return (*this);
   }

/*
* Division Operator
*/
BigInt& BigInt::operator/=(const BigInt& y)
   {
   if(y.sig_words() == 1 && power_of_2(y.word_at(0)))
      (*this) >>= (y.bits() - 1);
   else
      (*this) = (*this) / y;
   return (*this);
   }

/*
* Modulo Operator
*/
BigInt& BigInt::operator%=(const BigInt& mod)
   {
   return (*this = (*this) % mod);
   }

/*
* Modulo Operator
*/
word BigInt::operator%=(word mod)
   {
   if(mod == 0)
      throw BigInt::DivideByZero();
   if(power_of_2(mod))
       {
       word result = (word_at(0) & (mod - 1));
       clear();
       grow_to(2);
       get_reg()[0] = result;
       return result;
       }

   word remainder = 0;

   for(size_t j = sig_words(); j > 0; --j)
      remainder = bigint_modop(remainder, word_at(j-1), mod);
   clear();
   grow_to(2);

   if(remainder && sign() == BigInt::Negative)
      get_reg()[0] = mod - remainder;
   else
      get_reg()[0] = remainder;

   set_sign(BigInt::Positive);

   return word_at(0);
   }

/*
* Left Shift Operator
*/
BigInt& BigInt::operator<<=(size_t shift)
   {
   if(shift)
      {
      const size_t shift_words = shift / MP_WORD_BITS,
                   shift_bits  = shift % MP_WORD_BITS,
                   words = sig_words();

      grow_to(words + shift_words + (shift_bits ? 1 : 0));
      bigint_shl1(get_reg(), words, shift_words, shift_bits);
      }

   return (*this);
   }

/*
* Right Shift Operator
*/
BigInt& BigInt::operator>>=(size_t shift)
   {
   if(shift)
      {
      const size_t shift_words = shift / MP_WORD_BITS,
                   shift_bits  = shift % MP_WORD_BITS;

      bigint_shr1(get_reg(), sig_words(), shift_words, shift_bits);

      if(is_zero())
         set_sign(Positive);
      }

   return (*this);
   }

}

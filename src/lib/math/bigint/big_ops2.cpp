/*
* BigInt Assignment Operators
* (C) 1999-2007 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
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
      bigint_add2(mutable_data(), reg_size - 1, y.data(), y_sw);
   else
      {
      int32_t relative_size = bigint_cmp(data(), x_sw, y.data(), y_sw);

      if(relative_size < 0)
         {
         secure_vector<word> z(reg_size - 1);
         bigint_sub3(z.data(), y.data(), reg_size - 1, data(), x_sw);
         std::swap(m_reg, z);
         set_sign(y.sign());
         }
      else if(relative_size == 0)
         {
         zeroise(m_reg);
         set_sign(Positive);
         }
      else if(relative_size > 0)
         bigint_sub2(mutable_data(), x_sw, y.data(), y_sw);
      }

   return (*this);
   }

/*
* Subtraction Operator
*/
BigInt& BigInt::operator-=(const BigInt& y)
   {
   const size_t x_sw = sig_words(), y_sw = y.sig_words();

   int32_t relative_size = bigint_cmp(data(), x_sw, y.data(), y_sw);

   const size_t reg_size = std::max(x_sw, y_sw) + 1;
   grow_to(reg_size);

   if(relative_size < 0)
      {
      if(sign() == y.sign())
         bigint_sub2_rev(mutable_data(), y.data(), y_sw);
      else
         bigint_add2(mutable_data(), reg_size - 1, y.data(), y_sw);

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
         bigint_shl1(mutable_data(), x_sw, 0, 1);
      }
   else if(relative_size > 0)
      {
      if(sign() == y.sign())
         bigint_sub2(mutable_data(), x_sw, y.data(), y_sw);
      else
         bigint_add2(mutable_data(), reg_size - 1, y.data(), y_sw);
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
      bigint_linmul3(mutable_data(), y.data(), y_sw, word_at(0));
      }
   else if(y_sw == 1 && x_sw)
      {
      grow_to(x_sw + 2);
      bigint_linmul2(mutable_data(), x_sw, y.word_at(0));
      }
   else
      {
      grow_to(size() + y.size());

      secure_vector<word> z(data(), data() + x_sw);
      secure_vector<word> workspace(size());
      bigint_mul(*this, BigInt(*this), y, workspace.data());
      }

   return (*this);
   }

/*
* Division Operator
*/
BigInt& BigInt::operator/=(const BigInt& y)
   {
   if(y.sig_words() == 1 && is_power_of_2(y.word_at(0)))
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

   if(is_power_of_2(mod))
       {
       word result = (word_at(0) & (mod - 1));
       clear();
       grow_to(2);
       m_reg[0] = result;
       return result;
       }

   word remainder = 0;

   for(size_t j = sig_words(); j > 0; --j)
      remainder = bigint_modop(remainder, word_at(j-1), mod);
   clear();
   grow_to(2);

   if(remainder && sign() == BigInt::Negative)
      m_reg[0] = mod - remainder;
   else
      m_reg[0] = remainder;

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
      bigint_shl1(mutable_data(), words, shift_words, shift_bits);
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

      bigint_shr1(mutable_data(), sig_words(), shift_words, shift_bits);

      if(is_zero())
         set_sign(Positive);
      }

   return (*this);
   }

}

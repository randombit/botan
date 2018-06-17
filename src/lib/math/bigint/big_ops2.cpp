/*
* (C) 1999-2007,2018 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

namespace Botan {

BigInt& BigInt::add(const word y[], size_t y_sw, Sign y_sign)
   {
   const size_t x_sw = sig_words();

   if(sign() == y_sign)
      {
      const size_t reg_size = std::max(x_sw, y_sw) + 1;

      if(m_reg.size() < reg_size)
         grow_to(reg_size);

      bigint_add2(mutable_data(), reg_size - 1, y, y_sw);
      }
   else
      {
      const int32_t relative_size = bigint_cmp(data(), x_sw, y, y_sw);

      if(relative_size < 0)
         {
         const size_t reg_size = std::max(x_sw, y_sw);
         grow_to(reg_size);
         bigint_sub2_rev(mutable_data(), y, y_sw);
         set_sign(y_sign);
         }
      else if(relative_size == 0)
         {
         zeroise(m_reg);
         set_sign(Positive);
         }
      else if(relative_size > 0)
         {
         bigint_sub2(mutable_data(), x_sw, y, y_sw);
         }
      }

   return (*this);
   }

BigInt& BigInt::operator+=(const BigInt& y)
   {
   return add(y.data(), y.sig_words(), y.sign());
   }

BigInt& BigInt::operator+=(word y)
   {
   return add(&y, 1, Positive);
   }

BigInt& BigInt::sub(const word y[], size_t y_sw, Sign y_sign)
   {
   const size_t x_sw = sig_words();

   int32_t relative_size = bigint_cmp(data(), x_sw, y, y_sw);

   const size_t reg_size = std::max(x_sw, y_sw) + 1;
   grow_to(reg_size);

   if(relative_size < 0)
      {
      if(sign() == y_sign)
         bigint_sub2_rev(mutable_data(), y, y_sw);
      else
         bigint_add2(mutable_data(), reg_size - 1, y, y_sw);

      set_sign(y_sign == Positive ? Negative : Positive);
      }
   else if(relative_size == 0)
      {
      if(sign() == y_sign)
         {
         clear();
         set_sign(Positive);
         }
      else
         bigint_shl1(mutable_data(), x_sw, 0, 1);
      }
   else if(relative_size > 0)
      {
      if(sign() == y_sign)
         bigint_sub2(mutable_data(), x_sw, y, y_sw);
      else
         bigint_add2(mutable_data(), reg_size - 1, y, y_sw);
      }

   return (*this);
   }

BigInt& BigInt::operator-=(const BigInt& y)
   {
   return sub(y.data(), y.sig_words(), y.sign());
   }

BigInt& BigInt::operator-=(word y)
   {
   return sub(&y, 1, Positive);
   }

BigInt& BigInt::mod_add(const BigInt& s, const BigInt& mod, secure_vector<word>& ws)
   {
   if(this->is_negative() || s.is_negative() || mod.is_negative())
      throw Invalid_Argument("BigInt::mod_add expects all arguments are positive");

   // TODO add optimized version of this
   *this += s;
   this->reduce_below(mod, ws);

   return (*this);
   }

BigInt& BigInt::mod_sub(const BigInt& s, const BigInt& mod, secure_vector<word>& ws)
   {
   if(this->is_negative() || s.is_negative() || mod.is_negative())
      throw Invalid_Argument("BigInt::mod_sub expects all arguments are positive");

   const size_t t_sw = sig_words();
   const size_t s_sw = s.sig_words();
   const size_t mod_sw = mod.sig_words();

   if(t_sw > mod_sw || s_sw > mod_sw)
      throw Invalid_Argument("BigInt::mod_sub args larger than modulus");

   BOTAN_DEBUG_ASSERT(*this < mod);
   BOTAN_DEBUG_ASSERT(s < mod);

   int32_t relative_size = bigint_cmp(data(), t_sw, s.data(), s_sw);

   if(relative_size >= 0)
      {
      // this >= s in which case just subtract
      bigint_sub2(mutable_data(), t_sw, s.data(), s_sw);
      }
   else
      {
      // Otherwise we must sub s and then add p (or add (p - s) as here)

      if(ws.size() < mod_sw)
         ws.resize(mod_sw);

      word borrow = bigint_sub3(ws.data(), mod.data(), mod_sw, s.data(), s_sw);
      BOTAN_ASSERT_NOMSG(borrow == 0);

      if(m_reg.size() < mod_sw)
         grow_to(mod_sw);

      word carry = bigint_add2_nc(mutable_data(), m_reg.size(), ws.data(), mod_sw);
      BOTAN_ASSERT_NOMSG(carry == 0);
      }

   return (*this);
   }

BigInt& BigInt::rev_sub(const word y[], size_t y_sw, secure_vector<word>& ws)
   {
   /*
   *this = BigInt(y, y_sw) - *this;
   return *this;
   */
   if(this->sign() != BigInt::Positive)
      throw Invalid_State("BigInt::sub_rev requires this is positive");

   const size_t x_sw = this->sig_words();

   const int32_t relative_size = bigint_cmp(y, y_sw, this->data(), x_sw);

   ws.resize(std::max(y_sw, x_sw) + 1);
   clear_mem(ws.data(), ws.size());

   if(relative_size < 0)
      {
      bigint_sub3(ws.data(), this->data(), x_sw, y, y_sw);
      this->flip_sign();
      }
   else if(relative_size == 0)
      {
      ws.clear();
      }
   else if(relative_size > 0)
      {
      bigint_sub3(ws.data(), y, y_sw, this->data(), x_sw);
      }

   m_reg.swap(ws);

   return (*this);
   }

/*
* Multiplication Operator
*/
BigInt& BigInt::operator*=(const BigInt& y)
   {
   secure_vector<word> ws;
   return this->mul(y, ws);
   }

BigInt& BigInt::mul(const BigInt& y, secure_vector<word>& ws)
   {
   const size_t x_sw = sig_words();
   const size_t y_sw = y.sig_words();
   set_sign((sign() == y.sign()) ? Positive : Negative);

   if(x_sw == 0 || y_sw == 0)
      {
      clear();
      set_sign(Positive);
      }
   else if(x_sw == 1 && y_sw)
      {
      grow_to(y_sw + 1);
      bigint_linmul3(mutable_data(), y.data(), y_sw, word_at(0));
      }
   else if(y_sw == 1 && x_sw)
      {
      grow_to(x_sw + 1);
      bigint_linmul2(mutable_data(), x_sw, y.word_at(0));
      }
   else
      {
      const size_t new_size = x_sw + y_sw + 1;
      ws.resize(new_size);
      secure_vector<word> z_reg(new_size);

      bigint_mul(z_reg.data(), z_reg.size(),
                 data(), size(), x_sw,
                 y.data(), y.size(), y_sw,
                 ws.data(), ws.size());

      z_reg.swap(m_reg);
      }

   return (*this);
   }

BigInt& BigInt::square(secure_vector<word>& ws)
   {
   const size_t sw = sig_words();

   secure_vector<word> z(2*sw);
   ws.resize(z.size());

   bigint_sqr(z.data(), z.size(),
              data(), size(), sw,
              ws.data(), ws.size());

   swap_reg(z);
   set_sign(BigInt::Positive);

   return (*this);
   }

BigInt& BigInt::operator*=(word y)
   {
   if(y == 0)
      {
      clear();
      set_sign(Positive);
      }

   const size_t x_sw = sig_words();

   if(size() < x_sw + 1)
      grow_to(x_sw + 1);
   bigint_linmul2(mutable_data(), x_sw, y);

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
      const size_t shift_words = shift / BOTAN_MP_WORD_BITS,
                   shift_bits  = shift % BOTAN_MP_WORD_BITS,
                   words = sig_words();

      /*
      * FIXME - if shift_words == 0 && the top shift_bits of the top word
      * are zero then we know that no additional word is needed and can
      * skip the allocation.
      */
      const size_t needed_size = words + shift_words + (shift_bits ? 1 : 0);

      if(m_reg.size() < needed_size)
         grow_to(needed_size);

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
      const size_t shift_words = shift / BOTAN_MP_WORD_BITS,
                   shift_bits  = shift % BOTAN_MP_WORD_BITS;

      bigint_shr1(mutable_data(), sig_words(), shift_words, shift_bits);

      if(is_zero())
         set_sign(Positive);
      }

   return (*this);
   }

}

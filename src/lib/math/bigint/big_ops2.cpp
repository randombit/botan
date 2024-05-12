/*
* (C) 1999-2007,2018 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/mp_core.h>
#include <algorithm>

namespace Botan {

BigInt& BigInt::add(const word y[], size_t y_words, Sign y_sign) {
   const size_t x_sw = sig_words();

   grow_to(std::max(x_sw, y_words) + 1);

   if(sign() == y_sign) {
      bigint_add2(mutable_data(), size() - 1, y, y_words);
   } else {
      const int32_t relative_size = bigint_cmp(_data(), x_sw, y, y_words);

      if(relative_size >= 0) {
         // *this >= y
         bigint_sub2(mutable_data(), x_sw, y, y_words);
      } else {
         // *this < y
         bigint_sub2_rev(mutable_data(), y, y_words);
      }

      //this->sign_fixup(relative_size, y_sign);
      if(relative_size < 0) {
         set_sign(y_sign);
      } else if(relative_size == 0) {
         set_sign(Positive);
      }
   }

   return (*this);
}

BigInt& BigInt::mod_add(const BigInt& s, const BigInt& mod, secure_vector<word>& ws) {
   if(this->is_negative() || s.is_negative() || mod.is_negative()) {
      throw Invalid_Argument("BigInt::mod_add expects all arguments are positive");
   }

   BOTAN_DEBUG_ASSERT(*this < mod);
   BOTAN_DEBUG_ASSERT(s < mod);

   /*
   t + s or t + s - p == t - (p - s)

   So first compute ws = p - s

   Then compute t + s and t - ws

   If t - ws does not borrow, then that is the correct valued
   */

   const size_t mod_sw = mod.sig_words();
   BOTAN_ARG_CHECK(mod_sw > 0, "BigInt::mod_add modulus must be positive");

   this->grow_to(mod_sw);
   s.grow_to(mod_sw);

   // First mod_sw for p - s, 2*mod_sw for bigint_addsub workspace
   if(ws.size() < 3 * mod_sw) {
      ws.resize(3 * mod_sw);
   }

   word borrow = bigint_sub3(&ws[0], mod._data(), mod_sw, s._data(), mod_sw);
   BOTAN_DEBUG_ASSERT(borrow == 0);
   BOTAN_UNUSED(borrow);

   // Compute t - ws
   borrow = bigint_sub3(&ws[mod_sw], this->_data(), mod_sw, &ws[0], mod_sw);

   // Compute t + s
   bigint_add3_nc(&ws[mod_sw * 2], this->_data(), mod_sw, s._data(), mod_sw);

   CT::conditional_copy_mem(borrow, &ws[0], &ws[mod_sw * 2], &ws[mod_sw], mod_sw);
   set_words(&ws[0], mod_sw);

   return (*this);
}

BigInt& BigInt::mod_sub(const BigInt& s, const BigInt& mod, secure_vector<word>& ws) {
   if(this->is_negative() || s.is_negative() || mod.is_negative()) {
      throw Invalid_Argument("BigInt::mod_sub expects all arguments are positive");
   }

   // We are assuming in this function that *this and s are no more than mod_sw words long
   BOTAN_DEBUG_ASSERT(*this < mod);
   BOTAN_DEBUG_ASSERT(s < mod);

   const size_t mod_sw = mod.sig_words();

   this->grow_to(mod_sw);
   s.grow_to(mod_sw);

   if(ws.size() < mod_sw) {
      ws.resize(mod_sw);
   }

   if(mod_sw == 4) {
      bigint_mod_sub_n<4>(mutable_data(), s._data(), mod._data(), ws.data());
   } else if(mod_sw == 6) {
      bigint_mod_sub_n<6>(mutable_data(), s._data(), mod._data(), ws.data());
   } else {
      bigint_mod_sub(mutable_data(), s._data(), mod._data(), mod_sw, ws.data());
   }

   return (*this);
}

BigInt& BigInt::mod_mul(uint8_t y, const BigInt& mod, secure_vector<word>& ws) {
   BOTAN_ARG_CHECK(this->is_negative() == false, "*this must be positive");
   BOTAN_ARG_CHECK(y < 16, "y too large");

   BOTAN_DEBUG_ASSERT(*this < mod);

   *this *= static_cast<word>(y);
   this->reduce_below(mod, ws);
   return (*this);
}

BigInt& BigInt::rev_sub(const word y[], size_t y_sw, secure_vector<word>& ws) {
   if(this->sign() != BigInt::Positive) {
      throw Invalid_State("BigInt::sub_rev requires this is positive");
   }

   const size_t x_sw = this->sig_words();

   ws.resize(std::max(x_sw, y_sw));
   clear_mem(ws.data(), ws.size());

   const int32_t relative_size = bigint_sub_abs(ws.data(), _data(), x_sw, y, y_sw);

   this->cond_flip_sign(relative_size > 0);
   this->swap_reg(ws);

   return (*this);
}

/*
* Multiplication Operator
*/
BigInt& BigInt::operator*=(const BigInt& y) {
   secure_vector<word> ws;
   return this->mul(y, ws);
}

BigInt& BigInt::mul(const BigInt& y, secure_vector<word>& ws) {
   const size_t x_sw = sig_words();
   const size_t y_sw = y.sig_words();
   set_sign((sign() == y.sign()) ? Positive : Negative);

   if(x_sw == 0 || y_sw == 0) {
      clear();
      set_sign(Positive);
   } else if(x_sw == 1 && y_sw) {
      grow_to(y_sw + 1);
      bigint_linmul3(mutable_data(), y._data(), y_sw, word_at(0));
   } else if(y_sw == 1 && x_sw) {
      word carry = bigint_linmul2(mutable_data(), x_sw, y.word_at(0));
      set_word_at(x_sw, carry);
   } else {
      const size_t new_size = x_sw + y_sw + 1;
      ws.resize(new_size);
      secure_vector<word> z_reg(new_size);

      bigint_mul(z_reg.data(), z_reg.size(), _data(), size(), x_sw, y._data(), y.size(), y_sw, ws.data(), ws.size());

      this->swap_reg(z_reg);
   }

   return (*this);
}

BigInt& BigInt::square(secure_vector<word>& ws) {
   const size_t sw = sig_words();

   secure_vector<word> z(2 * sw);
   ws.resize(z.size());

   bigint_sqr(z.data(), z.size(), _data(), size(), sw, ws.data(), ws.size());

   swap_reg(z);
   set_sign(BigInt::Positive);

   return (*this);
}

BigInt& BigInt::operator*=(word y) {
   if(y == 0) {
      clear();
      set_sign(Positive);
   }

   const word carry = bigint_linmul2(mutable_data(), size(), y);
   set_word_at(size(), carry);

   return (*this);
}

/*
* Division Operator
*/
BigInt& BigInt::operator/=(const BigInt& y) {
   if(y.sig_words() == 1 && is_power_of_2(y.word_at(0))) {
      (*this) >>= (y.bits() - 1);
   } else {
      (*this) = (*this) / y;
   }
   return (*this);
}

/*
* Modulo Operator
*/
BigInt& BigInt::operator%=(const BigInt& mod) {
   return (*this = (*this) % mod);
}

/*
* Modulo Operator
*/
word BigInt::operator%=(word mod) {
   if(mod == 0) {
      throw Invalid_Argument("BigInt::operator%= divide by zero");
   }

   word remainder = 0;

   if(is_power_of_2(mod)) {
      remainder = (word_at(0) & (mod - 1));
   } else {
      const size_t sw = sig_words();
      for(size_t i = sw; i > 0; --i) {
         remainder = bigint_modop_vartime(remainder, word_at(i - 1), mod);
      }
   }

   if(remainder && sign() == BigInt::Negative) {
      remainder = mod - remainder;
   }

   m_data.set_to_zero();
   m_data.set_word_at(0, remainder);
   set_sign(BigInt::Positive);
   return remainder;
}

/*
* Left Shift Operator
*/
BigInt& BigInt::operator<<=(size_t shift) {
   const size_t sw = sig_words();
   const size_t new_size = sw + (shift + BOTAN_MP_WORD_BITS - 1) / BOTAN_MP_WORD_BITS;

   m_data.grow_to(new_size);

   bigint_shl1(m_data.mutable_data(), new_size, sw, shift);

   return (*this);
}

/*
* Right Shift Operator
*/
BigInt& BigInt::operator>>=(size_t shift) {
   bigint_shr1(m_data.mutable_data(), m_data.size(), shift);

   if(is_negative() && is_zero()) {
      set_sign(Positive);
   }

   return (*this);
}

}  // namespace Botan

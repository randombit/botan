/*
* BigInt Binary Operators
* (C) 1999-2007,2018 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/divide.h>
#include <botan/internal/mp_core.h>
#include <algorithm>

namespace Botan {

//static
BigInt BigInt::add2(const BigInt& x, const word y[], size_t y_words, BigInt::Sign y_sign) {
   const size_t x_sw = x.sig_words();

   BigInt z = BigInt::with_capacity(std::max(x_sw, y_words) + 1);

   if(x.sign() == y_sign) {
      bigint_add3(z.mutable_data(), x._data(), x_sw, y, y_words);
      z.set_sign(x.sign());
   } else {
      const int32_t relative_size = bigint_sub_abs(z.mutable_data(), x._data(), x_sw, y, y_words);

      //z.sign_fixup(relative_size, y_sign);
      if(relative_size < 0) {
         z.set_sign(y_sign);
      } else if(relative_size == 0) {
         z.set_sign(BigInt::Positive);
      } else {
         z.set_sign(x.sign());
      }
   }

   return z;
}

/*
* Multiplication Operator
*/
BigInt operator*(const BigInt& x, const BigInt& y) {
   const size_t x_sw = x.sig_words();
   const size_t y_sw = y.sig_words();

   BigInt z = BigInt::with_capacity(x.size() + y.size());

   if(x_sw == 1 && y_sw) {
      bigint_linmul3(z.mutable_data(), y._data(), y_sw, x.word_at(0));
   } else if(y_sw == 1 && x_sw) {
      bigint_linmul3(z.mutable_data(), x._data(), x_sw, y.word_at(0));
   } else if(x_sw && y_sw) {
      secure_vector<word> workspace(z.size());

      bigint_mul(z.mutable_data(),
                 z.size(),
                 x._data(),
                 x.size(),
                 x_sw,
                 y._data(),
                 y.size(),
                 y_sw,
                 workspace.data(),
                 workspace.size());
   }

   z.cond_flip_sign(x_sw > 0 && y_sw > 0 && x.sign() != y.sign());

   return z;
}

/*
* Multiplication Operator
*/
BigInt operator*(const BigInt& x, word y) {
   const size_t x_sw = x.sig_words();

   BigInt z = BigInt::with_capacity(x_sw + 1);

   if(x_sw && y) {
      bigint_linmul3(z.mutable_data(), x._data(), x_sw, y);
      z.set_sign(x.sign());
   }

   return z;
}

/*
* Division Operator
*/
BigInt operator/(const BigInt& x, const BigInt& y) {
   if(y.sig_words() == 1) {
      return x / y.word_at(0);
   }

   BigInt q, r;
   vartime_divide(x, y, q, r);
   return q;
}

/*
* Division Operator
*/
BigInt operator/(const BigInt& x, word y) {
   if(y == 0) {
      throw Invalid_Argument("BigInt::operator/ divide by zero");
   }

   BigInt q;
   word r;
   ct_divide_word(x, y, q, r);
   return q;
}

/*
* Modulo Operator
*/
BigInt operator%(const BigInt& n, const BigInt& mod) {
   if(mod.is_zero()) {
      throw Invalid_Argument("BigInt::operator% divide by zero");
   }
   if(mod.is_negative()) {
      throw Invalid_Argument("BigInt::operator% modulus must be > 0");
   }
   if(n.is_positive() && mod.is_positive() && n < mod) {
      return n;
   }

   if(mod.sig_words() == 1) {
      return BigInt::from_word(n % mod.word_at(0));
   }

   BigInt q, r;
   vartime_divide(n, mod, q, r);
   return r;
}

/*
* Modulo Operator
*/
word operator%(const BigInt& n, word mod) {
   if(mod == 0) {
      throw Invalid_Argument("BigInt::operator% divide by zero");
   }

   if(mod == 1) {
      return 0;
   }

   word remainder = 0;

   if(is_power_of_2(mod)) {
      remainder = (n.word_at(0) & (mod - 1));
   } else {
      const size_t sw = n.sig_words();
      for(size_t i = sw; i > 0; --i) {
         remainder = bigint_modop_vartime(remainder, n.word_at(i - 1), mod);
      }
   }

   if(remainder && n.sign() == BigInt::Negative) {
      return mod - remainder;
   }
   return remainder;
}

/*
* Left Shift Operator
*/
BigInt operator<<(const BigInt& x, size_t shift) {
   const size_t x_sw = x.sig_words();

   const size_t new_size = x_sw + (shift + BOTAN_MP_WORD_BITS - 1) / BOTAN_MP_WORD_BITS;
   BigInt y = BigInt::with_capacity(new_size);
   bigint_shl2(y.mutable_data(), x._data(), x_sw, shift);
   y.set_sign(x.sign());
   return y;
}

/*
* Right Shift Operator
*/
BigInt operator>>(const BigInt& x, size_t shift) {
   const size_t shift_words = shift / BOTAN_MP_WORD_BITS;
   const size_t x_sw = x.sig_words();

   if(shift_words >= x_sw) {
      return BigInt::zero();
   }

   BigInt y = BigInt::with_capacity(x_sw - shift_words);
   bigint_shr2(y.mutable_data(), x._data(), x_sw, shift);

   if(x.is_negative() && y.is_zero()) {
      y.set_sign(BigInt::Positive);
   } else {
      y.set_sign(x.sign());
   }

   return y;
}

}  // namespace Botan

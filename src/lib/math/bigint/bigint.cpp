/*
* BigInt Base
* (C) 1999-2011,2012,2014,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/rounding.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/loadstor.h>

namespace Botan {

BigInt::BigInt(const word words[], size_t length)
   {
   m_data.set_words(words, length);
   }

/*
* Construct a BigInt from a regular number
*/
BigInt::BigInt(uint64_t n)
   {
   if(n > 0)
      {
#if BOTAN_MP_WORD_BITS == 32
      m_data.set_word_at(0, static_cast<word>(n));
      m_data.set_word_at(1, static_cast<word>(n >> 32));
#else
      m_data.set_word_at(0, n);
#endif
      }

   }

/*
* Construct a BigInt of the specified size
*/
BigInt::BigInt(Sign s, size_t size)
   {
   m_data.set_size(size);
   m_signedness = s;
   }

/*
* Construct a BigInt from a string
*/
BigInt::BigInt(const std::string& str)
   {
   Base base = Decimal;
   size_t markers = 0;
   bool negative = false;

   if(str.length() > 0 && str[0] == '-')
      {
      markers += 1;
      negative = true;
      }

   if(str.length() > markers + 2 && str[markers    ] == '0' &&
                                    str[markers + 1] == 'x')
      {
      markers += 2;
      base = Hexadecimal;
      }

   *this = decode(cast_char_ptr_to_uint8(str.data()) + markers,
                  str.length() - markers, base);

   if(negative) set_sign(Negative);
   else         set_sign(Positive);
   }

BigInt::BigInt(const uint8_t input[], size_t length)
   {
   binary_decode(input, length);
   }

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(const uint8_t input[], size_t length, Base base)
   {
   *this = decode(input, length, base);
   }

BigInt::BigInt(const uint8_t buf[], size_t length, size_t max_bits)
   {
   if(8 * length > max_bits)
      length = (max_bits + 7) / 8;

   binary_decode(buf, length);

   if(8 * length > max_bits)
      *this >>= (8 - (max_bits % 8));
   }

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(RandomNumberGenerator& rng, size_t bits, bool set_high_bit)
   {
   randomize(rng, bits, set_high_bit);
   }

uint8_t BigInt::byte_at(size_t n) const
   {
   return get_byte(sizeof(word) - (n % sizeof(word)) - 1,
                   word_at(n / sizeof(word)));
   }

int32_t BigInt::cmp_word(word other) const
   {
   if(is_negative())
      return -1; // other is positive ...

   const size_t sw = this->sig_words();
   if(sw > 1)
      return 1; // must be larger since other is just one word ...

   return bigint_cmp(this->data(), sw, &other, 1);
   }

/*
* Comparison Function
*/
int32_t BigInt::cmp(const BigInt& other, bool check_signs) const
   {
   if(check_signs)
      {
      if(other.is_positive() && this->is_negative())
         return -1;

      if(other.is_negative() && this->is_positive())
         return 1;

      if(other.is_negative() && this->is_negative())
         return (-bigint_cmp(this->data(), this->size(),
                             other.data(), other.size()));
      }

   return bigint_cmp(this->data(), this->size(),
                     other.data(), other.size());
   }

bool BigInt::is_equal(const BigInt& other) const
   {
   if(this->sign() != other.sign())
      return false;

   return bigint_ct_is_eq(this->data(), this->sig_words(),
                          other.data(), other.sig_words()).is_set();
   }

bool BigInt::is_less_than(const BigInt& other) const
   {
   if(this->is_negative() && other.is_positive())
      return true;

   if(this->is_positive() && other.is_negative())
      return false;

   if(other.is_negative() && this->is_negative())
      {
      return !bigint_ct_is_lt(other.data(), other.sig_words(),
                              this->data(), this->sig_words(), true).is_set();
      }

   return bigint_ct_is_lt(this->data(), this->sig_words(),
                          other.data(), other.sig_words()).is_set();
   }

void BigInt::encode_words(word out[], size_t size) const
   {
   const size_t words = sig_words();

   if(words > size)
      throw Encoding_Error("BigInt::encode_words value too large to encode");

   clear_mem(out, size);
   copy_mem(out, data(), words);
   }

size_t BigInt::Data::calc_sig_words() const
   {
   const size_t sz = m_reg.size();
   size_t sig = sz;

   word sub = 1;

   for(size_t i = 0; i != sz; ++i)
      {
      const word w = m_reg[sz - i - 1];
      sub &= ct_is_zero(w);
      sig -= sub;
      }

   /*
   * This depends on the data so is poisoned, but unpoison it here as
   * later conditionals are made on the size.
   */
   CT::unpoison(sig);

   return sig;
   }

/*
* Return bits {offset...offset+length}
*/
uint32_t BigInt::get_substring(size_t offset, size_t length) const
   {
   if(length == 0 || length > 32)
      throw Invalid_Argument("BigInt::get_substring invalid substring length");

   const uint32_t mask = 0xFFFFFFFF >> (32 - length);

   const size_t word_offset = offset / BOTAN_MP_WORD_BITS;
   const size_t wshift = (offset % BOTAN_MP_WORD_BITS);

   /*
   * The substring is contained within one or at most two words. The
   * offset and length are not secret, so we can perform conditional
   * operations on those values.
   */
   const word w0 = word_at(word_offset);

   if(wshift == 0 || (offset + length) / BOTAN_MP_WORD_BITS == word_offset)
      {
      return static_cast<uint32_t>(w0 >> wshift) & mask;
      }
   else
      {
      const word w1 = word_at(word_offset + 1);
      return static_cast<uint32_t>((w0 >> wshift) | (w1 << (BOTAN_MP_WORD_BITS - wshift))) & mask;
      }
   }

/*
* Convert this number to a uint32_t, if possible
*/
uint32_t BigInt::to_u32bit() const
   {
   if(is_negative())
      throw Encoding_Error("BigInt::to_u32bit: Number is negative");
   if(bits() > 32)
      throw Encoding_Error("BigInt::to_u32bit: Number is too big to convert");

   uint32_t out = 0;
   for(size_t i = 0; i != 4; ++i)
      out = (out << 8) | byte_at(3-i);
   return out;
   }

/*
* Set bit number n
*/
void BigInt::conditionally_set_bit(size_t n, bool set_it)
   {
   const size_t which = n / BOTAN_MP_WORD_BITS;
   const word mask = static_cast<word>(set_it) << (n % BOTAN_MP_WORD_BITS);
   m_data.set_word_at(which, word_at(which) | mask);
   }

/*
* Clear bit number n
*/
void BigInt::clear_bit(size_t n)
   {
   const size_t which = n / BOTAN_MP_WORD_BITS;

   if(which < size())
      {
      const word mask = ~(static_cast<word>(1) << (n % BOTAN_MP_WORD_BITS));
      m_data.set_word_at(which, word_at(which) & mask);
      }
   }

size_t BigInt::bytes() const
   {
   return round_up(bits(), 8) / 8;
   }

size_t BigInt::top_bits_free() const
   {
   const size_t words = sig_words();

   const word top_word = word_at(words - 1);
   const size_t bits_used = high_bit(top_word);
   CT::unpoison(bits_used);
   return BOTAN_MP_WORD_BITS - bits_used;
   }

size_t BigInt::bits() const
   {
   const size_t words = sig_words();

   if(words == 0)
      return 0;

   const size_t full_words = (words - 1) * BOTAN_MP_WORD_BITS;
   const size_t top_bits = BOTAN_MP_WORD_BITS - top_bits_free();

   return full_words + top_bits;
   }

/*
* Calcluate the size in a certain base
*/
size_t BigInt::encoded_size(Base base) const
   {
   static const double LOG_2_BASE_10 = 0.30102999566;

   if(base == Binary)
      return bytes();
   else if(base == Hexadecimal)
      return 2*bytes();
   else if(base == Decimal)
      return static_cast<size_t>((bits() * LOG_2_BASE_10) + 1);
   else
      throw Invalid_Argument("Unknown base for BigInt encoding");
   }

/*
* Return the negation of this number
*/
BigInt BigInt::operator-() const
   {
   BigInt x = (*this);
   x.flip_sign();
   return x;
   }

size_t BigInt::reduce_below(const BigInt& p, secure_vector<word>& ws)
   {
   if(p.is_negative() || this->is_negative())
      throw Invalid_Argument("BigInt::reduce_below both values must be positive");

   const size_t p_words = p.sig_words();

   if(size() < p_words + 1)
      grow_to(p_words + 1);

   if(ws.size() < p_words + 1)
      ws.resize(p_words + 1);

   clear_mem(ws.data(), ws.size());

   size_t reductions = 0;

   for(;;)
      {
      word borrow = bigint_sub3(ws.data(), data(), p_words + 1, p.data(), p_words);
      if(borrow)
         break;

      ++reductions;
      swap_reg(ws);
      }

   return reductions;
   }

void BigInt::ct_reduce_below(const BigInt& mod, secure_vector<word>& ws, size_t bound)
   {
   if(mod.is_negative() || this->is_negative())
      throw Invalid_Argument("BigInt::ct_reduce_below both values must be positive");

   const size_t mod_words = mod.sig_words();

   grow_to(mod_words);

   const size_t sz = size();

   ws.resize(sz);

   clear_mem(ws.data(), sz);

   for(size_t i = 0; i != bound; ++i)
      {
      word borrow = bigint_sub3(ws.data(), data(), sz, mod.data(), mod_words);

      CT::Mask<word>::is_zero(borrow).select_n(mutable_data(), ws.data(), data(), sz);
      }
   }

/*
* Return the absolute value of this number
*/
BigInt BigInt::abs() const
   {
   BigInt x = (*this);
   x.set_sign(Positive);
   return x;
   }

void BigInt::binary_encode(uint8_t buf[]) const
   {
   this->binary_encode(buf, bytes());
   }

/*
* Encode this number into bytes
*/
void BigInt::binary_encode(uint8_t output[], size_t len) const
   {
   const size_t full_words = len / sizeof(word);
   const size_t extra_bytes = len % sizeof(word);

   for(size_t i = 0; i != full_words; ++i)
      {
      const word w = word_at(i);
      store_be(w, output + (len - (i+1)*sizeof(word)));
      }

   if(extra_bytes > 0)
      {
      const word w = word_at(full_words);

      for(size_t i = 0; i != extra_bytes; ++i)
         {
         output[extra_bytes - i - 1] = get_byte(sizeof(word) - i - 1, w);
         }
      }
   }

/*
* Set this number to the value in buf
*/
void BigInt::binary_decode(const uint8_t buf[], size_t length)
   {
   clear();

   const size_t full_words = length / sizeof(word);
   const size_t extra_bytes = length % sizeof(word);

   secure_vector<word> reg((round_up(full_words + (extra_bytes > 0 ? 1 : 0), 8)));

   for(size_t i = 0; i != full_words; ++i)
      {
      reg[i] = load_be<word>(buf + length - sizeof(word)*(i+1), 0);
      }

   if(extra_bytes > 0)
      {
      for(size_t i = 0; i != extra_bytes; ++i)
         reg[full_words] = (reg[full_words] << 8) | buf[i];
      }

   m_data.swap(reg);
   }

void BigInt::ct_cond_add(bool predicate, const BigInt& value)
   {
   if(this->is_negative() || value.is_negative())
      throw Invalid_Argument("BigInt::ct_cond_add requires both values to be positive");
   this->grow_to(1 + value.sig_words());

   bigint_cnd_add(static_cast<word>(predicate),
                  this->mutable_data(), this->size(),
                  value.data(), value.sig_words());
   }

void BigInt::ct_cond_swap(bool predicate, BigInt& other)
   {
   const size_t max_words = std::max(size(), other.size());
   grow_to(max_words);
   other.grow_to(max_words);

   bigint_cnd_swap(predicate, this->mutable_data(), other.mutable_data(), max_words);
   }

void BigInt::cond_flip_sign(bool predicate)
   {
   // This code is assuming Negative == 0, Positive == 1

   const auto mask = CT::Mask<uint8_t>::expand(predicate);

   const uint8_t current_sign = static_cast<uint8_t>(sign());

   const uint8_t new_sign = mask.select(current_sign ^ 1, current_sign);

   set_sign(static_cast<Sign>(new_sign));
   }

void BigInt::ct_cond_assign(bool predicate, const BigInt& other)
   {
   const size_t t_words = size();
   const size_t o_words = other.size();

   if(o_words < t_words)
      grow_to(o_words);

   const size_t r_words = std::max(t_words, o_words);

   const auto mask = CT::Mask<word>::expand(predicate);

   for(size_t i = 0; i != r_words; ++i)
      {
      const word o_word = other.word_at(i);
      const word t_word = this->word_at(i);
      this->set_word_at(i, mask.select(o_word, t_word));
      }

   const bool different_sign = sign() != other.sign();
   cond_flip_sign(predicate && different_sign);
   }

#if defined(BOTAN_HAS_VALGRIND)
void BigInt::const_time_poison() const
   {
   CT::poison(m_data.const_data(), m_data.size());
   }

void BigInt::const_time_unpoison() const
   {
   CT::unpoison(m_data.const_data(), m_data.size());
   }
#endif

void BigInt::const_time_lookup(secure_vector<word>& output,
                               const std::vector<BigInt>& vec,
                               size_t idx)
   {
   const size_t words = output.size();

   clear_mem(output.data(), output.size());

   CT::poison(&idx, sizeof(idx));

   for(size_t i = 0; i != vec.size(); ++i)
      {
      BOTAN_ASSERT(vec[i].size() >= words,
                   "Word size as expected in const_time_lookup");

      const auto mask = CT::Mask<word>::is_equal(i, idx);

      for(size_t w = 0; w != words; ++w)
         {
         const word viw = vec[i].word_at(w);
         output[w] = mask.if_set_return(viw);
         }
      }

   CT::unpoison(idx);
   CT::unpoison(output.data(), output.size());
   }

}

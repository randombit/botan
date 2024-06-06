/*
* BigInt Base
* (C) 1999-2011,2012,2014,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/rounding.h>

namespace Botan {

BigInt::BigInt(uint64_t n) {
#if BOTAN_MP_WORD_BITS == 64
   m_data.set_word_at(0, n);
#else
   m_data.set_word_at(1, static_cast<word>(n >> 32));
   m_data.set_word_at(0, static_cast<word>(n));
#endif
}

//static
BigInt BigInt::from_u64(uint64_t n) {
   BigInt bn;

#if BOTAN_MP_WORD_BITS == 64
   bn.set_word_at(0, n);
#else
   bn.set_word_at(1, static_cast<word>(n >> 32));
   bn.set_word_at(0, static_cast<word>(n));
#endif

   return bn;
}

//static
BigInt BigInt::from_word(word n) {
   BigInt bn;
   bn.set_word_at(0, n);
   return bn;
}

//static
BigInt BigInt::from_s32(int32_t n) {
   if(n >= 0) {
      return BigInt::from_u64(static_cast<uint64_t>(n));
   } else {
      return -BigInt::from_u64(static_cast<uint64_t>(-n));
   }
}

//static
BigInt BigInt::with_capacity(size_t size) {
   BigInt bn;
   bn.grow_to(size);
   return bn;
}

/*
* Construct a BigInt from a string
*/
BigInt::BigInt(std::string_view str) {
   Base base = Decimal;
   size_t markers = 0;
   bool negative = false;

   if(!str.empty() && str[0] == '-') {
      markers += 1;
      negative = true;
   }

   if(str.length() > markers + 2 && str[markers] == '0' && str[markers + 1] == 'x') {
      markers += 2;
      base = Hexadecimal;
   }

   *this = decode(cast_char_ptr_to_uint8(str.data()) + markers, str.length() - markers, base);

   if(negative) {
      set_sign(Negative);
   } else {
      set_sign(Positive);
   }
}

BigInt BigInt::from_string(std::string_view str) {
   return BigInt(str);
}

BigInt BigInt::from_bytes(std::span<const uint8_t> input) {
   BigInt r;
   r.assign_from_bytes(input);
   return r;
}

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(const uint8_t input[], size_t length, Base base) {
   *this = decode(input, length, base);
}

//static
BigInt BigInt::from_bytes_with_max_bits(const uint8_t input[], size_t length, size_t max_bits) {
   const size_t input_bits = 8 * length;

   auto bn = BigInt::from_bytes(std::span{input, length});

   if(input_bits > max_bits) {
      const size_t bits_to_shift = input_bits - max_bits;

      bn >>= bits_to_shift;
   }

   return bn;
}

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(RandomNumberGenerator& rng, size_t bits, bool set_high_bit) {
   randomize(rng, bits, set_high_bit);
}

uint8_t BigInt::byte_at(size_t n) const {
   return get_byte_var(sizeof(word) - (n % sizeof(word)) - 1, word_at(n / sizeof(word)));
}

int32_t BigInt::cmp_word(word other) const {
   if(is_negative()) {
      return -1;  // other is positive ...
   }

   const size_t sw = this->sig_words();
   if(sw > 1) {
      return 1;  // must be larger since other is just one word ...
   }

   return bigint_cmp(this->_data(), sw, &other, 1);
}

/*
* Comparison Function
*/
int32_t BigInt::cmp(const BigInt& other, bool check_signs) const {
   if(check_signs) {
      if(other.is_positive() && this->is_negative()) {
         return -1;
      }

      if(other.is_negative() && this->is_positive()) {
         return 1;
      }

      if(other.is_negative() && this->is_negative()) {
         return (-bigint_cmp(this->_data(), this->size(), other._data(), other.size()));
      }
   }

   return bigint_cmp(this->_data(), this->size(), other._data(), other.size());
}

bool BigInt::is_equal(const BigInt& other) const {
   if(this->sign() != other.sign()) {
      return false;
   }

   return bigint_ct_is_eq(this->_data(), this->sig_words(), other._data(), other.sig_words()).as_bool();
}

bool BigInt::is_less_than(const BigInt& other) const {
   if(this->is_negative() && other.is_positive()) {
      return true;
   }

   if(this->is_positive() && other.is_negative()) {
      return false;
   }

   if(other.is_negative() && this->is_negative()) {
      return bigint_ct_is_lt(other._data(), other.sig_words(), this->_data(), this->sig_words()).as_bool();
   }

   return bigint_ct_is_lt(this->_data(), this->sig_words(), other._data(), other.sig_words()).as_bool();
}

void BigInt::encode_words(word out[], size_t size) const {
   const size_t words = sig_words();

   if(words > size) {
      throw Encoding_Error("BigInt::encode_words value too large to encode");
   }

   clear_mem(out, size);
   copy_mem(out, _data(), words);
}

size_t BigInt::Data::calc_sig_words() const {
   const size_t sz = m_reg.size();
   size_t sig = sz;

   word sub = 1;

   for(size_t i = 0; i != sz; ++i) {
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
uint32_t BigInt::get_substring(size_t offset, size_t length) const {
   if(length == 0 || length > 32) {
      throw Invalid_Argument("BigInt::get_substring invalid substring length");
   }

   const uint32_t mask = 0xFFFFFFFF >> (32 - length);

   const size_t word_offset = offset / BOTAN_MP_WORD_BITS;
   const size_t wshift = (offset % BOTAN_MP_WORD_BITS);

   /*
   * The substring is contained within one or at most two words. The
   * offset and length are not secret, so we can perform conditional
   * operations on those values.
   */
   const word w0 = word_at(word_offset);

   if(wshift == 0 || (offset + length) / BOTAN_MP_WORD_BITS == word_offset) {
      return static_cast<uint32_t>(w0 >> wshift) & mask;
   } else {
      const word w1 = word_at(word_offset + 1);
      return static_cast<uint32_t>((w0 >> wshift) | (w1 << (BOTAN_MP_WORD_BITS - wshift))) & mask;
   }
}

/*
* Convert this number to a uint32_t, if possible
*/
uint32_t BigInt::to_u32bit() const {
   if(is_negative()) {
      throw Encoding_Error("BigInt::to_u32bit: Number is negative");
   }
   if(bits() > 32) {
      throw Encoding_Error("BigInt::to_u32bit: Number is too big to convert");
   }

   uint32_t out = 0;
   for(size_t i = 0; i != 4; ++i) {
      out = (out << 8) | byte_at(3 - i);
   }
   return out;
}

/*
* Clear bit number n
*/
void BigInt::clear_bit(size_t n) {
   const size_t which = n / BOTAN_MP_WORD_BITS;

   if(which < size()) {
      const word mask = ~(static_cast<word>(1) << (n % BOTAN_MP_WORD_BITS));
      m_data.set_word_at(which, word_at(which) & mask);
   }
}

size_t BigInt::bytes() const {
   return round_up(bits(), 8) / 8;
}

size_t BigInt::top_bits_free() const {
   const size_t words = sig_words();

   const word top_word = word_at(words - 1);
   const size_t bits_used = high_bit(CT::value_barrier(top_word));
   CT::unpoison(bits_used);
   return BOTAN_MP_WORD_BITS - bits_used;
}

size_t BigInt::bits() const {
   const size_t words = sig_words();

   if(words == 0) {
      return 0;
   }

   const size_t full_words = (words - 1) * BOTAN_MP_WORD_BITS;
   const size_t top_bits = BOTAN_MP_WORD_BITS - top_bits_free();

   return full_words + top_bits;
}

/*
* Return the negation of this number
*/
BigInt BigInt::operator-() const {
   BigInt x = (*this);
   x.flip_sign();
   return x;
}

size_t BigInt::reduce_below(const BigInt& p, secure_vector<word>& ws) {
   if(p.is_negative() || this->is_negative()) {
      throw Invalid_Argument("BigInt::reduce_below both values must be positive");
   }

   const size_t p_words = p.sig_words();

   if(size() < p_words + 1) {
      grow_to(p_words + 1);
   }

   if(ws.size() < p_words + 1) {
      ws.resize(p_words + 1);
   }

   clear_mem(ws.data(), ws.size());

   size_t reductions = 0;

   for(;;) {
      word borrow = bigint_sub3(ws.data(), _data(), p_words + 1, p._data(), p_words);
      if(borrow) {
         break;
      }

      ++reductions;
      swap_reg(ws);
   }

   return reductions;
}

void BigInt::ct_reduce_below(const BigInt& mod, secure_vector<word>& ws, size_t bound) {
   if(mod.is_negative() || this->is_negative()) {
      throw Invalid_Argument("BigInt::ct_reduce_below both values must be positive");
   }

   const size_t mod_words = mod.sig_words();

   grow_to(mod_words);

   const size_t sz = size();

   ws.resize(sz);

   clear_mem(ws.data(), sz);

   for(size_t i = 0; i != bound; ++i) {
      word borrow = bigint_sub3(ws.data(), _data(), sz, mod._data(), mod_words);

      CT::Mask<word>::is_zero(borrow).select_n(mutable_data(), ws.data(), _data(), sz);
   }
}

/*
* Return the absolute value of this number
*/
BigInt BigInt::abs() const {
   BigInt x = (*this);
   x.set_sign(Positive);
   return x;
}

/*
* Encode this number into bytes
*/
void BigInt::serialize_to(std::span<uint8_t> output) const {
   BOTAN_ARG_CHECK(this->bytes() <= output.size(), "Insufficient output space");

   this->binary_encode(output.data(), output.size());
}

/*
* Encode this number into bytes
*/
void BigInt::binary_encode(uint8_t output[], size_t len) const {
   const size_t full_words = len / sizeof(word);
   const size_t extra_bytes = len % sizeof(word);

   for(size_t i = 0; i != full_words; ++i) {
      const word w = word_at(i);
      store_be(w, output + (len - (i + 1) * sizeof(word)));
   }

   if(extra_bytes > 0) {
      const word w = word_at(full_words);

      for(size_t i = 0; i != extra_bytes; ++i) {
         output[extra_bytes - i - 1] = get_byte_var(sizeof(word) - i - 1, w);
      }
   }
}

/*
* Set this number to the value in buf
*/
void BigInt::assign_from_bytes(std::span<const uint8_t> bytes) {
   clear();

   const size_t length = bytes.size();
   const size_t full_words = length / sizeof(word);
   const size_t extra_bytes = length % sizeof(word);

   secure_vector<word> reg((round_up(full_words + (extra_bytes > 0 ? 1 : 0), 8)));

   for(size_t i = 0; i != full_words; ++i) {
      reg[i] = load_be<word>(bytes.last<sizeof(word)>());
      bytes = bytes.first(bytes.size() - sizeof(word));
   }

   if(!bytes.empty()) {
      BOTAN_ASSERT_NOMSG(extra_bytes == bytes.size());
      std::array<uint8_t, sizeof(word)> last_partial_word = {0};
      copy_mem(std::span{last_partial_word}.last(extra_bytes), bytes);
      reg[full_words] = load_be<word>(last_partial_word);
   }

   m_data.swap(reg);
}

void BigInt::ct_cond_add(bool predicate, const BigInt& value) {
   if(this->is_negative() || value.is_negative()) {
      throw Invalid_Argument("BigInt::ct_cond_add requires both values to be positive");
   }
   this->grow_to(1 + value.sig_words());

   bigint_cnd_add(static_cast<word>(predicate), this->mutable_data(), this->size(), value._data(), value.sig_words());
}

void BigInt::ct_shift_left(size_t shift) {
   auto shl_bit = [](const BigInt& a, BigInt& result) {
      BOTAN_DEBUG_ASSERT(a.size() + 1 == result.size());
      bigint_shl2(result.mutable_data(), a._data(), a.size(), 1);
      // shl2 may have shifted a bit into the next word, which must be dropped
      clear_mem(result.mutable_data() + result.size() - 1, 1);
   };

   auto shl_word = [](const BigInt& a, BigInt& result) {
      // the most significant word is not copied, aka. shifted out
      bigint_shl2(result.mutable_data(), a._data(), a.size() - 1 /* ignore msw */, BOTAN_MP_WORD_BITS);
      // we left-shifted by a full word, the least significant word must be zero'ed
      clear_mem(result.mutable_data(), 1);
   };

   BOTAN_ASSERT_NOMSG(size() > 0);

   constexpr size_t bits_in_word = sizeof(word) * 8;
   const size_t word_shift = shift >> ceil_log2(bits_in_word);             // shift / bits_in_word
   const size_t bit_shift = shift & ((1 << ceil_log2(bits_in_word)) - 1);  // shift % bits_in_word
   const size_t iterations = std::max(size(), bits_in_word) - 1;           // uint64_t i; i << 64 is undefined behaviour

   // In every iteration, shift one bit and one word to the left and use the
   // shift results only when they are within the shift range.
   BigInt tmp;
   tmp.resize(size() + 1 /* to hold the shifted-out word */);
   for(size_t i = 0; i < iterations; ++i) {
      shl_bit(*this, tmp);
      ct_cond_assign(i < bit_shift, tmp);
      shl_word(*this, tmp);
      ct_cond_assign(i < word_shift, tmp);
   }
}

void BigInt::ct_cond_swap(bool predicate, BigInt& other) {
   const size_t max_words = std::max(size(), other.size());
   grow_to(max_words);
   other.grow_to(max_words);

   bigint_cnd_swap(static_cast<word>(predicate), this->mutable_data(), other.mutable_data(), max_words);
}

void BigInt::cond_flip_sign(bool predicate) {
   // This code is assuming Negative == 0, Positive == 1

   const auto mask = CT::Mask<uint8_t>::expand(predicate);

   const uint8_t current_sign = static_cast<uint8_t>(sign());

   const uint8_t new_sign = mask.select(current_sign ^ 1, current_sign);

   set_sign(static_cast<Sign>(new_sign));
}

void BigInt::ct_cond_assign(bool predicate, const BigInt& other) {
   const size_t t_words = size();
   const size_t o_words = other.size();

   if(o_words < t_words) {
      grow_to(o_words);
   }

   const size_t r_words = std::max(t_words, o_words);

   const auto mask = CT::Mask<word>::expand(predicate);

   for(size_t i = 0; i != r_words; ++i) {
      const word o_word = other.word_at(i);
      const word t_word = this->word_at(i);
      this->set_word_at(i, mask.select(o_word, t_word));
   }

   const bool different_sign = sign() != other.sign();
   cond_flip_sign(predicate && different_sign);
}

#if defined(BOTAN_HAS_VALGRIND)
void BigInt::const_time_poison() const {
   CT::poison(m_data.const_data(), m_data.size());
}

void BigInt::const_time_unpoison() const {
   CT::unpoison(m_data.const_data(), m_data.size());
}
#endif

}  // namespace Botan

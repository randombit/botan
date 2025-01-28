/*
* MPI Algorithms
* (C) 1999-2010,2018,2024 Jack Lloyd
*     2006 Luca Piccarreta
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MP_CORE_OPS_H_
#define BOTAN_MP_CORE_OPS_H_

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/types.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_asmi.h>
#include <algorithm>
#include <array>
#include <span>

namespace Botan {

/*
* If cond == 0, does nothing.
* If cond > 0, swaps x[0:size] with y[0:size]
* Runs in constant time
*/
template <WordType W>
inline constexpr void bigint_cnd_swap(W cnd, W x[], W y[], size_t size) {
   const auto mask = CT::Mask<W>::expand(cnd);

   for(size_t i = 0; i != size; ++i) {
      const W a = x[i];
      const W b = y[i];
      x[i] = mask.select(b, a);
      y[i] = mask.select(a, b);
   }
}

template <WordType W>
inline constexpr W bigint_cnd_add(W cnd, W x[], size_t x_size, const W y[], size_t y_size) {
   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const auto mask = CT::Mask<W>::expand(cnd).value();

   W carry = 0;

   for(size_t i = 0; i != y_size; ++i) {
      x[i] = word_add(x[i], y[i] & mask, &carry);
   }

   for(size_t i = y_size; i != x_size; ++i) {
      x[i] = word_add(x[i], static_cast<W>(0), &carry);
   }

   return (mask & carry);
}

/*
* If cond > 0 adds x[0:size] and y[0:size] and returns carry
* Runs in constant time
*/
template <WordType W>
inline constexpr W bigint_cnd_add(W cnd, W x[], const W y[], size_t size) {
   return bigint_cnd_add(cnd, x, size, y, size);
}

/*
* If cond > 0 subtracts x[0:size] and y[0:size] and returns borrow
* Runs in constant time
*/
template <WordType W>
inline constexpr auto bigint_cnd_sub(W cnd, W x[], size_t x_size, const W y[], size_t y_size) -> W {
   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const auto mask = CT::Mask<W>::expand(cnd).value();

   W carry = 0;

   for(size_t i = 0; i != y_size; ++i) {
      x[i] = word_sub(x[i], y[i] & mask, &carry);
   }

   for(size_t i = y_size; i != x_size; ++i) {
      x[i] = word_sub(x[i], static_cast<W>(0), &carry);
   }

   return (mask & carry);
}

/*
* If cond > 0 adds x[0:size] and y[0:size] and returns carry
* Runs in constant time
*/
template <WordType W>
inline constexpr auto bigint_cnd_sub(W cnd, W x[], const W y[], size_t size) -> W {
   return bigint_cnd_sub(cnd, x, size, y, size);
}

/*
* Equivalent to
*   bigint_cnd_add( mask, x, y, size);
*   bigint_cnd_sub(~mask, x, y, size);
*
* Mask must be either 0 or all 1 bits
*/
template <WordType W>
inline constexpr void bigint_cnd_add_or_sub(CT::Mask<W> mask, W x[], const W y[], size_t size) {
   const size_t blocks = size - (size % 8);

   W carry = 0;
   W borrow = 0;

   W t0[8] = {0};
   W t1[8] = {0};

   for(size_t i = 0; i != blocks; i += 8) {
      carry = word8_add3(t0, x + i, y + i, carry);
      borrow = word8_sub3(t1, x + i, y + i, borrow);
      mask.select_n(x + i, t0, t1, 8);
   }

   for(size_t i = blocks; i != size; ++i) {
      const W a = word_add(x[i], y[i], &carry);
      const W s = word_sub(x[i], y[i], &borrow);

      x[i] = mask.select(a, s);
   }
}

/*
* Equivalent to
*   bigint_cnd_add( mask, x, size, y, size);
*   bigint_cnd_sub(~mask, x, size, z, size);
*
* Mask must be either 0 or all 1 bits
*
* Returns the carry or borrow resp
*/
template <WordType W>
inline constexpr auto bigint_cnd_addsub(CT::Mask<W> mask, W x[], const W y[], const W z[], size_t size) -> W {
   const size_t blocks = size - (size % 8);

   W carry = 0;
   W borrow = 0;

   W t0[8] = {0};
   W t1[8] = {0};

   for(size_t i = 0; i != blocks; i += 8) {
      carry = word8_add3(t0, x + i, y + i, carry);
      borrow = word8_sub3(t1, x + i, z + i, borrow);
      mask.select_n(x + i, t0, t1, 8);
   }

   for(size_t i = blocks; i != size; ++i) {
      t0[0] = word_add(x[i], y[i], &carry);
      t1[0] = word_sub(x[i], z[i], &borrow);
      x[i] = mask.select(t0[0], t1[0]);
   }

   return mask.select(carry, borrow);
}

/*
* 2s complement absolute value
* If cond > 0 sets x to ~x + 1
* Runs in constant time
*/
template <WordType W>
inline constexpr void bigint_cnd_abs(W cnd, W x[], size_t size) {
   const auto mask = CT::Mask<W>::expand(cnd);

   W carry = mask.if_set_return(1);
   for(size_t i = 0; i != size; ++i) {
      const W z = word_add(~x[i], static_cast<W>(0), &carry);
      x[i] = mask.select(z, x[i]);
   }
}

/**
* Two operand addition with carry out
*/
template <WordType W>
inline constexpr auto bigint_add2_nc(W x[], size_t x_size, const W y[], size_t y_size) -> W {
   W carry = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8) {
      carry = word8_add2(x + i, y + i, carry);
   }

   for(size_t i = blocks; i != y_size; ++i) {
      x[i] = word_add(x[i], y[i], &carry);
   }

   for(size_t i = y_size; i != x_size; ++i) {
      x[i] = word_add(x[i], static_cast<W>(0), &carry);
   }

   return carry;
}

/**
* Three operand addition with carry out
*/
template <WordType W>
inline constexpr auto bigint_add3_nc(W z[], const W x[], size_t x_size, const W y[], size_t y_size) -> W {
   if(x_size < y_size) {
      return bigint_add3_nc(z, y, y_size, x, x_size);
   }

   W carry = 0;

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8) {
      carry = word8_add3(z + i, x + i, y + i, carry);
   }

   for(size_t i = blocks; i != y_size; ++i) {
      z[i] = word_add(x[i], y[i], &carry);
   }

   for(size_t i = y_size; i != x_size; ++i) {
      z[i] = word_add(x[i], static_cast<W>(0), &carry);
   }

   return carry;
}

template <WordType W, size_t N>
inline constexpr auto bigint_add(std::span<W, N> z, std::span<const W, N> x, std::span<const W, N> y) -> W {
   if constexpr(N == 4) {
      return word4_add3<W>(z.data(), x.data(), y.data(), 0);
   } else if constexpr(N == 8) {
      return word8_add3<W>(z.data(), x.data(), y.data(), 0);
   } else {
      return bigint_add3_nc(z.data(), x.data(), N, y.data(), N);
   }
}

/**
* Two operand addition
* @param x the first operand (and output)
* @param x_size size of x
* @param y the second operand
* @param y_size size of y (must be <= x_size)
*/
template <WordType W>
inline constexpr void bigint_add2(W x[], size_t x_size, const W y[], size_t y_size) {
   x[x_size] += bigint_add2_nc(x, x_size, y, y_size);
}

/**
* Three operand addition
*/
template <WordType W>
inline constexpr void bigint_add3(W z[], const W x[], size_t x_size, const W y[], size_t y_size) {
   z[x_size > y_size ? x_size : y_size] += bigint_add3_nc(z, x, x_size, y, y_size);
}

/**
* Two operand subtraction
*/
template <WordType W>
inline constexpr auto bigint_sub2(W x[], size_t x_size, const W y[], size_t y_size) -> W {
   W borrow = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8) {
      borrow = word8_sub2(x + i, y + i, borrow);
   }

   for(size_t i = blocks; i != y_size; ++i) {
      x[i] = word_sub(x[i], y[i], &borrow);
   }

   for(size_t i = y_size; i != x_size; ++i) {
      x[i] = word_sub(x[i], static_cast<W>(0), &borrow);
   }

   return borrow;
}

/**
* Two operand subtraction, x = y - x; assumes y >= x
*/
template <WordType W>
inline constexpr void bigint_sub2_rev(W x[], const W y[], size_t y_size) {
   W borrow = 0;

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8) {
      borrow = word8_sub2_rev(x + i, y + i, borrow);
   }

   for(size_t i = blocks; i != y_size; ++i) {
      x[i] = word_sub(y[i], x[i], &borrow);
   }

   BOTAN_ASSERT(borrow == 0, "y must be greater than x");
}

/**
* Three operand subtraction
*
* Expects that x_size >= y_size
*
* Writes to z[0:x_size] and returns borrow
*/
template <WordType W>
inline constexpr auto bigint_sub3(W z[], const W x[], size_t x_size, const W y[], size_t y_size) -> W {
   W borrow = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8) {
      borrow = word8_sub3(z + i, x + i, y + i, borrow);
   }

   for(size_t i = blocks; i != y_size; ++i) {
      z[i] = word_sub(x[i], y[i], &borrow);
   }

   for(size_t i = y_size; i != x_size; ++i) {
      z[i] = word_sub(x[i], static_cast<W>(0), &borrow);
   }

   return borrow;
}

/**
* Conditional subtraction for Montgomery reduction
*
* This function assumes that (x0 || x) is less than 2*p
*
* Computes z[0:N] = (x0 || x[0:N]) - p[0:N]
*
* If z would be positive, returns z[0:N]
* Otherwise returns original input x
*/
template <WordType W>
inline constexpr void bigint_monty_maybe_sub(size_t N, W z[], W x0, const W x[], const W p[]) {
   W borrow = 0;

   const size_t blocks = N - (N % 8);

   for(size_t i = 0; i != blocks; i += 8) {
      borrow = word8_sub3(z + i, x + i, p + i, borrow);
   }

   for(size_t i = blocks; i != N; ++i) {
      z[i] = word_sub(x[i], p[i], &borrow);
   }

   borrow = (x0 - borrow) > x0;

   CT::conditional_assign_mem(borrow, z, x, N);
}

/**
* Conditional subtraction for Montgomery reduction
*
* This function assumes that (x0 || x) is less than 2*p
*
* Computes z[0:N] = (x0 || x[0:N]) - p[0:N]
*
* If z would be positive, returns z[0:N]
* Otherwise returns original input x
*/
template <size_t N, WordType W>
inline constexpr void bigint_monty_maybe_sub(W z[N], W x0, const W x[N], const W y[N]) {
   W borrow = 0;

   if constexpr(N == 4) {
      borrow = word4_sub3(z, x, y, borrow);
   } else if constexpr(N == 8) {
      borrow = word8_sub3(z, x, y, borrow);
   } else {
      const constexpr size_t blocks = N - (N % 8);
      for(size_t i = 0; i != blocks; i += 8) {
         borrow = word8_sub3(z + i, x + i, y + i, borrow);
      }

      for(size_t i = blocks; i != N; ++i) {
         z[i] = word_sub(x[i], y[i], &borrow);
      }
   }

   borrow = (x0 - borrow) > x0;

   CT::conditional_assign_mem(borrow, z, x, N);
}

/**
* Return abs(x-y), ie if x >= y, then compute z = x - y
* Otherwise compute z = y - x
* No borrow is possible since the result is always >= 0
*
* Returns ~0 if x >= y or 0 if x < y
* @param z output array of at least N words
* @param x input array of N words
* @param y input array of N words
* @param N length of x and y
* @param ws array of at least 2*N words
*/
template <WordType W>
inline constexpr auto bigint_sub_abs(W z[], const W x[], const W y[], size_t N, W ws[]) -> CT::Mask<W> {
   // Subtract in both direction then conditional copy out the result

   W* ws0 = ws;
   W* ws1 = ws + N;

   W borrow0 = 0;
   W borrow1 = 0;

   const size_t blocks = N - (N % 8);

   for(size_t i = 0; i != blocks; i += 8) {
      borrow0 = word8_sub3(ws0 + i, x + i, y + i, borrow0);
      borrow1 = word8_sub3(ws1 + i, y + i, x + i, borrow1);
   }

   for(size_t i = blocks; i != N; ++i) {
      ws0[i] = word_sub(x[i], y[i], &borrow0);
      ws1[i] = word_sub(y[i], x[i], &borrow1);
   }

   return CT::conditional_copy_mem(borrow0, z, ws1, ws0, N);
}

/*
* Shift Operations
*/
template <WordType W>
inline constexpr void bigint_shl1(W x[], size_t x_size, size_t x_words, size_t shift) {
   const size_t word_shift = shift / WordInfo<W>::bits;
   const size_t bit_shift = shift % WordInfo<W>::bits;

   copy_mem(x + word_shift, x, x_words);
   clear_mem(x, word_shift);

   const auto carry_mask = CT::Mask<W>::expand(bit_shift);
   const W carry_shift = carry_mask.if_set_return(WordInfo<W>::bits - bit_shift);

   W carry = 0;
   for(size_t i = word_shift; i != x_size; ++i) {
      const W w = x[i];
      x[i] = (w << bit_shift) | carry;
      carry = carry_mask.if_set_return(w >> carry_shift);
   }
}

template <WordType W>
inline constexpr void bigint_shr1(W x[], size_t x_size, size_t shift) {
   const size_t word_shift = shift / WordInfo<W>::bits;
   const size_t bit_shift = shift % WordInfo<W>::bits;

   const size_t top = x_size >= word_shift ? (x_size - word_shift) : 0;

   if(top > 0) {
      copy_mem(x, x + word_shift, top);
   }
   clear_mem(x + top, std::min(word_shift, x_size));

   const auto carry_mask = CT::Mask<W>::expand(bit_shift);
   const W carry_shift = carry_mask.if_set_return(WordInfo<W>::bits - bit_shift);

   W carry = 0;

   for(size_t i = 0; i != top; ++i) {
      const W w = x[top - i - 1];
      x[top - i - 1] = (w >> bit_shift) | carry;
      carry = carry_mask.if_set_return(w << carry_shift);
   }
}

template <WordType W>
inline constexpr void bigint_shl2(W y[], const W x[], size_t x_size, size_t shift) {
   const size_t word_shift = shift / WordInfo<W>::bits;
   const size_t bit_shift = shift % WordInfo<W>::bits;

   copy_mem(y + word_shift, x, x_size);

   const auto carry_mask = CT::Mask<W>::expand(bit_shift);
   const W carry_shift = carry_mask.if_set_return(WordInfo<W>::bits - bit_shift);

   W carry = 0;
   for(size_t i = word_shift; i != x_size + word_shift + 1; ++i) {
      const W w = y[i];
      y[i] = (w << bit_shift) | carry;
      carry = carry_mask.if_set_return(w >> carry_shift);
   }
}

template <WordType W>
inline constexpr void bigint_shr2(W y[], const W x[], size_t x_size, size_t shift) {
   const size_t word_shift = shift / WordInfo<W>::bits;
   const size_t bit_shift = shift % WordInfo<W>::bits;
   const size_t new_size = x_size < word_shift ? 0 : (x_size - word_shift);

   if(new_size > 0) {
      copy_mem(y, x + word_shift, new_size);
   }

   const auto carry_mask = CT::Mask<W>::expand(bit_shift);
   const W carry_shift = carry_mask.if_set_return(WordInfo<W>::bits - bit_shift);

   W carry = 0;
   for(size_t i = new_size; i > 0; --i) {
      W w = y[i - 1];
      y[i - 1] = (w >> bit_shift) | carry;
      carry = carry_mask.if_set_return(w << carry_shift);
   }
}

/*
* Linear Multiply - returns the carry
*/
template <WordType W>
[[nodiscard]] inline constexpr auto bigint_linmul2(W x[], size_t x_size, W y) -> W {
   const size_t blocks = x_size - (x_size % 8);

   W carry = 0;

   for(size_t i = 0; i != blocks; i += 8) {
      carry = word8_linmul2(x + i, y, carry);
   }

   for(size_t i = blocks; i != x_size; ++i) {
      x[i] = word_madd2(x[i], y, &carry);
   }

   return carry;
}

template <WordType W>
inline constexpr void bigint_linmul3(W z[], const W x[], size_t x_size, W y) {
   const size_t blocks = x_size - (x_size % 8);

   W carry = 0;

   for(size_t i = 0; i != blocks; i += 8) {
      carry = word8_linmul3(z + i, x + i, y, carry);
   }

   for(size_t i = blocks; i != x_size; ++i) {
      z[i] = word_madd2(x[i], y, &carry);
   }

   z[x_size] = carry;
}

/**
* Compare x and y
* Return -1 if x < y
* Return 0 if x == y
* Return 1 if x > y
*/
template <WordType W>
inline constexpr int32_t bigint_cmp(const W x[], size_t x_size, const W y[], size_t y_size) {
   static_assert(sizeof(W) >= sizeof(uint32_t), "Size assumption");

   const W LT = static_cast<W>(-1);
   const W EQ = 0;
   const W GT = 1;

   const size_t common_elems = std::min(x_size, y_size);

   W result = EQ;  // until found otherwise

   for(size_t i = 0; i != common_elems; i++) {
      const auto is_eq = CT::Mask<W>::is_equal(x[i], y[i]);
      const auto is_lt = CT::Mask<W>::is_lt(x[i], y[i]);

      result = is_eq.select(result, is_lt.select(LT, GT));
   }

   if(x_size < y_size) {
      W mask = 0;
      for(size_t i = x_size; i != y_size; i++) {
         mask |= y[i];
      }

      // If any bits were set in high part of y, then x < y
      result = CT::Mask<W>::is_zero(mask).select(result, LT);
   } else if(y_size < x_size) {
      W mask = 0;
      for(size_t i = y_size; i != x_size; i++) {
         mask |= x[i];
      }

      // If any bits were set in high part of x, then x > y
      result = CT::Mask<W>::is_zero(mask).select(result, GT);
   }

   CT::unpoison(result);
   BOTAN_DEBUG_ASSERT(result == LT || result == GT || result == EQ);
   return static_cast<int32_t>(result);
}

/**
* Compare x and y
* Return ~0 if x[0:x_size] < y[0:y_size] or 0 otherwise
* If lt_or_equal is true, returns ~0 also for x == y
*/
template <WordType W>
inline constexpr auto bigint_ct_is_lt(const W x[], size_t x_size, const W y[], size_t y_size, bool lt_or_equal = false)
   -> CT::Mask<W> {
   const size_t common_elems = std::min(x_size, y_size);

   auto is_lt = CT::Mask<W>::expand(lt_or_equal);

   for(size_t i = 0; i != common_elems; i++) {
      const auto eq = CT::Mask<W>::is_equal(x[i], y[i]);
      const auto lt = CT::Mask<W>::is_lt(x[i], y[i]);
      is_lt = eq.select_mask(is_lt, lt);
   }

   if(x_size < y_size) {
      W mask = 0;
      for(size_t i = x_size; i != y_size; i++) {
         mask |= y[i];
      }
      // If any bits were set in high part of y, then is_lt should be forced true
      is_lt |= CT::Mask<W>::expand(mask);
   } else if(y_size < x_size) {
      W mask = 0;
      for(size_t i = y_size; i != x_size; i++) {
         mask |= x[i];
      }

      // If any bits were set in high part of x, then is_lt should be false
      is_lt &= CT::Mask<W>::is_zero(mask);
   }

   return is_lt;
}

template <WordType W>
inline constexpr auto bigint_ct_is_eq(const W x[], size_t x_size, const W y[], size_t y_size) -> CT::Mask<W> {
   const size_t common_elems = std::min(x_size, y_size);

   W diff = 0;

   for(size_t i = 0; i != common_elems; i++) {
      diff |= (x[i] ^ y[i]);
   }

   // If any bits were set in high part of x/y, then they are not equal
   if(x_size < y_size) {
      for(size_t i = x_size; i != y_size; i++) {
         diff |= y[i];
      }
   } else if(y_size < x_size) {
      for(size_t i = y_size; i != x_size; i++) {
         diff |= x[i];
      }
   }

   return CT::Mask<W>::is_zero(diff);
}

/**
* Set z to abs(x-y), ie if x >= y, then compute z = x - y
* Otherwise compute z = y - x
* No borrow is possible since the result is always >= 0
*
* Return the relative size of x vs y (-1, 0, 1)
*
* @param z output array of max(x_size,y_size) words
* @param x input param
* @param x_size length of x
* @param y input param
* @param y_size length of y
*/
template <WordType W>
inline constexpr int32_t bigint_sub_abs(W z[], const W x[], size_t x_size, const W y[], size_t y_size) {
   const int32_t relative_size = bigint_cmp(x, x_size, y, y_size);

   // Swap if relative_size == -1
   const bool need_swap = relative_size < 0;
   CT::conditional_swap_ptr(need_swap, x, y);
   CT::conditional_swap(need_swap, x_size, y_size);

   /*
   * We know at this point that x >= y so if y_size is larger than
   * x_size, we are guaranteed they are just leading zeros which can
   * be ignored
   */
   y_size = std::min(x_size, y_size);

   bigint_sub3(z, x, x_size, y, y_size);

   return relative_size;
}

/**
* Set t to t-s modulo mod
*
* @param t first integer
* @param s second integer
* @param mod the modulus
* @param mod_sw size of t, s, and mod
* @param ws workspace of size mod_sw
*/
template <WordType W>
inline constexpr void bigint_mod_sub(W t[], const W s[], const W mod[], size_t mod_sw, W ws[]) {
   // ws = t - s
   const W borrow = bigint_sub3(ws, t, mod_sw, s, mod_sw);

   // Conditionally add back the modulus
   bigint_cnd_add(borrow, ws, mod, mod_sw);

   copy_mem(t, ws, mod_sw);
}

/**
* Compute ((n1<<bits) + n0) / d
*/
template <WordType W>
inline constexpr auto bigint_divop_vartime(W n1, W n0, W d) -> W {
   if(d == 0) {
      throw Invalid_Argument("bigint_divop_vartime divide by zero");
   }

   if constexpr(WordInfo<W>::dword_is_native) {
      typename WordInfo<W>::dword n = n1;
      n <<= WordInfo<W>::bits;
      n |= n0;
      return static_cast<W>(n / d);
   } else {
      W high = n1 % d;
      W quotient = 0;

      for(size_t i = 0; i != WordInfo<W>::bits; ++i) {
         const W high_top_bit = high >> (WordInfo<W>::bits - 1);

         high <<= 1;
         high |= (n0 >> (WordInfo<W>::bits - 1 - i)) & 1;
         quotient <<= 1;

         if(high_top_bit || high >= d) {
            high -= d;
            quotient |= 1;
         }
      }

      return quotient;
   }
}

/**
* Compute ((n1<<bits) + n0) % d
*/
template <WordType W>
inline constexpr auto bigint_modop_vartime(W n1, W n0, W d) -> W {
   if(d == 0) {
      throw Invalid_Argument("bigint_modop_vartime divide by zero");
   }

   W z = bigint_divop_vartime(n1, n0, d);
   W carry = 0;
   z = word_madd2(z, d, &carry);
   return (n0 - z);
}

/*
* Compute an integer x such that (a*x) == -1 (mod 2^n)
*
* Throws an exception if input is even, since in that case no inverse
* exists. If input is odd, then input and 2^n are relatively prime and
* the inverse exists.
*/
template <WordType W>
inline constexpr auto monty_inverse(W a) -> W {
   if(a % 2 == 0) {
      throw Invalid_Argument("monty_inverse only valid for odd integers");
   }

   /*
   * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
   * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
   */

   W b = 1;
   W r = 0;

   for(size_t i = 0; i != WordInfo<W>::bits; ++i) {
      const W bi = b % 2;
      r >>= 1;
      r += bi << (WordInfo<W>::bits - 1);

      b -= a * bi;
      b >>= 1;
   }

   // Now invert in addition space
   r = (WordInfo<W>::max - r) + 1;

   return r;
}

template <size_t S, WordType W, size_t N>
inline constexpr W shift_left(std::array<W, N>& x) {
   static_assert(S < WordInfo<W>::bits, "Shift too large");

   W carry = 0;
   for(size_t i = 0; i != N; ++i) {
      const W w = x[i];
      x[i] = (w << S) | carry;
      carry = w >> (WordInfo<W>::bits - S);
   }

   return carry;
}

template <size_t S, WordType W, size_t N>
inline constexpr W shift_right(std::array<W, N>& x) {
   static_assert(S < WordInfo<W>::bits, "Shift too large");

   W carry = 0;
   for(size_t i = 0; i != N; ++i) {
      const W w = x[N - 1 - i];
      x[N - 1 - i] = (w >> S) | carry;
      carry = w << (WordInfo<W>::bits - S);
   }

   return carry;
}

// Should be consteval but this triggers a bug in Clang 14
template <WordType W, size_t N>
constexpr auto hex_to_words(const char (&s)[N]) {
   // Char count includes null terminator which we ignore
   const constexpr size_t C = N - 1;

   // Number of nibbles that a word can hold
   const constexpr size_t NPW = (WordInfo<W>::bits / 4);

   // Round up to the next number of words that will fit the input
   const constexpr size_t S = (C + NPW - 1) / NPW;

   auto hex2int = [](char c) -> int8_t {
      if(c >= '0' && c <= '9') {
         return static_cast<int8_t>(c - '0');
      } else if(c >= 'a' && c <= 'f') {
         return static_cast<int8_t>(c - 'a' + 10);
      } else if(c >= 'A' && c <= 'F') {
         return static_cast<int8_t>(c - 'A' + 10);
      } else {
         return -1;
      }
   };

   std::array<W, S> r = {0};

   for(size_t i = 0; i != C; ++i) {
      const int8_t c = hex2int(s[i]);
      if(c >= 0) {
         shift_left<4>(r);
         r[0] += c;
      }
   }

   return r;
}

/*
* Comba Multiplication / Squaring
*/
BOTAN_FUZZER_API void bigint_comba_mul4(word z[8], const word x[4], const word y[4]);
BOTAN_FUZZER_API void bigint_comba_mul6(word z[12], const word x[6], const word y[6]);
BOTAN_FUZZER_API void bigint_comba_mul7(word z[14], const word x[7], const word y[7]);
BOTAN_FUZZER_API void bigint_comba_mul8(word z[16], const word x[8], const word y[8]);
BOTAN_FUZZER_API void bigint_comba_mul9(word z[18], const word x[9], const word y[9]);
BOTAN_FUZZER_API void bigint_comba_mul16(word z[32], const word x[16], const word y[16]);
BOTAN_FUZZER_API void bigint_comba_mul24(word z[48], const word x[24], const word y[24]);

BOTAN_FUZZER_API void bigint_comba_sqr4(word out[8], const word in[4]);
BOTAN_FUZZER_API void bigint_comba_sqr6(word out[12], const word in[6]);
BOTAN_FUZZER_API void bigint_comba_sqr7(word out[14], const word x[7]);
BOTAN_FUZZER_API void bigint_comba_sqr8(word out[16], const word in[8]);
BOTAN_FUZZER_API void bigint_comba_sqr9(word out[18], const word in[9]);
BOTAN_FUZZER_API void bigint_comba_sqr16(word out[32], const word in[16]);
BOTAN_FUZZER_API void bigint_comba_sqr24(word out[48], const word in[24]);

/*
* Comba Fixed Length Multiplication
*/
template <size_t N, WordType W>
constexpr inline void comba_mul(W z[2 * N], const W x[N], const W y[N]) {
   if(!std::is_constant_evaluated()) {
      if constexpr(std::same_as<W, word> && N == 4) {
         return bigint_comba_mul4(z, x, y);
      }
      if constexpr(std::same_as<W, word> && N == 6) {
         return bigint_comba_mul6(z, x, y);
      }
      if constexpr(std::same_as<W, word> && N == 7) {
         return bigint_comba_mul7(z, x, y);
      }
      if constexpr(std::same_as<W, word> && N == 8) {
         return bigint_comba_mul8(z, x, y);
      }
      if constexpr(std::same_as<W, word> && N == 9) {
         return bigint_comba_mul9(z, x, y);
      }
      if constexpr(std::same_as<W, word> && N == 16) {
         return bigint_comba_mul16(z, x, y);
      }
   }

   word3<W> accum;

   for(size_t i = 0; i != 2 * N; ++i) {
      const size_t start = i + 1 < N ? 0 : i + 1 - N;
      const size_t end = std::min(N, i + 1);

      for(size_t j = start; j != end; ++j) {
         accum.mul(x[j], y[i - j]);
      }
      z[i] = accum.extract();
   }
}

template <size_t N, WordType W>
constexpr inline void comba_sqr(W z[2 * N], const W x[N]) {
   if(!std::is_constant_evaluated()) {
      if constexpr(std::same_as<W, word> && N == 4) {
         return bigint_comba_sqr4(z, x);
      }
      if constexpr(std::same_as<W, word> && N == 6) {
         return bigint_comba_sqr6(z, x);
      }
      if constexpr(std::same_as<W, word> && N == 7) {
         return bigint_comba_sqr7(z, x);
      }
      if constexpr(std::same_as<W, word> && N == 8) {
         return bigint_comba_sqr8(z, x);
      }
      if constexpr(std::same_as<W, word> && N == 9) {
         return bigint_comba_sqr9(z, x);
      }
      if constexpr(std::same_as<W, word> && N == 16) {
         return bigint_comba_sqr16(z, x);
      }
   }

   word3<W> accum;

   for(size_t i = 0; i != 2 * N; ++i) {
      const size_t start = i + 1 < N ? 0 : i + 1 - N;
      const size_t end = std::min(N, i + 1);

      for(size_t j = start; j != end; ++j) {
         accum.mul(x[j], x[i - j]);
      }
      z[i] = accum.extract();
   }
}

/*
* Montgomery reduction
*
* Each of these functions makes the following assumptions:
*
* z_size == 2*p_size
* ws_size >= p_size
*/
BOTAN_FUZZER_API void bigint_monty_redc_4(word z[8], const word p[4], word p_dash, word ws[]);
BOTAN_FUZZER_API void bigint_monty_redc_6(word z[12], const word p[6], word p_dash, word ws[]);
BOTAN_FUZZER_API void bigint_monty_redc_8(word z[16], const word p[8], word p_dash, word ws[]);
BOTAN_FUZZER_API void bigint_monty_redc_16(word z[32], const word p[16], word p_dash, word ws[]);
BOTAN_FUZZER_API void bigint_monty_redc_24(word z[48], const word p[24], word p_dash, word ws[]);
BOTAN_FUZZER_API void bigint_monty_redc_32(word z[64], const word p[32], word p_dash, word ws[]);

BOTAN_FUZZER_API
void bigint_monty_redc_generic(word z[], size_t z_size, const word p[], size_t p_size, word p_dash, word ws[]);

/**
* Montgomery Reduction
* @param z integer to reduce, of size exactly 2*p_size. Output is in
* the first p_size words, higher words are set to zero.
* @param p modulus
* @param p_size size of p
* @param p_dash Montgomery value
* @param ws array of at least p_size words
* @param ws_size size of ws in words
*/
inline void bigint_monty_redc(word z[], const word p[], size_t p_size, word p_dash, word ws[], size_t ws_size) {
   const size_t z_size = 2 * p_size;

   BOTAN_ARG_CHECK(ws_size >= p_size, "Montgomery reduction workspace too small");

   if(p_size == 4) {
      bigint_monty_redc_4(z, p, p_dash, ws);
   } else if(p_size == 6) {
      bigint_monty_redc_6(z, p, p_dash, ws);
   } else if(p_size == 8) {
      bigint_monty_redc_8(z, p, p_dash, ws);
   } else if(p_size == 16) {
      bigint_monty_redc_16(z, p, p_dash, ws);
   } else if(p_size == 24) {
      bigint_monty_redc_24(z, p, p_dash, ws);
   } else if(p_size == 32) {
      bigint_monty_redc_32(z, p, p_dash, ws);
   } else {
      bigint_monty_redc_generic(z, z_size, p, p_size, p_dash, ws);
   }
}

/**
* Basecase O(N^2) multiplication
*/
BOTAN_FUZZER_API
void basecase_mul(word z[], size_t z_size, const word x[], size_t x_size, const word y[], size_t y_size);

/**
* Basecase O(N^2) squaring
*/
BOTAN_FUZZER_API
void basecase_sqr(word z[], size_t z_size, const word x[], size_t x_size);

/*
* High Level Multiplication/Squaring Interfaces
*/
void bigint_mul(word z[],
                size_t z_size,
                const word x[],
                size_t x_size,
                size_t x_sw,
                const word y[],
                size_t y_size,
                size_t y_sw,
                word workspace[],
                size_t ws_size);

void bigint_sqr(word z[], size_t z_size, const word x[], size_t x_size, size_t x_sw, word workspace[], size_t ws_size);

/**
* Return 2**B - C
*/
template <WordType W, size_t N, W C>
consteval std::array<W, N> crandall_p() {
   static_assert(C % 2 == 1);
   std::array<W, N> P;
   for(size_t i = 0; i != N; ++i) {
      P[i] = WordInfo<W>::max;
   }
   P[0] = WordInfo<W>::max - (C - 1);
   return P;
}

/**
* Reduce z modulo p = 2**B - C where C is small
*
* z is assumed to be at most (p-1)**2
*
* For details on the algorithm see
* - Handbook of Applied Cryptography, Algorithm 14.47
* - Guide to Elliptic Curve Cryptography, Algorithm 2.54 and Note 2.55
*
*/
template <WordType W, size_t N, W C>
constexpr std::array<W, N> redc_crandall(std::span<const W, 2 * N> z) {
   static_assert(N >= 2);

   std::array<W, N> hi = {};

   // hi = hi * c + lo

   W carry = 0;
   for(size_t i = 0; i != N; ++i) {
      hi[i] = word_madd3(z[i + N], C, z[i], &carry);
   }

   // hi += carry * C
   word carry_c[2] = {0};
   carry_c[0] = word_madd2(carry, C, &carry_c[1]);

   carry = bigint_add2_nc(hi.data(), N, carry_c, 2);

   constexpr auto P = crandall_p<W, N, C>();

   std::array<W, N> r = {};
   bigint_monty_maybe_sub<N, W>(r.data(), carry, hi.data(), P.data());

   return r;
}

/**
* Set r to r - C. Then if r < 0, add P to r
*/
template <size_t N, WordType W>
constexpr inline void bigint_correct_redc(std::array<W, N>& r, const std::array<W, N>& P, const std::array<W, N>& C) {
   // TODO look into combining the two operations for important values of N
   W borrow = bigint_sub2(r.data(), N, C.data(), N);
   bigint_cnd_add(borrow, r.data(), N, P.data(), N);
}

}  // namespace Botan

#endif

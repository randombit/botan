/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_IMPL_H_
#define BOTAN_PCURVES_IMPL_H_

#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pcurves_algos.h>
#include <botan/internal/pcurves_mul.h>
#include <botan/internal/pcurves_util.h>
#include <botan/internal/stl_util.h>
#include <concepts>
#include <vector>

namespace Botan {

/*
This file implements a system for compile-time instantiation of elliptic curve arithmetic.

All computations including point multiplication are implemented to be constant time,
with the exception of any function which includes "vartime" or equivalent in its
name. Randomization techniques (scalar blinding, point rerandomization) are also
used, largely to guard against situations where a compiler inserts a conditional jump
where not expected.

A specific elliptic curve is created by creating a set of EllipticCurveParameters,
which are templatized over the relevant constants (p, a, b, etc) and then
passing that set of parameters to an EllipticCurve template.

For a simple example of how these are used see pcurves_brainpool256r1.cpp

The system also includes various hooks which allow for specialized representations of
field elements (for curves where a modular reduction technique faster than Montgomery
is available) and to provide pre-computed addition chains for field and scalar
inversions. See pcurves_secp256r1.cpp or pcurves_secp256k1.cpp for examples with all
the bells and whistles.
*/

/**
* Montomgomery Representation of Integers
*
* Integers modulo a prime (IntMod, see below) use some representation that
* allows for fast arithmetic.
*
* The default representation used is Montgomery arithmetic. Curves with
* specialized fields (eg Mersenne primes, Solinas primes, or Crandall primes)
* provide a different type as the FieldRep parameter to the EllipticCurve
* template.
*
* Since the curve parameters are public and known at compile time, we can
* similarly compute the Montgomery parameters at compile time.
*/
template <typename Params>
class MontgomeryRep final {
   public:
      using Self = MontgomeryRep<Params>;

      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      static_assert(N > 0 && (Params::P[0] & 1) == 1, "Invalid Montgomery modulus");

      static constexpr auto P_dash = monty_inverse(P[0]);

      static constexpr auto R1 = montygomery_r(P);
      static constexpr auto R2 = mul_mod(R1, R1, P);
      static constexpr auto R3 = mul_mod(R1, R2, P);

      /**
      * Return the constant one, pre-converted into Montgomery form
      */
      constexpr static std::array<W, N> one() { return R1; }

      /**
      * Modular reduction
      */
      constexpr static std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         if constexpr(P_dash == 1) {
            return monty_redc_pdash1(z, P);
         } else {
            return monty_redc(z, P, P_dash);
         }
      }

      /**
      * Convert an integer into Montgomery representation
      */
      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) {
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), x.data(), R2.data());
         return Self::redc(z);
      }

      /**
      * Wide reduction modulo the prime
      *
      * Modular reduces an input of up to twice the length of the modulus, and
      * converts it into Montgomery form.
      */
      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) {
         auto redc_x = Self::redc(x);
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), redc_x.data(), R3.data());
         return Self::redc(z);
      }

      /**
      * Convert an integer out of Montgomery representation
      */
      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) {
         std::array<W, 2 * N> ze = {};
         copy_mem(std::span{ze}.template first<N>(), z);
         return Self::redc(ze);
      }
};

/**
* Integers Modulo (a Prime)
*
* This is used to store and manipulate integers modulo the field (for the affine
* x/y or Jacobian x/y/z coordinates) and group order (for scalar arithmetic).
*
* This class is parameterized by Rep which handles the modular reduction step,
* as well (if required) any conversions into or out of the inner
* representation. This is primarily for Montgomery arithmetic; specialized
* reduction methods instead keep the integer in the "standard" form.
*
* _Most_ of the code in this class does work for arbitrary moduli. However
* at least div2 and invert make assumptions that the modulus is prime.
*
* Any function that does not contain "vartime" or equivalent in the name is
* written such that it does not leak information about its arguments via control
* flow or memory access patterns.
*/
template <typename Rep>
class IntMod final {
   private:
      static constexpr auto P = Rep::P;
      static constexpr size_t N = Rep::N;
      typedef typename Rep::W W;

      static constexpr auto P_MINUS_2 = p_minus<2>(P);

   public:
      static constexpr size_t BITS = count_bits(P);
      static constexpr size_t BYTES = (BITS + 7) / 8;

      static constexpr auto P_MOD_4 = P[0] % 4;

      using Self = IntMod<Rep>;

      // Default value is zero
      constexpr IntMod() : m_val({}) {}

      IntMod(const Self& other) = default;
      IntMod(Self&& other) = default;
      IntMod& operator=(const Self& other) = default;
      IntMod& operator=(Self&& other) = default;
      ~IntMod() = default;

      /**
      * Return integer zero
      *
      * Note this assumes that the representation of zero is an all zero
      * sequence of words. This is true for both Montgomery and standard
      * representations.
      */
      static constexpr Self zero() { return Self(std::array<W, N>{0}); }

      /**
      * Return integer one
      */
      static constexpr Self one() { return Self(Rep::one()); }

      /**
      * Consume an array of words and convert it to an IntMod
      *
      * This handles the Montgomery conversion, if required.
      *
      * Note that this function assumes that `w` represents an integer that is
      * less than the modulus.
      */
      template <size_t L>
      static constexpr Self from_words(std::array<W, L> w) {
         if constexpr(L == N) {
            return Self(Rep::to_rep(w));
         } else {
            static_assert(L < N);
            std::array<W, N> ew = {};
            copy_mem(std::span{ew}.template first<L>(), w);
            return Self(Rep::to_rep(ew));
         }
      }

      /**
      * Check in constant time if this is equal to zero
      */
      constexpr CT::Choice is_zero() const { return CT::all_zeros(m_val.data(), m_val.size()).as_choice(); }

      /**
      * Check in constant time if this not equal to zero
      */
      constexpr CT::Choice is_nonzero() const { return !is_zero(); }

      /**
      * Check in constant time if this equal to one
      */
      constexpr CT::Choice is_one() const { return (*this == Self::one()); }

      /**
      * Check in constant time if this is an even integer
      */
      constexpr CT::Choice is_even() const {
         auto v = Rep::from_rep(m_val);
         return !CT::Choice::from_int(v[0] & 0x01);
      }

      /**
      * Modular addition; return c = a + b
      */
      friend constexpr Self operator+(const Self& a, const Self& b) {
         std::array<W, N> t;

         W carry = 0;
         for(size_t i = 0; i != N; ++i) {
            t[i] = word_add(a.m_val[i], b.m_val[i], &carry);
         }

         std::array<W, N> r;
         bigint_monty_maybe_sub<N>(r.data(), carry, t.data(), P.data());
         return Self(r);
      }

      /**
      * Modular subtraction; return c = a - b
      */
      friend constexpr Self operator-(const Self& a, const Self& b) {
         std::array<W, N> r;
         W carry = 0;
         for(size_t i = 0; i != N; ++i) {
            r[i] = word_sub(a.m_val[i], b.m_val[i], &carry);
         }

         bigint_cnd_add(carry, r.data(), N, P.data(), N);
         return Self(r);
      }

      /**
      * Return the value of this divided by 2
      */
      Self div2() const {
         // The inverse of 2 modulo P is (P/2)+1; this avoids a constexpr time
         // general inversion, which some compilers can't handle
         constexpr auto INV_2 = p_div_2_plus_1(Rep::P);

         // We could multiply by INV_2 but there is a better way ...

         std::array<W, N> t = value();
         W borrow = shift_right<1>(t);

         // If value was odd, add (P/2)+1
         bigint_cnd_add(borrow, t.data(), N, INV_2.data(), N);

         return Self(t);
      }

      /// Return (*this) multiplied by 2
      constexpr Self mul2() const {
         std::array<W, N> t = value();
         W carry = shift_left<1>(t);

         std::array<W, N> r;
         bigint_monty_maybe_sub<N>(r.data(), carry, t.data(), P.data());
         return Self(r);
      }

      /// Return (*this) multiplied by 3
      constexpr Self mul3() const { return mul2() + (*this); }

      /// Return (*this) multiplied by 4
      constexpr Self mul4() const { return mul2().mul2(); }

      /// Return (*this) multiplied by 8
      constexpr Self mul8() const { return mul2().mul2().mul2(); }

      /**
      * Modular multiplication; return c = a * b
      */
      friend constexpr Self operator*(const Self& a, const Self& b) {
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), a.data(), b.data());
         return Self(Rep::redc(z));
      }

      /**
      * Modular multiplication; set this to this * other
      */
      constexpr Self& operator*=(const Self& other) {
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), data(), other.data());
         m_val = Rep::redc(z);
         return (*this);
      }

      /**
      * Conditional assignment
      *
      * If `cond` is true, sets *this to `nx`
      */
      constexpr void conditional_assign(CT::Choice cond, const Self& nx) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            m_val[i] = choose(mask, nx.m_val[i], m_val[i]);
         }
      }

      /**
      * Conditional assignment
      *
      * If `cond` is true, sets `x` to `nx` and `y` to `ny`
      */
      static constexpr void conditional_assign(Self& x, Self& y, CT::Choice cond, const Self& nx, const Self& ny) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            x.m_val[i] = choose(mask, nx.m_val[i], x.m_val[i]);
            y.m_val[i] = choose(mask, ny.m_val[i], y.m_val[i]);
         }
      }

      /**
      * Conditional assignment
      *
      * If `cond` is true, sets `x` to `nx`, `y` to `ny`, and `z` to `nz`
      */
      static constexpr void conditional_assign(
         Self& x, Self& y, Self& z, CT::Choice cond, const Self& nx, const Self& ny, const Self& nz) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            x.m_val[i] = choose(mask, nx.m_val[i], x.m_val[i]);
            y.m_val[i] = choose(mask, ny.m_val[i], y.m_val[i]);
            z.m_val[i] = choose(mask, nz.m_val[i], z.m_val[i]);
         }
      }

      /**
      * Conditional swap
      *
      * If `cond` is true, swaps the values of `x` and `y`
      */
      static constexpr void conditional_swap(CT::Choice cond, Self& x, Self& y) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            auto nx = choose(mask, y.m_val[i], x.m_val[i]);
            auto ny = choose(mask, x.m_val[i], y.m_val[i]);
            x.m_val[i] = nx;
            y.m_val[i] = ny;
         }
      }

      /**
      * Modular squaring
      *
      * Returns the square of this after modular reduction
      */
      constexpr Self square() const {
         std::array<W, 2 * N> z;
         comba_sqr<N>(z.data(), this->data());
         return Self(Rep::redc(z));
      }

      /**
      * Repeated modular squaring
      *
      * Returns the nth square of this
      *
      * (Alternate view, returns this raised to the 2^nth power)
      */
      constexpr void square_n(size_t n) {
         std::array<W, 2 * N> z;
         for(size_t i = 0; i != n; ++i) {
            comba_sqr<N>(z.data(), this->data());
            m_val = Rep::redc(z);
         }
      }

      /**
      * Modular negation
      *
      * Returns the additive inverse of (*this)
      */
      constexpr Self negate() const {
         const W x_is_zero = ~CT::all_zeros(this->data(), N).value();

         std::array<W, N> r;
         W carry = 0;
         for(size_t i = 0; i != N; ++i) {
            r[i] = word_sub(P[i] & x_is_zero, m_val[i], &carry);
         }

         return Self(r);
      }

      /**
      * Modular Exponentiation (Variable Time)
      *
      * This function is variable time with respect to the exponent. It should
      * only be used when exp is not secret. In the current code, `exp` is
      * always a compile-time constant.
      *
      * This function should not leak any information about this, since the
      * value being operated on may be a secret.
      *
      * TODO: this interface should be changed so that the exponent is always a
      * compile-time constant; this should allow some interesting optimizations.
      */
      constexpr Self pow_vartime(const std::array<W, N>& exp) const {
         constexpr size_t WindowBits = (Self::BITS <= 256) ? 4 : 5;
         constexpr size_t WindowElements = (1 << WindowBits) - 1;

         constexpr size_t Windows = (Self::BITS + WindowBits - 1) / WindowBits;

         /*
         A simple fixed width window modular multiplication.

         TODO: investigate using sliding window here
         */

         std::array<Self, WindowElements> tbl;

         tbl[0] = (*this);

         for(size_t i = 1; i != WindowElements; ++i) {
            // Conditional ok: table indexes are public here
            if(i % 2 == 1) {
               tbl[i] = tbl[i / 2].square();
            } else {
               tbl[i] = tbl[i - 1] * tbl[0];
            }
         }

         auto r = Self::one();

         const size_t w0 = read_window_bits<WindowBits>(std::span{exp}, (Windows - 1) * WindowBits);

         // Conditional ok: this function is variable time
         if(w0 > 0) {
            r = tbl[w0 - 1];
         }

         for(size_t i = 1; i != Windows; ++i) {
            r.square_n(WindowBits);

            const size_t w = read_window_bits<WindowBits>(std::span{exp}, (Windows - i - 1) * WindowBits);

            // Conditional ok: this function is variable time
            if(w > 0) {
               r *= tbl[w - 1];
            }
         }

         return r;
      }

      /**
      * Returns the modular inverse, or 0 if no modular inverse exists.
      *
      * If the modulus is prime the only value that has no modular inverse is 0.
      *
      * This uses Fermat's little theorem, and so assumes that p is prime
      *
      * Since P is public, P-2 is as well, thus using a variable time modular
      * exponentiation routine is safe.
      *
      * This function is only used if the curve does not provide an addition
      * chain for specific inversions (see for example pcurves_secp256r1.cpp)
      */
      constexpr Self invert() const { return pow_vartime(Self::P_MINUS_2); }

      /**
      * Helper for variable time BEEA
      *
      * Note this function assumes that its arguments are in the standard
      * domain, not the Montgomery domain. invert_vartime converts its argument
      * out of Montgomery, and then back to Montgomery when returning the result.
      */
      static constexpr void _invert_vartime_div2_helper(Self& a, Self& x) {
         constexpr auto INV_2 = p_div_2_plus_1(Rep::P);

         // Conditional ok: this function is variable time
         while((a.m_val[0] & 1) != 1) {
            shift_right<1>(a.m_val);

            W borrow = shift_right<1>(x.m_val);

            // Conditional ok: this function is variable time
            if(borrow) {
               bigint_add2_nc(x.m_val.data(), N, INV_2.data(), N);
            }
         }
      }

      /**
      * Returns the modular inverse, or 0 if no modular inverse exists.
      *
      * This function assumes that the modulus is prime
      *
      * This function does something a bit nasty and converts from the normal
      * representation (for scalars, Montgomery) into the "standard"
      * representation. This relies on the fact that we aren't doing any
      * multiplications within this function, just additions, subtractions,
      * division by 2, and comparisons.
      *
      * The reason is there is no good way to compare integers in the Montgomery
      * domain; we could convert out for each comparison but this is slower than
      * just doing a constant-time inversion.
      *
      * This is loosely based on the algorithm BoringSSL uses in
      * BN_mod_inverse_odd, which is a variant of the Binary Extended Euclidean
      * algorithm. It is optimized somewhat by taking advantage of a couple of
      * observations.
      *
      * In the first two iterations, the control flow is known because `a` is
      * less than the modulus and not zero, and we know that the modulus is
      * odd. So we peel out those iterations. This also avoids having to
      * initialize `a` with the modulus, because we instead set it directly to
      * what the first loop iteration would have updated it to. This ensures
      * that all values are always less than or equal to the modulus.
      *
      * Then we take advantage of the fact that in each iteration of the loop,
      * at the end we update either b/x or a/y, but never both.  In the next
      * iteration of the loop, we attempt to modify b/x or a/y depending on the
      * low zero bits of b or a. But if a or b were not updated in the previous
      * iteration than they will still be odd, and nothing will happen. Instead
      * update just the pair we need to update, right after writing to b/x or
      * a/y resp.
      */
      constexpr Self invert_vartime() const {
         // Conditional ok: this function is variable time
         if(this->is_zero().as_bool()) {
            return Self::zero();
         }

         auto x = Self(std::array<W, N>{1});  // 1 in standard domain
         auto b = Self(this->to_words());     // *this in standard domain

         // First loop iteration
         Self::_invert_vartime_div2_helper(b, x);

         auto a = b.negate();
         // y += x but y is zero at the outset
         auto y = x;

         // First half of second loop iteration
         Self::_invert_vartime_div2_helper(a, y);

         for(;;) {
            // Conditional ok: this function is variable time
            if(a.m_val == b.m_val) {
               // At this point it should be that a == b == 1
               auto r = y.negate();

               // Convert back to Montgomery if required
               r.m_val = Rep::to_rep(r.m_val);
               return r;
            }

            auto nx = x + y;

            /*
            * Otherwise either b > a or a > b
            *
            * If b > a we want to set b to b - a
            * Otherwise we want to set a to a - b
            *
            * Compute r = b - a and check if it underflowed
            * If it did not then we are in the b > a path
            */
            std::array<W, N> r;
            word carry = bigint_sub3(r.data(), b.data(), N, a.data(), N);

            // Conditional ok: this function is variable time
            if(carry == 0) {
               // b > a
               b.m_val = r;
               x = nx;
               Self::_invert_vartime_div2_helper(b, x);
            } else {
               // We know this can't underflow because a > b
               bigint_sub3(r.data(), a.data(), N, b.data(), N);
               a.m_val = r;
               y = nx;
               Self::_invert_vartime_div2_helper(a, y);
            }
         }
      }

      /**
      * Return the modular square root if it exists
      *
      * The CT::Choice indicates if the square root exists or not.
      */
      constexpr std::pair<Self, CT::Choice> sqrt() const {
         if constexpr(Self::P_MOD_4 == 3) {
            // The easy case for square root is when p == 3 (mod 4)

            constexpr auto P_PLUS_1_OVER_4 = p_plus_1_over_4(P);
            auto z = pow_vartime(P_PLUS_1_OVER_4);

            // Zero out the return value if it would otherwise be incorrect
            const CT::Choice correct = (z.square() == *this);
            z.conditional_assign(!correct, Self::zero());
            return {z, correct};
         } else {
            // Shanks-Tonelli, following I.4 in RFC 9380

            /*
            Constants:
            1. c1, the largest integer such that 2^c1 divides q - 1.
            2. c2 = (q - 1) / (2^c1)        # Integer arithmetic
            3. c3 = (c2 - 1) / 2            # Integer arithmetic
            4. c4, a non-square value in F
            5. c5 = c4^c2 in F
            */
            constexpr auto C1_C2 = shanks_tonelli_c1c2(Self::P);
            constexpr std::array<W, N> C3 = shanks_tonelli_c3(C1_C2.second);
            constexpr std::array<W, N> P_MINUS_1_OVER_2 = p_minus_1_over_2(Self::P);
            constexpr Self C4 = shanks_tonelli_c4<Self>(P_MINUS_1_OVER_2);
            constexpr Self C5 = C4.pow_vartime(C1_C2.second);

            const Self& x = (*this);

            auto z = x.pow_vartime(C3);
            auto t = z.square();
            t *= x;
            z *= x;
            auto b = t;
            auto c = C5;

            for(size_t i = C1_C2.first; i >= 2; i--) {
               b.square_n(i - 2);
               const CT::Choice e = b.is_one();
               z.conditional_assign(!e, z * c);
               c.square_n(1);
               t.conditional_assign(!e, t * c);
               b = t;
            }

            // Zero out the return value if it would otherwise be incorrect
            const CT::Choice correct = (z.square() == *this);
            z.conditional_assign(!correct, Self::zero());
            return {z, correct};
         }
      }

      /**
      * Constant time integer equality test
      *
      * Since both this and other are in Montgomery representation (if applicable),
      * we can always compare the words directly, without having to convert out.
      */
      constexpr CT::Choice operator==(const Self& other) const {
         return CT::is_equal(this->data(), other.data(), N).as_choice();
      }

      /**
      * Constant time integer inequality test
      */
      constexpr CT::Choice operator!=(const Self& other) const { return !(*this == other); }

      /**
      * Convert the integer to standard representation and return the sequence of words
      */
      constexpr std::array<W, Self::N> to_words() const { return Rep::from_rep(m_val); }

      /**
      * Serialize the integer to a bytestring
      */
      constexpr void serialize_to(std::span<uint8_t, Self::BYTES> bytes) const {
         auto v = Rep::from_rep(m_val);
         std::reverse(v.begin(), v.end());

         if constexpr(Self::BYTES == N * WordInfo<W>::bytes) {
            store_be(bytes, v);
         } else {
            // Remove leading zero bytes
            const auto padded_bytes = store_be(v);
            constexpr size_t extra = N * WordInfo<W>::bytes - Self::BYTES;
            copy_mem(bytes, std::span{padded_bytes}.template subspan<extra, Self::BYTES>());
         }
      }

      /**
      * Store the raw words to an array
      *
      * See pcurves_wrap.h for why/where this is used
      */
      template <size_t L>
      std::array<W, L> stash_value() const {
         static_assert(L >= N);
         std::array<W, L> stash = {};
         for(size_t i = 0; i != N; ++i) {
            stash[i] = m_val[i];
         }
         return stash;
      }

      /**
      * Restore the value previously stashed
      *
      * See pcurves_wrap.h for why/where this is used
      */
      template <size_t L>
      static Self from_stash(const std::array<W, L>& stash) {
         static_assert(L >= N);
         std::array<W, N> val = {};
         for(size_t i = 0; i != N; ++i) {
            val[i] = stash[i];
         }
         return Self(val);
      }

      /**
      * Deserialize an integer from a bytestring
      *
      * Returns nullopt if the input is an encoding greater than or equal P
      *
      * This function also requires that the bytestring be exactly of the expected
      * length; short bytestrings, or a long bytestring with leading zero bytes, are
      * also rejected.
      */
      static std::optional<Self> deserialize(std::span<const uint8_t> bytes) {
         // Conditional ok: input length is public
         if(bytes.size() != Self::BYTES) {
            return {};
         }

         const auto words = bytes_to_words<W, N, BYTES>(bytes.first<Self::BYTES>());

         // Conditional acceptable: std::optional is implicitly not constant time
         if(!bigint_ct_is_lt(words.data(), N, P.data(), N).as_bool()) {
            return {};
         }

         // Safe because we checked above that words is an integer < P
         return Self::from_words(words);
      }

      /**
      * Modular reduce a larger input
      *
      * This takes a bytestring that is at most twice the length of the modulus, and
      * modular reduces it.
      */
      template <size_t L>
      static constexpr Self from_wide_bytes(std::span<const uint8_t, L> bytes) {
         static_assert(8 * L <= 2 * Self::BITS);
         std::array<uint8_t, 2 * BYTES> padded_bytes = {};
         copy_mem(std::span{padded_bytes}.template last<L>(), bytes);
         return Self(Rep::wide_to_rep(bytes_to_words<W, 2 * N, 2 * BYTES>(std::span{padded_bytes})));
      }

      /**
      * Modular reduce a larger input
      *
      * This takes a bytestring that is at most twice the length of the modulus, and
      * modular reduces it.
      */
      static constexpr std::optional<Self> from_wide_bytes_varlen(std::span<const uint8_t> bytes) {
         // Conditional ok: input length is public
         if(bytes.size() > 2 * Self::BYTES) {
            return {};
         }

         std::array<uint8_t, 2 * Self::BYTES> padded_bytes = {};
         copy_mem(std::span{padded_bytes}.last(bytes.size()), bytes);
         return Self(Rep::wide_to_rep(bytes_to_words<W, 2 * N, 2 * BYTES>(std::span{padded_bytes})));
      }

      /**
      * Return a random integer value in [1,p)
      *
      * This uses rejection sampling. This could have alternatively been implemented
      * by oversampling the random number generator and then performing a wide
      * reduction. The main reason that approach is avoided here is because it makes
      * testing ECDSA-style known answer tests more difficult.
      *
      * This function avoids returning zero since in almost all contexts where a
      * random integer is desired we want a random integer in Z_p*
      */
      static Self random(RandomNumberGenerator& rng) {
         constexpr size_t MAX_ATTEMPTS = 1000;

         std::array<uint8_t, Self::BYTES> buf;

         for(size_t i = 0; i != MAX_ATTEMPTS; ++i) {
            rng.randomize(buf);

            // Zero off high bits that if set would certainly cause us
            // to be out of range
            if constexpr(Self::BITS % 8 != 0) {
               constexpr uint8_t mask = 0xFF >> (8 - (Self::BITS % 8));
               buf[0] &= mask;
            }

            // Conditionals ok: rejection sampling reveals only values we didn't use
            if(auto s = Self::deserialize(buf)) {
               if(s.value().is_nonzero().as_bool()) {
                  return s.value();
               }
            }
         }

         throw Internal_Error("Failed to generate random Scalar within bounded number of attempts");
      }

      /**
      * Create a small compile time constant
      *
      * Notice this function is consteval, and so can only be called at compile time
      */
      static consteval Self constant(int8_t x) {
         std::array<W, 1> v;
         v[0] = (x >= 0) ? x : -x;
         auto s = Self::from_words(v);
         return (x >= 0) ? s : s.negate();
      }

      constexpr void _const_time_poison() const { CT::poison(m_val); }

      constexpr void _const_time_unpoison() const { CT::unpoison(m_val); }

   private:
      constexpr const std::array<W, N>& value() const { return m_val; }

      constexpr const W* data() const { return m_val.data(); }

      explicit constexpr IntMod(std::array<W, N> v) : m_val(v) {}

      std::array<W, N> m_val;
};

/**
* Affine Curve Point
*
* This contains a pair of integers (x,y) which satisfy the curve equation
*/
template <typename FieldElement, typename Params>
class AffineCurvePoint final {
   public:
      static constexpr size_t BYTES = 1 + 2 * FieldElement::BYTES;

      using Self = AffineCurvePoint<FieldElement, Params>;

      // Note this constructor does not check the validity of the x/y pair
      // This must be verified prior to this constructor being called
      constexpr AffineCurvePoint(const FieldElement& x, const FieldElement& y) : m_x(x), m_y(y) {}

      constexpr AffineCurvePoint() : m_x(FieldElement::zero()), m_y(FieldElement::zero()) {}

      static constexpr Self identity() { return Self(FieldElement::zero(), FieldElement::zero()); }

      // Helper for ct_select of pcurves_generic
      static constexpr Self identity(const Self&) { return Self(FieldElement::zero(), FieldElement::zero()); }

      constexpr CT::Choice is_identity() const { return x().is_zero() && y().is_zero(); }

      AffineCurvePoint(const Self& other) = default;
      AffineCurvePoint(Self&& other) = default;
      AffineCurvePoint& operator=(const Self& other) = default;
      AffineCurvePoint& operator=(Self&& other) = default;
      ~AffineCurvePoint() = default;

      constexpr Self negate() const { return Self(x(), y().negate()); }

      /**
      * Serialize the point in uncompressed format
      */
      constexpr void serialize_to(std::span<uint8_t, Self::BYTES> bytes) const {
         BOTAN_STATE_CHECK(this->is_identity().as_bool() == false);
         BufferStuffer pack(bytes);
         pack.append(0x04);
         x().serialize_to(pack.next<FieldElement::BYTES>());
         y().serialize_to(pack.next<FieldElement::BYTES>());
         BOTAN_DEBUG_ASSERT(pack.full());
      }

      /**
      * If idx is zero then return the identity element. Otherwise return pts[idx - 1]
      *
      * Returns the identity element also if idx is out of range
      */
      static constexpr auto ct_select(std::span<const Self> pts, size_t idx) {
         auto result = Self::identity(pts[0]);

         // Intentionally wrapping; set to maximum size_t if idx == 0
         const size_t idx1 = static_cast<size_t>(idx - 1);
         for(size_t i = 0; i != pts.size(); ++i) {
            const auto found = CT::Mask<size_t>::is_equal(idx1, i).as_choice();
            result.conditional_assign(found, pts[i]);
         }

         return result;
      }

      /**
      * Return the affine x coordinate
      */
      constexpr const FieldElement& x() const { return m_x; }

      /**
      * Return the affine y coordinate
      */
      constexpr const FieldElement& y() const { return m_y; }

      /**
      * Conditional assignment of an affine point
      */
      constexpr void conditional_assign(CT::Choice cond, const Self& pt) {
         FieldElement::conditional_assign(m_x, m_y, cond, pt.x(), pt.y());
      }

      constexpr void _const_time_poison() const { CT::poison_all(m_x, m_y); }

      constexpr void _const_time_unpoison() const { CT::unpoison_all(m_x, m_y); }

   private:
      FieldElement m_x;
      FieldElement m_y;
};

/**
* Projective curve point
*
* This uses Jacobian coordinates
*/
template <typename FieldElement, typename Params>
class ProjectiveCurvePoint {
   public:
      // We can't pass a FieldElement directly because FieldElement is
      // not "structural" due to having private members, so instead
      // recreate it here from the words.
      static constexpr FieldElement A = FieldElement::from_words(Params::AW);

      static constexpr bool A_is_zero = A.is_zero().as_bool();
      static constexpr bool A_is_minus_3 = (A == FieldElement::constant(-3)).as_bool();

      using Self = ProjectiveCurvePoint<FieldElement, Params>;
      using AffinePoint = AffineCurvePoint<FieldElement, Params>;

      /**
      * Convert a point from affine to projective form
      */
      static constexpr Self from_affine(const AffinePoint& pt) {
         /*
         * If the point is the identity element (x=0, y=0) then instead of
         * creating (x, y, 1) = (0, 0, 1) we want our projective identity
         * encoding of (0, 1, 0)
         *
         * Which we can achieve by a conditional swap of y and z if the
         * affine point is the identity.
         */

         auto x = pt.x();
         auto y = pt.y();
         auto z = FieldElement::one();

         FieldElement::conditional_swap(pt.is_identity(), y, z);

         return ProjectiveCurvePoint(x, y, z);
      }

      /**
      * Return the identity element
      */
      static constexpr Self identity() { return Self(FieldElement::zero(), FieldElement::one(), FieldElement::zero()); }

      /**
      * Default constructor: the identity element
      */
      constexpr ProjectiveCurvePoint() :
            m_x(FieldElement::zero()), m_y(FieldElement::one()), m_z(FieldElement::zero()) {}

      /**
      * Affine constructor: take x/y coordinates
      */
      constexpr ProjectiveCurvePoint(const FieldElement& x, const FieldElement& y) :
            m_x(x), m_y(y), m_z(FieldElement::one()) {}

      /**
      * Projective constructor: take x/y/z coordinates
      */
      constexpr ProjectiveCurvePoint(const FieldElement& x, const FieldElement& y, const FieldElement& z) :
            m_x(x), m_y(y), m_z(z) {}

      ProjectiveCurvePoint(const Self& other) = default;
      ProjectiveCurvePoint(Self&& other) = default;
      ProjectiveCurvePoint& operator=(const Self& other) = default;
      ProjectiveCurvePoint& operator=(Self&& other) = default;
      ~ProjectiveCurvePoint() = default;

      friend constexpr Self operator+(const Self& a, const Self& b) { return Self::add(a, b); }

      friend constexpr Self operator+(const Self& a, const AffinePoint& b) { return Self::add_mixed(a, b); }

      friend constexpr Self operator+(const AffinePoint& a, const Self& b) { return Self::add_mixed(b, a); }

      constexpr Self& operator+=(const Self& other) {
         (*this) = (*this) + other;
         return (*this);
      }

      constexpr Self& operator+=(const AffinePoint& other) {
         (*this) = (*this) + other;
         return (*this);
      }

      friend constexpr Self operator-(const Self& a, const Self& b) { return a + b.negate(); }

      constexpr CT::Choice is_identity() const { return z().is_zero(); }

      constexpr void conditional_assign(CT::Choice cond, const Self& pt) {
         FieldElement::conditional_assign(m_x, m_y, m_z, cond, pt.x(), pt.y(), pt.z());
      }

      /**
      * Mixed (projective + affine) point addition
      */
      constexpr static Self add_mixed(const Self& a, const AffinePoint& b) {
         return point_add_mixed<Self, AffinePoint, FieldElement>(a, b, FieldElement::one());
      }

      // Either add or subtract based on the CT::Choice
      constexpr static Self add_or_sub(const Self& a, const AffinePoint& b, CT::Choice sub) {
         return point_add_or_sub_mixed<Self, AffinePoint, FieldElement>(a, b, sub, FieldElement::one());
      }

      /**
      * Projective point addition
      */
      constexpr static Self add(const Self& a, const Self& b) { return point_add<Self, FieldElement>(a, b); }

      /**
      * Iterated point doubling
      */
      constexpr Self dbl_n(size_t n) const {
         if constexpr(Self::A_is_minus_3) {
            return dbl_n_a_minus_3(*this, n);
         } else if constexpr(Self::A_is_zero) {
            return dbl_n_a_zero(*this, n);
         } else {
            return dbl_n_generic(*this, A, n);
         }
      }

      /**
      * Point doubling
      */
      constexpr Self dbl() const {
         if constexpr(Self::A_is_minus_3) {
            return dbl_a_minus_3(*this);
         } else if constexpr(Self::A_is_zero) {
            return dbl_a_zero(*this);
         } else {
            return dbl_generic(*this, A);
         }
      }

      /**
      * Point negation
      */
      constexpr Self negate() const { return Self(x(), y().negate(), z()); }

      /**
      * Randomize the point representation
      *
      * Projective coordinates are redundant; if (x,y,z) is a projective
      * point then so is (x*r^2,y*r^3,z*r) for any non-zero r.
      */
      void randomize_rep(RandomNumberGenerator& rng) {
         // In certain contexts we may be called with a Null_RNG; in that case the
         // caller is accepting that randomization will not occur

         // Conditional ok: caller's RNG state (seeded vs not) is presumed public
         if(rng.is_seeded()) {
            auto r = FieldElement::random(rng);

            auto r2 = r.square();
            auto r3 = r2 * r;

            m_x *= r2;
            m_y *= r3;
            m_z *= r;
         }
      }

      /**
      * Return the projective x coordinate
      */
      constexpr const FieldElement& x() const { return m_x; }

      /**
      * Return the projective y coordinate
      */
      constexpr const FieldElement& y() const { return m_y; }

      /**
      * Return the projective z coordinate
      */
      constexpr const FieldElement& z() const { return m_z; }

      constexpr void _const_time_poison() const { CT::poison_all(m_x, m_y, m_z); }

      constexpr void _const_time_unpoison() const { CT::unpoison_all(m_x, m_y, m_z); }

   private:
      FieldElement m_x;
      FieldElement m_y;
      FieldElement m_z;
};

/**
* Elliptic Curve Parameters
*
* These are constructed using compile time strings which contain the relevant values
* (P, A, B, the group order, and the group generator x/y coordinates)
*/
template <StringLiteral PS,
          StringLiteral AS,
          StringLiteral BS,
          StringLiteral NS,
          StringLiteral GXS,
          StringLiteral GYS,
          int8_t ZI = 0>
class EllipticCurveParameters {
   public:
      typedef word W;

      static constexpr auto PW = hex_to_words<W>(PS.value);
      static constexpr auto NW = hex_to_words<W>(NS.value);
      static constexpr auto AW = hex_to_words<W>(AS.value);
      static constexpr auto BW = hex_to_words<W>(BS.value);
      static constexpr auto GXW = hex_to_words<W>(GXS.value);
      static constexpr auto GYW = hex_to_words<W>(GYS.value);

      static constexpr int8_t Z = ZI;
};

/**
* This exists soley as a hack which somewhat reduces symbol lengths
*/
template <WordType WI, size_t NI, std::array<WI, NI> PI>
struct IntParams {
   public:
      typedef WI W;
      static constexpr size_t N = NI;
      static constexpr auto P = PI;
};

/**
* Elliptic Curve
*
* Takes as input a set of parameters, and instantiates the elliptic curve
*/
template <typename Params, template <typename FieldParamsT> typename FieldRep = MontgomeryRep>
class EllipticCurve {
   public:
      typedef typename Params::W W;

      typedef W WordType;

      static constexpr auto PW = Params::PW;
      static constexpr auto NW = Params::NW;
      static constexpr auto AW = Params::AW;

      // Simplifying assumption
      static_assert(PW.size() == NW.size());

      static constexpr size_t Words = PW.size();

      class ScalarParams final : public IntParams<W, Words, NW> {};

      using Scalar = IntMod<MontgomeryRep<ScalarParams>>;

      class FieldParams final : public IntParams<W, Words, PW> {};

      using FieldElement = IntMod<FieldRep<FieldParams>>;

      using AffinePoint = AffineCurvePoint<FieldElement, Params>;
      using ProjectivePoint = ProjectiveCurvePoint<FieldElement, Params>;

      static constexpr size_t OrderBits = Scalar::BITS;
      static constexpr size_t PrimeFieldBits = FieldElement::BITS;

      static constexpr FieldElement A = FieldElement::from_words(Params::AW);
      static constexpr FieldElement B = FieldElement::from_words(Params::BW);

      static_assert(B.is_nonzero().as_bool(), "B must be non-zero");

      static constexpr AffinePoint G =
         AffinePoint(FieldElement::from_words(Params::GXW), FieldElement::from_words(Params::GYW));

      static constexpr FieldElement SSWU_Z = FieldElement::constant(Params::Z);

      static constexpr bool ValidForSswuHash =
         (Params::Z != 0 && A.is_nonzero().as_bool() && B.is_nonzero().as_bool() && FieldElement::P_MOD_4 == 3);

      static constexpr bool OrderIsLessThanField = bigint_cmp(NW.data(), Words, PW.data(), Words) == -1;

      /**
      * Return (x^3 + A*x + B) mod p
      */
      static constexpr FieldElement x3_ax_b(const FieldElement& x) { return (x.square() + A) * x + B; }
};

/**
* Blinded Scalar
*
* This randomizes the scalar representation by computing s + n*k,
* where n is the group order and k is a random value
*
* Note that the field arithmetic and point multiplication algorithms
* implemented in this file are already constant time; blinding is used here as
* an additional precaution to guard against compilers introducing conditional
* jumps where not expected.
*
* If you would like a "go faster" button, change the BlindingEnabled variable
* below to false.
*/
template <typename C, size_t WindowBits>
class BlindedScalarBits final {
   private:
      typedef typename C::W W;

      static constexpr bool BlindingEnabled = true;

      // Decide size of scalar blinding factor based on bitlength of the scalar
      //
      // This can return any value between 0 and the scalar bit length, as long
      // as it is a multiple of the word size.
      //
      // TODO(Botan4) this function should be consteval but cannot currently to a bug
      // in older versions of Clang. Change to consteval when minimum Clang is bumped.
      static constexpr size_t blinding_bits(size_t sb) {
         constexpr size_t wb = WordInfo<W>::bits;

         static_assert(wb == 32 || wb == 64, "Unexpected W size");

         if(sb == 521) {
            /*
            Treat P-521 as if it was a 512 bit field; otherwise it is penalized
            by the below computation, using either 160 or 192 bits of blinding
            (depending on wb), vs 128 bits used for 512 bit groups.
            */
            return blinding_bits(512);
         } else {
            // For blinding use 1/4 the order, rounded up to the next word
            return ((sb / 4 + wb - 1) / wb) * wb;
         }
      }

      static constexpr size_t BlindingBits = blinding_bits(C::OrderBits);

      static_assert(BlindingBits % WordInfo<W>::bits == 0);
      static_assert(BlindingBits < C::Scalar::BITS);

   public:
      static constexpr size_t Bits = C::Scalar::BITS + (BlindingEnabled ? BlindingBits : 0);
      static constexpr size_t Bytes = (Bits + 7) / 8;

      constexpr size_t bits() const { return Bits; }

      BlindedScalarBits(const typename C::Scalar& scalar, RandomNumberGenerator& rng) {
         if constexpr(BlindingEnabled) {
            constexpr size_t mask_words = BlindingBits / WordInfo<W>::bits;
            constexpr size_t mask_bytes = mask_words * WordInfo<W>::bytes;

            constexpr size_t n_words = C::Words;

            uint8_t maskb[mask_bytes] = {0};
            if(rng.is_seeded()) {
               rng.randomize(maskb, mask_bytes);
            } else {
               // If we don't have an RNG we don't have many good options. We
               // could just omit the blinding entirely, but this changes the
               // size of the blinded scalar, which we're expecting otherwise is
               // knowable at compile time. So generate a mask by XORing the
               // bytes of the scalar together. At worst, it's equivalent to
               // omitting the blinding entirely.

               std::array<uint8_t, C::Scalar::BYTES> sbytes;
               scalar.serialize_to(sbytes);
               for(size_t i = 0; i != sbytes.size(); ++i) {
                  maskb[i % mask_bytes] ^= sbytes[i];
               }
            }

            W mask[n_words] = {0};
            load_le(mask, maskb, mask_words);
            mask[mask_words - 1] |= WordInfo<W>::top_bit;
            mask[0] |= 1;

            W mask_n[2 * n_words] = {0};

            const auto sw = scalar.to_words();

            // Compute masked scalar s + k*n
            comba_mul<n_words>(mask_n, mask, C::NW.data());
            bigint_add2_nc(mask_n, 2 * n_words, sw.data(), sw.size());

            std::reverse(mask_n, mask_n + 2 * n_words);
            m_bytes = store_be<std::vector<uint8_t>>(mask_n);
         } else {
            static_assert(Bytes == C::Scalar::BYTES);
            m_bytes.resize(Bytes);
            scalar.serialize_to(std::span{m_bytes}.template first<Bytes>());
         }

         CT::poison(m_bytes.data(), m_bytes.size());
      }

      size_t get_window(size_t offset) const {
         // Extract a WindowBits sized window out of s, depending on offset.
         return read_window_bits<WindowBits>(std::span{m_bytes}, offset);
      }

      ~BlindedScalarBits() {
         secure_scrub_memory(m_bytes.data(), m_bytes.size());
         CT::unpoison(m_bytes.data(), m_bytes.size());
      }

      BlindedScalarBits(const BlindedScalarBits& other) = delete;
      BlindedScalarBits(BlindedScalarBits&& other) = delete;
      BlindedScalarBits& operator=(const BlindedScalarBits& other) = delete;
      BlindedScalarBits& operator=(BlindedScalarBits&& other) = delete;

   private:
      // TODO this could be a fixed size array
      std::vector<uint8_t> m_bytes;
};

template <typename C, size_t WindowBits>
class UnblindedScalarBits final {
   public:
      static constexpr size_t Bits = C::Scalar::BITS;

      UnblindedScalarBits(const typename C::Scalar& scalar) { scalar.serialize_to(std::span{m_bytes}); }

      size_t get_window(size_t offset) const {
         // Extract a WindowBits sized window out of s, depending on offset.
         return read_window_bits<WindowBits>(std::span{m_bytes}, offset);
      }

   private:
      std::array<uint8_t, C::Scalar::BYTES> m_bytes;
};

template <typename C, size_t W>
class PrecomputedBaseMulTable final {
   public:
      typedef typename C::Scalar Scalar;
      typedef typename C::AffinePoint AffinePoint;
      typedef typename C::ProjectivePoint ProjectivePoint;

      static constexpr size_t WindowBits = W;
      static_assert(WindowBits >= 1 && WindowBits <= 8);

      using BlindedScalar = BlindedScalarBits<C, WindowBits>;

      static constexpr size_t Windows = (BlindedScalar::Bits + WindowBits - 1) / WindowBits;

      PrecomputedBaseMulTable(const AffinePoint& p) : m_table(basemul_setup<C, WindowBits>(p, BlindedScalar::Bits)) {}

      ProjectivePoint mul(const Scalar& s, RandomNumberGenerator& rng) const {
         const BlindedScalar scalar(s, rng);
         return basemul_exec<C, WindowBits>(m_table, scalar, rng);
      }

   private:
      std::vector<AffinePoint> m_table;
};

/**
* Precomputed point multiplication table
*
* This is a standard fixed window multiplication using W-bit wide window.
*/
template <typename C, size_t W>
class WindowedMulTable final {
   public:
      typedef typename C::Scalar Scalar;
      typedef typename C::AffinePoint AffinePoint;
      typedef typename C::ProjectivePoint ProjectivePoint;

      static constexpr size_t WindowBits = W;
      static_assert(WindowBits >= 1 && WindowBits <= 8);

      using BlindedScalar = BlindedScalarBits<C, WindowBits>;

      static constexpr size_t Windows = (BlindedScalar::Bits + WindowBits - 1) / WindowBits;

      static_assert(Windows > 1);

      // 2^W elements, less the identity element
      static constexpr size_t TableSize = (1 << WindowBits) - 1;

      WindowedMulTable(const AffinePoint& p) : m_table(varpoint_setup<C, TableSize>(p)) {}

      ProjectivePoint mul(const Scalar& s, RandomNumberGenerator& rng) const {
         const BlindedScalar bits(s, rng);
         return varpoint_exec<C, WindowBits>(m_table, bits, rng);
      }

   private:
      std::vector<AffinePoint> m_table;
};

/**
* Precomputed point multiplication table with Booth
*/
template <typename C, size_t W>
class WindowedBoothMulTable final {
   public:
      typedef typename C::Scalar Scalar;
      typedef typename C::AffinePoint AffinePoint;
      typedef typename C::ProjectivePoint ProjectivePoint;

      static constexpr size_t TableBits = W;
      static_assert(TableBits >= 1 && TableBits <= 7);

      static constexpr size_t WindowBits = TableBits + 1;

      using BlindedScalar = BlindedScalarBits<C, WindowBits + 1>;

      static constexpr size_t compute_full_windows(size_t sb, size_t wb) {
         if(sb % wb == 0) {
            return (sb - 1) / wb;
         } else {
            return sb / wb;
         }
      }

      static constexpr size_t FullWindows = compute_full_windows(BlindedScalar::Bits + 1, WindowBits);

      static constexpr size_t compute_initial_shift(size_t sb, size_t wb) {
         if(sb % wb == 0) {
            return wb;
         } else {
            return sb - (sb / wb) * wb;
         }
      }

      static constexpr size_t InitialShift = compute_initial_shift(BlindedScalar::Bits + 1, WindowBits);

      static_assert(FullWindows * WindowBits + InitialShift == BlindedScalar::Bits + 1);
      static_assert(InitialShift > 0);

      // 2^W elements [1*P, 2*P, ..., 2^W*P]
      static constexpr size_t TableSize = 1 << TableBits;

      WindowedBoothMulTable(const AffinePoint& p) : m_table(varpoint_setup<C, TableSize>(p)) {}

      ProjectivePoint mul(const Scalar& s, RandomNumberGenerator& rng) const {
         const BlindedScalar bits(s, rng);

         auto accum = ProjectivePoint::identity();
         CT::poison(accum);

         for(size_t i = 0; i != FullWindows; ++i) {
            const size_t idx = BlindedScalar::Bits - InitialShift - WindowBits * i;

            const size_t w_i = bits.get_window(idx);
            const auto [tidx, tneg] = booth_recode<WindowBits>(w_i);

            // Conditional ok: loop iteration count is public
            if(i == 0) {
               accum = ProjectivePoint::from_affine(m_table.ct_select(tidx));
               accum.conditional_assign(tneg, accum.negate());
            } else {
               accum = ProjectivePoint::add_or_sub(accum, m_table.ct_select(tidx), tneg);
            }

            accum = accum.dbl_n(WindowBits);

            // Conditional ok: loop iteration count is public
            if(i <= 3) {
               accum.randomize_rep(rng);
            }
         }

         // final window (note one bit shorter than previous reads)
         const size_t w_l = bits.get_window(0) & ((1 << WindowBits) - 1);
         const auto [tidx, tneg] = booth_recode<WindowBits>(w_l << 1);
         accum = ProjectivePoint::add_or_sub(accum, m_table.ct_select(tidx), tneg);

         CT::unpoison(accum);
         return accum;
      }

   private:
      template <size_t B, std::unsigned_integral T>
      static constexpr std::pair<size_t, CT::Choice> booth_recode(T x) {
         static_assert(B < sizeof(T) * 8 - 2, "Invalid B");

         auto s_mask = CT::Mask<T>::expand(x >> B);
         const T neg_x = (1 << (B + 1)) - x - 1;
         T d = s_mask.select(neg_x, x);
         d = (d >> 1) + (d & 1);

         return std::make_pair(static_cast<size_t>(d), s_mask.as_choice());
      }

      AffinePointTable<C> m_table;
};

template <typename C, size_t W>
class WindowedMul2Table final {
   public:
      // We look at W bits of each scalar per iteration
      static_assert(W >= 1 && W <= 4);

      typedef typename C::Scalar Scalar;
      typedef typename C::AffinePoint AffinePoint;
      typedef typename C::ProjectivePoint ProjectivePoint;

      WindowedMul2Table(const AffinePoint& p, const AffinePoint& q) : m_table(mul2_setup<C, W>(p, q)) {}

      /**
      * Constant time 2-ary multiplication
      */
      ProjectivePoint mul2(const Scalar& s1, const Scalar& s2, RandomNumberGenerator& rng) const {
         using BlindedScalar = BlindedScalarBits<C, W>;
         BlindedScalar bits1(s1, rng);
         BlindedScalar bits2(s2, rng);

         return mul2_exec<C, W>(m_table, bits1, bits2, rng);
      }

   private:
      AffinePointTable<C> m_table;
};

template <typename C, size_t W>
class VartimeMul2Table final {
   public:
      // We look at W bits of each scalar per iteration
      static_assert(W >= 1 && W <= 4);

      static constexpr size_t WindowBits = W;

      using Scalar = typename C::Scalar;
      using AffinePoint = typename C::AffinePoint;
      using ProjectivePoint = typename C::ProjectivePoint;

      VartimeMul2Table(const AffinePoint& p, const AffinePoint& q) :
            m_table(to_affine_batch<C>(mul2_setup<C, W>(p, q))) {}

      /**
      * Variable time 2-ary multiplication
      *
      * A common use of 2-ary multiplication is when verifying the commitments
      * of an elliptic curve signature. Since in this case the inputs are all
      * public, there is no problem with variable time computation.
      *
      * TODO in the future we could use joint sparse form here.
      */
      ProjectivePoint mul2_vartime(const Scalar& s1, const Scalar& s2) const {
         constexpr size_t Windows = (Scalar::BITS + WindowBits - 1) / WindowBits;

         const UnblindedScalarBits<C, W> bits1(s1);
         const UnblindedScalarBits<C, W> bits2(s2);

         bool s1_is_zero = s1.is_zero().as_bool();
         bool s2_is_zero = s2.is_zero().as_bool();

         // Conditional ok: this function is variable time
         if(s1_is_zero && s2_is_zero) {
            return ProjectivePoint::identity();
         }

         auto [w_0, first_nonempty_window] = [&]() {
            for(size_t i = 0; i != Windows; ++i) {
               const size_t w_1 = bits1.get_window((Windows - i - 1) * WindowBits);
               const size_t w_2 = bits2.get_window((Windows - i - 1) * WindowBits);
               const size_t window = w_1 + (w_2 << WindowBits);
               // Conditional ok: this function is variable time
               if(window > 0) {
                  return std::make_pair(window, i);
               }
            }
            // We checked for s1 == s2 == 0 above, so we must see a window eventually
            BOTAN_ASSERT_UNREACHABLE();
         }();

         BOTAN_ASSERT_NOMSG(w_0 > 0);
         auto accum = ProjectivePoint::from_affine(m_table[w_0 - 1]);

         for(size_t i = first_nonempty_window + 1; i < Windows; ++i) {
            accum = accum.dbl_n(WindowBits);

            const size_t w_1 = bits1.get_window((Windows - i - 1) * WindowBits);
            const size_t w_2 = bits2.get_window((Windows - i - 1) * WindowBits);

            const size_t window = w_1 + (w_2 << WindowBits);

            // Conditional ok: this function is variable time
            if(window > 0) {
               accum += m_table[window - 1];
            }
         }

         return accum;
      }

   private:
      std::vector<AffinePoint> m_table;
};

/**
* SSWU constant C2 - (B / (Z * A))
*
* See RFC 9380 section 6.6.2
*/
template <typename C>
const auto& SSWU_C2()
   requires C::ValidForSswuHash
{
   // TODO(Botan4) Make this a constexpr once compilers have caught up
   static const typename C::FieldElement C2 = C::B * invert_field_element<C>(C::SSWU_Z * C::A);
   return C2;
}

/**
* SSWU constant C1 - (-B / A)
*
* See RFC 9380 section 6.6.2
*/
template <typename C>
const auto& SSWU_C1()
   requires C::ValidForSswuHash
{
   // TODO(Botan4) Make this a constexpr
   // We derive it from C2 to avoid a second inversion
   static const typename C::FieldElement C1 = (SSWU_C2<C>() * C::SSWU_Z).negate();
   return C1;
}

/**
* Map to curve (SSWU)
*
* See RFC 9380 ("Hashing to Elliptic Curves") section 6.6.2
*/
template <typename C>
inline auto map_to_curve_sswu(const typename C::FieldElement& u) -> typename C::AffinePoint {
   CT::poison(u);
   const auto z_u2 = C::SSWU_Z * u.square();  // z * u^2
   const auto z2_u4 = z_u2.square();
   const auto tv1 = invert_field_element<C>(z2_u4 + z_u2);
   auto x1 = SSWU_C1<C>() * (C::FieldElement::one() + tv1);
   x1.conditional_assign(tv1.is_zero(), SSWU_C2<C>());
   const auto gx1 = C::x3_ax_b(x1);

   const auto x2 = z_u2 * x1;
   const auto gx2 = C::x3_ax_b(x2);

   // Will be zero if gx1 is not a square
   const auto [gx1_sqrt, gx1_is_square] = sqrt_field_element<C>(gx1);

   auto x = x2;
   // By design one of gx1 and gx2 must be a quadratic residue
   auto y = sqrt_field_element<C>(gx2).first;

   C::FieldElement::conditional_assign(x, y, gx1_is_square, x1, gx1_sqrt);

   y.conditional_assign(y.is_even() != u.is_even(), y.negate());

   auto pt = typename C::AffinePoint(x, y);

   CT::unpoison(pt);
   return pt;
}

/**
* Hash to curve (SSWU); RFC 9380
*
* This is the Simplified Shallue-van de Woestijne-Ulas (SSWU) map.
*
* The parameter expand_message models the function of RFC 9380 and is provided
* by higher levels. For the curves implemented here it will typically be XMD,
* but could also be an XOF (expand_message_xof) or a MHF like Argon2.
*
* For details see RFC 9380 sections 3, 5.2 and 6.6.2.
*/
template <typename C, bool RO, std::invocable<std::span<uint8_t>> ExpandMsg>
   requires C::ValidForSswuHash
inline auto hash_to_curve_sswu(const ExpandMsg& expand_message)
   -> std::conditional_t<RO, typename C::ProjectivePoint, typename C::AffinePoint> {
   constexpr size_t SecurityLevel = (C::OrderBits + 1) / 2;
   constexpr size_t L = (C::PrimeFieldBits + SecurityLevel + 7) / 8;
   constexpr size_t Cnt = RO ? 2 : 1;

   std::array<uint8_t, L * Cnt> uniform_bytes;
   expand_message(uniform_bytes);

   if constexpr(RO) {
      const auto u0 = C::FieldElement::from_wide_bytes(std::span<const uint8_t, L>(uniform_bytes.data(), L));
      const auto u1 = C::FieldElement::from_wide_bytes(std::span<const uint8_t, L>(uniform_bytes.data() + L, L));

      auto accum = C::ProjectivePoint::from_affine(map_to_curve_sswu<C>(u0));
      accum += map_to_curve_sswu<C>(u1);
      return accum;
   } else {
      const auto u = C::FieldElement::from_wide_bytes(std::span<const uint8_t, L>(uniform_bytes.data(), L));
      return map_to_curve_sswu<C>(u);
   }
}

}  // namespace Botan

#endif

/*
* (C) 1999-2011,2016,2018,2019,2020,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mod_inv.h>

#include <botan/numthry.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

BigInt inverse_mod_odd_modulus(const BigInt& n, const BigInt& mod) {
   // Caller should assure these preconditions:
   BOTAN_ASSERT_NOMSG(n.is_positive());
   BOTAN_ASSERT_NOMSG(mod.is_positive());
   BOTAN_ASSERT_NOMSG(n < mod);
   BOTAN_ASSERT_NOMSG(mod >= 3 && mod.is_odd());

   /*
   This uses a modular inversion algorithm designed by Niels Möller
   and implemented in Nettle. The same algorithm was later also
   adapted to GMP in mpn_sec_invert.

   It can be easily implemented in a way that does not depend on
   secret branches or memory lookups, providing resistance against
   some forms of side channel attack.

   There is also a description of the algorithm in Appendix 5 of "Fast
   Software Polynomial Multiplication on ARM Processors using the NEON Engine"
   by Danilo Câmara, Conrado P. L. Gouvêa, Julio López, and Ricardo
   Dahab in LNCS 8182
      https://inria.hal.science/hal-01506572/document

   Thanks to Niels for creating the algorithm, explaining some things
   about it, and the reference to the paper.
   */

   const size_t mod_words = mod.sig_words();
   BOTAN_ASSERT(mod_words > 0, "Not empty");

   secure_vector<word> tmp_mem(5 * mod_words);

   word* v_w = &tmp_mem[0];
   word* u_w = &tmp_mem[1 * mod_words];
   word* b_w = &tmp_mem[2 * mod_words];
   word* a_w = &tmp_mem[3 * mod_words];
   word* mp1o2 = &tmp_mem[4 * mod_words];

   CT::poison(tmp_mem.data(), tmp_mem.size());

   copy_mem(a_w, n._data(), std::min(n.size(), mod_words));
   copy_mem(b_w, mod._data(), std::min(mod.size(), mod_words));
   u_w[0] = 1;
   // v_w = 0

   // compute (mod + 1) / 2 which [because mod is odd] is equal to
   // (mod / 2) + 1
   copy_mem(mp1o2, mod._data(), std::min(mod.size(), mod_words));
   bigint_shr1(mp1o2, mod_words, 1);
   word carry = bigint_add2_nc(mp1o2, mod_words, u_w, 1);
   BOTAN_ASSERT_NOMSG(carry == 0);

   // Only n.bits() + mod.bits() iterations are required, but avoid leaking the size of n
   const size_t execs = 2 * mod.bits();

   for(size_t i = 0; i != execs; ++i) {
      const word odd_a = a_w[0] & 1;

      //if(odd_a) a -= b
      word underflow = bigint_cnd_sub(odd_a, a_w, b_w, mod_words);

      //if(underflow) { b -= a; a = abs(a); swap(u, v); }
      bigint_cnd_add(underflow, b_w, a_w, mod_words);
      bigint_cnd_abs(underflow, a_w, mod_words);
      bigint_cnd_swap(underflow, u_w, v_w, mod_words);

      // a >>= 1
      bigint_shr1(a_w, mod_words, 1);

      //if(odd_a) u -= v;
      word borrow = bigint_cnd_sub(odd_a, u_w, v_w, mod_words);

      // if(borrow) u += p
      bigint_cnd_add(borrow, u_w, mod._data(), mod_words);

      const word odd_u = u_w[0] & 1;

      // u >>= 1
      bigint_shr1(u_w, mod_words, 1);

      //if(odd_u) u += mp1o2;
      bigint_cnd_add(odd_u, u_w, mp1o2, mod_words);
   }

   const auto a_is_0 = CT::all_zeros(a_w, mod_words);

   auto b_is_1 = CT::Mask<word>::is_equal(b_w[0], 1);
   for(size_t i = 1; i != mod_words; ++i) {
      b_is_1 &= CT::Mask<word>::is_zero(b_w[i]);
   }

   BOTAN_ASSERT(a_is_0.as_bool(), "A is zero");

   // if b != 1 then gcd(n,mod) > 1 and inverse does not exist
   // in which case zero out the result to indicate this
   (~b_is_1).if_set_zero_out(v_w, mod_words);

   /*
   * We've placed the result in the lowest words of the temp buffer.
   * So just clear out the other values and then give that buffer to a
   * BigInt.
   */
   clear_mem(&tmp_mem[mod_words], 4 * mod_words);

   CT::unpoison(tmp_mem.data(), tmp_mem.size());

   BigInt r;
   r.swap_reg(tmp_mem);
   return r;
}

BigInt inverse_mod_pow2(const BigInt& a1, size_t k) {
   /*
   * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
   * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
   */

   if(a1.is_even() || k == 0) {
      return BigInt::zero();
   }
   if(k == 1) {
      return BigInt::one();
   }

   BigInt a = a1;
   a.mask_bits(k);

   BigInt b = BigInt::one();
   BigInt X = BigInt::zero();
   BigInt newb;

   const size_t a_words = a.sig_words();

   X.grow_to(round_up(k, BOTAN_MP_WORD_BITS) / BOTAN_MP_WORD_BITS);
   b.grow_to(a_words);

   /*
   Hide the exact value of k. k is anyway known to word length
   granularity because of the length of a, so no point in doing more
   than this.
   */
   const size_t iter = round_up(k, BOTAN_MP_WORD_BITS);

   for(size_t i = 0; i != iter; ++i) {
      const bool b0 = b.get_bit(0);
      X.conditionally_set_bit(i, b0);
      newb = b - a;
      b.ct_cond_assign(b0, newb);
      b >>= 1;
   }

   X.mask_bits(k);

   CT::unpoison(X);
   return X;
}

}  // namespace

std::optional<BigInt> inverse_mod_general(const BigInt& x, const BigInt& mod) {
   BOTAN_ARG_CHECK(x > 0, "x must be greater than zero");
   BOTAN_ARG_CHECK(mod > 0, "mod must be greater than zero");
   BOTAN_ARG_CHECK(x < mod, "x must be less than m");

   // Easy case where gcd > 1 so no inverse exists
   if(x.is_even() && mod.is_even()) {
      return std::nullopt;
   }

   if(mod.is_odd()) {
      BigInt z = inverse_mod_odd_modulus(x, mod);
      if(z.is_zero()) {
         return std::nullopt;
      } else {
         return z;
      }
   }

   // If x is even and mod is even we already returned 0
   // If x is even and mod is odd we jumped directly to odd-modulus algo
   BOTAN_ASSERT_NOMSG(x.is_odd());

   const size_t mod_lz = low_zero_bits(mod);
   BOTAN_ASSERT_NOMSG(mod_lz > 0);
   const size_t mod_bits = mod.bits();
   BOTAN_ASSERT_NOMSG(mod_bits > mod_lz);

   if(mod_lz == mod_bits - 1) {
      // In this case we are performing an inversion modulo 2^k
      auto z = inverse_mod_pow2(x, mod_lz);
      if(z.is_zero()) {
         return std::nullopt;
      } else {
         return z;
      }
   }

   if(mod_lz == 1) {
      /*
      Inversion modulo 2*o is an easier special case of CRT

      This is exactly the main CRT flow below but taking advantage of
      the fact that any odd number ^-1 modulo 2 is 1. As a result both
      inv_2k and c can be taken to be 1, m2k is 2, and h is always
      either 0 or 1, and its value depends only on the low bit of inv_o.

      This is worth special casing because we generate RSA primes such
      that phi(n) is of this form. However this only works for keys
      that we generated in this way; pre-existing keys will typically
      fall back to the general algorithm below.
      */

      const BigInt o = mod >> 1;
      const BigInt inv_o = inverse_mod_odd_modulus(ct_modulo(x, o), o);

      // No modular inverse in this case:
      if(inv_o == 0) {
         return std::nullopt;
      }

      BigInt h = inv_o;
      h.ct_cond_add(!inv_o.get_bit(0), o);
      return h;
   }

   /*
   * In this case we are performing an inversion modulo 2^k*o for
   * some k >= 2 and some odd (not necessarily prime) integer.
   * Compute the inversions modulo 2^k and modulo o, then combine them
   * using CRT, which is possible because 2^k and o are relatively prime.
   */

   const BigInt o = mod >> mod_lz;
   const BigInt inv_o = inverse_mod_odd_modulus(ct_modulo(x, o), o);
   const BigInt inv_2k = inverse_mod_pow2(x, mod_lz);

   // No modular inverse in this case:
   if(inv_o == 0 || inv_2k == 0) {
      return std::nullopt;
   }

   const BigInt m2k = BigInt::power_of_2(mod_lz);
   // Compute the CRT parameter
   const BigInt c = inverse_mod_pow2(o, mod_lz);

   // This should never happen; o is odd so gcd is 1 and inverse mod 2^k exists
   BOTAN_ASSERT_NOMSG(!c.is_zero());

   // Compute h = c*(inv_2k-inv_o) mod 2^k
   BigInt h = c * (inv_2k - inv_o);
   const bool h_neg = h.is_negative();
   h.set_sign(BigInt::Positive);
   h.mask_bits(mod_lz);
   const bool h_nonzero = h.is_nonzero();
   h.ct_cond_assign(h_nonzero && h_neg, m2k - h);

   // Return result inv_o + h * o
   h *= o;
   h += inv_o;
   return h;
}

BigInt inverse_mod_secret_prime(const BigInt& x, const BigInt& p) {
   BOTAN_ARG_CHECK(x.is_positive() && p.is_positive(), "Parameters must be positive");
   BOTAN_ARG_CHECK(x < p, "x must be less than p");
   BOTAN_ARG_CHECK(p.is_odd() and p > 1, "Primes are odd integers greater than 1");

   // TODO possibly use FLT, or the algorithm presented for this case in
   // Handbook of Elliptic and Hyperelliptic Curve Cryptography

   return inverse_mod_odd_modulus(x, p);
}

BigInt inverse_mod_public_prime(const BigInt& x, const BigInt& p) {
   return inverse_mod_secret_prime(x, p);
}

BigInt inverse_mod_rsa_public_modulus(const BigInt& x, const BigInt& n) {
   BOTAN_ARG_CHECK(n.is_positive() && n.is_odd(), "RSA public modulus must be odd and positive");
   BOTAN_ARG_CHECK(x.is_positive() && x < n, "Input must be positive and less than RSA modulus");
   BigInt z = inverse_mod_odd_modulus(x, n);
   BOTAN_ASSERT(!z.is_zero(), "Accidentally factored the public modulus");  // whoops
   return z;
}

namespace {

uint64_t barrett_mod_65537(uint64_t x) {
   constexpr uint64_t mod = 65537;
   constexpr size_t s = 32;
   constexpr uint64_t c = (static_cast<uint64_t>(1) << s) / mod;

   uint64_t q = (x * c) >> s;
   uint64_t r = x - q * mod;

   auto r_gt_mod = CT::Mask<uint64_t>::is_gte(r, mod);
   return r - r_gt_mod.if_set_return(mod);
}

word inverse_mod_65537(word x) {
   // Need 64-bit here as accum*accum exceeds 32-bit if accum=0x10000
   uint64_t accum = 1;
   // Basic square and multiply, with all bits of exponent set
   for(size_t i = 0; i != 16; ++i) {
      accum = barrett_mod_65537(accum * accum);
      accum = barrett_mod_65537(accum * x);
   }
   return static_cast<word>(accum);
}

}  // namespace

BigInt compute_rsa_secret_exponent(const BigInt& e, const BigInt& phi_n, const BigInt& p, const BigInt& q) {
   /*
   * Both p - 1 and q - 1 are chosen to be relatively prime to e. Thus
   * phi(n), the least common multiple of p - 1 and q - 1, is also
   * relatively prime to e.
   */
   BOTAN_DEBUG_ASSERT(gcd(e, phi_n) == 1);

   if(e == 65537) {
      /*
      Arazi's algorithm for inversion of prime x modulo a non-prime

      "GCD-Free Algorithms for Computing Modular Inverses"
      Marc Joye and Pascal Paillier, CHES 2003 (LNCS 2779)
      https://marcjoye.github.io/papers/JP03gcdfree.pdf

      This could be extended to cover other cases such as e=3 or e=17 but
      these days 65537 is the standard RSA public exponent
      */

      constexpr word e_w = 65537;

      const word phi_mod_e = ct_mod_word(phi_n, e_w);
      const word inv_phi_mod_e = inverse_mod_65537(phi_mod_e);
      BOTAN_DEBUG_ASSERT((inv_phi_mod_e * phi_mod_e) % e_w == 1);
      const word neg_inv_phi_mod_e = (e_w - inv_phi_mod_e);
      return ct_divide_word((phi_n * neg_inv_phi_mod_e) + 1, e_w);
   } else {
      // TODO possibly do something else taking advantage of the special structure here

      BOTAN_UNUSED(p, q);
      if(auto d = inverse_mod_general(e, phi_n)) {
         return *d;
      } else {
         throw Internal_Error("Failed to compute RSA secret exponent");
      }
   }
}

BigInt inverse_mod(const BigInt& n, const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "modulus cannot be negative");
   BOTAN_ARG_CHECK(!n.is_negative(), "value cannot be negative");

   if(n.is_zero() || (n.is_even() && mod.is_even())) {
      return BigInt::zero();
   }

   if(n >= mod) {
      return inverse_mod(ct_modulo(n, mod), mod);
   }

   return inverse_mod_general(n, mod).value_or(BigInt::zero());
}

}  // namespace Botan

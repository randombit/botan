/*
* (C) 2016,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/primality.h>

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/rng.h>
#include <botan/internal/monty.h>
#include <botan/internal/monty_exp.h>
#include <algorithm>

namespace Botan {

bool is_lucas_probable_prime(const BigInt& C, const Modular_Reducer& mod_C) {
   if(C == 2 || C == 3 || C == 5 || C == 7 || C == 11 || C == 13) {
      return true;
   }

   if(C <= 1 || C.is_even()) {
      return false;
   }

   BigInt D = BigInt::from_word(5);

   for(;;) {
      int32_t j = jacobi(D, C);
      if(j == 0) {
         return false;
      }

      if(j == -1) {
         break;
      }

      // Check 5, -7, 9, -11, 13, -15, 17, ...
      if(D.is_negative()) {
         D.flip_sign();
         D += 2;
      } else {
         D += 2;
         D.flip_sign();
      }

      if(D == 17 && is_perfect_square(C).is_nonzero()) {
         return false;
      }
   }

   const BigInt K = C + 1;
   const size_t K_bits = K.bits() - 1;

   BigInt U = BigInt::one();
   BigInt V = BigInt::one();

   BigInt Ut, Vt, U2, V2;

   for(size_t i = 0; i != K_bits; ++i) {
      const bool k_bit = K.get_bit(K_bits - 1 - i);

      Ut = mod_C.multiply(U, V);

      Vt = mod_C.reduce(mod_C.square(V) + mod_C.multiply(D, mod_C.square(U)));
      Vt.ct_cond_add(Vt.is_odd(), C);
      Vt >>= 1;
      Vt = mod_C.reduce(Vt);

      U = Ut;
      V = Vt;

      U2 = mod_C.reduce(Ut + Vt);
      U2.ct_cond_add(U2.is_odd(), C);
      U2 >>= 1;

      V2 = mod_C.reduce(Vt + Ut * D);
      V2.ct_cond_add(V2.is_odd(), C);
      V2 >>= 1;

      U.ct_cond_assign(k_bit, U2);
      V.ct_cond_assign(k_bit, V2);
   }

   return (U == 0);
}

bool is_bailie_psw_probable_prime(const BigInt& n, const Modular_Reducer& mod_n) {
   if(n == 2) {
      return true;
   } else if(n <= 1 || n.is_even()) {
      return false;
   }

   auto monty_n = std::make_shared<Montgomery_Params>(n, mod_n);
   const auto base = BigInt::from_word(2);
   return passes_miller_rabin_test(n, mod_n, monty_n, base) && is_lucas_probable_prime(n, mod_n);
}

bool passes_miller_rabin_test(const BigInt& n,
                              const Modular_Reducer& mod_n,
                              const std::shared_ptr<Montgomery_Params>& monty_n,
                              const BigInt& a) {
   if(n < 3 || n.is_even()) {
      return false;
   }

   BOTAN_ASSERT_NOMSG(n > 1);

   const BigInt n_minus_1 = n - 1;
   const size_t s = low_zero_bits(n_minus_1);
   const BigInt nm1_s = n_minus_1 >> s;
   const size_t n_bits = n.bits();

   const size_t powm_window = 4;

   auto powm_a_n = monty_precompute(monty_n, a, powm_window);

   BigInt y = monty_execute(*powm_a_n, nm1_s, n_bits).value();

   if(y == 1 || y == n_minus_1) {
      return true;
   }

   for(size_t i = 1; i != s; ++i) {
      y = mod_n.square(y);

      if(y == 1) {  // found a non-trivial square root
         return false;
      }

      /*
      -1 is the trivial square root of unity, so ``a`` is not a
      witness for this number - give up
      */
      if(y == n_minus_1) {
         return true;
      }
   }

   return false;
}

bool is_miller_rabin_probable_prime(const BigInt& n,
                                    const Modular_Reducer& mod_n,
                                    RandomNumberGenerator& rng,
                                    size_t test_iterations) {
   if(n < 3 || n.is_even()) {
      return false;
   }

   auto monty_n = std::make_shared<Montgomery_Params>(n, mod_n);

   for(size_t i = 0; i != test_iterations; ++i) {
      const BigInt a = BigInt::random_integer(rng, BigInt::from_word(2), n);

      if(!passes_miller_rabin_test(n, mod_n, monty_n, a)) {
         return false;
      }
   }

   // Failed to find a counterexample
   return true;
}

size_t miller_rabin_test_iterations(size_t n_bits, size_t prob, bool random) {
   const size_t base = (prob + 2) / 2;  // worst case 4^-t error rate

   /*
   * If the candidate prime was maliciously constructed, we can't rely
   * on arguments based on p being random.
   */
   if(random == false) {
      return base;
   }

   /*
   * For randomly chosen numbers we can use the estimates from
   * http://www.math.dartmouth.edu/~carlp/PDF/paper88.pdf
   *
   * These values are derived from the inequality for p(k,t) given on
   * the second page.
   */
   if(prob <= 128) {
      if(n_bits >= 1536) {
         return 4;  // < 2^-133
      }
      if(n_bits >= 1024) {
         return 6;  // < 2^-133
      }
      if(n_bits >= 512) {
         return 12;  // < 2^-129
      }
      if(n_bits >= 256) {
         return 29;  // < 2^-128
      }
   }

   /*
   If the user desires a smaller error probability than we have
   precomputed error estimates for, just fall back to using the worst
   case error rate.
   */
   return base;
}

}  // namespace Botan

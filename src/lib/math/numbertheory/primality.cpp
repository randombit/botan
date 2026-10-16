/*
* (C) 2016,2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/primality.h>

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/rng.h>
#include <botan/internal/barrett.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/monty.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/mp_core.h>

namespace Botan {

namespace {

bool lucas_test(const BigInt& C, const Barrett_Reduction& mod_C) {
   BOTAN_ARG_CHECK(C.signum() >= 0, "Argument must be non-negative");

   if(C == 2 || C == 3 || C == 5 || C == 7 || C == 11 || C == 13) {
      return true;
   }

   if(C <= 1 || C.is_even()) {
      return false;
   }

   BigInt D = BigInt::from_word(5);

   for(;;) {
      const int32_t j = jacobi(D, C);
      if(j == 0) {
         return false;
      }

      if(j == -1) {
         break;
      }

      // Check 5, -7, 9, -11, 13, -15, 17, ...
      if(D.signum() < 0) {
         D.flip_sign();
         D += 2;
      } else {
         D += 2;
         D.flip_sign();
      }

      if(D == 17 && is_perfect_square(C).signum() != 0) {
         return false;
      }
   }

   if(D.signum() < 0) {
      D += C;
   }

   const BigInt K = C + 1;
   const size_t K_bits = K.bits() - 1;

   BigInt U = BigInt::one();
   BigInt V = BigInt::one();

   BigInt Ut;
   BigInt Vt;
   BigInt U2;
   BigInt V2;

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

      V2 = mod_C.reduce(Vt + mod_C.multiply(Ut, D));
      V2.ct_cond_add(V2.is_odd(), C);
      V2 >>= 1;

      U.ct_cond_assign(k_bit, U2);
      V.ct_cond_assign(k_bit, V2);
   }

   return (U == 0);
}

/*
* Window size for variable time exponentiation of an exponent of exp_bits
*/
size_t vartime_window_bits(size_t exp_bits) {
   if(exp_bits <= 256) {
      return 4;
   } else if(exp_bits <= 1024) {
      return 5;
   } else if(exp_bits <= 2048) {
      return 6;
   } else {
      return 7;
   }
}

/**
* Precomputed values shared by all Miller-Rabin tests of a single n
*/
class Miller_Rabin_Test final {
   public:
      Miller_Rabin_Test(const BigInt& n, const Montgomery_Params& monty_n, bool vartime) :
            m_monty_n(monty_n), m_vartime(vartime) {
         BOTAN_ARG_CHECK(n >= 3 && n.is_odd(), "Invalid integer for Miller-Rabin test");

         const size_t N = m_monty_n.p_words();

         const BigInt n_minus_1 = n - 1;
         /*
         * This unpoison is not ideal but realistically there is no way to
         * hide the number of loop iterations (below). The main user of
         * secret primes is RSA and we always generate RSA primes such that
         * p == 3 (mod 4), which means s is always 1.
         */
         m_s = CT::driveby_unpoison(low_zero_bits(n_minus_1));
         m_d = n_minus_1 >> m_s;
         m_d_bits = m_d.bits();

         // 1 and -1 in Montgomery form
         m_one.assign(m_monty_n.R1()._as_span().first(N).begin(), m_monty_n.R1()._as_span().first(N).end());
         m_minus_one.resize(N);
         bigint_sub3(m_minus_one.data(), n._data(), N, m_one.data(), N);
      }

      /**
      * Perform a single Miller-Rabin test with the specified base
      */
      bool passes(const BigInt& a) const {
         Montgomery_Int y = [&]() {
            if(m_vartime) {
               const auto powm_a = monty_precompute(m_monty_n, a, vartime_window_bits(m_d_bits), false);
               return monty_execute_vartime(*powm_a, m_d);
            } else {
               const auto powm_a = monty_precompute(m_monty_n, a, 4, true);
               return monty_execute(*powm_a, m_d, m_d_bits);
            }
         }();

         if(is_one(y) || is_minus_one(y)) {
            return true;
         }

         secure_vector<word> ws(2 * m_monty_n.p_words());

         for(size_t i = 1; i != m_s; ++i) {
            y.square_this_n_times(ws, 1);

            if(is_one(y)) {  // found a non-trivial square root
               return false;
            }

            /*
            -1 is the trivial square root of unity, so ``a`` is not a
            witness for this number - give up
            */
            if(is_minus_one(y)) {
               return true;
            }
         }

         return false;
      }

   private:
      bool is_one(const Montgomery_Int& y) const {
         return CT::is_equal(y.repr().data(), m_one.data(), m_one.size()).as_bool();
      }

      bool is_minus_one(const Montgomery_Int& y) const {
         return CT::is_equal(y.repr().data(), m_minus_one.data(), m_minus_one.size()).as_bool();
      }

      Montgomery_Params m_monty_n;
      bool m_vartime;
      size_t m_s;
      BigInt m_d;
      size_t m_d_bits;
      secure_vector<word> m_one;
      secure_vector<word> m_minus_one;
};

bool miller_rabin_test(const BigInt& n,
                       const Montgomery_Params& monty_n,
                       RandomNumberGenerator& rng,
                       size_t test_iterations,
                       bool vartime) {
   if(n < 3 || n.is_even()) {
      return false;
   }

   const Miller_Rabin_Test mr(n, monty_n, vartime);

   for(size_t i = 0; i != test_iterations; ++i) {
      const BigInt a = BigInt::random_integer(rng, BigInt::from_word(2), n);

      if(!mr.passes(a)) {
         return false;
      }
   }

   // Failed to find a counterexample
   return true;
}

bool bailie_psw_test(const BigInt& n, const Montgomery_Params& monty_n, bool vartime) {
   if(n == 2) {
      return true;
   } else if(n <= 1 || n.is_even()) {
      return false;
   }

   const Miller_Rabin_Test mr(n, monty_n, vartime);
   if(!mr.passes(BigInt::from_word(2))) {
      return false;
   }

   return vartime ? is_lucas_probable_prime_vartime(n, monty_n) : is_lucas_probable_prime(n, monty_n);
}

}  // namespace

bool is_lucas_probable_prime(const BigInt& n, const Montgomery_Params& monty_n) {
   return lucas_test(n, Barrett_Reduction::for_secret_modulus(monty_n.p()));
}

bool is_lucas_probable_prime_vartime(const BigInt& n, const Montgomery_Params& monty_n) {
   // Currently identical to the constant time version
   return lucas_test(n, Barrett_Reduction::for_public_modulus(monty_n.p()));
}

bool is_bailie_psw_probable_prime(const BigInt& n, const Montgomery_Params& monty_n) {
   return bailie_psw_test(n, monty_n, false);
}

bool is_bailie_psw_probable_prime_vartime(const BigInt& n, const Montgomery_Params& monty_n) {
   return bailie_psw_test(n, monty_n, true);
}

bool is_bailie_psw_probable_prime(const BigInt& n) {
   if(n == 2) {
      return true;
   } else if(n <= 1 || n.is_even()) {
      return false;
   }

   return bailie_psw_test(n, Montgomery_Params(n), false);
}

bool is_bailie_psw_probable_prime_vartime(const BigInt& n) {
   if(n == 2) {
      return true;
   } else if(n <= 1 || n.is_even()) {
      return false;
   }

   return bailie_psw_test(n, Montgomery_Params(n), true);
}

bool is_miller_rabin_probable_prime(const BigInt& n,
                                    const Montgomery_Params& monty_n,
                                    RandomNumberGenerator& rng,
                                    size_t test_iterations) {
   return miller_rabin_test(n, monty_n, rng, test_iterations, false);
}

bool is_miller_rabin_probable_prime_vartime(const BigInt& n,
                                            const Montgomery_Params& monty_n,
                                            RandomNumberGenerator& rng,
                                            size_t test_iterations) {
   return miller_rabin_test(n, monty_n, rng, test_iterations, true);
}

size_t miller_rabin_test_iterations(size_t n_bits, size_t prob, bool random) {
   // Cap prob at 512 bits as _way_ more than enough; a random fault causing
   // false accept is much more likely to occur than an actual 2^-512 event is.

   prob = std::min<size_t>(512, prob);

   const size_t base = (prob + 2) / 2;  // worst case 4^-t error rate

   /*
   * If the candidate prime was maliciously constructed, we can't rely
   * on arguments based on p being random.
   */
   if(!random) {
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

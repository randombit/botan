/*
* (C) 2016,2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/primality.h>

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/monty.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/target_info.h>
#include <tuple>
#include <utility>

#if defined(BOTAN_HAS_THREAD_UTILS) && !defined(BOTAN_HAS_VALGRIND)
   #include <botan/internal/thread_pool.h>
#endif

namespace Botan {

namespace {

/*
* Jacobi symbol (a/n) for odd n and a < n, returned as masks for the symbol
* being -1 or 0
*
* This is the binary algorithm run for a fixed number of iterations, so it is
* constant time with respect to a. The value of n is public.
*/
std::pair<CT::Mask<word>, CT::Mask<word>> ct_jacobi_word(word a, word n) {
   // Each iteration reduces the total bit length of a and n by at least one,
   // ending with a == 0 and n == gcd(a, n)
   const size_t iterations = 2 * high_bit(n);

   word s = 0;  // the sign, in bit 1

   for(size_t i = 0; i != iterations; ++i) {
      const auto a_odd = CT::Mask<word>::expand_bit(a, 0);
      const auto swap = a_odd & CT::Mask<word>::is_lt(a, n);

      // (a/n) = -(n/a) if a and n are both 3 (mod 4)
      s ^= swap.if_set_return(a & n & 2);
      swap.conditional_swap(a, n);

      a -= a_odd.if_set_return(n);
      a >>= 1;

      // (2/n) = -1 if n is 3 or 5 (mod 8)
      s ^= (n ^ (n >> 1)) & 2;
   }

   const auto gcd_is_one = CT::Mask<word>::is_equal(n, 1);
   return {gcd_is_one & CT::Mask<word>::expand(s), ~gcd_is_one};
}

/*
* Search count entries of the sequence 5, -7, 9, -11, 13, ..., starting at
* index first, for the first D with Jacobi symbol (D/C) != 1
*
* This is constant time with respect to C. Returns masks indicating if such
* a D was found and if (D/C) == 0, along with the index of D.
*/
std::tuple<CT::Mask<word>, CT::Mask<word>, word> selfridge_search(const BigInt& C, size_t first, size_t count) {
   auto found = CT::Mask<word>::cleared();
   auto symbol_zero = CT::Mask<word>::cleared();
   word index = 0;

   for(size_t i = first; i != first + count; ++i) {
      const word d = 5 + 2 * i;

      // Every D in the sequence is 1 (mod 4), which implies (D/C) == (C/|D|)
      const word r = ct_mod_word(C, d);
      CT::poison(r);
      const auto [minus_one, zero] = ct_jacobi_word(r, d);

      const auto first_hit = ~found & (minus_one | zero);
      index = first_hit.select(static_cast<word>(i), index);
      symbol_zero |= first_hit & zero;
      found |= first_hit;
   }

   return {found, symbol_zero, index};
}

/*
* Lucas probable prime test, following FIPS 186-4 C.3.3 with all values
* kept in Montgomery form
*/
bool lucas_test(const BigInt& C, const Montgomery_Params& monty_C, bool vartime) {
   BOTAN_ARG_CHECK(C.signum() >= 0, "Argument must be non-negative");

   if(C == 2 || C == 3 || C == 5 || C == 7 || C == 11 || C == 13) {
      return true;
   }

   if(C <= 1 || C.is_even()) {
      return false;
   }

   /*
   * Find the first D in the sequence 5, -7, 9, -11, 13, ... with (D/C) == -1
   *
   * Which D is chosen depends on C, so the constant time variant checks a
   * block of 256 values at once, revealing only which block contained D. For
   * a random prime C, the first block fails with probability about 2^-96.
   */
   const size_t block = vartime ? 8 : 256;

   word D_index = 0;
   for(size_t first = 0;; first += block) {
      const auto [found, symbol_zero, index] = selfridge_search(C, first, block);

      if(found.as_bool()) {
         if(symbol_zero.as_bool()) {
            return false;
         }
         D_index = index;
         break;
      }

      // A perfect square has no D with (D/C) == -1
      if(first == 0 && is_perfect_square(C).signum() != 0) {
         return false;
      }
   }

   if(vartime) {
      CT::unpoison(D_index);
   }

   const word D = 5 + 2 * D_index;
   const bool D_negative = (D_index % 2) == 1;

   const BigInt K = C + 1;
   const size_t K_bits = K.bits() - 1;

   secure_vector<word> ws;

   Montgomery_Int U = Montgomery_Int::one(monty_C);
   Montgomery_Int V = U;
   Montgomery_Int Ut = U;
   Montgomery_Int Vt = U;
   Montgomery_Int U2 = U;
   Montgomery_Int V2 = U;
   Montgomery_Int T = U;

   // z += D*t, overwriting t
   const auto add_D_times = [&](Montgomery_Int& z, Montgomery_Int& t) {
      t.mul_by_word(D);
      if(vartime) {
         if(D_negative) {
            z -= t;
         } else {
            z += t;
         }
      } else {
         t.ct_cond_negate(D_negative);
         z += t;
      }
   };

   for(size_t i = 0; i != K_bits; ++i) {
      const bool k_bit = K.get_bit(K_bits - 1 - i);

      // U_temp = U V
      Ut = U;
      Ut.mul_by(V, ws);

      // V_temp = (V^2 + D U^2) / 2
      T = U;
      T.square_this_n_times(ws, 1);
      Vt = V;
      Vt.square_this_n_times(ws, 1);
      add_D_times(Vt, T);
      Vt.div2();

      if(!vartime || k_bit) {
         // U_i = (U_temp + V_temp) / 2
         U2 = Ut;
         U2 += Vt;
         U2.div2();

         // V_i = (V_temp + D U_temp) / 2
         T = Ut;
         V2 = Vt;
         add_D_times(V2, T);
         V2.div2();
      }

      if(vartime) {
         if(k_bit) {
            U = U2;
            V = V2;
         } else {
            U = Ut;
            V = Vt;
         }
      } else {
         U = Ut;
         V = Vt;
         U.ct_cond_assign(k_bit, U2);
         V.ct_cond_assign(k_bit, V2);
      }
   }

   return U.is_zero();
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

#if defined(BOTAN_HAS_THREAD_UTILS) && !defined(BOTAN_HAS_VALGRIND)

/*
* Miller-Rabin tests per thread pool job
*
* The cost of a test grows roughly quadratically with the size of n, so
* smaller n get more tests per job to keep each job worth dispatching.
*/
size_t miller_rabin_tests_per_job(size_t n_bits) {
   constexpr size_t ref_bits = 1024;
   constexpr size_t ref_tests = 8;
   if(n_bits > ref_bits) {
      return ref_tests;
   } else {
      return std::max(ref_tests, (ref_tests * ref_bits * ref_bits) / (n_bits * n_bits));
   }
}

#endif

bool miller_rabin_lucas_test(
   const BigInt& n, const Montgomery_Params& monty_n, RandomNumberGenerator& rng, size_t t, bool vartime) {
   if(n < 3 || n.is_even()) {
      return false;
   }
   if(t == 0) {
      t = 1;
   }

   const Miller_Rabin_Test mr(n, monty_n, vartime);

   const auto random_base = [&]() { return BigInt::random_integer(rng, BigInt::from_word(2), n); };

   // A single test first, since that alone rejects almost all composites
   if(!mr.passes(random_base())) {
      return false;
   }
   t -= 1;

#if defined(BOTAN_HAS_THREAD_UTILS) && !defined(BOTAN_HAS_VALGRIND)
   auto& pool = Thread_Pool::global_instance();
   const size_t tests_per_job = miller_rabin_tests_per_job(n.bits());

   // The Lucas test costs about as much as three Miller-Rabin tests
   if(pool.worker_count() > 0 && t > 0 && t + 3 >= tests_per_job) {
      // The jobs cannot share the RNG, so draw all of the bases here
      std::vector<BigInt> bases;
      bases.reserve(t);
      for(size_t i = 0; i != t; ++i) {
         bases.push_back(random_base());
      }

      // Split the tests into jobs of (nearly) equal size
      const size_t job_tests = ceil_division(t, ceil_division(t, tests_per_job));
      const size_t jobs = ceil_division(t, job_tests);

      const auto passes_tests = [&](size_t from, size_t to) {
         for(size_t i = from; i != to; ++i) {
            if(!mr.passes(bases[i])) {
               return false;
            }
         }
         return true;
      };

      std::vector<Joining_Future<bool>> futures;
      futures.reserve(jobs);

      futures.push_back(pool.run([&]() { return lucas_test(n, monty_n, vartime); }));

      // The first job runs in this thread, the rest in the pool
      for(size_t j = 1; j < jobs; ++j) {
         const size_t from = j * job_tests;
         const size_t to = std::min(t, from + job_tests);
         futures.push_back(pool.run([&, from, to]() { return passes_tests(from, to); }));
      }

      bool passes = passes_tests(0, std::min(t, job_tests));

      // Collect every result, so that an exception from any job propagates
      for(auto& future : futures) {
         passes = future.get() && passes;
      }

      return passes;
   }
#endif

   for(size_t i = 0; i != t; ++i) {
      if(!mr.passes(random_base())) {
         return false;
      }
   }

   return lucas_test(n, monty_n, vartime);
}

bool bailie_psw_test(const BigInt& n, const Montgomery_Params& monty_n, bool vartime) {
   if(n == 2) {
      return true;
   } else if(n <= 1 || n.is_even()) {
      return false;
   }

   const Miller_Rabin_Test mr(n, monty_n, vartime);
   return mr.passes(BigInt::from_word(2)) && lucas_test(n, monty_n, vartime);
}

}  // namespace

bool is_lucas_probable_prime(const BigInt& n, const Montgomery_Params& monty_n) {
   return lucas_test(n, monty_n, false);
}

bool is_lucas_probable_prime_vartime(const BigInt& n, const Montgomery_Params& monty_n) {
   return lucas_test(n, monty_n, true);
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

bool is_miller_rabin_lucas_probable_prime(const BigInt& n,
                                          const Montgomery_Params& monty_n,
                                          RandomNumberGenerator& rng,
                                          size_t test_iterations) {
   return miller_rabin_lucas_test(n, monty_n, rng, test_iterations, false);
}

bool is_miller_rabin_lucas_probable_prime_vartime(const BigInt& n,
                                                  const Montgomery_Params& monty_n,
                                                  RandomNumberGenerator& rng,
                                                  size_t test_iterations) {
   return miller_rabin_lucas_test(n, monty_n, rng, test_iterations, true);
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

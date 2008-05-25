/*************************************************
* Division Algorithm Source File                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/bigintfuncs.h>
#include <botan/mp_core.h>
#include <botan/libstate.h>
#include <botan/mp_asmi.h>
#ifdef TA_COLL_T
#include <botan/ta.h>
#endif
#ifdef MM_COLL_T
#include <botan/ta.h>
#endif
#include <assert.h>
#ifdef TA_COUNT_MR
#include <botan/ta.h>
#endif

namespace Botan
{

namespace
{

/*************************************************
* Handle signed operands, if necessary           *
*************************************************/
void sign_fixup(const BigInt& x, const BigInt& y, BigInt& q, BigInt& r)
   {
   if (x.sign() == BigInt::Negative)
      {
      q.flip_sign();
      if (r.is_nonzero())
         {
         --q;
         r = y.abs() - r;
         }
      }
   if (y.sign() == BigInt::Negative)
      q.flip_sign();
   }

}

/*************************************************
* Solve x = q * y + r                            *
*************************************************/
void divide(const BigInt& x, const BigInt& y_arg, BigInt& q, BigInt& r)
   {
   if (y_arg.is_zero())
      throw BigInt::DivideByZero();

   BigInt y = y_arg;
   const u32bit y_words = y.sig_words();
   r = x;

   r.set_sign(BigInt::Positive);
   y.set_sign(BigInt::Positive);

   s32bit compare = r.cmp(y);

   if (compare < 0)
      q = 0;
   else if (compare ==  0)
      {
      q = 1;
      r = 0;
      }
   else
      {
      u32bit shifts = 0;
      word y_top = y[y.sig_words()-1];
      while (y_top < MP_WORD_TOP_BIT)
         {
         y_top <<= 1;
         ++shifts;
         }
      y <<= shifts;
      r <<= shifts;

      const u32bit n = r.sig_words() - 1, t = y_words - 1;
#ifdef TA_COLL_T
      nov_ecdsa_div_words_inner = n;
#endif
      q.get_reg().create(n - t + 1);
      if (n <= t)
         {
         while (r > y)
            {
            r -= y;
            ++q;
            }
         r >>= shifts;
         sign_fixup(x, y_arg, q, r);
         return;
         }

      BigInt temp = y << (MP_WORD_BITS * (n-t));

      while (r >= temp)
         {
         r -= temp;
         ++q[n-t];
         }

      for (u32bit j = n; j != t; --j)
         {
         const word x_j0  = r.word_at(j);
         const word x_j1 = r.word_at(j-1);
         const word y_t  = y.word_at(t);

         if (x_j0 == y_t)
            q[j-t-1] = MP_WORD_MAX;
         else
            q[j-t-1] = bigint_divop(x_j0, x_j1, y_t);

         while (bigint_divcore(q[j-t-1], y_t, y.word_at(t-1),
                               x_j0, x_j1, r.word_at(j-2)))
            --q[j-t-1];

         r -= (q[j-t-1] * y) << (MP_WORD_BITS * (j-t-1));
         if (r.is_negative())
            {
            r += y << (MP_WORD_BITS * (j-t-1));
            --q[j-t-1];
            }
         }
      r >>= shifts;
      }

   sign_fixup(x, y_arg, q, r);
   }

/*************************************************
* Return the number of 0 bits at the end of n    *
*************************************************/
u32bit low_zero_bits(const BigInt& n)
   {
   if (n.is_zero()) return 0;

   u32bit bits = 0, max_bits = n.bits();
   while ((n.get_bit(bits) == 0) && bits < max_bits)
      ++bits;
   return bits;
   }

/*************************************************
* Calculate the GCD                              *
*************************************************/
BigInt gcd(const BigInt& a, const BigInt& b)
   {
   if (a.is_zero() || b.is_zero()) return 0;
   if (a == 1 || b == 1)           return 1;

   BigInt x = a, y = b;
   x.set_sign(BigInt::Positive);
   y.set_sign(BigInt::Positive);
   u32bit shift = std::min(low_zero_bits(x), low_zero_bits(y));

   x >>= shift;
   y >>= shift;

   while (x.is_nonzero())
      {
      x >>= low_zero_bits(x);
      y >>= low_zero_bits(y);
      if (x >= y)
         {
         x -= y;
         x >>= 1;
         }
      else
         {
         y -= x;
         y >>= 1;
         }
      }

   return (y << shift);
   }

/*************************************************
* Calculate the LCM                              *
*************************************************/
BigInt lcm(const BigInt& a, const BigInt& b)
   {
   return ((a * b) / gcd(a, b));
   }

/*************************************************
* Find the Modular Inverse                       *
*************************************************/
BigInt inverse_mod(const BigInt& n, const BigInt& mod)
   {
   if (mod.is_zero())
      throw BigInt::DivideByZero();
   if (mod.is_negative() || n.is_negative())
      throw Invalid_Argument("inverse_mod: arguments must be non-negative");

   if (n.is_zero() || (n.is_even() && mod.is_even()))
      return 0;

   BigInt x = mod, y = n, u = mod, v = n;
   BigInt A = 1, B = 0, C = 0, D = 1;

   while (u.is_nonzero())
      {
      u32bit zero_bits = low_zero_bits(u);
      u >>= zero_bits;
      for (u32bit j = 0; j != zero_bits; ++j)
         {
         if (A.is_odd() || B.is_odd())
            {
            A += y;
            B -= x;
            }
         A >>= 1;
         B >>= 1;
         }

      zero_bits = low_zero_bits(v);
      v >>= zero_bits;
      for (u32bit j = 0; j != zero_bits; ++j)
         {
         if (C.is_odd() || D.is_odd())
            {
            C += y;
            D -= x;
            }
         C >>= 1;
         D >>= 1;
         }

      if (u >= v)
         {
         u -= v;
         A -= C;
         B -= D;
         }
      else
         {
         v -= u;
         C -= A;
         D -= B;
         }
      }

   if (v != 1)
      return 0;

   while (D.is_negative()) D += mod;
   while (D >= mod) D -= mod;

   return D;
   }

/*************************************************
* Modular Exponentiation                         *
*************************************************/
BigInt power_mod(const BigInt& base, const BigInt& exp, const BigInt& mod)
   {
   Power_Mod pow_mod(mod);
   pow_mod.set_base(base);
   pow_mod.set_exponent(exp);
   return pow_mod.execute();
   }

/*************************************************
* Do simple tests of primality                   *
*************************************************/
s32bit simple_primality_tests(const BigInt& n)
   {
   const s32bit NOT_PRIME = -1, UNKNOWN = 0, PRIME = 1;

   if (n == 2)
      return PRIME;
   if (n <= 1 || n.is_even())
      return NOT_PRIME;

   if (n <= PRIMES[PRIME_TABLE_SIZE-1])
      {
      const word num = n.word_at(0);
      for (u32bit j = 0; PRIMES[j]; ++j)
         {
         if (num == PRIMES[j]) return PRIME;
         if (num <  PRIMES[j]) return NOT_PRIME;
         }
      return NOT_PRIME;
      }

   u32bit check_first = std::min(n.bits() / 32, PRIME_PRODUCTS_TABLE_SIZE);
   for (u32bit j = 0; j != check_first; ++j)
      if (gcd(n, PRIME_PRODUCTS[j]) != 1)
         return NOT_PRIME;

   return UNKNOWN;
   }

/*************************************************
* Fast check of primality                        *
*************************************************/
bool check_prime(const BigInt& n)
   {
   return run_primality_tests(n, 0);
   }

/*************************************************
* Test for primality                             *
*************************************************/
bool is_prime(const BigInt& n)
   {
   return run_primality_tests(n, 1);
   }

/*************************************************
* Verify primality                               *
*************************************************/
bool verify_prime(const BigInt& n)
   {
   return run_primality_tests(n, 2);
   }

/*************************************************
* Verify primality                               *
*************************************************/
bool run_primality_tests(const BigInt& n, u32bit level)
   {
   s32bit simple_tests = simple_primality_tests(n);
   if (simple_tests) return (simple_tests == 1) ? true : false;
   return passes_mr_tests(n, level);
   }


/*************************************************
* Miller-Rabin Iterations                        *
*************************************************/
u32bit miller_rabin_test_iterations(u32bit bits, bool verify)
   {
   struct mapping
      {
         u32bit bits;
         u32bit verify_iter;
         u32bit check_iter;
      };

   static const mapping tests[] =
      {
         {
            50, 55, 25
         },
         {  100, 38, 22 },
         {  160, 32, 18 },
         {  163, 31, 17 },
         {  168, 30, 16 },
         {  177, 29, 16 },
         {  181, 28, 15 },
         {  185, 27, 15 },
         {  190, 26, 15 },
         {  195, 25, 14 },
         {  201, 24, 14 },
         {  208, 23, 14 },
         {  215, 22, 13 },
         {  222, 21, 13 },
         {  231, 20, 13 },
         {  241, 19, 12 },
         {  252, 18, 12 },
         {  264, 17, 12 },
         {  278, 16, 11 },
         {  294, 15, 10 },
         {  313, 14,  9 },
         {  334, 13,  8 },
         {  360, 12,  8 },
         {  392, 11,  7 },
         {  430, 10,  7 },
         {  479,  9,  6 },
         {  542,  8,  6 },
         {  626,  7,  5 },
         {  746,  6,  4 },
         {  926,  5,  3 },
         { 1232,  4,  2 },
         { 1853,  3,  2 },
         {    0,  0,  0 }
      };

   for (u32bit j = 0; tests[j].bits; ++j)
      {
      if (bits <= tests[j].bits)
         if (verify)
            return tests[j].verify_iter;
         else
            return tests[j].check_iter;
      }
   return 2;
   }


/*************************************************
* Miller-Rabin Constructor                       *
*************************************************/
MillerRabin_Test::MillerRabin_Test(const BigInt& num)
   {
   if (num.is_even() || num < 3)
      throw Invalid_Argument("MillerRabin_Test: Invalid number for testing");

   n = num;
   n_minus_1 = n - 1;
   s = low_zero_bits(n_minus_1);
   r = n_minus_1 >> s;

   pow_mod = Fixed_Exponent_Power_Mod(r, n);
   reducer = Modular_Reducer(n);
   }


/*************************************************
* Miller-Rabin Test                              *
*************************************************/
bool MillerRabin_Test::passes_test(const BigInt& a)
   {
   if (a < 2 || a >= n_minus_1)
      throw Invalid_Argument("Bad size for nonce in Miller-Rabin test");

   global_state().pulse(PRIME_TESTING);

   BigInt y = pow_mod(a);
   if (y == 1 || y == n_minus_1)
      return true;

   for (u32bit j = 1; j != s; ++j)
      {
      global_state().pulse(PRIME_TESTING);
      y = reducer.square(y);

      if (y == 1)
         return false;
      if (y == n_minus_1)
         return true;
      }
   return false;
   }

/*************************************************
* Test for primaility using Miller-Rabin         *
*************************************************/
bool passes_mr_tests(const BigInt& n, u32bit level)
   {
   const u32bit PREF_NONCE_BITS = 40;

   if (level > 2)
      level = 2;

   MillerRabin_Test mr(n);

   if (!mr.passes_test(2))
      return false;

   if (level == 0)
      return true;

   const u32bit NONCE_BITS = std::min(n.bits() - 1, PREF_NONCE_BITS);

   const bool verify = (level == 2);

   u32bit tests = miller_rabin_test_iterations(n.bits(), verify);

   BigInt nonce;
   for (u32bit j = 0; j != tests; ++j)
      {
      if (verify) nonce = random_integer(NONCE_BITS);
      else       nonce = PRIMES[j];

      if (!mr.passes_test(nonce))
         return false;
      }
   return true;
   }

/*************************************************
* Shanks-Tonelli algorithm                       *
* Added by Falko Strenzke                        *
*************************************************/
BigInt ressol(const BigInt& value, const BigInt& p)
   {
   if (value < BigInt(0) || p < BigInt(0))
      {
      throw Invalid_Argument("arguments to ressol() must be positive, which wasn´t the case");
      }
   BigInt v;
   BigInt a(value);
   if (a < 0)
      {
      a += p;
      }
   if (a == 0)
      {
      return BigInt(0);
      }
   if (p == 2)
      {
      return a;
      }
   // p=3mod4
   if (p.get_bit(0) && p.get_bit(1))
      {
      if (Botan::jacobi(a,p) == 1)
         { // a quadr. residue mod p
         v = p + 1;
         /* the following right shift in java.BigInteger (as in FlexiProvider):
         * -----------
         *Returns a BigInteger whose value is (this >> n). Sign extension is performed.
         * The shift distance, n, may be
         * negative, in which case this method performs a left shift.
         * (Computes floor(this / 2n).)
         * ------------
         * concerning the following right shift:
         * it isn´t a problem because v is definitly positive anyway
         */
         v >>= 2;
         return Botan::power_mod(a, v, p);
         }

      throw No_Quadratic_Residue();

      }
   long long int t = 0;
   BigInt k = p - 1;
   long long int s = 0;
   while (!k.get_bit(0)) // while k is even
      {
      s++;
      k >>= 1;
      }
   k -= 1;
   k >>= 1;

   BigInt r = Botan::power_mod(a, k, p);
   BigInt n = r * r %p;
   n = n * a %p;
   if (n == 1)
      {
      return r;
      }
   // non quadratic residue
   BigInt z(2);
   while (Botan::jacobi(z,p) == 1) // while z quadratic residue
      {
      z += 1;
      }
   v = k;
   v += v;
   v += 1;
   BigInt c = Botan::power_mod(c, v, p);

   while (n > 1)
      {
      k = n;
      t = s;
      s = 0;
      while (k != 1)
         {
         k = k * k % p;
         s++;
         }
      t -= s; // if t becomes negative here, we have an overflow, since it is unsigned
      if (t == 0)
         {

         throw No_Quadratic_Residue();
         }
      v = 1;
      for (long long int i=0; i<t-1; i++)
         {
         v <<= 1;
         }
      c = Botan::power_mod(c,v,p);
      r = r * c % p;
      c = c * c % p;
      n = n * c % p;
      }
   return r;
   }
/**
*calculates R=b^n (here b=2) with R>m (and R beeing as small as possible) for an odd modulus m.
* no check for oddity is performed!
*/
BigInt montgm_calc_r_oddmod(const BigInt& prime)
   {
   u32bit n = prime.sig_words();
   BigInt result(1);
   result <<= n*MP_WORD_BITS;
   return result;

   }

/**
*calculates m' with r*r^-1 - m*m' = 1
* where r^-1 is the multiplicative inverse of r to the modulus m
*/
BigInt montgm_calc_m_dash(const BigInt& r, const BigInt& m, const BigInt& r_inv )
   {
   BigInt result = ((r * r_inv) - BigInt(1))/m;
   return result;
   }
BigInt montg_trf_to_mres(const BigInt& ord_res, const BigInt& r, const BigInt& m)
   {
   BigInt result(ord_res);
   result *= r;
   result %= m;
   return result;
   }
BigInt montg_trf_to_ordres(const BigInt& m_res, const BigInt& m, const BigInt& r_inv)
   {
   BigInt result(m_res);
   result *= r_inv;
   result %= m;
   return result;
   }


void inner_montg_mult_sos(word result[], const word* a_bar, const word* b_bar, const word* n, const word* n_dash, u32bit s)
   {
   SecureVector<word> t;
   t.grow_to(2*s+1);
   word tmp_carry = 0;

   for (u32bit i=0; i<s; i++)
      {
      word C = 0;
      word S = 0;
      for (u32bit j=0; j<s; j++)
         {
         // we use:
         // word word_madd3(word a, word b, word c, word d, word* carry)
         // returns a * b + c + d and resets the carry (not using it as input)

         S = word_madd3(a_bar[j], b_bar[i], t[i+j], C, &tmp_carry);
         C = tmp_carry;
         t[i+j] = S;
         }
      t[i+s] = C;
      }


   for (u32bit i=0; i<s; i++)
      {
      // word word_madd2(word a, word b, word c, word* carry)
      // returns a * b + c, resets the carry

      word C = 0;
      word unused_carry = 0;
      word m =  word_madd2(t[i], n_dash[0], 0, &unused_carry);

      for (u32bit j=0; j<s; j++)
         {
         tmp_carry = 0;
         word S = word_madd3(m, n[j], t[i+j], C, &tmp_carry);
         C = tmp_carry;
         t[i+j] = S;
         }

      //// mp_mulop.cpp:
      ////word bigint_mul_add_words(word z[], const word x[], u32bit x_size, word y)
      u32bit cnt = 0;
      while (C > 0)
         {
         // we need not worry here about C > 1, because the other operand is zero
         word tmp = word_add(t[i+s+cnt], 0, &C);
         t[i+s+cnt] = tmp;
         cnt++;
         }
      }
   SecureVector<word> u;
   u.grow_to(s+1);
   for (u32bit j=0; j<s+1; j++)
      {
      u[j] = t[j+s];
      }

   word B = 0;
   word D = 0;
   for (u32bit i=0; i<s; i++)
      {
      D = word_sub(u[i], n[i], &B);
      t[i] = D;
      }
   D = word_sub(u[s], 0, &B);
   t[s] = D;
   if (B == 0)
      {
#ifdef TA_COUNT_MR
      montgm_red++;
#endif
#ifdef MM_COLL_T
      montgm_red++;
#endif
#ifdef TA_COLL_T
      // waste some time...
      for (volatile unsigned int i = 0; i < ta_mm_red_bloat; i++)
         {
         }

#endif

      for (u32bit i=0; i<s; i++)
         {
         result[i] = t[i];
         }
      }
   else
      {
      for (u32bit i=0; i<s; i++)
         {
         result[i] = u[i];
         }
      }
   }

void montg_mult(BigInt& result, BigInt& a_bar, BigInt& b_bar, const BigInt& m, const BigInt& m_dash, const BigInt )
   {
#ifdef TA_COUNT_MR
   montgm_mult++;
#endif

   if (m.is_zero() || m_dash.is_zero())
      {
      throw Invalid_Argument("montg_mult(): neither modulus nor m_dash may be zero (and one of them was)");
      }
   if (a_bar.is_zero() || b_bar.is_zero())
      {
      result = 0;
      }
   u32bit s = m.sig_words();
   a_bar.grow_to(s);
   b_bar.grow_to(s);

   result.grow_to(s);

   inner_montg_mult_sos(result.get_reg(), a_bar.data(), b_bar.data(), m.data(), m_dash.data(), s);

   }

namespace
{
// used by mod_mul_secure
inline unsigned secure_add_till_size(BigInt & in_out,
                                     BigInt const& lower_border,
                                     BigInt const& block)
   {
   unsigned numo_adds = 0;
   while(in_out <= lower_border)
      {
      in_out += block;
      numo_adds++;
      }
   return numo_adds;
   }

}
BigInt const mod_mul_secure(BigInt const& a, BigInt const& b, BigInt const& m)
   {
   // devide the modulus into smaller parts
   const unsigned mod_parts = 10;
   const BigInt part_size = m/mod_parts + 1; // addition +1 necessary
   // because of round down
   //          BigInt DEBUG_prod = mod_parts * part_size;
   //          assert(mod_parts * part_size >= m);
   // find the number of necessary additions for a
   //const BigInt need_add_a = (p-a)/part_size;

   BigInt a_dash(a);
   BigInt b_dash(b);
   unsigned numo_adds_a = secure_add_till_size(a_dash, m, part_size); // numo_adds_a
   unsigned numo_adds_b = secure_add_till_size(b_dash, m, part_size); // numo_adds_b
   BigInt x = numo_adds_a * part_size;
   BigInt y = numo_adds_b * part_size;
   assert(numo_adds_a <= mod_parts);
   assert(numo_adds_b <= mod_parts);
   assert(a_dash >= m);
   assert(b_dash >= m);

   // now perform still necessary dummy additions from zero on
   unsigned cnt_a = 0;
   BigInt dummy_a(0);
   assert(mod_parts >= numo_adds_a);
   while(cnt_a < (mod_parts - x))
      {
      dummy_a += part_size;
      cnt_a++;
      }
   unsigned cnt_b = 0;
   BigInt dummy_b(0);
   assert(mod_parts >= numo_adds_b);
   while(cnt_b < (mod_parts - y))
      {
      dummy_b += part_size;
      cnt_b++;
      }

   BigInt c_dash = a_dash * b_dash;
   //BigInt c_dash = a_dash.mult_secure(b_dash, 2*m);
   c_dash %= m;
   //BigInt xy = x.mult_secure(y,m);
   BigInt xy = x * y;
   //BigInt ay = a.mult_secure(y,m);
   BigInt ay = a * y;
   //BigInt bx = b.mult_secure(x,m);
   BigInt bx = b * x;
   return ((c_dash - ay - bx - xy) % m); // if a is small
   // then a * y is fast, this should be a problem

   }

}

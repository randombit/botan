/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BIGINT)

#if defined(BOTAN_HAS_NUMBERTHEORY)

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <iterator>

#include <sstream>
#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/numthry.h>
#include <botan/reducer.h>

#if defined(BOTAN_HAS_EC_CURVE_GFP)
#include <botan/curve_nistp.h>
#endif

using namespace Botan;

namespace {

BOTAN_TEST_CASE(bigint_to_u32bit, "BigInt to_u32bit", {
   for(size_t i = 0; i != 32; ++i)
      {
      const u32bit in = 1 << i;
      BOTAN_TEST(in, BigInt(in).to_u32bit(), "in range round trips");
      }
   });

BigInt test_integer(RandomNumberGenerator& rng, size_t bits, BigInt max)
   {
   /*
   Produces integers with long runs of ones and zeros, for testing for
   carry handling problems.
   */
   BigInt x = 0;

   auto flip_prob = [](size_t i) {
      if(i % 64 == 0)
         return .5;
      if(i % 32 == 0)
         return .4;
      if(i % 8 == 0)
         return .05;
      return .01;
   };

   bool active = rng.next_byte() % 2;
   for(size_t i = 0; i != bits; ++i)
      {
      x <<= 1;
      x += static_cast<int>(active);

      const double prob = flip_prob(i);
      const double sample = double(rng.next_byte() % 100) / 100.0; // biased

      if(sample < prob)
         active = !active;
      }

   if(max > 0)
      {
      while(x >= max)
         {
         const size_t b = x.bits() - 1;
         BOTAN_ASSERT(x.get_bit(b) == true, "Set");
         x.clear_bit(b);
         }
      }

   return x;
   }

#if defined(BOTAN_HAS_EC_CURVE_GFP)

void nist_redc_test(Test_State& _test,
                    const std::string& prime_name,
                    const BigInt& p,
                    std::function<void (BigInt&, secure_vector<word>&)> redc_fn)
   {
   auto& rng = test_rng();
   const BigInt p2 = p*p;
   const size_t trials = 100;
   const size_t p_bits = p.bits();

   Modular_Reducer p_redc(p);
   secure_vector<word> ws;

   for(size_t i = 0; i != trials; ++i)
      {
      const BigInt x = test_integer(rng, 2*p_bits, p2);

      // TODO: time and report all three approaches
      const BigInt v1 = x % p;
      const BigInt v2 = p_redc.reduce(x);

      BigInt v3 = x;
      redc_fn(v3, ws);

      BOTAN_TEST(v1, v2, "reference");
      BOTAN_TEST(v2, v3, "specialized");

      if(v1 != v2 || v2 != v3)
         std::cout << "Prime " << prime_name << " input " << x << "\n";
      }
   }

#if defined(BOTAN_HAS_NIST_PRIME_REDUCERS_W32)

BOTAN_TEST_CASE(bigint_redc_p192, "P-192 reduction", {
   nist_redc_test(_test, "P-192", prime_p192(), redc_p192);
   });

BOTAN_TEST_CASE(bigint_redc_p224, "P-224 reduction", {
   nist_redc_test(_test, "P-224", prime_p224(), redc_p224);
   });

BOTAN_TEST_CASE(bigint_redc_p256, "P-256 reduction", {
   nist_redc_test(_test, "P-256", prime_p256(), redc_p256);
   });

BOTAN_TEST_CASE(bigint_redc_p384, "P-384 reduction", {
   nist_redc_test(_test, "P-384", prime_p384(), redc_p384);
   });

#endif

BOTAN_TEST_CASE(bigint_redc_p521, "P-521 reduction", {
   nist_redc_test(_test, "P-521", prime_p521(), redc_p521);
   });

#endif

void strip_comments(std::string& line)
   {
   if(line.find('#') != std::string::npos)
      line = line.erase(line.find('#'), std::string::npos);
   }

/* Strip comments, whitespace, etc */
void strip(std::string& line)
   {
   strip_comments(line);

#if 0
   while(line.find(' ') != std::string::npos)
      line = line.erase(line.find(' '), 1);
#endif

   while(line.find('\t') != std::string::npos)
      line = line.erase(line.find('\t'), 1);
   }

std::vector<std::string> parse(const std::string& line)
   {
   const char DELIMITER = ':';
   std::vector<std::string> substr;
   std::string::size_type start = 0, end = line.find(DELIMITER);
   while(end != std::string::npos)
      {
      substr.push_back(line.substr(start, end-start));
      start = end+1;
      end = line.find(DELIMITER, start);
      }
   if(line.size() > start)
      substr.push_back(line.substr(start));
   while(substr.size() <= 4) // at least 5 substr, some possibly empty
      substr.push_back("");
   return substr;
   }

// c==expected, d==a op b, e==a op= b
size_t results(std::string op,
               const BigInt& a, const BigInt& b,
               const BigInt& c, const BigInt& d, const BigInt& e)
   {
   std::string op1 = "operator" + op;
   std::string op2 = op1 + "=";

   if(c == d && d == e)
      return 0;
   else
      {
      std::cout << std::endl;

      std::cout << "ERROR: " << op1 << std::endl;

      std::cout << "a = " << std::hex << a << std::endl;
      std::cout << "b = " << std::hex << b << std::endl;

      std::cout << "c = " << std::hex << c << std::endl;
      std::cout << "d = " << std::hex << d << std::endl;
      std::cout << "e = " << std::hex << e << std::endl;

      if(d != e)
         {
         std::cout << "ERROR: " << op1 << " | " << op2
                   << " mismatch" << std::endl;
         }
      return 1;
      }
   }

size_t check_add(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt c(args[2]);

   BigInt d = a + b;
   BigInt e = a;
   e += b;

   if(results("+", a, b, c, d, e))
      return 1;

   d = b + a;
   e = b;
   e += a;

   return results("+", a, b, c, d, e);
   }

size_t check_sub(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt c(args[2]);

   BigInt d = a - b;
   BigInt e = a;
   e -= b;

   return results("-", a, b, c, d, e);
   }

size_t check_mul(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt c(args[2]);

   /*
   std::cout << "a = " << args[0] << "\n"
             << "b = " << args[1] << std::endl;
   */
   /* This makes it more likely the fast multiply algorithms will be usable,
      which is what we really want to test here (the simple n^2 multiply is
      pretty well tested at this point).
   */
   a.grow_to(64);
   b.grow_to(64);

   BigInt d = a * b;
   BigInt e = a;
   e *= b;

   if(results("*", a, b, c, d, e))
      return 1;

   d = b * a;
   e = b;
   e *= a;

   return results("*", a, b, c, d, e);
   }

size_t check_sqr(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);

   a.grow_to(64);
   b.grow_to(64);

   BigInt c = square(a);
   BigInt d = a * a;

   return results("sqr", a, a, b, c, d);
   }

size_t check_div(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt c(args[2]);

   BigInt d = a / b;
   BigInt e = a;
   e /= b;

   return results("/", a, b, c, d, e);
   }

size_t check_mod(const std::vector<std::string>& args,
                 Botan::RandomNumberGenerator& rng)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt c(args[2]);

   BigInt d = a % b;
   BigInt e = a;
   e %= b;

   size_t got = results("%", a, b, c, d, e);

   if(got) return got;

   word b_word = b.word_at(0);

   /* Won't work for us, just pick one at random */
   while(b_word == 0)
      for(size_t j = 0; j != 2*sizeof(word); j++)
         b_word = (b_word << 4) ^ rng.next_byte();

   b = b_word;

   c = a % b; /* we declare the BigInt % BigInt version to be correct here */

   word d2 = a % b_word;
   e = a;
   e %= b_word;

   return results("%(word)", a, b, c, d2, e);
   }

size_t check_shl(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   size_t b = std::atoi(args[1].c_str());
   BigInt c(args[2]);

   BigInt d = a << b;
   BigInt e = a;
   e <<= b;

   return results("<<", a, b, c, d, e);
   }

size_t check_shr(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   size_t b = std::atoi(args[1].c_str());
   BigInt c(args[2]);

   BigInt d = a >> b;
   BigInt e = a;
   e >>= b;

   return results(">>", a, b, c, d, e);
   }

/* Make sure that (a^b)%m == r */
size_t check_powmod(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt m(args[2]);
   BigInt c(args[3]);

   BigInt r = power_mod(a, b, m);

   if(c != r)
      {
      std::cout << "ERROR: power_mod" << std::endl;
      std::cout << "a = " << std::hex << a << std::endl;
      std::cout << "b = " << std::hex << b << std::endl;
      std::cout << "m = " << std::hex << m << std::endl;
      std::cout << "c = " << std::hex << c << std::endl;
      std::cout << "r = " << std::hex << r << std::endl;
      return 1;
      }
   return 0;
   }

/* Make sure that n is prime or not prime, according to should_be_prime */
size_t is_primetest(const std::vector<std::string>& args,
                       Botan::RandomNumberGenerator& rng)
   {
   BigInt n(args[0]);
   bool should_be_prime = (args[1] == "1");

   bool is_prime = Botan::is_prime(n, rng);

   if(is_prime != should_be_prime)
      {
      std::cout << "ERROR: is_prime" << std::endl;
      std::cout << "n = " << n << std::endl;
      std::cout << is_prime << " != " << should_be_prime << std::endl;
      }
   return 0;
   }

}

size_t test_bigint()
   {
   const std::string filename = TEST_DATA_DIR "/mp_valid.dat";
   std::ifstream test_data(filename);

   if(!test_data)
      throw Botan::Stream_IO_Error("Couldn't open test file " + filename);

   size_t total_errors = 0;
   size_t errors = 0, alg_count = 0;
   std::string algorithm;
   bool first = true;
   size_t counter = 0;

   auto& rng = test_rng();

   while(!test_data.eof())
      {
      if(test_data.bad() || test_data.fail())
         throw Botan::Stream_IO_Error("File I/O error reading from " +
                                      filename);

      std::string line;
      std::getline(test_data, line);

      strip(line);
      if(line.size() == 0) continue;

      // Do line continuation
      while(line[line.size()-1] == '\\' && !test_data.eof())
         {
         line.replace(line.size()-1, 1, "");
         std::string nextline;
         std::getline(test_data, nextline);
         strip(nextline);
         if(nextline.size() == 0) continue;
         line += nextline;
         }

      if(line[0] == '[' && line[line.size() - 1] == ']')
         {
         if(!first)
            test_report("Bigint " + algorithm, alg_count, errors);

         algorithm = line.substr(1, line.size() - 2);

         total_errors += errors;
         errors = 0;
         alg_count = 0;
         counter = 0;

         first = false;
         continue;
         }

      std::vector<std::string> substr = parse(line);

      // std::cout << "Testing: " << algorithm << std::endl;

      size_t new_errors = 0;
      if(algorithm.find("Addition") != std::string::npos)
         new_errors = check_add(substr);
      else if(algorithm.find("Subtraction") != std::string::npos)
         new_errors = check_sub(substr);
      else if(algorithm.find("Multiplication") != std::string::npos)
         new_errors = check_mul(substr);
      else if(algorithm.find("Square") != std::string::npos)
         new_errors = check_sqr(substr);
      else if(algorithm.find("Division") != std::string::npos)
         new_errors = check_div(substr);
      else if(algorithm.find("Modulo") != std::string::npos)
         new_errors = check_mod(substr, rng);
      else if(algorithm.find("LeftShift") != std::string::npos)
         new_errors = check_shl(substr);
      else if(algorithm.find("RightShift") != std::string::npos)
         new_errors = check_shr(substr);
      else if(algorithm.find("ModExp") != std::string::npos)
         new_errors = check_powmod(substr);
      else if(algorithm.find("PrimeTest") != std::string::npos)
         new_errors = is_primetest(substr, rng);
      else
         std::cout << "Unknown MPI test " << algorithm << std::endl;

      counter++;
      alg_count++;
      errors += new_errors;

      if(new_errors)
         std::cout << "ERROR: BigInt " << algorithm << " failed test #"
                   << std::dec << alg_count << std::endl;
      }

   total_errors += test_bigint_to_u32bit();

#if defined(BOTAN_HAS_EC_CURVE_GFP)

#if defined(BOTAN_HAS_NIST_PRIME_REDUCERS_W32)
   total_errors += test_bigint_redc_p192();
   total_errors += test_bigint_redc_p224();
   total_errors += test_bigint_redc_p256();
   total_errors += test_bigint_redc_p384();
 #endif

   total_errors += test_bigint_redc_p521();
#endif

   return total_errors;
   }

#else

UNTESTED_WARNING(bigint);

#endif // BOTAN_HAS_NUMBERTHEORY

#else

SKIP_TEST(bigint);

#endif // BOTAN_HAS_BIGINT

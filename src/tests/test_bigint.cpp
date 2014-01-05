/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "tests.h"

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <iterator>

#include <botan/auto_rng.h>
#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/numthry.h>

using namespace Botan;

namespace {

size_t test_make_prime()
   {
   AutoSeeded_RNG rng;

   std::set<BigInt> primes;

   std::map<int, int> bit_count;

   int not_new = 0;

   while(primes.size() < 10000)
      {
      u32bit start_cnt = primes.size();

      u32bit bits = 18;

      if(rng.next_byte() % 128 == 0)
         bits -= rng.next_byte() % (bits-2);

      bit_count[bits]++;

      //std::cout << "random_prime(" << bits << ")\n";

      BigInt p = random_prime(rng, bits);

      if(p.bits() != bits)
         {
         std::cout << "Asked for " << bits << " got " << p
                   << " " << p.bits() << " bits\n";
         return 1;
         }

      primes.insert(random_prime(rng, bits));

      if(primes.size() != start_cnt)
         std::cout << primes.size() << "\n";
      else
         not_new++;

      //std::cout << "miss: " << not_new << "\n";

      if(not_new % 100000 == 0)
         {
         for(std::map<int, int>::iterator i = bit_count.begin();
             i != bit_count.end(); ++i)
            std::cout << "bit_count[" << i->first << "] = "
                      << i->second << "\n";
         std::copy(primes.begin(), primes.end(),
                   std::ostream_iterator<BigInt>(std::cout, " "));
         }
      }

   std::cout << "Generated all? primes\n";
   /*
   for(u32bit j = 0; j != PRIME_TABLE_SIZE; ++j)
      {
      if(primes.count(PRIMES[j]) != 1)
         std::cout << "Missing " << PRIMES[j] << "\n";
      }
   */
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
size_t check_primetest(const std::vector<std::string>& args,
                       Botan::RandomNumberGenerator& rng)
   {
   BigInt n(args[0]);
   bool should_be_prime = (args[1] == "1");

   bool is_prime = Botan::verify_prime(n, rng);

   if(is_prime != should_be_prime)
      {
      std::cout << "ERROR: verify_prime" << std::endl;
      std::cout << "n = " << n << std::endl;
      std::cout << is_prime << " != " << should_be_prime << std::endl;
      }
   return 0;
   }

}

size_t test_bigint()
   {
   const std::string filename = TEST_DATA_DIR "/mp_valid.dat";
   std::ifstream test_data(filename.c_str());

   if(!test_data)
      throw Botan::Stream_IO_Error("Couldn't open test file " + filename);

   size_t total_errors = 0;
   size_t errors = 0, alg_count = 0;
   std::string algorithm;
   bool first = true;
   size_t counter = 0;

   AutoSeeded_RNG rng;

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

#if DEBUG
      std::cout << "Testing: " << algorithm << std::endl;
#endif

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
         new_errors = check_primetest(substr, rng);
      else
         std::cout << "Unknown MPI test " << algorithm << std::endl;

      counter++;
      alg_count++;
      errors += new_errors;

      if(new_errors)
         std::cout << "ERROR: BigInt " << algorithm << " failed test #"
                   << std::dec << alg_count << std::endl;
      }

   //total_errors += test_make_prime();

   return total_errors;
   }


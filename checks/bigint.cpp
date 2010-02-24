/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <cstdlib>

#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/numthry.h>
using namespace Botan;

#include "common.h"
#include "validate.h"

#define DEBUG 0

u32bit check_add(const std::vector<std::string>&);
u32bit check_sub(const std::vector<std::string>&);
u32bit check_mul(const std::vector<std::string>&);
u32bit check_sqr(const std::vector<std::string>&);
u32bit check_div(const std::vector<std::string>&);
u32bit check_mod(const std::vector<std::string>&,
                 Botan::RandomNumberGenerator& rng);
u32bit check_shr(const std::vector<std::string>&);
u32bit check_shl(const std::vector<std::string>&);

u32bit check_powmod(const std::vector<std::string>&);
u32bit check_primetest(const std::vector<std::string>&,
                       Botan::RandomNumberGenerator&);

u32bit do_bigint_tests(const std::string& filename,
                       Botan::RandomNumberGenerator& rng)
   {
   std::ifstream test_data(filename.c_str());

   if(!test_data)
      throw Botan::Stream_IO_Error("Couldn't open test file " + filename);

   u32bit errors = 0, alg_count = 0;
   std::string algorithm;
   bool first = true;
   u32bit counter = 0;

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
         algorithm = line.substr(1, line.size() - 2);
         alg_count = 0;
         counter = 0;

         if(!first)
            std::cout << std::endl;
         std::cout << "Testing BigInt " << algorithm << ": ";
         std::cout.flush();
         first = false;
         continue;
         }

      std::vector<std::string> substr = parse(line);

#if DEBUG
      std::cout << "Testing: " << algorithm << std::endl;
#endif

      u32bit new_errors = 0;
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

      if(counter % 3 == 0)
         {
         std::cout << '.';
         std::cout.flush();
         }
      counter++;
      alg_count++;
      errors += new_errors;

      if(new_errors)
         std::cout << "ERROR: BigInt " << algorithm << " failed test #"
                   << std::dec << alg_count << std::endl;
      }
   std::cout << std::endl;
   return errors;
   }

namespace {

// c==expected, d==a op b, e==a op= b
u32bit results(std::string op,
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

}

u32bit check_add(const std::vector<std::string>& args)
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

u32bit check_sub(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt c(args[2]);

   BigInt d = a - b;
   BigInt e = a;
   e -= b;

   return results("-", a, b, c, d, e);
   }

u32bit check_mul(const std::vector<std::string>& args)
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
   a.grow_reg(32);
   b.grow_reg(32);

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

u32bit check_sqr(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);

   a.grow_reg(16);
   b.grow_reg(16);

   BigInt c = square(a);
   BigInt d = a * a;

   return results("sqr", a, a, b, c, d);
   }

u32bit check_div(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt c(args[2]);

   BigInt d = a / b;
   BigInt e = a;
   e /= b;

   return results("/", a, b, c, d, e);
   }

u32bit check_mod(const std::vector<std::string>& args,
                 Botan::RandomNumberGenerator& rng)
   {
   BigInt a(args[0]);
   BigInt b(args[1]);
   BigInt c(args[2]);

   BigInt d = a % b;
   BigInt e = a;
   e %= b;

   u32bit got = results("%", a, b, c, d, e);

   if(got) return got;

   word b_word = b.word_at(0);

   /* Won't work for us, just pick one at random */
   while(b_word == 0)
      for(u32bit j = 0; j != 2*sizeof(word); j++)
         b_word = (b_word << 4) ^ rng.next_byte();

   b = b_word;

   c = a % b; /* we declare the BigInt % BigInt version to be correct here */

   word d2 = a % b_word;
   e = a;
   e %= b_word;

   return results("%(word)", a, b, c, d2, e);
   }

u32bit check_shl(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   u32bit b = std::atoi(args[1].c_str());
   BigInt c(args[2]);

   BigInt d = a << b;
   BigInt e = a;
   e <<= b;

   return results("<<", a, b, c, d, e);
   }

u32bit check_shr(const std::vector<std::string>& args)
   {
   BigInt a(args[0]);
   u32bit b = std::atoi(args[1].c_str());
   BigInt c(args[2]);

   BigInt d = a >> b;
   BigInt e = a;
   e >>= b;

   return results(">>", a, b, c, d, e);
   }

/* Make sure that (a^b)%m == r */
u32bit check_powmod(const std::vector<std::string>& args)
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
u32bit check_primetest(const std::vector<std::string>& args,
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

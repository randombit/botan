/*
* (C) 2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BIGINT)
  #include <botan/bigint.h>
  #include <botan/numthry.h>
  #include <botan/reducer.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_BIGINT)

class BigInt_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_bigint_sizes());
         results.push_back(test_random_integer());

         return results;
         }
   private:
      Test::Result test_bigint_sizes()
         {
         Test::Result result("BigInt size functions");

         for(size_t bit : { 1, 8, 16, 31, 32, 64, 97, 128, 179, 192, 512, 521 })
            {
            BigInt a;

            a.set_bit(bit);

            // Test 2^n and 2^n-1
            for(size_t i = 0; i != 2; ++i)
               {
               const size_t exp_bits = bit + 1 - i;
               result.test_eq("BigInt::bits", a.bits(), exp_bits);
               result.test_eq("BigInt::bytes", a.bytes(),
                              (exp_bits % 8 == 0) ? (exp_bits / 8) : (exp_bits + 8 - exp_bits % 8) / 8);

               if(bit == 1 && i == 1)
                  {
                  result.test_is_eq("BigInt::to_u32bit zero", a.to_u32bit(), static_cast<uint32_t>(1));
                  }
               else if(bit <= 31 || (bit == 32 && i == 1))
                  {
                  result.test_is_eq("BigInt::to_u32bit", a.to_u32bit(), static_cast<uint32_t>((uint64_t(1) << bit) - i));
                  }
               else
                  {
                  try {
                     a.to_u32bit();
                     result.test_failure("BigInt::to_u32bit roundtripped out of range value");
                  }
                  catch(std::exception&)
                     {
                     result.test_success("BigInt::to_u32bit rejected out of range");
                     }
                  }

               a--;
               }
            }

         return result;
         }

      Test::Result test_random_integer()
         {
         Test::Result result("BigInt::random_integer");

         result.start_timer();

         const size_t ITERATIONS = 5000;

         std::vector<size_t> min_ranges{ 0 };
         std::vector<size_t> max_ranges{ 10 };

         // This gets slow quickly:
         if(Test::soak_level() > 10)
            {
            min_ranges.push_back(10);
            max_ranges.push_back(100);

            if(Test::soak_level() > 50)
               {
               min_ranges.push_back(79);
               max_ranges.push_back(293);
               }
            }

         for(size_t range_min : min_ranges)
            {
            for(size_t range_max : max_ranges)
               {
               if(range_min >= range_max)
                  continue;

               std::vector<size_t> counts(range_max - range_min);

               for(size_t i = 0; i != counts.size() * ITERATIONS; ++i)
                  {
                  uint32_t r = BigInt::random_integer(Test::rng(), range_min, range_max).to_u32bit();
                  result.test_gte("random_integer", r, range_min);
                  result.test_lt("random_integer", r, range_max);
                  counts[r - range_min] += 1;
                  }

               for(size_t i = 0; i != counts.size(); ++i)
                  {
                  double ratio = static_cast<double>(counts[i]) / ITERATIONS;
                  double dev = std::min(ratio, std::fabs(1.0 - ratio));

                  if(dev < .15)
                     {
                     result.test_success("distribution within expected range");
                     }
                  else
                     {
                     result.test_failure("distribution " + std::to_string(dev) +
                                         " outside expected range with count" +
                                         std::to_string(counts[i]));
                     }
                  }
               }
            }

         result.end_timer();

         return result;
         }
   };

BOTAN_REGISTER_TEST("bigint_unit", BigInt_Unit_Tests);

class BigInt_KAT_Tests : public Text_Based_Test
   {
   public:
      BigInt_KAT_Tests() : Text_Based_Test("bigint.vec",
                                           std::vector<std::string>{"Output"},
                                           {"In1","In2","Input","Shift","Modulus","Value","Base","Exponent","IsPrime"})
         {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         Test::Result result("BigInt " + algo);

         using Botan::BigInt;

         if(algo == "Addition")
            {
            const BigInt a = get_req_bn(vars, "In1");
            const BigInt b = get_req_bn(vars, "In2");
            const BigInt c = get_req_bn(vars, "Output");
            BigInt d = a + b;

            result.test_eq("a + b", a + b, c);
            result.test_eq("b + a", b + a, c);

            BigInt e = a;
            e += b;
            result.test_eq("a += b", e, c);

            e = b;
            e += a;
            result.test_eq("b += a", e, c);
            }
         else if(algo == "Subtraction")
            {
            const BigInt a = get_req_bn(vars, "In1");
            const BigInt b = get_req_bn(vars, "In2");
            const BigInt c = get_req_bn(vars, "Output");
            BigInt d = a - b;

            result.test_eq("a - b", a - b, c);

            BigInt e = a;
            e -= b;
            result.test_eq("a -= b", e, c);
            }
         else if(algo == "Multiplication")
            {
            const BigInt a = get_req_bn(vars, "In1");
            const BigInt b = get_req_bn(vars, "In2");
            const BigInt c = get_req_bn(vars, "Output");

            result.test_eq("a * b", a * b, c);
            result.test_eq("b * a", b * a, c);

            BigInt e = a;
            e *= b;
            result.test_eq("a *= b", e, c);

            e = b;
            e *= a;
            result.test_eq("b *= a", e, c);
            }
         else if(algo == "Square")
            {
            const BigInt a = get_req_bn(vars, "Input");
            const BigInt c = get_req_bn(vars, "Output");

            result.test_eq("a * a", a * a, c);
            result.test_eq("sqr(a)", square(a), c);
            }
         else if(algo == "Division")
            {
            const BigInt a = get_req_bn(vars, "In1");
            const BigInt b = get_req_bn(vars, "In2");
            const BigInt c = get_req_bn(vars, "Output");

            result.test_eq("a / b", a / b, c);

            BigInt e = a;
            e /= b;
            result.test_eq("a /= b", e, c);
            }
         else if(algo == "Modulo")
            {
            const BigInt a = get_req_bn(vars, "In1");
            const BigInt b = get_req_bn(vars, "In2");
            const BigInt c = get_req_bn(vars, "Output");

            result.test_eq("a % b", a % b, c);

            BigInt e = a;
            e %= b;
            result.test_eq("a %= b", e, c);
            }
         else if(algo == "LeftShift")
            {
            const BigInt value = get_req_bn(vars, "Value");
            const size_t shift = get_req_bn(vars, "Shift").to_u32bit();
            const BigInt output = get_req_bn(vars, "Output");

            result.test_eq("a << s", value << shift, output);

            BigInt e = value;
            e <<= shift;
            result.test_eq("a <<= s", e, output);
            }
         else if(algo == "RightShift")
            {
            const BigInt value = get_req_bn(vars, "Value");
            const size_t shift = get_req_bn(vars, "Shift").to_u32bit();
            const BigInt output = get_req_bn(vars, "Output");

            result.test_eq("a >> s", value >> shift, output);

            BigInt e = value;
            e >>= shift;
            result.test_eq("a >>= s", e, output);
            }
         else if(algo == "ModExp")
            {
            const BigInt value = get_req_bn(vars, "Base");
            const BigInt exponent = get_req_bn(vars, "Exponent");
            const BigInt modulus = get_req_bn(vars, "Modulus");
            const BigInt output = get_req_bn(vars, "Output");

            result.test_eq("power_mod", Botan::power_mod(value, exponent, modulus), output);
            }
         else if(algo == "PrimeTest")
            {
            const BigInt value = get_req_bn(vars, "Value");
            const bool v_is_prime = get_req_sz(vars, "IsPrime") > 0;

            result.test_eq("value", Botan::is_prime(value, Test::rng()), v_is_prime);
            }
         else
            {
            result.test_failure("Unknown BigInt algorithm " + algo);
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("bigint_kat", BigInt_KAT_Tests);

#endif

}

}

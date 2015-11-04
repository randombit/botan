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

         results.push_back(test_to_u32bit());

         return results;
         }
   private:
      Test::Result test_to_u32bit()
         {
         Test::Result result("BigInt::to_u32bit");

         for(size_t i = 0; i < 32; ++i)
            {
            const size_t in = static_cast<size_t>(1) << i;

            try
               {
               const size_t out = Botan::BigInt(in).to_u32bit();
               result.test_eq("in range to_u32bit round trips", in, out);
               }
            catch(std::exception& e)
               {
               result.test_failure("rejected input " + std::to_string(in) + " " + e.what());
               }
            }
         return result;
         }
   };

BOTAN_REGISTER_TEST("bigint_unit", BigInt_Unit_Tests);

class BigInt_KAT_Tests : public Text_Based_Test
   {
   public:
      BigInt_KAT_Tests() : Text_Based_Test(Test::data_file("bigint.vec"),
                                           std::vector<std::string>{"Output"},
                                           {"In1","In2","Input","Shift","Modulus","Value","Base","Exponent","IsPrime"})
         {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars)
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

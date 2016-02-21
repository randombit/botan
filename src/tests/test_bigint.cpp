/*
* (C) 2009,2015,2016 Jack Lloyd
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

using Botan::BigInt;

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

class BigInt_Add_Test : public Text_Based_Test
   {
   public:
      BigInt_Add_Test() : Text_Based_Test("bn/add.vec", {"In1","In2","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Addition");

         using Botan::BigInt;

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

         return result;
         }

   };

BOTAN_REGISTER_TEST("bn_add", BigInt_Add_Test);

class BigInt_Sub_Test : public Text_Based_Test
   {
   public:
      BigInt_Sub_Test() : Text_Based_Test("bn/sub.vec", {"In1","In2","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Subtraction");

         const BigInt a = get_req_bn(vars, "In1");
         const BigInt b = get_req_bn(vars, "In2");
         const BigInt c = get_req_bn(vars, "Output");

         BigInt d = a - b;

         result.test_eq("a - b", a - b, c);

         BigInt e = a;
         e -= b;
         result.test_eq("a -= b", e, c);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_sub", BigInt_Sub_Test);

class BigInt_Mul_Test : public Text_Based_Test
   {
   public:
      BigInt_Mul_Test() : Text_Based_Test("bn/mul.vec", {"In1","In2","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Multiply");

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

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_mul", BigInt_Mul_Test);

class BigInt_Sqr_Test : public Text_Based_Test
   {
   public:
      BigInt_Sqr_Test() : Text_Based_Test("bn/sqr.vec", {"Input","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Square");

         const BigInt input = get_req_bn(vars, "Input");
         const BigInt output = get_req_bn(vars, "Output");

         result.test_eq("a * a", input * input, output);
         result.test_eq("sqr(a)", square(input), output);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_sqr", BigInt_Sqr_Test);

class BigInt_Div_Test : public Text_Based_Test
   {
   public:
      BigInt_Div_Test() : Text_Based_Test("bn/divide.vec", {"In1","In2","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Divide");

         const BigInt a = get_req_bn(vars, "In1");
         const BigInt b = get_req_bn(vars, "In2");
         const BigInt c = get_req_bn(vars, "Output");

         result.test_eq("a / b", a / b, c);

         BigInt e = a;
         e /= b;
         result.test_eq("a /= b", e, c);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_div", BigInt_Div_Test);

class BigInt_Mod_Test : public Text_Based_Test
   {
   public:
      BigInt_Mod_Test() : Text_Based_Test("bn/mod.vec", {"In1","In2","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Mod");

         const BigInt a = get_req_bn(vars, "In1");
         const BigInt b = get_req_bn(vars, "In2");
         const BigInt c = get_req_bn(vars, "Output");

         result.test_eq("a % b", a % b, c);

         BigInt e = a;
         e %= b;
         result.test_eq("a %= b", e, c);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_mod", BigInt_Mod_Test);

class BigInt_Lshift_Test : public Text_Based_Test
   {
   public:
      BigInt_Lshift_Test() : Text_Based_Test("bn/lshift.vec", {"Value","Shift","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Lshift");

         const BigInt value = get_req_bn(vars, "Value");
         const size_t shift = get_req_bn(vars, "Shift").to_u32bit();
         const BigInt output = get_req_bn(vars, "Output");

         result.test_eq("a << s", value << shift, output);

         BigInt e = value;
         e <<= shift;
         result.test_eq("a <<= s", e, output);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_lshift", BigInt_Lshift_Test);

class BigInt_Rshift_Test : public Text_Based_Test
   {
   public:
      BigInt_Rshift_Test() : Text_Based_Test("bn/rshift.vec", {"Value","Shift","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Rshift");

         const BigInt value = get_req_bn(vars, "Value");
         const size_t shift = get_req_bn(vars, "Shift").to_u32bit();
         const BigInt output = get_req_bn(vars, "Output");

         result.test_eq("a >> s", value >> shift, output);

         BigInt e = value;
         e >>= shift;
         result.test_eq("a >>= s", e, output);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_rshift", BigInt_Rshift_Test);

class BigInt_Powmod_Test : public Text_Based_Test
   {
   public:
      BigInt_Powmod_Test() : Text_Based_Test("bn/powmod.vec", {"Base","Exponent","Modulus","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Powmod");

         const BigInt value = get_req_bn(vars, "Base");
         const BigInt exponent = get_req_bn(vars, "Exponent");
         const BigInt modulus = get_req_bn(vars, "Modulus");
         const BigInt output = get_req_bn(vars, "Output");

         result.test_eq("power_mod", Botan::power_mod(value, exponent, modulus), output);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_powmod", BigInt_Powmod_Test);

class BigInt_IsPrime_Test : public Text_Based_Test
   {
   public:
      BigInt_IsPrime_Test() : Text_Based_Test("bn/isprime.vec", {"Value","IsPrime"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt IsPrime");

         const BigInt value = get_req_bn(vars, "Value");
         const bool v_is_prime = get_req_sz(vars, "IsPrime") > 0;

         result.test_eq("is_prime", Botan::is_prime(value, Test::rng()), v_is_prime);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_isprime", BigInt_IsPrime_Test);

class BigInt_Ressol_Test : public Text_Based_Test
   {
   public:
      BigInt_Ressol_Test() : Text_Based_Test("bn/ressol.vec", {"Input","Modulus","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt Ressol");

         const Botan::BigInt a = get_req_bn(vars, "Input");
         const Botan::BigInt p = get_req_bn(vars, "Modulus");
         const Botan::BigInt exp = get_req_bn(vars, "Output");

         const Botan::BigInt a_sqrt = Botan::ressol(a, p);

         result.test_eq("ressol", a_sqrt, exp);

         if(a_sqrt > 1)
            {
            const Botan::BigInt a_sqrt2 = (a_sqrt*a_sqrt) % p;
            result.test_eq("square correct", a_sqrt2, a);
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_ressol", BigInt_Ressol_Test);

class BigInt_InvMod_Test : public Text_Based_Test
   {
   public:
      BigInt_InvMod_Test() : Text_Based_Test("bn/invmod.vec", {"Input","Modulus","Output"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BigInt InvMod");

         const Botan::BigInt a = get_req_bn(vars, "Input");
         const Botan::BigInt mod = get_req_bn(vars, "Modulus");
         const Botan::BigInt expected = get_req_bn(vars, "Output");

         const Botan::BigInt a_inv = Botan::inverse_mod(a, mod);

         result.test_eq("inverse_mod", a_inv, expected);

         if(a_inv > 1)
            {
            result.test_eq("inverse ok", (a * a_inv) % mod, 1);
            }

         if(mod.is_odd())
            {
            result.test_eq("ct_inverse_odd_modulus",
                           ct_inverse_mod_odd_modulus(a, mod),
                           expected);
            }

         if(mod.is_odd() && a_inv != 0)
            {
            result.test_eq("normalized_montgomery_inverse",
                           normalized_montgomery_inverse(a, mod),
                           expected);
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("bn_invmod", BigInt_InvMod_Test);

#endif

}

}

/*
* (C) 2009,2015,2016 Jack Lloyd
* (C) 2024           Fabian Albert, René Meusel -  Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include "test_rng.h"
   #include <botan/bigint.h>
   #include <botan/numthry.h>
   #include <botan/reducer.h>
   #include <botan/internal/ct_utils.h>
   #include <botan/internal/divide.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/mod_inv.h>
   #include <botan/internal/mp_core.h>
   #include <botan/internal/parsing.h>
   #include <botan/internal/primality.h>
   #include <botan/internal/stl_util.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_NUMBERTHEORY)

using Botan::BigInt;

class BigInt_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_bigint_sizes());
         results.push_back(test_random_prime());
         results.push_back(test_encode());
         results.push_back(test_bigint_io());
         results.push_back(test_get_substring());

         return results;
      }

   private:
      static Test::Result test_bigint_sizes() {
         Test::Result result("BigInt size functions");

         for(size_t bit : {1, 8, 16, 31, 32, 64, 97, 128, 179, 192, 512, 521}) {
            BigInt a;

            a.set_bit(bit);

            // Test 2^n and 2^n-1
            for(size_t i = 0; i != 2; ++i) {
               const size_t exp_bits = bit + 1 - i;
               result.test_eq("BigInt::bits", a.bits(), exp_bits);
               result.test_eq(
                  "BigInt::bytes", a.bytes(), (exp_bits % 8 == 0) ? (exp_bits / 8) : (exp_bits + 8 - exp_bits % 8) / 8);

               if(bit == 1 && i == 1) {
                  result.test_is_eq("BigInt::to_u32bit zero", a.to_u32bit(), static_cast<uint32_t>(1));
               } else if(bit <= 31 || (bit == 32 && i == 1)) {
                  result.test_is_eq(
                     "BigInt::to_u32bit", a.to_u32bit(), static_cast<uint32_t>((uint64_t(1) << bit) - i));
               } else {
                  try {
                     a.to_u32bit();
                     result.test_failure("BigInt::to_u32bit roundtripped out of range value");
                  } catch(std::exception&) {
                     result.test_success("BigInt::to_u32bit rejected out of range");
                  }
               }

               a--;
            }
         }

         return result;
      }

      static Test::Result test_random_prime() {
         Test::Result result("BigInt prime generation");

         auto rng = Test::new_rng("random_prime");

         result.test_throws(
            "Invalid bit size", "random_prime: Can't make a prime of 0 bits", [&]() { Botan::random_prime(*rng, 0); });
         result.test_throws(
            "Invalid bit size", "random_prime: Can't make a prime of 1 bits", [&]() { Botan::random_prime(*rng, 1); });
         result.test_throws("Invalid arg", "random_prime Invalid value for equiv/modulo", [&]() {
            Botan::random_prime(*rng, 2, 1, 0, 2);
         });

         BigInt p = Botan::random_prime(*rng, 2);
         result.confirm("Only two 2-bit primes", p == 2 || p == 3);

         p = Botan::random_prime(*rng, 3);
         result.confirm("Only two 3-bit primes", p == 5 || p == 7);

         p = Botan::random_prime(*rng, 4);
         result.confirm("Only two 4-bit primes", p == 11 || p == 13);

         for(size_t bits = 5; bits <= 32; ++bits) {
            p = Botan::random_prime(*rng, bits);
            result.test_eq("Expected bit size", p.bits(), bits);
            result.test_eq("P is prime", Botan::is_prime(p, *rng), true);
         }

         const size_t safe_prime_bits = 65;
         const BigInt safe_prime = Botan::random_safe_prime(*rng, safe_prime_bits);
         result.test_eq("Safe prime size", safe_prime.bits(), safe_prime_bits);
         result.confirm("P is prime", Botan::is_prime(safe_prime, *rng));
         result.confirm("(P-1)/2 is prime", Botan::is_prime((safe_prime - 1) / 2, *rng));

         return result;
      }

      static Test::Result test_encode() {
         Test::Result result("BigInt encoding functions");

         const auto n1 = Botan::BigInt::from_u64(0xffff);
         const auto n2 = Botan::BigInt::from_u64(1023);

         const auto encoded_n1 = n1.serialize(256);
         const auto encoded_n2 = n2.serialize(256);
         const auto expected = Botan::concat(encoded_n1, encoded_n2);

         const auto encoded_n1_n2 = BigInt::encode_fixed_length_int_pair(n1, n2, 256);
         result.test_eq("encode_fixed_length_int_pair", encoded_n1_n2, expected);

         for(size_t i = 0; i < 256 - n1.bytes(); ++i) {
            if(encoded_n1[i] != 0) {
               result.test_failure("BigInt::serialize", "no zero byte");
            }
         }

         return result;
      }

      static Test::Result test_get_substring() {
         Test::Result result("BigInt get_substring");

         const size_t rbits = 1024;

         auto rng = Test::new_rng("get_substring");

         const Botan::BigInt r(*rng, rbits);

         for(size_t wlen = 1; wlen <= 32; ++wlen) {
            for(size_t offset = 0; offset != rbits + 64; ++offset) {
               const uint32_t val = r.get_substring(offset, wlen);

               Botan::BigInt t = r >> offset;
               t.mask_bits(wlen);

               const uint32_t cmp = t.to_u32bit();

               result.test_eq("Same value", size_t(val), size_t(cmp));
            }
         }

         return result;
      }

      static Test::Result test_bigint_io() {
         Test::Result result("BigInt IO operators");

         const std::map<std::string, Botan::BigInt> str_to_val = {{"-13", -Botan::BigInt(13)},
                                                                  {"0", Botan::BigInt(0)},
                                                                  {"0x13", Botan::BigInt(0x13)},
                                                                  {"1", Botan::BigInt(1)},
                                                                  {"4294967297", Botan::BigInt(2147483648) * 2 + 1}};

         for(const auto& vec : str_to_val) {
            Botan::BigInt n;
            std::istringstream iss;

            iss.str(vec.first);
            iss >> n;
            result.test_eq("input '" + vec.first + "'", n, vec.second);
         }

         auto check_bigint_formatting = [&](const Botan::BigInt& n,
                                            const std::string& dec,
                                            const std::string& hex,
                                            const std::string& neg_dec,
                                            const std::string& neg_hex) {
            std::ostringstream oss;
            oss << n;
            result.test_eq("output decimal", oss.str(), dec);

            oss.str("");
            oss << (-n);
            result.test_eq("output negative decimal", oss.str(), neg_dec);

            oss.str("");
            oss << std::hex << n;
            result.test_eq("output hex", oss.str(), hex);

            oss.str("");
            oss << std::hex << (-n);
            result.test_eq("output negative hex", oss.str(), neg_hex);
         };

         check_bigint_formatting(Botan::BigInt(33), "33", "0x21", "-33", "-0x21");
         check_bigint_formatting(Botan::BigInt::from_s32(-33), "-33", "-0x21", "33", "0x21");
         check_bigint_formatting(Botan::BigInt(255), "255", "0xFF", "-255", "-0xFF");
         check_bigint_formatting(Botan::BigInt(0), "0", "0x00", "0", "0x00");
         check_bigint_formatting(Botan::BigInt(5), "5", "0x05", "-5", "-0x05");

         result.test_throws("octal output not supported", [&]() {
            Botan::BigInt n(5);
            std::ostringstream oss;
            oss << std::oct << n;
         });

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bigint_unit", BigInt_Unit_Tests);

class BigInt_Cmp_Test final : public Text_Based_Test {
   public:
      BigInt_Cmp_Test() : Text_Based_Test("bn/cmp.vec", "X,Y,R") {}

      Test::Result run_one_test(const std::string& op, const VarMap& vars) override {
         Test::Result result("BigInt Comparison " + op);

         const BigInt x = vars.get_req_bn("X");
         const BigInt y = vars.get_req_bn("Y");
         const bool expected = vars.get_req_bool("R");

         if(op == "EQ") {
            result.confirm("Values equal", x == y, expected);
         } else if(op == "LT") {
            result.confirm("Values LT", x < y, expected);

            if(expected) {
               result.confirm("If LT then reverse is GT", y >= x);
            } else {
               result.confirm("If not LT then GTE", x >= y);
            }
         } else if(op == "LTE") {
            result.confirm("Values LTE", x <= y, expected);

            if(expected) {
               result.confirm("If LTE then either LT or EQ", x < y || x == y);
            } else {
               result.confirm("If not LTE then GT", x > y);
            }
         } else {
            throw Test_Error("Unknown BigInt comparison type " + op);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_cmp", BigInt_Cmp_Test);

class BigInt_Add_Test final : public Text_Based_Test {
   public:
      BigInt_Add_Test() : Text_Based_Test("bn/add.vec", "In1,In2,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Addition");

         using Botan::BigInt;

         const BigInt a = vars.get_req_bn("In1");
         const BigInt b = vars.get_req_bn("In2");
         const BigInt c = vars.get_req_bn("Output");

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

BOTAN_REGISTER_TEST("math", "bn_add", BigInt_Add_Test);

class BigInt_Sub_Test final : public Text_Based_Test {
   public:
      BigInt_Sub_Test() : Text_Based_Test("bn/sub.vec", "In1,In2,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Subtraction");

         const BigInt a = vars.get_req_bn("In1");
         const BigInt b = vars.get_req_bn("In2");
         const BigInt c = vars.get_req_bn("Output");

         result.test_eq("a - b", a - b, c);

         BigInt e = a;
         e -= b;
         result.test_eq("a -= b", e, c);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_sub", BigInt_Sub_Test);

class BigInt_Mul_Test final : public Text_Based_Test {
   public:
      BigInt_Mul_Test() : Text_Based_Test("bn/mul.vec", "In1,In2,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Multiply");

         const BigInt a = vars.get_req_bn("In1");
         const BigInt b = vars.get_req_bn("In2");
         const BigInt c = vars.get_req_bn("Output");

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

BOTAN_REGISTER_TEST("math", "bn_mul", BigInt_Mul_Test);

class BigInt_Sqr_Test final : public Text_Based_Test {
   public:
      BigInt_Sqr_Test() : Text_Based_Test("bn/sqr.vec", "Input,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Square");

         const BigInt input = vars.get_req_bn("Input");
         const BigInt output = vars.get_req_bn("Output");

         result.test_eq("a * a", input * input, output);
         result.test_eq("sqr(a)", square(input), output);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_sqr", BigInt_Sqr_Test);

class BigInt_Div_Test final : public Text_Based_Test {
   public:
      BigInt_Div_Test() : Text_Based_Test("bn/divide.vec", "In1,In2,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Divide");

         const BigInt a = vars.get_req_bn("In1");
         const BigInt b = vars.get_req_bn("In2");
         const BigInt c = vars.get_req_bn("Output");

         result.test_eq("a / b", a / b, c);

         BigInt e = a;
         e /= b;
         result.test_eq("a /= b", e, c);

         if(b.sig_words() == 1) {
            const Botan::word bw = b.word_at(0);
            result.test_eq("bw ok", Botan::BigInt::from_word(bw), b);

            Botan::BigInt ct_q;
            Botan::word ct_r;
            Botan::ct_divide_word(a, bw, ct_q, ct_r);
            result.test_eq("ct_divide_word q", ct_q, c);
            result.test_eq("ct_divide_word r", ct_q * b + ct_r, a);
         }

         Botan::BigInt ct_q, ct_r;
         Botan::ct_divide(a, b, ct_q, ct_r);
         result.test_eq("ct_divide q", ct_q, c);
         result.test_eq("ct_divide r", ct_q * b + ct_r, a);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_div", BigInt_Div_Test);

class BigInt_DivPow2k_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("BigInt ct_divide_pow2k");

         for(size_t k = 2; k != 128; ++k) {
            auto div1 = Botan::ct_divide_pow2k(k, 1);
            result.test_eq("ct_divide_pow2k div 1", div1, Botan::BigInt::power_of_2(k));

            auto div2 = Botan::ct_divide_pow2k(k, 2);
            result.test_eq("ct_divide_pow2k div 2", div2, Botan::BigInt::power_of_2(k - 1));

            auto div4 = Botan::ct_divide_pow2k(k, 4);
            result.test_eq("ct_divide_pow2k div 4", div4, Botan::BigInt::power_of_2(k - 2));
         }

         for(size_t k = 4; k != 512; ++k) {
            const BigInt pow2k = BigInt::power_of_2(k);

            for(size_t y_bits = k / 2; y_bits <= (k + 2); ++y_bits) {
               const BigInt y(rng(), y_bits, false);
               if(y.is_zero()) {
                  continue;
               }
               const BigInt ct_pow2k = ct_divide_pow2k(k, y);
               const BigInt ref = BigInt::power_of_2(k) / y;

               result.test_eq("ct_divide_pow2k matches Knuth division", ct_pow2k, ref);
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("math", "bn_div_pow2k", BigInt_DivPow2k_Test);

class BigInt_Mod_Test final : public Text_Based_Test {
   public:
      BigInt_Mod_Test() : Text_Based_Test("bn/mod.vec", "In1,In2,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Mod");

         const BigInt a = vars.get_req_bn("In1");
         const BigInt b = vars.get_req_bn("In2");
         const BigInt expected = vars.get_req_bn("Output");

         result.test_eq("a % b", a % b, expected);

         BigInt e = a;
         e %= b;
         result.test_eq("a %= b", e, expected);

         auto mod_b_pub = Botan::Modular_Reducer::for_public_modulus(b);
         result.test_eq("Barrett public", mod_b_pub.reduce(a), expected);

         auto mod_b_sec = Botan::Modular_Reducer::for_secret_modulus(b);
         result.test_eq("Barrett secret", mod_b_sec.reduce(a), expected);

         // if b fits into a Botan::word test %= operator for words
         if(b.sig_words() == 1) {
            const Botan::word b_word = b.word_at(0);

            e = a;
            e %= b_word;
            result.test_eq("a %= b (as word)", e, expected);

            result.test_eq("a % b (as word)", a % b_word, expected);

            Botan::BigInt ct_q;
            Botan::word ct_r;
            Botan::ct_divide_word(a, b.word_at(0), ct_q, ct_r);
            result.test_eq("ct_divide_u8 r", ct_r, expected);
         }

         Botan::BigInt ct_q, ct_r;
         Botan::ct_divide(a, b, ct_q, ct_r);
         result.test_eq("ct_divide r", ct_r, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_mod", BigInt_Mod_Test);

class BigInt_GCD_Test final : public Text_Based_Test {
   public:
      BigInt_GCD_Test() : Text_Based_Test("bn/gcd.vec", "X,Y,GCD") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt GCD");

         const BigInt x = vars.get_req_bn("X");
         const BigInt y = vars.get_req_bn("Y");
         const BigInt expected = vars.get_req_bn("GCD");

         const BigInt g1 = Botan::gcd(x, y);
         result.test_eq("gcd", g1, expected);

         const BigInt g2 = Botan::gcd(y, x);
         result.test_eq("gcd", g2, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_gcd", BigInt_GCD_Test);

class BigInt_Jacobi_Test final : public Text_Based_Test {
   public:
      BigInt_Jacobi_Test() : Text_Based_Test("bn/jacobi.vec", "A,N,J") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Jacobi");

         const BigInt a = vars.get_req_bn("A");
         const BigInt n = vars.get_req_bn("N");
         const std::string expected = vars.get_req_str("J");

         const int32_t j = Botan::jacobi(a, n);

         if(j == 0) {
            result.test_eq("jacobi", expected, "0");
         } else if(j == -1) {
            result.test_eq("jacobi", expected, "-1");
         } else {
            result.test_eq("jacobi", expected, "1");
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_jacobi", BigInt_Jacobi_Test);

class BigInt_Lshift_Test final : public Text_Based_Test {
   public:
      BigInt_Lshift_Test() : Text_Based_Test("bn/lshift.vec", "Value,Shift,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Lshift");

         const BigInt value = vars.get_req_bn("Value");
         const size_t shift = vars.get_req_bn("Shift").to_u32bit();
         const BigInt output = vars.get_req_bn("Output");

         result.test_eq("a << s", value << shift, output);

         BigInt e = value;
         e <<= shift;
         result.test_eq("a <<= s", e, output);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_lshift", BigInt_Lshift_Test);

class BigInt_Rshift_Test final : public Text_Based_Test {
   public:
      BigInt_Rshift_Test() : Text_Based_Test("bn/rshift.vec", "Value,Shift,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Rshift");

         const BigInt value = vars.get_req_bn("Value");
         const size_t shift = vars.get_req_bn("Shift").to_u32bit();
         const BigInt output = vars.get_req_bn("Output");

         result.test_eq("a >> s", value >> shift, output);

         BigInt e = value;
         e >>= shift;
         result.test_eq("a >>= s", e, output);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_rshift", BigInt_Rshift_Test);

Test::Result test_const_time_left_shift() {
   Test::Result result("BigInt const time shift");
   const size_t bits = Test::run_long_tests() ? 4096 : 2048;

   auto rng = Test::new_rng("const_time_left_shift");

   result.start_timer();

   Botan::BigInt a = Botan::BigInt::with_capacity(bits / sizeof(Botan::word));
   for(size_t i = 0; i < bits; ++i) {
      if(rng->next_byte() & 1) {
         a.set_bit(i);
      }
   }

   for(size_t i = 0; i < bits; ++i) {
      auto ct = a;
      auto chk = a;
      Botan::CT::poison(ct);
      ct.ct_shift_left(i);
      Botan::CT::unpoison(ct);
      chk <<= i;
      result.test_eq(Botan::fmt("ct << {}", i), ct, chk);
   }

   result.end_timer();

   return result;
}

class BigInt_Powmod_Test final : public Text_Based_Test {
   public:
      BigInt_Powmod_Test() : Text_Based_Test("bn/powmod.vec", "Base,Exponent,Modulus,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Powmod");

         const BigInt base = vars.get_req_bn("Base");
         const BigInt exponent = vars.get_req_bn("Exponent");
         const BigInt modulus = vars.get_req_bn("Modulus");
         const BigInt expected = vars.get_req_bn("Output");

         result.test_eq("power_mod", Botan::power_mod(base, exponent, modulus), expected);
         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_powmod", BigInt_Powmod_Test);

class BigInt_IsPrime_Test final : public Text_Based_Test {
   public:
      BigInt_IsPrime_Test() : Text_Based_Test("bn/isprime.vec", "X") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         if(header != "Prime" && header != "NonPrime") {
            throw Test_Error("Bad header for prime test " + header);
         }

         const BigInt value = vars.get_req_bn("X");
         const bool is_prime = (header == "Prime");

         Test::Result result("BigInt Test " + header);
         result.test_eq("is_prime", Botan::is_prime(value, this->rng()), is_prime);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_isprime", BigInt_IsPrime_Test);

class BigInt_IsSquare_Test final : public Text_Based_Test {
   public:
      BigInt_IsSquare_Test() : Text_Based_Test("bn/perfect_square.vec", "X,R") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const BigInt value = vars.get_req_bn("X");
         const BigInt expected = vars.get_req_bn("R");
         const BigInt computed = Botan::is_perfect_square(value);

         Test::Result result("BigInt IsSquare");
         result.test_eq("is_perfect_square", computed, expected);
         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_issquare", BigInt_IsSquare_Test);

class BigInt_Sqrt_Modulo_Prime_Test final : public Text_Based_Test {
   public:
      BigInt_Sqrt_Modulo_Prime_Test() : Text_Based_Test("bn/sqrt_modulo_prime.vec", "Input,Modulus,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Sqrt Modulo Prime");

         const Botan::BigInt a = vars.get_req_bn("Input");
         const Botan::BigInt p = vars.get_req_bn("Modulus");
         const Botan::BigInt exp = vars.get_req_bn("Output");

         const Botan::BigInt a_sqrt = Botan::sqrt_modulo_prime(a, p);

         result.test_eq("sqrt_modulo_prime", a_sqrt, exp);

         if(a_sqrt > 1) {
            const Botan::BigInt a_sqrt2 = (a_sqrt * a_sqrt) % p;
            result.test_eq("square correct", a_sqrt2, a);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_sqrt_modulo_prime", BigInt_Sqrt_Modulo_Prime_Test);

class BigInt_InvMod_Test final : public Text_Based_Test {
   public:
      BigInt_InvMod_Test() : Text_Based_Test("bn/invmod.vec", "Input,Modulus,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt InvMod");

         const Botan::BigInt a = vars.get_req_bn("Input");
         const Botan::BigInt mod = vars.get_req_bn("Modulus");
         const Botan::BigInt expected = vars.get_req_bn("Output");

         result.test_eq("inverse_mod", Botan::inverse_mod(a, mod), expected);

         if(a < mod && a > 0 && a < mod) {
            auto g = Botan::inverse_mod_general(a, mod);
            if(g.has_value()) {
               result.test_eq("inverse_mod_general", g.value(), expected);
               result.test_eq("inverse works", ((g.value() * a) % mod), BigInt::one());
            } else {
               result.confirm("inverse_mod_general", expected.is_zero());
            }

            if(Botan::is_prime(mod, rng()) && mod != 2) {
               BOTAN_ASSERT_NOMSG(expected > 0);
               result.test_eq("inverse_mod_secret_prime", Botan::inverse_mod_secret_prime(a, mod), expected);
               result.test_eq("inverse_mod_public_prime", Botan::inverse_mod_public_prime(a, mod), expected);
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_invmod", BigInt_InvMod_Test);

class BigInt_Rand_Test final : public Text_Based_Test {
   public:
      BigInt_Rand_Test() : Text_Based_Test("bn/random.vec", "Seed,Min,Max,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("BigInt Random");

         const std::vector<uint8_t> seed = vars.get_req_bin("Seed");
         const Botan::BigInt min = vars.get_req_bn("Min");
         const Botan::BigInt max = vars.get_req_bn("Max");
         const Botan::BigInt expected = vars.get_req_bn("Output");

         Fixed_Output_RNG rng(seed);
         Botan::BigInt generated = BigInt::random_integer(rng, min, max);

         result.test_eq("random_integer KAT", generated, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "bn_rand", BigInt_Rand_Test);

class Lucas_Primality_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         const uint32_t lucas_max = (Test::run_long_tests() ? 100000 : 6000);

         // OEIS A217120
         std::set<uint32_t> lucas_pp{
            323,   377,   1159,  1829,  3827,  5459,  5777,  9071,  9179,  10877, 11419, 11663, 13919, 14839, 16109,
            16211, 18407, 18971, 19043, 22499, 23407, 24569, 25199, 25877, 26069, 27323, 32759, 34943, 35207, 39059,
            39203, 39689, 40309, 44099, 46979, 47879, 50183, 51983, 53663, 56279, 58519, 60377, 63881, 69509, 72389,
            73919, 75077, 77219, 79547, 79799, 82983, 84419, 86063, 90287, 94667, 97019, 97439,
         };

         Test::Result result("Lucas primality test");

         for(uint32_t i = 3; i <= lucas_max; i += 2) {
            auto mod_i = Botan::Modular_Reducer::for_public_modulus(i);
            const bool passes_lucas = Botan::is_lucas_probable_prime(i, mod_i);
            const bool is_prime = Botan::is_prime(i, this->rng());

            const bool is_lucas_pp = (is_prime == false && passes_lucas == true);

            if(is_lucas_pp) {
               result.confirm("Lucas pseudoprime is in list", lucas_pp.count(i) == 1);
            } else {
               result.confirm("Lucas non-pseudoprime is not in list", !lucas_pp.contains(i));
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("math", "bn_lucas", Lucas_Primality_Test);

class RSA_Compute_Exp_Test : public Test {
   public:
      std::vector<Test::Result> run() override {
         const size_t iter = 4000;

         Test::Result result("RSA compute exponent");

         const auto e = Botan::BigInt::from_u64(65537);

         /*
         * Rather than create a fresh p/q for each iteration this test creates
         * a pool of primes then selects 2 at random as p/q
         */

         const auto random_primes = [&]() {
            std::vector<Botan::BigInt> rp;
            for(size_t i = 0; i != iter / 10; ++i) {
               size_t bits = (128 + (i % 1024)) % 4096;
               auto p = Botan::random_prime(rng(), bits);
               if(gcd(p - 1, e) == 1) {
                  rp.push_back(p);
               }
            }
            return rp;
         }();

         for(size_t i = 0; i != iter; ++i) {
            const size_t p_idx = random_index(rng(), random_primes.size());
            const size_t q_idx = random_index(rng(), random_primes.size());

            if(p_idx == q_idx) {
               continue;
            }

            const auto& p = random_primes[p_idx];
            const auto& q = random_primes[q_idx];

            auto phi_n = lcm(p - 1, q - 1);

            auto d = Botan::compute_rsa_secret_exponent(e, phi_n, p, q);

            auto one = (e * d) % phi_n;

            result.test_eq("compute_rsa_secret_exponent returned inverse", (e * d) % phi_n, Botan::BigInt::one());
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("math", "rsa_compute_d", RSA_Compute_Exp_Test);

class DSA_ParamGen_Test final : public Text_Based_Test {
   public:
      DSA_ParamGen_Test() : Text_Based_Test("bn/dsa_gen.vec", "P,Q,Counter,Seed") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         const std::vector<uint8_t> seed = vars.get_req_bin("Seed");
         const size_t offset = vars.get_req_sz("Counter");

         const Botan::BigInt exp_P = vars.get_req_bn("P");
         const Botan::BigInt exp_Q = vars.get_req_bn("Q");

         const std::vector<std::string> header_parts = Botan::split_on(header, ',');

         if(header_parts.size() != 2) {
            throw Test_Error("Unexpected header '" + header + "' in DSA param gen test");
         }

         const size_t p_bits = Botan::to_u32bit(header_parts[1]);
         const size_t q_bits = Botan::to_u32bit(header_parts[0]);

         Test::Result result("DSA Parameter Generation");

         try {
            Botan::BigInt gen_P, gen_Q;
            if(Botan::generate_dsa_primes(this->rng(), gen_P, gen_Q, p_bits, q_bits, seed, offset)) {
               result.test_eq("P", gen_P, exp_P);
               result.test_eq("Q", gen_Q, exp_Q);
            } else {
               result.test_failure("Seed did not generate a DSA parameter");
            }
         } catch(Botan::Lookup_Error&) {}

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "dsa_param", DSA_ParamGen_Test);

std::vector<Test::Result> test_bigint_serialization() {
   auto rng = Test::new_rng("test_bigint_serialization");

   return {
      CHECK("BigInt binary serialization",
            [](Test::Result& res) {
               Botan::BigInt a(0x1234567890ABCDEF);
               auto enc = a.serialize();
               res.test_eq("BigInt::serialize", enc, Botan::hex_decode("1234567890ABCDEF"));

               auto enc10 = a.serialize(10);
               res.test_eq("BigInt::serialize", enc10, Botan::hex_decode("00001234567890ABCDEF"));

               res.test_throws("BigInt::serialize rejects short output", [&]() { a.serialize(7); });
            }),

      CHECK("BigInt truncated/padded binary serialization",
            [&](Test::Result& res) {
               Botan::BigInt a(0xFEDCBA9876543210);

               std::vector<uint8_t> enc1(a.bytes() - 1);
               a.binary_encode(enc1.data(), enc1.size());
               res.test_eq("BigInt::binary_encode", enc1, Botan::hex_decode("DCBA9876543210"));

               std::vector<uint8_t> enc2(a.bytes() - 3);
               a.binary_encode(enc2.data(), enc2.size());
               res.test_eq("BigInt::binary_encode", enc2, Botan::hex_decode("9876543210"));

               std::vector<uint8_t> enc3(a.bytes() + 1);
               a.binary_encode(enc3.data(), enc3.size());
               res.test_eq("BigInt::binary_encode", enc3, Botan::hex_decode("00FEDCBA9876543210"));

               // make sure that the padding is actually written
               std::vector<uint8_t> enc4(a.bytes() + 3);
               rng->randomize(enc4);
               a.binary_encode(enc4.data(), enc4.size());
               res.test_eq("BigInt::binary_encode", enc4, Botan::hex_decode("000000FEDCBA9876543210"));

               Botan::BigInt b(Botan::hex_decode("FEDCBA9876543210BAADC0FFEE"));

               std::vector<uint8_t> enc5(b.bytes() + 12);
               rng->randomize(enc5);
               b.binary_encode(enc5.data(), enc5.size());
               res.test_eq("BigInt::binary_encode",
                           enc5,
                           Botan::hex_decode("000000000000000000000000FEDCBA9876543210BAADC0FFEE"));
            }),
   };
}

BOTAN_REGISTER_TEST_FN("math", "bignum_auxiliary", test_const_time_left_shift, test_bigint_serialization);

#endif

}  // namespace

}  // namespace Botan_Tests

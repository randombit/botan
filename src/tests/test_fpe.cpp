/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_FPE_FE1)
   #include <botan/fpe_fe1.h>
#endif

#if defined(BOTAN_HAS_FPE_FF1)
   #include <botan/exceptn.h>
   #include <botan/fpe_ff1.h>
   #include <botan/internal/ct_utils.h>
   #include <botan/internal/parsing.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_FPE_FE1)

class FPE_FE1_Tests final : public Text_Based_Test {
   public:
      FPE_FE1_Tests() : Text_Based_Test("fpe_fe1.vec", "Mod,In,Out,Key,Tweak") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const Botan::BigInt modulus = vars.get_req_bn("Mod");
         const Botan::BigInt input = vars.get_req_bn("In");
         const Botan::BigInt expected = vars.get_req_bn("Out");
         const auto key = Botan::SymmetricKey(vars.get_req_bin("Key"));
         const std::vector<uint8_t> tweak = vars.get_req_bin("Tweak");

         Test::Result result("FPE_FE1");

         const Botan::BigInt got = Botan::FPE::fe1_encrypt(modulus, input, key, tweak);

         result.test_bn_eq("ciphertext", got, expected);

         const Botan::BigInt decry = Botan::FPE::fe1_decrypt(modulus, got, key, tweak);

         result.test_bn_eq("decrypted", decry, input);

         return result;
      }
};

BOTAN_REGISTER_TEST("misc", "fpe_fe1", FPE_FE1_Tests);

#endif

#if defined(BOTAN_HAS_FPE_FF1)

std::vector<uint16_t> parse_numerals(const std::string& str) {
   std::vector<uint16_t> numerals;
   for(const auto& numeral : Botan::split_on(str, ',')) {
      numerals.push_back(static_cast<uint16_t>(Botan::to_u32bit(numeral)));
   }
   return numerals;
}

std::string format_numerals(std::span<const uint16_t> numerals) {
   std::string str;
   for(const uint16_t numeral : numerals) {
      if(!str.empty()) {
         str += ",";
      }
      str += std::to_string(numeral);
   }
   return str;
}

class FPE_FF1_KAT_Tests final : public Text_Based_Test {
   public:
      FPE_FF1_KAT_Tests() : Text_Based_Test("fpe_ff1.vec", "Radix,Key,Tweak,In,Out") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const size_t radix = vars.get_req_sz("Radix");
         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const std::vector<uint8_t> tweak = vars.get_req_bin("Tweak");
         const std::string input = vars.get_req_str("In");
         const std::string expected = vars.get_req_str("Out");

         Test::Result result("FPE_FF1");

         Botan::FPE_FF1 ff1(radix);
         ff1.set_key(key);

         std::vector<uint16_t> buf = parse_numerals(input);

         Botan::CT::poison(buf);
         ff1.encrypt(buf, tweak);
         Botan::CT::unpoison(buf);
         result.test_str_eq("ciphertext", format_numerals(buf), expected);

         Botan::CT::poison(buf);
         ff1.decrypt(buf, tweak);
         Botan::CT::unpoison(buf);
         result.test_str_eq("decrypted", format_numerals(buf), input);

         return result;
      }
};

BOTAN_REGISTER_TEST("misc", "fpe_ff1", FPE_FF1_KAT_Tests);

class FPE_FF1_Input_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("FPE_FF1 input validation");

         result.test_throws<Botan::Invalid_Argument>("radix 0", []() { const Botan::FPE_FF1 ff1(0); });
         result.test_throws<Botan::Invalid_Argument>("radix 1", []() { const Botan::FPE_FF1 ff1(1); });
         result.test_throws<Botan::Invalid_Argument>("radix 65537", []() { const Botan::FPE_FF1 ff1(65537); });

         result.test_sz_eq("minimum length radix 2", Botan::FPE_FF1(2).minimum_length(), 20);
         result.test_sz_eq("minimum length radix 10", Botan::FPE_FF1(10).minimum_length(), 6);
         result.test_sz_eq("minimum length radix 999", Botan::FPE_FF1(999).minimum_length(), 3);
         result.test_sz_eq("minimum length radix 1000", Botan::FPE_FF1(1000).minimum_length(), 2);
         result.test_sz_eq("minimum length radix 65536", Botan::FPE_FF1(65536).minimum_length(), 2);

         Botan::FPE_FF1 ff1(10);
         const std::vector<uint8_t> tweak;

         std::vector<uint16_t> ok = {1, 2, 3, 4, 5, 6};
         result.test_throws<Botan::Invalid_State>("no key", [&]() { ff1.encrypt(ok, tweak); });

         result.test_throws<Botan::Invalid_Key_Length>("bad key length",
                                                       [&]() { ff1.set_key(std::vector<uint8_t>(20)); });

         ff1.set_key(std::vector<uint8_t>(16));
         ff1.encrypt(ok, tweak);
         ff1.decrypt(ok, tweak);
         result.test_str_eq("round trip", format_numerals(ok), "1,2,3,4,5,6");

         std::vector<uint16_t> too_short = {1, 2, 3, 4, 5};
         result.test_throws<Botan::Invalid_Argument>("encrypt short input", [&]() { ff1.encrypt(too_short, tweak); });
         result.test_throws<Botan::Invalid_Argument>("decrypt short input", [&]() { ff1.decrypt(too_short, tweak); });

         std::vector<uint16_t> bad_numeral = {1, 2, 3, 4, 5, 10};
         result.test_throws<Botan::Invalid_Argument>("encrypt bad numeral", [&]() { ff1.encrypt(bad_numeral, tweak); });
         result.test_throws<Botan::Invalid_Argument>("decrypt bad numeral", [&]() { ff1.decrypt(bad_numeral, tweak); });

         ff1.clear();
         result.test_throws<Botan::Invalid_State>("cleared", [&]() { ff1.encrypt(ok, tweak); });

         return {result};
      }
};

BOTAN_REGISTER_TEST("misc", "fpe_ff1_inputs", FPE_FF1_Input_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests

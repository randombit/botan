/*
* (C) 2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <functional>

namespace Botan_Tests {

class CT_Mask_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("CT::Mask");

         result.test_eq_sz("CT::is_zero8", Botan::CT::Mask<uint8_t>::is_zero(0).value(), 0xFF);
         result.test_eq_sz("CT::is_zero8", Botan::CT::Mask<uint8_t>::is_zero(1).value(), 0x00);
         result.test_eq_sz("CT::is_zero8", Botan::CT::Mask<uint8_t>::is_zero(0xFF).value(), 0x00);

         result.test_eq_sz("CT::is_zero16", Botan::CT::Mask<uint16_t>::is_zero(0).value(), 0xFFFF);
         result.test_eq_sz("CT::is_zero16", Botan::CT::Mask<uint16_t>::is_zero(1).value(), 0x0000);
         result.test_eq_sz("CT::is_zero16", Botan::CT::Mask<uint16_t>::is_zero(0xFF).value(), 0x0000);

         result.test_eq_sz("CT::is_zero32", Botan::CT::Mask<uint32_t>::is_zero(0).value(), 0xFFFFFFFF);
         result.test_eq_sz("CT::is_zero32", Botan::CT::Mask<uint32_t>::is_zero(1).value(), 0x00000000);
         result.test_eq_sz("CT::is_zero32", Botan::CT::Mask<uint32_t>::is_zero(0xFF).value(), 0x00000000);

         result.test_eq_sz("CT::is_less8", Botan::CT::Mask<uint8_t>::is_lt(0, 1).value(), 0xFF);
         result.test_eq_sz("CT::is_less8", Botan::CT::Mask<uint8_t>::is_lt(1, 0).value(), 0x00);
         result.test_eq_sz("CT::is_less8", Botan::CT::Mask<uint8_t>::is_lt(0xFF, 5).value(), 0x00);

         result.test_eq_sz("CT::is_less16", Botan::CT::Mask<uint16_t>::is_lt(0, 1).value(), 0xFFFF);
         result.test_eq_sz("CT::is_less16", Botan::CT::Mask<uint16_t>::is_lt(1, 0).value(), 0x0000);
         result.test_eq_sz("CT::is_less16", Botan::CT::Mask<uint16_t>::is_lt(0xFFFF, 5).value(), 0x0000);

         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(0, 1).value(), 0xFFFFFFFF);
         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(1, 0).value(), 0x00000000);
         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(0xFFFF5, 5).value(), 0x00000000);
         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(0xFFFFFFFF, 5).value(), 0x00000000);
         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(5, 0xFFFFFFFF).value(), 0xFFFFFFFF);

         for(auto bad_input : {0, 1}) {
            for(size_t input_length : {0, 1, 2, 32}) {
               for(size_t offset = 0; offset != input_length + 1; ++offset) {
                  const auto mask = Botan::CT::Mask<uint8_t>::expand(static_cast<uint8_t>(bad_input));

                  std::vector<uint8_t> input(input_length);
                  this->rng().randomize(input.data(), input.size());

                  auto output = Botan::CT::copy_output(mask, input.data(), input.size(), offset);

                  result.test_eq_sz("CT::copy_output capacity", output.capacity(), input.size());

                  if(bad_input) {
                     result.confirm("If bad input, no output", output.empty());
                  } else {
                     if(offset >= input_length) {
                        result.confirm("If offset is too large, output is empty", output.empty());
                     } else {
                        result.test_eq_sz("CT::copy_output length", output.size(), input.size() - offset);

                        for(size_t i = 0; i != output.size(); ++i) {
                           result.test_eq_sz("CT::copy_output offset", output[i], input[i + offset]);
                        }
                     }
                  }
               }
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("ct_utils", "ct_mask", CT_Mask_Tests);

class CT_Choice_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("CT::Choice");

         result.test_eq("CT::Choice::yes", Botan::CT::Choice::yes().as_bool(), true);
         result.test_eq("CT::Choice::no", Botan::CT::Choice::no().as_bool(), false);

         test_choice_from_int<uint8_t>("uint8_t", result);
         test_choice_from_int<uint16_t>("uint16_t", result);
         test_choice_from_int<uint32_t>("uint32_t", result);
         test_choice_from_int<uint64_t>("uint64_t", result);

         return {result};
      }

   private:
      template <std::unsigned_integral T>
      void test_choice_from_int(const char* type_name, Result& result) {
         const auto tname = Botan::fmt("CT::Choice::from_int<{}>", type_name);
         constexpr size_t tbits = sizeof(T) * 8;

         result.test_eq(tname, Botan::CT::Choice::from_int<T>(0).as_bool(), false);
         for(size_t b = 0; b != tbits; ++b) {
            const auto choice = Botan::CT::Choice::from_int<T>(static_cast<T>(1) << b);
            result.test_eq(tname, choice.as_bool(), true);
         }
      }
};

BOTAN_REGISTER_TEST("ct_utils", "ct_choice", CT_Choice_Tests);

class CT_Option_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("CT::Option");

         class Val {
            public:
               Val() : m_val() {}

               Val(uint8_t x) : m_val{x, x, x, x} {}

               void conditional_assign(Botan::CT::Choice choice, const Val& other) {
                  Botan::CT::conditional_assign_mem(choice, m_val, other.m_val, 4);
               }

               bool operator==(const Val& other) const { return std::memcmp(m_val, other.m_val, 4) == 0; }

               Val& operator++() {
                  // totally arbitrary here ...
                  m_val[0] += 1;
                  return (*this);
               }

            private:
               uint8_t m_val[4];
         };

         test_ct_option<Val>(result, Val(42), Val(23));
         test_ct_option<uint8_t>(result, 42, 23);
         test_ct_option<uint16_t>(result, 4242, 2323);
         test_ct_option<uint32_t>(result, 42424242, 23232323);
         test_ct_option<uint64_t>(result, 4242424242424242, 2323232323232323);

         return {result};
      }

   private:
      template <typename T>
      void test_ct_option(Test::Result& result, const T& value, const T& value2) {
         auto unset = Botan::CT::Option<T>();
         result.test_eq("Unset does not have value", unset.has_value().as_bool(), false);
         result.test_throws("Unset Option throws if value is called", [&]() { unset.value(); });
         result.confirm("Unset Option returns alternative with value_or", unset.value_or(value) == value);
         result.confirm("Unset Option returns alternative with value_or", unset.value_or(value2) == value2);
         result.confirm(
            "Unset Option returns nullopt for as_optional_vartime", unset.as_optional_vartime().has_value(), false);

         auto next = [](const T& v) -> T {
            T n = v;
            ++n;
            return n;
         };

         result.test_eq("Unset Option transform returns unset", unset.transform(next).has_value().as_bool(), false);

         auto set = Botan::CT::Option<T>(value);
         result.test_eq("Set does have value", set.has_value().as_bool(), true);
         result.confirm("Set Option has the expected value", set.value() == value);
         result.confirm("Set Option returns original with value_or", set.value_or(value2) == value);
         result.confirm("Set Option returns something for as_optional_vartime",
                        set.as_optional_vartime().value() == value);

         result.confirm("Set Option transform returns set", set.transform(next).value() == next(value));
      }
};

BOTAN_REGISTER_TEST("ct_utils", "ct_option", CT_Option_Tests);

}  // namespace Botan_Tests

/*
* (C) 2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>

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
            for(size_t input_length = 0; input_length != 64; ++input_length) {
               for(size_t offset = 0; offset != input_length + 5; ++offset) {
                  const auto accept = !Botan::CT::Choice::from_int(static_cast<uint32_t>(bad_input));

                  std::vector<uint8_t> input(input_length);
                  this->rng().randomize(input.data(), input.size());

                  std::vector<uint8_t> output(input_length);

                  auto written = Botan::CT::copy_output(accept, output, input, offset);

                  if(bad_input) {
                     result.confirm("If bad input, no output", !written.has_value().as_bool());
                  } else {
                     if(offset > input_length) {
                        result.confirm("If offset is too large, no output", !written.has_value().as_bool());
                     } else {
                        const size_t bytes = written.value();
                        result.test_eq_sz("CT::copy_output length", bytes, input.size() - offset);

                        for(size_t i = 0; i != bytes; ++i) {
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

namespace {

template <typename T = void>
struct Poisonable {
      mutable bool poisoned = false;  // NOLINT(misc-non-private-member-variables-in-classes)

      void _const_time_poison() const { poisoned = true; }

      void _const_time_unpoison() const { poisoned = false; }
};

std::vector<Test::Result> test_higher_level_ct_poison() {
   return {
      CHECK("custom poisonable object",
            [](Test::Result& result) {
               Poisonable p;
               result.confirm("not poisoned", p.poisoned == false);
               Botan::CT::poison(p);
               result.confirm("poisoned", p.poisoned == true);
               Botan::CT::unpoison(p);
               result.confirm("unpoisoned", p.poisoned == false);
            }),

      CHECK("poison multiple objects",
            [](Test::Result& result) {
               // template is useless, but p1, p2, and p3 are different types and we
               // want to make sure that poison_all/unpoison_all can deal with that.
               Poisonable<int> p1;
               Poisonable<double> p2;
               Poisonable<std::string> p3;

               result.confirm("all not poisoned", !p1.poisoned && !p2.poisoned && !p3.poisoned);
               Botan::CT::poison_all(p1, p2, p3);
               result.confirm("all poisoned", p1.poisoned && p2.poisoned && p3.poisoned);
               Botan::CT::unpoison_all(p1, p2, p3);
               result.confirm("all unpoisoned", !p1.poisoned && !p2.poisoned && !p3.poisoned);
            }),

      CHECK("scoped poison",
            [](Test::Result& result) {
               // template is useless, but p1, p2, and p3 are different types and we
               // want to make sure that poison_all/unpoison_all can deal with that.
               Poisonable<int> p1;
               Poisonable<double> p2;
               Poisonable<std::string> p3;

               result.confirm("not poisoned", !p1.poisoned && !p2.poisoned, !p3.poisoned);

               {
                  auto scope = Botan::CT::scoped_poison(p1, p2, p3);
                  result.confirm("poisoned", p1.poisoned && p2.poisoned && p3.poisoned);
               }

               result.confirm("unpoisoned", !p1.poisoned && !p2.poisoned && !p3.poisoned);
            }),

      CHECK("poison a range of poisonable objects",
            [](Test::Result& result) {
               auto is_poisoned = [](const auto& p) { return p.poisoned; };

               std::vector<Poisonable<>> v(10);
               result.confirm("none poisoned", std::none_of(v.begin(), v.end(), is_poisoned));

               Botan::CT::poison_range(v);
               result.confirm("all poisoned", std::all_of(v.begin(), v.end(), is_poisoned));

               Botan::CT::unpoison_range(v);
               result.confirm("all unpoisoned", std::none_of(v.begin(), v.end(), is_poisoned));
            }),

      CHECK("poison a poisonable objects with driveby_poison",
            [](Test::Result& result) {
               Poisonable p;
               result.confirm("not poisoned", p.poisoned == false);
               Poisonable p_poisoned =
                  Botan::CT::driveby_poison(std::move(p));  // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
               result.confirm("poisoned", p_poisoned.poisoned == true);
               Poisonable p_unpoisoned = Botan::CT::driveby_unpoison(
                  std::move(p_poisoned));  // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
               result.confirm("unpoisoned", p_unpoisoned.poisoned == false);
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("ct_utils", "ct_poison", test_higher_level_ct_poison);

}  // namespace Botan_Tests

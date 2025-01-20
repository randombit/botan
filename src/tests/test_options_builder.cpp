/*
* (C) 2024 Jack Lloyd
*     2024 René Meusel - Rohde & Schwarz Cybersecurity
*
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/options_builder.h>

#include <iostream>

namespace Botan_Tests {

namespace {

struct Void {};

struct TestOptionsContainer {
      // NOLINTBEGIN(misc-non-private-member-variables-in-classes)

      Botan::Option<"string", std::string> test_string;
      Botan::Option<"pointer", std::unique_ptr<Void>> test_unique_ptr;
      Botan::Option<"buffer", std::vector<uint8_t>> test_buffer;
      Botan::Option<"array", std::array<uint8_t, 8>> test_array;
      Botan::Option<"bool", bool> test_bool;

      // NOLINTEND(misc-non-private-member-variables-in-classes)

      auto all_options() const { return std::tie(test_string, test_unique_ptr, test_buffer, test_array, test_bool); }
};

class TestOptions final : public Botan::Options<TestOptionsContainer> {
   public:
      using Options::Options;

   public:
      [[nodiscard]] auto get_string() { return take(options().test_string); }

      [[nodiscard]] auto get_unique_ptr() { return take(options().test_unique_ptr); }

      [[nodiscard]] auto get_buffer() { return take(options().test_buffer); }

      [[nodiscard]] auto get_array() { return take(options().test_array); }

      [[nodiscard]] auto get_bool() { return take(options().test_bool); }
};

class TestOptionsBuilder final : public Botan::OptionsBuilder<TestOptions> {
   public:
      using OptionsBuilder::OptionsBuilder;

   public:
      TestOptionsBuilder& with_string(std::string_view value) & {
         set_or_throw(options().test_string, std::string(value));
         return *this;
      }

      TestOptionsBuilder with_string(std::string_view value) && { return std::move(with_string(value)); }

      TestOptionsBuilder& with_unique_ptr(std::unique_ptr<Void> value) & {
         set_or_throw(options().test_unique_ptr, std::move(value));
         return *this;
      }

      TestOptionsBuilder with_unique_ptr(std::unique_ptr<Void> value) && {
         return std::move(with_unique_ptr(std::move(value)));
      }

      TestOptionsBuilder& with_buffer(std::vector<uint8_t> value) & {
         set_or_throw(options().test_buffer, std::move(value));
         return *this;
      }

      TestOptionsBuilder with_buffer(std::vector<uint8_t> value) && { return std::move(with_buffer(std::move(value))); }

      TestOptionsBuilder& with_array(std::array<uint8_t, 8> value) & {
         set_or_throw(options().test_array, value);
         return *this;
      }

      TestOptionsBuilder with_array(std::array<uint8_t, 8> value) && { return std::move(with_array(value)); }

      TestOptionsBuilder& with_bool(bool value) & {
         set_or_throw(options().test_bool, value);
         return *this;
      }

      TestOptionsBuilder with_bool(bool value) && { return std::move(with_bool(value)); }
};

size_t occurences(std::string_view haystack, std::string_view needle) {
   size_t count = 0;
   size_t pos = 0;
   while((pos = haystack.find(needle, pos)) != std::string::npos) {
      ++count;
      pos += needle.size();
   }
   return count;
}

TestOptions all_set() {
   return TestOptionsBuilder()
      .with_string("hello")
      .with_unique_ptr(std::make_unique<Void>())
      .with_buffer(std::vector<uint8_t>{0, 1, 2})
      .with_array(std::array<uint8_t, 8>{7, 6, 5, 4, 3, 2, 1, 0})
      .with_bool(true)
      .commit();
};

std::vector<Test::Result> test_default_options_builder() {
   return {
      CHECK("default builder creates empty options",
            [](Test::Result& result) {
               TestOptions options = TestOptionsBuilder().commit();
               result.confirm("string is empty", !options.get_string().optional().has_value());
               result.confirm("pointer is empty", !options.get_unique_ptr().optional().has_value());
               result.confirm("buffer is empty", !options.get_buffer().optional().has_value());
               result.confirm("array is empty", !options.get_array().optional().has_value());
               result.confirm("bool is empty", !options.get_bool().optional().has_value());
            }),

      CHECK("default builder does not contain anything",
            [](Test::Result& result) {
               TestOptions options = TestOptionsBuilder().commit();
               result.test_throws<Botan::Invalid_Argument>("string throws",
                                                           [&] { std::ignore = options.get_string().required(); });
               result.test_throws<Botan::Invalid_Argument>("pointer throws",
                                                           [&] { std::ignore = options.get_unique_ptr().required(); });
               result.test_throws<Botan::Invalid_Argument>("buffer throws",
                                                           [&] { std::ignore = options.get_buffer().required(); });
               result.test_throws<Botan::Invalid_Argument>("array throws",
                                                           [&] { std::ignore = options.get_array().required(); });
               result.test_throws<Botan::Invalid_Argument>("bool throws",
                                                           [&] { std::ignore = options.get_bool().required(); });
            }),

      CHECK("default builder passes on defaults",
            [](Test::Result& result) {
               TestOptions options = TestOptionsBuilder().commit();
               result.test_eq("string default", options.get_string().or_default("default"), "default");
               result.test_not_null("pointer default", options.get_unique_ptr().or_default(std::make_unique<Void>()));
               result.test_eq("buffer default",
                              options.get_buffer().or_default(std::vector<uint8_t>{0, 1, 2}),
                              std::vector<uint8_t>{0, 1, 2});
               result.test_is_eq("array default",
                                 options.get_array().or_default(std::array<uint8_t, 8>{0, 2, 4, 6, 8, 10, 12, 14}),
                                 std::array<uint8_t, 8>{0, 2, 4, 6, 8, 10, 12, 14});
               result.test_eq("bool default", options.get_bool().or_default(true), true);
            }),

      CHECK("default builder to_string",
            [](Test::Result& result) {
               TestOptions options = TestOptionsBuilder().commit();
               result.test_eq("5x <unset>", occurences(options.to_string(), "<unset>"), 5);
               result.test_eq("1x string", occurences(options.to_string(), "string"), 1);
               result.test_eq("1x pointer", occurences(options.to_string(), "pointer"), 1);
               result.test_eq("1x buffer", occurences(options.to_string(), "buffer"), 1);
               result.test_eq("1x array", occurences(options.to_string(), "array"), 1);
               result.test_eq("1x bool", occurences(options.to_string(), "bool"), 1);
            }),

      CHECK("default builder is fully consumed",
            [](Test::Result& result) {
               TestOptions options = TestOptionsBuilder().commit();
               result.test_no_throw("consumption validation is successful",
                                    [&] { options.validate_option_consumption(); });
            }),
   };
}

std::vector<Test::Result> test_validation_of_options() {
   return {
      CHECK(
         "builder with all options set",
         [&](Test::Result& result) {
            TestOptions options = all_set();

            result.test_throws<Botan::Invalid_Argument>("not fully consumed",
                                                        [&] { options.validate_option_consumption(); });

            result.test_eq("string", options.get_string().required(), "hello");
            result.test_not_null("pointer", options.get_unique_ptr().required());
            result.test_eq("buffer", options.get_buffer().required(), std::vector<uint8_t>{0, 1, 2});
            result.test_is_eq("array", options.get_array().required(), std::array<uint8_t, 8>{7, 6, 5, 4, 3, 2, 1, 0});
            result.test_eq("bool", options.get_bool().required(), true);

            result.test_no_throw("fully consumed", [&] { options.validate_option_consumption(); });
         }),

      CHECK("each option can be taken only once",
            [&](Test::Result& result) {
               TestOptions options = all_set();
               std::ignore = options.get_string().required();
               std::ignore = options.get_unique_ptr().required();
               std::ignore = options.get_buffer().required();
               std::ignore = options.get_array().required();
               std::ignore = options.get_bool().required();

               result.test_no_throw("fully consumed", [&] { options.validate_option_consumption(); });

               result.test_throws<Botan::Invalid_Argument>("string throws",
                                                           [&] { std::ignore = options.get_string().required(); });
               result.test_throws<Botan::Invalid_Argument>("pointer throws",
                                                           [&] { std::ignore = options.get_unique_ptr().required(); });
               result.test_throws<Botan::Invalid_Argument>("buffer throws",
                                                           [&] { std::ignore = options.get_buffer().required(); });
               result.test_throws<Botan::Invalid_Argument>("array throws",
                                                           [&] { std::ignore = options.get_array().required(); });
               result.test_throws<Botan::Invalid_Argument>("bool throws",
                                                           [&] { std::ignore = options.get_bool().required(); });
            }),

      CHECK("builder with all options set ignores all defaults",
            [&](Test::Result& result) {
               TestOptions options = all_set();
               result.test_eq("string", options.get_string().or_default("default"), "hello");
               result.test_not_null("pointer", options.get_unique_ptr().or_default(nullptr));
               result.test_eq("buffer",
                              options.get_buffer().or_default(std::vector<uint8_t>{0, 8, 15}),
                              std::vector<uint8_t>{0, 1, 2});
               result.test_is_eq("array",
                                 options.get_array().or_default(std::array<uint8_t, 8>{0, 2, 4, 6, 8, 10, 12, 14}),
                                 std::array<uint8_t, 8>{7, 6, 5, 4, 3, 2, 1, 0});
               result.test_eq("bool", options.get_bool().or_default(false), true);

               result.test_no_throw("fully consumed", [&] { options.validate_option_consumption(); });
            }),

      CHECK("builder with all options set throws for not_implemented",
            [&](Test::Result& result) {
               TestOptions options = all_set();
               result.test_throws<Botan::Not_Implemented>("string throws",
                                                          [&] { options.get_string().not_implemented("reason"); });
               result.test_throws<Botan::Not_Implemented>("pointer throws",
                                                          [&] { options.get_unique_ptr().not_implemented("reason"); });
               result.test_throws<Botan::Not_Implemented>("buffer throws",
                                                          [&] { options.get_buffer().not_implemented("reason"); });
               result.test_throws<Botan::Not_Implemented>("array throws",
                                                          [&] { options.get_array().not_implemented("reason"); });
               result.test_throws<Botan::Not_Implemented>("bool throws",
                                                          [&] { options.get_bool().not_implemented("reason"); });

               result.test_no_throw("fully consumed", [&] { options.validate_option_consumption(); });
            }),

      CHECK("consumption validation lists unused options",
            [&](Test::Result& result) {
               TestOptions options = all_set();

               const auto error_message = [&]() -> std::string {
                  try {
                     options.validate_option_consumption();
                  } catch(const Botan::Invalid_Argument& e) {
                     return e.what();
                  }

                  return "nothing thrown";
               }();

               result.test_eq("string mentioned", occurences(error_message, "string"), 1);
               result.test_eq("pointer mentioned", occurences(error_message, "pointer"), 1);
               result.test_eq("buffer mentioned", occurences(error_message, "buffer"), 1);
               result.test_eq("array mentioned", occurences(error_message, "array"), 1);
               result.test_eq("bool mentioned", occurences(error_message, "bool"), 1);
            }),
   };
}

std::vector<Test::Result> test_stringification_of_options() {
   return {
      CHECK("builder with all options set to_string",
            [&](Test::Result& result) {
               TestOptions options = all_set();
               result.test_eq("0x <unset>", occurences(options.to_string(), "<unset>"), 0);

               result.test_eq("1x string", occurences(options.to_string(), "string"), 1);
               result.test_eq("1x hello", occurences(options.to_string(), "hello"), 1);

               result.test_eq("1x pointer", occurences(options.to_string(), "pointer"), 1);
               result.test_eq("1x unique_ptr", occurences(options.to_string(), "unique_ptr"), 1);

               result.test_eq("1x buffer", occurences(options.to_string(), "buffer"), 1);
               result.test_eq("1x 000102", occurences(options.to_string(), "000102"), 1);

               result.test_eq("1x array", occurences(options.to_string(), "array"), 1);
               result.test_eq("1x 0706050403020100", occurences(options.to_string(), "0706050403020100"), 1);

               result.test_eq("1x bool", occurences(options.to_string(), "bool"), 1);
               result.test_eq("1x true", occurences(options.to_string(), "true"), 1);

               result.test_throws("to_string does not consume anything",
                                  [&] { options.validate_option_consumption(); });
            }),

      CHECK("long buffers are truncated",
            [](Test::Result& result) {
               auto options = TestOptionsBuilder()
                                 .with_buffer(Test::new_rng(__func__)->random_vec<std::vector<uint8_t>>(1024))
                                 .commit();
               result.test_eq("...", occurences(options.to_string(), "..."), 1);
               result.test_eq("960 more bytes", occurences(options.to_string(), "960 more bytes"), 1);
            }),
   };
};

}  // namespace

BOTAN_REGISTER_TEST_FN("utils", "default_options_builder", test_default_options_builder);
BOTAN_REGISTER_TEST_FN("utils", "validation_of_options", test_validation_of_options);
BOTAN_REGISTER_TEST_FN("utils", "options_to_string", test_stringification_of_options);

}  // namespace Botan_Tests

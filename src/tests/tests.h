/*
* (C) 2014,2015 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_H_
#define BOTAN_TESTS_H_

#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/symkey.h>
#include <botan/types.h>
#include <functional>
#include <iosfwd>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <set>
#include <sstream>
#include <string>
#include <typeindex>
#include <unordered_map>
#include <variant>
#include <vector>

namespace Botan {

#if defined(BOTAN_HAS_BIGINT)
class BigInt;
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
class EC_Point;
#endif

}  // namespace Botan

namespace Botan_Tests {

#if defined(BOTAN_HAS_BIGINT)
using Botan::BigInt;
#endif

class Test_Error : public Botan::Exception {
   public:
      explicit Test_Error(const std::string& what) : Exception("Test error", what) {}

      Botan::ErrorType error_type() const noexcept override { return Botan::ErrorType::Unknown; }
};

class Test_Aborted final : public Test_Error {
   public:
      explicit Test_Aborted(const std::string& what) : Test_Error(what) {}
};

class Test_Options {
   public:
      Test_Options() = default;

      Test_Options(const std::vector<std::string>& requested_tests,
                   const std::vector<std::string>& skip_tests,
                   const std::string& data_dir,
                   const std::string& pkcs11_lib,
                   const std::string& provider,
                   const std::string& drbg_seed,
                   const std::string& xml_results_dir,
                   const std::vector<std::string>& report_properties,
                   size_t test_runs,
                   size_t test_threads,
                   bool verbose,
                   bool log_success,
                   bool run_online_tests,
                   bool run_long_tests,
                   bool run_memory_intensive_tests,
                   bool abort_on_first_fail,
                   bool no_stdout) :
            m_requested_tests(requested_tests),
            m_skip_tests(skip_tests.begin(), skip_tests.end()),
            m_data_dir(data_dir),
            m_pkcs11_lib(pkcs11_lib),
            m_provider(provider),
            m_drbg_seed(drbg_seed),
            m_xml_results_dir(xml_results_dir),
            m_report_properties(report_properties),
            m_test_runs(test_runs),
            m_test_threads(test_threads),
            m_verbose(verbose),
            m_log_success(log_success),
            m_run_online_tests(run_online_tests),
            m_run_long_tests(run_long_tests),
            m_run_memory_intensive_tests(run_memory_intensive_tests),
            m_abort_on_first_fail(abort_on_first_fail),
            m_no_stdout(no_stdout) {}

      const std::vector<std::string>& requested_tests() const { return m_requested_tests; }

      const std::set<std::string>& skip_tests() const { return m_skip_tests; }

      const std::string& data_dir() const { return m_data_dir; }

      const std::string& pkcs11_lib() const { return m_pkcs11_lib; }

      const std::string& provider() const { return m_provider; }

      const std::string& drbg_seed() const { return m_drbg_seed; }

      const std::string& xml_results_dir() const { return m_xml_results_dir; }

      std::map<std::string, std::string> report_properties() const;

      size_t test_runs() const { return m_test_runs; }

      size_t test_threads() const { return m_test_threads; }

      bool log_success() const { return m_log_success; }

      bool run_online_tests() const { return m_run_online_tests; }

      bool run_long_tests() const { return m_run_long_tests; }

      bool run_memory_intensive_tests() const { return m_run_memory_intensive_tests; }

      bool abort_on_first_fail() const { return m_abort_on_first_fail; }

      bool no_stdout() const { return m_no_stdout; }

      bool verbose() const { return m_verbose; }

   private:
      std::vector<std::string> m_requested_tests;
      std::set<std::string> m_skip_tests;
      std::string m_data_dir;
      std::string m_pkcs11_lib;
      std::string m_provider;
      std::string m_drbg_seed;
      std::string m_xml_results_dir;
      std::vector<std::string> m_report_properties;
      size_t m_test_runs;
      size_t m_test_threads;
      bool m_verbose;
      bool m_log_success;
      bool m_run_online_tests;
      bool m_run_long_tests;
      bool m_run_memory_intensive_tests;
      bool m_abort_on_first_fail;
      bool m_no_stdout;
};

namespace detail {

template <typename, typename = void>
constexpr bool has_Botan_to_string = false;
template <typename T>
constexpr bool has_Botan_to_string<T, std::void_t<decltype(Botan::to_string(std::declval<T>()))>> = true;

template <typename, typename = void>
constexpr bool has_std_to_string = false;
template <typename T>
constexpr bool has_std_to_string<T, std::void_t<decltype(std::to_string(std::declval<T>()))>> = true;

template <typename, typename = void>
constexpr bool has_ostream_operator = false;
template <typename T>
constexpr bool
   has_ostream_operator<T, std::void_t<decltype(operator<<(std::declval<std::ostringstream&>(), std::declval<T>()))>> =
      true;

template <typename T>
struct is_optional : std::false_type {};

template <typename T>
struct is_optional<std::optional<T>> : std::true_type {};

template <typename T>
constexpr bool is_optional_v = is_optional<T>::value;

}  // namespace detail

/**
 * A code location consisting of the source file path and a line
 */
struct CodeLocation {
      std::string path;
      unsigned int line;
};

/*
* A generic test which returns a set of results when run.
* The tests may not all have the same type (for example test
* "block" returns results for "AES-128" and "AES-256").
*
* For most test cases you want Text_Based_Test derived below
*/
class Test {
   public:
      /*
      * Some number of test results, all associated with who()
      */
      class Result final {
         public:
            explicit Result(std::string who) : m_who(std::move(who)), m_timestamp(std::chrono::system_clock::now()) {}

            /**
             * This 'consolidation constructor' creates a single test result from
             * a vector of downstream test result objects.
             */
            Result(std::string who, const std::vector<Result>& downstream_results);

            size_t tests_passed() const { return m_tests_passed; }

            size_t tests_failed() const { return m_fail_log.size(); }

            size_t tests_run() const { return tests_passed() + tests_failed(); }

            bool any_results() const { return tests_run() > 0; }

            const std::string& who() const { return m_who; }

            const std::vector<std::string>& failures() const { return m_fail_log; }

            const std::vector<std::string>& notes() const { return m_log; }

            std::optional<std::chrono::nanoseconds> elapsed_time() const {
               if(m_ns_taken == 0) {
                  return std::nullopt;
               } else {
                  return std::chrono::nanoseconds(m_ns_taken);
               }
            }

            const std::chrono::system_clock::time_point& timestamp() const { return m_timestamp; }

            std::string result_string() const;

            static Result Failure(const std::string& who, const std::string& what) {
               Result r(who);
               r.test_failure(what);
               return r;
            }

            static Result Note(const std::string& who, const std::string& what) {
               Result r(who);
               r.test_note(what);
               return r;
            }

            static Result OfExpectedFailure(bool expecting_failure, const Test::Result& result) {
               if(!expecting_failure) {
                  return result;
               }

               if(result.tests_failed() == 0) {
                  Result r = result;
                  r.test_failure("Expected this test to fail, but it did not");
                  return r;
               } else {
                  Result r(result.who());
                  r.test_note("Got expected failure");
                  return r;
               }
            }

            void merge(const Result& other, bool ignore_test_name = false);

            void test_note(const std::string& note, const char* extra = nullptr);

            template <typename Alloc>
            void test_note(const std::string& who, const std::vector<uint8_t, Alloc>& vec) {
               const std::string hex = Botan::hex_encode(vec);
               return test_note(who, hex.c_str());
            }

            void note_missing(const std::string& thing);

            bool test_success(const std::string& note = "");

            bool test_failure(const std::string& err);

            bool test_failure(const std::string& what, const std::string& error);

            void test_failure(const std::string& what, const uint8_t buf[], size_t buf_len);

            template <typename Alloc>
            void test_failure(const std::string& what, const std::vector<uint8_t, Alloc>& buf) {
               test_failure(what, buf.data(), buf.size());
            }

            bool confirm(const std::string& what, bool expr, bool expected = true) {
               return test_eq(what, expr, expected);
            }

            /**
             * Require a condition, throw Test_Aborted otherwise
             * Note: works best when combined with CHECK scopes!
             */
            void require(const std::string& what, bool expr, bool expected = true) {
               if(!confirm(what, expr, expected)) {
                  throw Test_Aborted("test aborted, because required condition was not met: " + what);
               }
            }

            template <typename T>
            bool test_is_eq(const T& produced, const T& expected) {
               return test_is_eq("comparison", produced, expected);
            }

            template <typename T>
            bool test_is_eq(const std::string& what, const T& produced, const T& expected) {
               std::ostringstream out;
               out << m_who << " " << what;

               if(produced == expected) {
                  out << " produced expected result";
                  return test_success(out.str());
               } else {
                  out << " produced unexpected result '" << to_string(produced) << "' expected '" << to_string(expected)
                      << "'";
                  return test_failure(out.str());
               }
            }

            template <typename T>
            bool test_not_null(const std::string& what, const T& ptr) {
               if(ptr == nullptr) {
                  return test_failure(what + " was null");
               } else {
                  return test_success(what + " was not null");
               }
            }

            template <typename T>
            bool test_not_nullopt(const std::string& what, std::optional<T> val) {
               if(val == std::nullopt) {
                  return test_failure(what + " was nullopt");
               } else {
                  return test_success(what + " was not nullopt");
               }
            }

            bool test_eq(const std::string& what, const char* produced, const char* expected);

            bool test_is_nonempty(const std::string& what_is_it, const std::string& to_examine);

            bool test_eq(const std::string& what, const std::string& produced, const std::string& expected);

            bool test_eq(const std::string& what, bool produced, bool expected);

            bool test_eq(const std::string& what, size_t produced, size_t expected);
            bool test_eq_sz(const std::string& what, size_t produced, size_t expected);

            bool test_eq(const std::string& what,
                         const Botan::OctetString& produced,
                         const Botan::OctetString& expected);

            template <typename I1, typename I2>
            bool test_int_eq(I1 x, I2 y, const char* what) {
               return test_eq(what, static_cast<size_t>(x), static_cast<size_t>(y));
            }

            template <typename I1, typename I2>
            bool test_int_eq(const std::string& what, I1 x, I2 y) {
               return test_eq(what, static_cast<size_t>(x), static_cast<size_t>(y));
            }

            bool test_lt(const std::string& what, size_t produced, size_t expected);
            bool test_lte(const std::string& what, size_t produced, size_t expected);
            bool test_gt(const std::string& what, size_t produced, size_t expected);
            bool test_gte(const std::string& what, size_t produced, size_t expected);

            template <typename T>
            bool test_rc_ok(const std::string& func, T rc) {
               static_assert(std::is_integral<T>::value, "Integer required.");

               if(rc != 0) {
                  std::ostringstream err;
                  err << m_who;
                  err << " " << func;
                  err << " unexpectedly failed with error code " << rc;
                  return test_failure(err.str());
               }

               return test_success();
            }

            template <typename T>
            bool test_rc_fail(const std::string& func, const std::string& why, T rc) {
               static_assert(std::is_integral<T>::value, "Integer required.");

               if(rc == 0) {
                  std::ostringstream err;
                  err << m_who;
                  err << " call to " << func << " unexpectedly succeeded";
                  err << " expecting failure because " << why;
                  return test_failure(err.str());
               }

               return test_success();
            }

            bool test_rc(const std::string& func, int expected, int rc);

            bool test_rc_init(const std::string& func, int rc);

            bool test_ne(const std::string& what, size_t produced, size_t expected);

            bool test_ne(const std::string& what, const std::string& str1, const std::string& str2);

#if defined(BOTAN_HAS_BIGINT)
            bool test_eq(const std::string& what, const BigInt& produced, const BigInt& expected);
            bool test_ne(const std::string& what, const BigInt& produced, const BigInt& expected);
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
            bool test_eq(const std::string& what, const Botan::EC_Point& a, const Botan::EC_Point& b);
#endif

            bool test_eq(const char* producer,
                         const std::string& what,
                         const uint8_t produced[],
                         size_t produced_len,
                         const uint8_t expected[],
                         size_t expected_len);

            bool test_ne(const std::string& what,
                         const uint8_t produced[],
                         size_t produced_len,
                         const uint8_t expected[],
                         size_t expected_len);

            template <typename Alloc1, typename Alloc2>
            bool test_eq(const std::string& what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected) {
               return test_eq(nullptr, what, produced.data(), produced.size(), expected.data(), expected.size());
            }

            template <typename Alloc1, typename Alloc2>
            bool test_eq(const std::string& producer,
                         const std::string& what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected) {
               return test_eq(
                  producer.c_str(), what, produced.data(), produced.size(), expected.data(), expected.size());
            }

            template <typename Alloc>
            bool test_eq(const std::string& what,
                         const std::vector<uint8_t, Alloc>& produced,
                         const char* expected_hex) {
               const std::vector<uint8_t> expected = Botan::hex_decode(expected_hex);
               return test_eq(nullptr, what, produced.data(), produced.size(), expected.data(), expected.size());
            }

            template <typename Alloc1, typename Alloc2>
            bool test_ne(const std::string& what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected) {
               return test_ne(what, produced.data(), produced.size(), expected.data(), expected.size());
            }

         private:
            class ThrowExpectations {
               public:
                  ThrowExpectations(std::function<void()> fn) :
                        m_fn(std::move(fn)), m_expect_success(false), m_consumed(false) {}

                  ThrowExpectations(const ThrowExpectations&) = delete;
                  ThrowExpectations& operator=(const ThrowExpectations&) = delete;
                  ThrowExpectations(ThrowExpectations&&) = default;
                  ThrowExpectations& operator=(ThrowExpectations&&) = default;

                  ~ThrowExpectations() { BOTAN_ASSERT_NOMSG(m_consumed); }

                  ThrowExpectations& expect_success() {
                     BOTAN_ASSERT_NOMSG(!m_expected_message && !m_expected_exception_type);
                     m_expect_success = true;
                     return *this;
                  }

                  ThrowExpectations& expect_message(const std::string& message) {
                     BOTAN_ASSERT_NOMSG(!m_expect_success);
                     m_expected_message = message;
                     return *this;
                  }

                  template <typename ExT>
                  ThrowExpectations& expect_exception_type() {
                     BOTAN_ASSERT_NOMSG(!m_expect_success);
                     m_expected_exception_type = typeid(ExT);
                     return *this;
                  }

                  bool check(const std::string& test_name, Test::Result& result);

               private:
                  std::function<void()> m_fn;
                  bool m_expect_success;
                  std::optional<std::string> m_expected_message;
                  std::optional<std::type_index> m_expected_exception_type;
                  bool m_consumed;
            };

         public:
            bool test_throws(const std::string& what, const std::function<void()>& fn);

            bool test_throws(const std::string& what, const std::string& expected, const std::function<void()>& fn);

            bool test_no_throw(const std::string& what, const std::function<void()>& fn);

            template <typename ExceptionT>
            bool test_throws(const std::string& what, const std::function<void()>& fn) {
               return ThrowExpectations(fn).expect_exception_type<ExceptionT>().check(what, *this);
            }

            template <typename ExceptionT>
            bool test_throws(const std::string& what, const std::string& expected, const std::function<void()>& fn) {
               return ThrowExpectations(fn).expect_exception_type<ExceptionT>().expect_message(expected).check(what,
                                                                                                               *this);
            }

            void set_ns_consumed(uint64_t ns) { m_ns_taken = ns; }

            void start_timer();
            void end_timer();

            void set_code_location(CodeLocation where) { m_where = std::move(where); }

            const std::optional<CodeLocation>& code_location() const { return m_where; }

         private:
            template <typename T>
            std::string to_string(const T& v) {
               if constexpr(detail::is_optional_v<T>) {
                  return (v.has_value()) ? to_string(v.value()) : std::string("std::nullopt");
               } else if constexpr(detail::has_Botan_to_string<T>) {
                  return Botan::to_string(v);
               } else if constexpr(detail::has_ostream_operator<T>) {
                  std::ostringstream oss;
                  oss << v;
                  return oss.str();
               } else if constexpr(detail::has_std_to_string<T>) {
                  return std::to_string(v);
               } else {
                  return "<?>";
               }
            }

         private:
            std::string m_who;
            std::optional<CodeLocation> m_where;
            std::chrono::system_clock::time_point m_timestamp;
            uint64_t m_started = 0;
            uint64_t m_ns_taken = 0;
            size_t m_tests_passed = 0;
            std::vector<std::string> m_fail_log;
            std::vector<std::string> m_log;
      };

      virtual ~Test() = default;
      virtual std::vector<Test::Result> run() = 0;

      virtual std::vector<std::string> possible_providers(const std::string&);

      void initialize(std::string test_name, CodeLocation location);

      const std::string& test_name() const { return m_test_name; }

      Botan::RandomNumberGenerator& rng() const;

      const std::optional<CodeLocation>& registration_location() const { return m_registration_location; }

      /// @p smoke_test are run first in an unfiltered test run
      static void register_test(const std::string& category,
                                const std::string& name,
                                bool smoke_test,
                                bool needs_serialization,
                                std::function<std::unique_ptr<Test>()> maker_fn);

      static std::set<std::string> registered_tests();
      static std::set<std::string> registered_test_categories();
      static std::vector<std::string> filter_registered_tests(const std::vector<std::string>& requested,
                                                              const std::set<std::string>& to_be_skipped);

      static std::unique_ptr<Test> get_test(const std::string& test_name);
      static bool test_needs_serialization(const std::string& test_name);

      static std::string data_file(const std::string& what);
      static std::string data_file_as_temporary_copy(const std::string& what);

      static std::string format_time(uint64_t nanoseconds);

      static std::string format_time(const std::chrono::nanoseconds nanoseconds) {
         return format_time(nanoseconds.count());
      }

      template <typename Alloc>
      static std::vector<uint8_t, Alloc> mutate_vec(const std::vector<uint8_t, Alloc>& v,
                                                    Botan::RandomNumberGenerator& rng,
                                                    bool maybe_resize = false,
                                                    size_t min_offset = 0) {
         std::vector<uint8_t, Alloc> r = v;

         if(maybe_resize && (r.empty() || rng.next_byte() < 32)) {
            // TODO: occasionally truncate, insert at random index
            const size_t add = 1 + (rng.next_byte() % 16);
            r.resize(r.size() + add);
            rng.randomize(&r[r.size() - add], add);
         }

         if(r.size() > min_offset) {
            const size_t offset = std::max<size_t>(min_offset, rng.next_byte() % r.size());
            const uint8_t perturb = rng.next_nonzero_byte();
            r[offset] ^= perturb;
         }

         return r;
      }

      static void set_test_options(const Test_Options& opts);

      static void set_test_rng_seed(std::span<const uint8_t> seed, size_t epoch = 0);

      static const Test_Options& options() { return m_opts; }

      static bool run_long_tests() { return options().run_long_tests(); }

      static bool run_memory_intensive_tests() { return options().run_memory_intensive_tests(); }

      static const std::string& data_dir() { return options().data_dir(); }

      static const std::string& pkcs11_lib() { return options().pkcs11_lib(); }

      static std::string temp_file_name(const std::string& basename);
      static bool copy_file(const std::string& from, const std::string& to);

      static std::vector<std::string> provider_filter(const std::vector<std::string>& providers);

      static std::string read_data_file(const std::string& path);
      static std::vector<uint8_t> read_binary_data_file(const std::string& path);

      static std::unique_ptr<Botan::RandomNumberGenerator> new_rng(std::string_view test_name);
      static std::shared_ptr<Botan::RandomNumberGenerator> new_shared_rng(std::string_view test_name);

      static std::string random_password(Botan::RandomNumberGenerator& rng);
      static uint64_t timestamp();  // nanoseconds arbitrary epoch

      static std::vector<Test::Result> flatten_result_lists(std::vector<std::vector<Test::Result>> result_lists);

   private:
      static Test_Options m_opts;
      static std::string m_test_rng_seed;

      /// The string ID that was used to register this test
      std::string m_test_name;
      /// The source file location where the test was registered
      std::optional<CodeLocation> m_registration_location;
      /// The test-specific RNG state
      mutable std::unique_ptr<Botan::RandomNumberGenerator> m_test_rng;
};

/*
* Register the test with the runner
*/
template <typename Test_Class>
class TestClassRegistration {
   public:
      TestClassRegistration(const std::string& category,
                            const std::string& name,
                            bool smoke_test,
                            bool needs_serialization,
                            CodeLocation registration_location) {
         Test::register_test(category, name, smoke_test, needs_serialization, [=] {
            auto test = std::make_unique<Test_Class>();
            test->initialize(name, registration_location);
            return test;
         });
      }
};

#define BOTAN_REGISTER_TEST(category, name, Test_Class) \
   const TestClassRegistration<Test_Class> reg_##Test_Class##_tests(category, name, false, false, {__FILE__, __LINE__})
#define BOTAN_REGISTER_SERIALIZED_TEST(category, name, Test_Class) \
   const TestClassRegistration<Test_Class> reg_##Test_Class##_tests(category, name, false, true, {__FILE__, __LINE__})
#define BOTAN_REGISTER_SMOKE_TEST(category, name, Test_Class) \
   const TestClassRegistration<Test_Class> reg_##Test_Class##_tests(category, name, true, false, {__FILE__, __LINE__})
#define BOTAN_REGISTER_SERIALIZED_SMOKE_TEST(category, name, Test_Class) \
   const TestClassRegistration<Test_Class> reg_##Test_Class##_tests(category, name, true, true, {__FILE__, __LINE__})

typedef Test::Result (*test_fn)();
typedef std::vector<Test::Result> (*test_fn_vec)();

class FnTest : public Test {
   private:
      using TestFnVariant = std::variant<test_fn, test_fn_vec>;

      template <typename TestFn>
      std::vector<TestFnVariant> make_variant_vector(TestFn fn) {
         using T = std::decay_t<decltype(fn)>;
         static_assert(std::is_same_v<T, test_fn> || std::is_same_v<T, test_fn_vec>,
                       "functions passed to BOTAN_REGISTER_TEST_FN must either return a "
                       "single Test::Result or a std::vector of Test::Result");
         return {fn};
      }

      template <typename TestFn, typename... TestFns>
      std::vector<TestFnVariant> make_variant_vector(const TestFn& fn, const TestFns&... fns) {
         auto functions = make_variant_vector(fns...);
         functions.emplace_back(fn);
         return functions;
      }

   public:
      template <typename... TestFns>
      FnTest(TestFns... fns) : m_fns(make_variant_vector(fns...)) {}

      std::vector<Test::Result> run() override {
         std::vector<Test::Result> result;

         for(auto fn_variant = m_fns.crbegin(); fn_variant != m_fns.crend(); ++fn_variant) {
            std::visit(
               [&](auto&& fn) {
                  using T = std::decay_t<decltype(fn)>;
                  if constexpr(std::is_same_v<T, test_fn>) {
                     result.emplace_back(fn());
                  } else {
                     const auto results = fn();
                     result.insert(result.end(), results.begin(), results.end());
                  }
               },
               *fn_variant);
         }

         return result;
      }

   private:
      std::vector<TestFnVariant> m_fns;
};

class TestFnRegistration {
   public:
      template <typename... TestFns>
      TestFnRegistration(const std::string& category,
                         const std::string& name,
                         bool smoke_test,
                         bool needs_serialization,
                         CodeLocation registration_location,
                         TestFns... fn) {
         Test::register_test(category, name, smoke_test, needs_serialization, [=] {
            auto test = std::make_unique<FnTest>(fn...);
            test->initialize(name, registration_location);
            return test;
         });
      }
};

#define BOTAN_REGISTER_TEST_FN(category, name, ...) \
   static const TestFnRegistration reg_##fn_name(category, name, false, false, {__FILE__, __LINE__}, __VA_ARGS__)
#define BOTAN_REGISTER_SMOKE_TEST_FN(category, name, ...) \
   static const TestFnRegistration reg_##fn_name(category, name, true, false, {__FILE__, __LINE__}, __VA_ARGS__)
#define BOTAN_REGISTER_SERIALIZED_TEST_FN(category, name, ...) \
   static const TestFnRegistration reg_##fn_name(category, name, false, true {__FILE__, __LINE__}, __VA_ARGS__)
#define BOTAN_REGISTER_SERIALIZED_SMOKE_TEST_FN(category, name, ...) \
   static const TestFnRegistration reg_##fn_name(category, name, true, true {__FILE__, __LINE__}, __VA_ARGS__)

class VarMap {
   public:
      void clear() { m_vars.clear(); }

      void add(const std::string& key, const std::string& value) { m_vars[key] = value; }

      bool has_key(const std::string& key) const { return m_vars.count(key) == 1; }

      bool get_req_bool(const std::string& key) const;

      std::vector<uint8_t> get_req_bin(const std::string& key) const;
      std::vector<uint8_t> get_opt_bin(const std::string& key) const;

      std::vector<std::vector<uint8_t>> get_req_bin_list(const std::string& key) const;

#if defined(BOTAN_HAS_BIGINT)
      Botan::BigInt get_req_bn(const std::string& key) const;
      Botan::BigInt get_opt_bn(const std::string& key, const Botan::BigInt& def_value) const;
#endif

      std::string get_req_str(const std::string& key) const;
      std::string get_opt_str(const std::string& key, const std::string& def_value) const;

      size_t get_req_sz(const std::string& key) const;

      uint8_t get_req_u8(const std::string& key) const;
      uint32_t get_req_u32(const std::string& key) const;
      uint64_t get_req_u64(const std::string& key) const;

      size_t get_opt_sz(const std::string& key, size_t def_value) const;

      uint64_t get_opt_u64(const std::string& key, uint64_t def_value) const;

   private:
      std::unordered_map<std::string, std::string> m_vars;
};

/*
* A test based on reading an input file which contains key/value pairs
* Special note: the last value in required_key (there must be at least
* one), is the output key. This triggers the callback.
*
* Calls run_one_test with the variables set. If an ini-style [header]
* is used in the file, then header will be set to that value. This allows
* splitting up tests between [valid] and [invalid] tests, or different
* related algorithms tested in the same file. Use the get_XXX functions
* on VarMap to retrieve formatted values.
*
* If most of your tests are text-based but you find yourself with a few
* odds-and-ends tests that you want to do, override run_final_tests which
* can test whatever it likes and returns a vector of Results.
*/
class Text_Based_Test : public Test {
   public:
      Text_Based_Test(const std::string& input_file,
                      const std::string& required_keys,
                      const std::string& optional_keys = "");

      virtual bool clear_between_callbacks() const { return true; }

      std::vector<Test::Result> run() override;

   protected:
      std::string get_next_line();

      virtual Test::Result run_one_test(const std::string& header, const VarMap& vars) = 0;
      // Called before run_one_test
      virtual bool skip_this_test(const std::string& header, const VarMap& vars);

      virtual std::vector<Test::Result> run_final_tests() { return std::vector<Test::Result>(); }

   private:
      std::string m_data_src;
      std::set<std::string> m_required_keys;
      std::set<std::string> m_optional_keys;
      std::string m_output_key;

      bool m_first = true;
      std::unique_ptr<std::istream> m_cur;
      std::string m_cur_src_name;
      std::deque<std::string> m_srcs;
      std::vector<uint64_t> m_cpu_flags;
};

/**
 * This is a convenience wrapper to write small self-contained and in particular
 * exception-safe unit tests. If some (unexpected) exception is thrown in one of
 * the CHECK-scopes, it will fail the particular test gracefully with a human-
 * understandable failure output.
 *
 * Example Usage:
 *
 * ```
 * std::vector<Test::Result> test_something()
 *    {
 *    return
 *       {
 *       CHECK("some unit test name", [](Test::Result& r)
 *          {
 *          r.confirm("some observation", 1+1 == 2);
 *          }),
 *       CHECK("some other unit test name", [](Test::Result& r)
 *          {
 *          // ...
 *          })
 *       };
 *    }
 *
 * BOTAN_REGISTER_TEST_FN("some_category", "some_test_name", test_something);
 * ```
 */
template <typename FunT>
Test::Result CHECK(const char* name, FunT check_fun) {
   Botan_Tests::Test::Result r(name);

   try {
      check_fun(r);
   } catch(const Botan_Tests::Test_Aborted&) {
      // pass, failure was already noted in the responsible `require`
   } catch(const std::exception& ex) {
      r.test_failure("failed unexpectedly", ex.what());
   } catch(...) {
      r.test_failure("failed with unknown exception");
   }

   return r;
}

}  // namespace Botan_Tests

#endif

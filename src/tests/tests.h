/*
* (C) 2014,2015 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_H_
#define BOTAN_TESTS_H_

/*
Warning: be very careful about adding any new includes here

Each include is parsed for every test file which can get quite expensive
*/

#include <botan/types.h>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

#if defined(BOTAN_HAS_BIGINT)
class BigInt;
#endif

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
class EC_Point;
#endif

}  // namespace Botan

namespace Botan_Tests {

#if defined(BOTAN_HAS_BIGINT)
using Botan::BigInt;
#endif

class Test_Error : public std::runtime_error {
   public:
      explicit Test_Error(std::string_view what);
};

class Test_Aborted final : public Test_Error {
   public:
      explicit Test_Aborted(std::string_view what) : Test_Error(what) {}
};

class Test_Options {
   public:
      Test_Options() = default;

      Test_Options(const std::vector<std::string>& requested_tests,
                   const std::vector<std::string>& skip_tests,
                   const std::string& data_dir,
                   const std::string& pkcs11_lib,
                   const std::string& provider,
                   const std::string& tpm2_tcti_name,
                   const std::string& tpm2_tcti_conf,
                   size_t tpm2_persistent_rsa_handle,
                   size_t tpm2_persistent_ecc_handle,
                   const std::string& tpm2_persistent_auth_value,
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
            m_skip_tests(skip_tests),
            m_data_dir(data_dir),
            m_pkcs11_lib(pkcs11_lib),
            m_provider(provider),
            m_tpm2_tcti_name(tpm2_tcti_name),
            m_tpm2_tcti_conf(tpm2_tcti_conf),
            m_tpm2_persistent_rsa_handle(tpm2_persistent_rsa_handle),
            m_tpm2_persistent_ecc_handle(tpm2_persistent_ecc_handle),
            m_tpm2_persistent_auth_value(tpm2_persistent_auth_value),
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

      const std::vector<std::string>& skip_tests() const { return m_skip_tests; }

      const std::string& data_dir() const { return m_data_dir; }

      const std::string& pkcs11_lib() const { return m_pkcs11_lib; }

      const std::string& provider() const { return m_provider; }

      const std::optional<std::string>& tpm2_tcti_name() const { return m_tpm2_tcti_name; }

      const std::optional<std::string>& tpm2_tcti_conf() const { return m_tpm2_tcti_conf; }

      uint32_t tpm2_persistent_rsa_handle() const { return static_cast<uint32_t>(m_tpm2_persistent_rsa_handle); }

      uint32_t tpm2_persistent_ecc_handle() const { return static_cast<uint32_t>(m_tpm2_persistent_ecc_handle); }

      const std::string& tpm2_persistent_auth_value() const { return m_tpm2_persistent_auth_value; }

      const std::string& drbg_seed() const { return m_drbg_seed; }

      const std::string& xml_results_dir() const { return m_xml_results_dir; }

      const std::vector<std::string>& report_properties() const { return m_report_properties; }

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
      std::vector<std::string> m_skip_tests;
      std::string m_data_dir;
      std::string m_pkcs11_lib;
      std::string m_provider;
      std::optional<std::string> m_tpm2_tcti_name;
      std::optional<std::string> m_tpm2_tcti_conf;
      size_t m_tpm2_persistent_rsa_handle = 0;
      size_t m_tpm2_persistent_ecc_handle = 0;
      std::string m_tpm2_persistent_auth_value;
      std::string m_drbg_seed;
      std::string m_xml_results_dir;
      std::vector<std::string> m_report_properties;
      size_t m_test_runs = 0;
      size_t m_test_threads = 0;
      bool m_verbose = false;
      bool m_log_success = false;
      bool m_run_online_tests = false;
      bool m_run_long_tests = false;
      bool m_run_memory_intensive_tests = false;
      bool m_abort_on_first_fail = false;
      bool m_no_stdout = false;
};

namespace detail {

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
      const char* path;
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
            explicit Result(std::string_view who);

            /**
             * This 'consolidation constructor' creates a single test result from
             * a vector of downstream test result objects.
             */
            Result(std::string_view who, const std::vector<Result>& downstream_results);

            size_t tests_passed() const { return m_tests_passed; }

            size_t tests_failed() const { return m_fail_log.size(); }

            size_t tests_run() const { return tests_passed() + tests_failed(); }

            bool any_results() const { return tests_run() > 0; }

            const std::string& who() const { return m_who; }

            const std::vector<std::string>& failures() const { return m_fail_log; }

            const std::vector<std::string>& notes() const { return m_log; }

            std::optional<uint64_t> elapsed_time() const {
               if(m_ns_taken == 0) {
                  return std::nullopt;
               } else {
                  return m_ns_taken;
               }
            }

            // Nanoseconds since epoch
            uint64_t timestamp() const { return m_timestamp; }

            std::string result_string() const;

            static Result Failure(std::string_view who, std::string_view what) {
               Result r(who);
               r.test_failure(what);
               return r;
            }

            static Result Note(std::string_view who, std::string_view what) {
               Result r(who);
               r.test_note(what);
               return r;
            }

            void merge(const Result& other, bool ignore_test_name = false);

            void test_note(std::string_view note, const char* extra = nullptr);

            void test_note(std::string_view note, std::span<const uint8_t> context);

            void note_missing(std::string_view whatever);

            bool test_success(std::string_view note = "");

            bool test_failure(std::string_view err);

            bool test_failure(std::string_view what, std::string_view error);

            void test_failure(std::string_view what, const uint8_t buf[], size_t buf_len);

            void test_failure(std::string_view what, std::span<const uint8_t> context);

            /**
             * Require a condition, throw Test_Aborted otherwise
             * Note: works best when combined with CHECK scopes!
             */
            void require(std::string_view what, bool expr, bool expected = true);

            template <typename T>
            bool test_is_eq(const T& produced, const T& expected) {
               return test_is_eq("comparison", produced, expected);
            }

            template <typename T>
            bool test_is_eq(std::string_view what, const T& produced, const T& expected) {
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
            bool test_not_null(std::string_view what, const T& ptr) {
               if(ptr == nullptr) {
                  return test_failure(what, "was null");
               } else {
                  return test_success("not null");
               }
            }

            bool test_eq(std::string_view what, const char* produced, const char* expected);

            bool test_is_nonempty(std::string_view what_is_it, std::string_view to_examine);

            bool test_eq(std::string_view what, std::string_view produced, std::string_view expected);

            /* Test predicates on bool */
            bool test_bool_eq(std::string_view what, bool produced, bool expected);

            bool test_is_false(std::string_view what, bool produced);

            bool test_is_true(std::string_view what, bool produced);

            /* Test predicates on size_t */
            bool test_sz_eq(std::string_view what, size_t produced, size_t expected);
            bool test_sz_ne(std::string_view what, size_t produced, size_t expected);
            bool test_sz_lt(std::string_view what, size_t produced, size_t expected);
            bool test_sz_lte(std::string_view what, size_t produced, size_t expected);
            bool test_sz_gt(std::string_view what, size_t produced, size_t expected);
            bool test_sz_gte(std::string_view what, size_t produced, size_t expected);

            /* Type-hinted unsigned integer equality predicates */
            bool test_u8_eq(uint8_t produced, uint8_t expected);
            bool test_u8_eq(std::string_view what, uint8_t produced, uint8_t expected);

            bool test_u16_eq(uint16_t produced, uint16_t expected);
            bool test_u16_eq(std::string_view what, uint16_t produced, uint16_t expected);

            bool test_u32_eq(uint32_t produced, uint32_t expected);
            bool test_u32_eq(std::string_view what, uint32_t produced, uint32_t expected);

            bool test_u64_eq(uint64_t produced, uint64_t expected);
            bool test_u64_eq(std::string_view what, uint64_t produced, uint64_t expected);

            /* Test predicates on integer return codes */
            bool test_rc_ok(std::string_view func, int rc);
            bool test_rc_fail(std::string_view func, std::string_view why, int rc);
            bool test_rc(std::string_view func, int expected, int rc);
            bool test_rc_init(std::string_view func, int rc);

            bool test_ne(std::string_view what, std::string_view str1, std::string_view str2);

            /* Test predicates on optional values */

            template <typename T>
            bool test_opt_not_null(std::string_view what, const std::optional<T>& val) {
               if(val == std::nullopt) {
                  return test_failure(what, "was nullopt");
               } else {
                  return test_success("not nullopt");
               }
            }

            bool test_opt_u8_eq(std::string_view what, std::optional<uint8_t> a, std::optional<uint8_t> b);

#if defined(BOTAN_HAS_BIGINT)
            bool test_eq(std::string_view what, const BigInt& produced, const BigInt& expected);
            bool test_ne(std::string_view what, const BigInt& produced, const BigInt& expected);
#endif

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
            bool test_eq(std::string_view what, const Botan::EC_Point& a, const Botan::EC_Point& b);
#endif

            bool test_eq(const char* producer,
                         std::string_view what,
                         const uint8_t produced[],
                         size_t produced_size,
                         const uint8_t expected[],
                         size_t expected_size);

            bool test_ne(std::string_view what,
                         const uint8_t produced[],
                         size_t produced_len,
                         const uint8_t expected[],
                         size_t expected_len);

            bool test_eq(std::string_view what, std::span<const uint8_t> produced, std::span<const uint8_t> expected) {
               return test_eq(nullptr, what, produced.data(), produced.size(), expected.data(), expected.size());
            }

            bool test_eq(std::string_view producer,
                         std::string_view what,
                         std::span<const uint8_t> produced,
                         std::span<const uint8_t> expected) {
               return test_eq(std::string(producer).c_str(),
                              what,
                              produced.data(),
                              produced.size(),
                              expected.data(),
                              expected.size());
            }

            bool test_eq(std::string_view what, std::span<const uint8_t> produced, const char* expected_hex);

            template <std::size_t N>
            bool test_eq(std::string_view what,
                         const std::array<uint8_t, N>& produced,
                         const std::array<uint8_t, N>& expected) {
               return test_eq(nullptr, what, produced.data(), produced.size(), expected.data(), expected.size());
            }

            bool test_ne(std::string_view what, std::span<const uint8_t> produced, std::span<const uint8_t> expected) {
               return test_ne(what, produced.data(), produced.size(), expected.data(), expected.size());
            }

         private:
            class ThrowExpectations {
               public:
                  explicit ThrowExpectations(std::function<void()> fn) : m_fn(std::move(fn)) {}

                  ThrowExpectations(const ThrowExpectations&) = delete;
                  ThrowExpectations& operator=(const ThrowExpectations&) = delete;
                  ThrowExpectations(ThrowExpectations&&) = default;
                  ThrowExpectations& operator=(ThrowExpectations&&) = default;

                  ~ThrowExpectations();

                  ThrowExpectations& expect_success();

                  ThrowExpectations& expect_message(std::string_view message);

                  template <typename ExT>
                  ThrowExpectations& expect_exception_type() {
                     assert_that_success_is_not_expected();

                     m_expected_exception_check_fn = [](const std::exception_ptr& e) {
                        try {
                           if(e) {
                              std::rethrow_exception(e);
                           }
                        } catch(const ExT&) {
                           return true;
                        } catch(...) {
                           return false;
                        }
                        return false;
                     };
                     return *this;
                  }

                  bool check(std::string_view test_name, Test::Result& result);

               private:
                  void assert_that_success_is_not_expected() const;

                  std::function<void()> m_fn;
                  std::optional<std::string> m_expected_message;
                  std::function<bool(std::exception_ptr)> m_expected_exception_check_fn;
                  bool m_expect_success = false;
                  bool m_consumed = false;
            };

         public:
            bool test_throws(std::string_view what, std::function<void()> fn);

            bool test_throws(std::string_view what, std::string_view expected, std::function<void()> fn);

            bool test_no_throw(std::string_view what, std::function<void()> fn);

            template <typename ExceptionT>
            bool test_throws(std::string_view what, std::function<void()> fn) {
               return ThrowExpectations(std::move(fn)).expect_exception_type<ExceptionT>().check(what, *this);
            }

            template <typename ExceptionT>
            bool test_throws(std::string_view what, std::string_view expected, std::function<void()> fn) {
               // clang-format off
               return ThrowExpectations(std::move(fn)).expect_exception_type<ExceptionT>().expect_message(expected).check(what, *this);
               // clang-format on
            }

            void set_ns_consumed(uint64_t ns) { m_ns_taken = ns; }

            void start_timer();
            void end_timer();

            void set_code_location(CodeLocation where) { m_where = where; }

            const std::optional<CodeLocation>& code_location() const { return m_where; }

         private:
            template <typename T>
            std::string to_string(const T& v) {
               if constexpr(detail::is_optional_v<T>) {
                  return (v.has_value()) ? to_string(v.value()) : std::string("std::nullopt");
               } else if constexpr(detail::has_ostream_operator<T>) {
                  std::ostringstream oss;
                  oss << v;
                  return oss.str();
               } else if constexpr(detail::has_std_to_string<T>) {
                  //static_assert(false, "no std::to_string for you");
                  return std::to_string(v);
               } else {
                  //static_assert(false, "unknown type");
                  return "<?>";
               }
            }

         private:
            std::string m_who;
            std::optional<CodeLocation> m_where;
            uint64_t m_timestamp;
            uint64_t m_started = 0;
            uint64_t m_ns_taken = 0;
            size_t m_tests_passed = 0;
            std::vector<std::string> m_fail_log;
            std::vector<std::string> m_log;
      };

      virtual ~Test();

      Test();
      Test(const Test& other) = delete;
      Test(Test&& other) = default;
      Test& operator=(const Test& other) = delete;
      Test& operator=(Test&& other) = delete;

      virtual std::vector<Test::Result> run() = 0;

      virtual std::vector<std::string> possible_providers(const std::string& alg);

      void initialize(std::string test_name, CodeLocation location);

      const std::string& test_name() const { return m_test_name; }

      Botan::RandomNumberGenerator& rng() const;

      /**
       * Use this if a test needs some supported EC group but it is not relevant
       * which one exactly. This tries to find a commonly used group that is
       * both supported in this build and as small as possible (for test speed).
       *
       * If @p preferred_groups is non-empty, a group from that list is chosen
       *
       * @returns the name of a supported EC group, or std::nullopt if no
       *          supported EC group could be found for this build
       */
      static std::optional<std::string> supported_ec_group_name(std::vector<std::string> preferred_groups = {});

      const std::optional<CodeLocation>& registration_location() const { return m_registration_location; }

      /// @p smoke_test are run first in an unfiltered test run
      static void register_test(const std::string& category,
                                const std::string& name,
                                bool smoke_test,
                                bool needs_serialization,
                                std::function<std::unique_ptr<Test>()> maker_fn);

      static std::vector<std::string> registered_tests();
      static std::vector<std::string> registered_test_categories();

      static std::vector<std::string> filter_registered_tests(const std::vector<std::string>& requested,
                                                              const std::vector<std::string>& to_be_skipped);

      static std::unique_ptr<Test> get_test(const std::string& test_name);
      static bool test_needs_serialization(const std::string& test_name);

      static std::string data_dir(const std::string& subdir);
      static std::vector<std::string> files_in_data_dir(const std::string& subdir);
      static std::string data_file(const std::string& file);
      static std::string data_file_as_temporary_copy(const std::string& what);

      static std::string format_time(uint64_t nanoseconds);

      static std::vector<uint8_t> mutate_vec(const std::vector<uint8_t>& v,
                                             Botan::RandomNumberGenerator& rng,
                                             bool maybe_resize = false,
                                             size_t min_offset = 0);

      static void set_test_options(const Test_Options& opts);

      static void set_test_rng_seed(std::span<const uint8_t> seed, size_t epoch = 0);

      static const Test_Options& options() { return m_opts; }

      static bool run_long_tests() { return options().run_long_tests(); }

      static bool run_memory_intensive_tests() { return options().run_memory_intensive_tests(); }

      static const std::string& pkcs11_lib() { return options().pkcs11_lib(); }

      static std::string temp_file_name(const std::string& basename);
      static bool copy_file(const std::string& from, const std::string& to);

      static std::vector<std::string> provider_filter(const std::vector<std::string>& providers);

      static std::string read_data_file(const std::string& path);
      static std::vector<uint8_t> read_binary_data_file(const std::string& path);

      static std::unique_ptr<Botan::RandomNumberGenerator> new_rng(std::string_view test_name);
      static std::shared_ptr<Botan::RandomNumberGenerator> new_shared_rng(std::string_view test_name);

      static std::string random_password(Botan::RandomNumberGenerator& rng);
      static size_t random_index(Botan::RandomNumberGenerator& rng, size_t max);
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
                            const CodeLocation& registration_location) {
         Test::register_test(category, name, smoke_test, needs_serialization, [=] {
            auto test = std::make_unique<Test_Class>();
            test->initialize(name, registration_location);
            return test;
         });
      }
};

// NOLINTBEGIN(*-macro-usage)

#define BOTAN_REGISTER_TEST(category, name, Test_Class) \
   /* NOLINTNEXTLINE(cert-err58-cpp) */                 \
   const TestClassRegistration<Test_Class> reg_##Test_Class##_tests(category, name, false, false, {__FILE__, __LINE__})
#define BOTAN_REGISTER_SERIALIZED_TEST(category, name, Test_Class) \
   /* NOLINTNEXTLINE(cert-err58-cpp) */                            \
   const TestClassRegistration<Test_Class> reg_##Test_Class##_tests(category, name, false, true, {__FILE__, __LINE__})
#define BOTAN_REGISTER_SMOKE_TEST(category, name, Test_Class) \
   /* NOLINTNEXTLINE(cert-err58-cpp) */                       \
   const TestClassRegistration<Test_Class> reg_##Test_Class##_tests(category, name, true, false, {__FILE__, __LINE__})
#define BOTAN_REGISTER_SERIALIZED_SMOKE_TEST(category, name, Test_Class) \
   /* NOLINTNEXTLINE(cert-err58-cpp) */                                  \
   const TestClassRegistration<Test_Class> reg_##Test_Class##_tests(category, name, true, true, {__FILE__, __LINE__})

// NOLINTEND(*-macro-usage)

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
      explicit FnTest(TestFns... fns) : m_fns(make_variant_vector(fns...)) {}

      std::vector<Test::Result> run() override {
         std::vector<Test::Result> result;

         // TODO(Botan4) use std::ranges::reverse_view here once available (need newer Clang)
         // NOLINTNEXTLINE(modernize-loop-convert)
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
                         const CodeLocation& registration_location,
                         TestFns... fn) {
         Test::register_test(category, name, smoke_test, needs_serialization, [=] {
            auto test = std::make_unique<FnTest>(fn...);
            test->initialize(name, registration_location);
            return test;
         });
      }
};

// NOLINTBEGIN(*-macro-usage)

#define BOTAN_REGISTER_TEST_FN_IMPL(category, name, smoke_test, needs_serialization, fn0, ...) \
   /* NOLINTNEXTLINE(cert-err58-cpp) */                                                        \
   static const TestFnRegistration register_##fn0(                                             \
      category, name, smoke_test, needs_serialization, {__FILE__, __LINE__}, fn0 __VA_OPT__(, ) __VA_ARGS__)

#define BOTAN_REGISTER_TEST_FN(category, name, ...) \
   BOTAN_REGISTER_TEST_FN_IMPL(category, name, false, false, __VA_ARGS__)
#define BOTAN_REGISTER_SMOKE_TEST_FN(category, name, ...) \
   BOTAN_REGISTER_TEST_FN_IMPL(category, name, true, false, __VA_ARGS__)
#define BOTAN_REGISTER_SERIALIZED_TEST_FN(category, name, ...) \
   BOTAN_REGISTER_TEST_FN_IMPL(category, name, false, true, __VA_ARGS__)
#define BOTAN_REGISTER_SERIALIZED_SMOKE_TEST_FN(category, name, ...) \
   BOTAN_REGISTER_TEST_FN_IMPL(category, name, true, true, __VA_ARGS__)

// NOLINTEND(*-macro-usage)

class VarMap {
   public:
      bool has_key(const std::string& key) const;

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

      void clear();

      void add(const std::string& key, const std::string& value);

   private:
      std::optional<std::string> get_var(const std::string& key) const;

      std::vector<std::pair<std::string, std::string>> m_vars;
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
      Text_Based_Test(const std::string& data_src,
                      const std::string& required_keys_str,
                      const std::string& optional_keys_str = "");

      Text_Based_Test(const Text_Based_Test& other) = delete;
      Text_Based_Test(Text_Based_Test&& other) = default;
      Text_Based_Test& operator=(const Text_Based_Test& other) = delete;
      Text_Based_Test& operator=(Text_Based_Test&& other) = delete;

      ~Text_Based_Test() override;

      virtual bool clear_between_callbacks() const { return true; }

      std::vector<Test::Result> run() override;

   private:
      virtual Test::Result run_one_test(const std::string& header, const VarMap& vars) = 0;
      // Called before run_one_test
      virtual bool skip_this_test(const std::string& header, const VarMap& vars);

      virtual std::vector<Test::Result> run_final_tests() { return std::vector<Test::Result>(); }

   private:
      class Text_Based_Test_Data;
      std::unique_ptr<Text_Based_Test_Data> m_data;
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
 *          r.test_is_true("some observation", 1+1 == 2);
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

/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/hex.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <botan/internal/stl_util.h>
#include <fstream>
#include <iomanip>
#include <sstream>

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
#endif

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
   #include <botan/ec_point.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <stdlib.h>
   #include <unistd.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
   #include <version>
   #if defined(__cpp_lib_filesystem)
      #include <filesystem>
   #endif
#endif

namespace Botan_Tests {

void Test::Result::merge(const Result& other, bool ignore_test_name) {
   if(who() != other.who()) {
      if(!ignore_test_name) {
         throw Test_Error("Merging tests from different sources");
      }

      // When deliberately merging results with different names, the code location is
      // likely inconsistent and must be discarded.
      m_where.reset();
   } else {
      m_where = other.m_where;
   }

   m_timestamp = std::min(m_timestamp, other.m_timestamp);
   m_ns_taken += other.m_ns_taken;
   m_tests_passed += other.m_tests_passed;
   m_fail_log.insert(m_fail_log.end(), other.m_fail_log.begin(), other.m_fail_log.end());
   m_log.insert(m_log.end(), other.m_log.begin(), other.m_log.end());
}

void Test::Result::start_timer() {
   if(m_started == 0) {
      m_started = Test::timestamp();
   }
}

void Test::Result::end_timer() {
   if(m_started > 0) {
      m_ns_taken += Test::timestamp() - m_started;
      m_started = 0;
   }
}

void Test::Result::test_note(const std::string& note, const char* extra) {
   if(!note.empty()) {
      std::ostringstream out;
      out << who() << " " << note;
      if(extra) {
         out << ": " << extra;
      }
      m_log.push_back(out.str());
   }
}

void Test::Result::note_missing(const std::string& whatever) {
   static std::set<std::string> s_already_seen;

   if(!s_already_seen.contains(whatever)) {
      test_note("Skipping tests due to missing " + whatever);
      s_already_seen.insert(whatever);
   }
}

bool Test::Result::ThrowExpectations::check(const std::string& test_name, Test::Result& result) {
   m_consumed = true;

   try {
      m_fn();
      if(!m_expect_success) {
         return result.test_failure(test_name + " failed to throw expected exception");
      }
   } catch(const std::exception& ex) {
      if(m_expect_success) {
         return result.test_failure(test_name + " threw unexpected exception: " + ex.what());
      }
      if(m_expected_exception_type.has_value() && m_expected_exception_type.value() != typeid(ex)) {
         return result.test_failure(test_name + " threw unexpected exception: " + ex.what());
      }
      if(m_expected_message.has_value() && m_expected_message.value() != ex.what()) {
         return result.test_failure(test_name + " threw exception with unexpected message (expected: '" +
                                    m_expected_message.value() + "', got: '" + ex.what() + "')");
      }
   } catch(...) {
      if(m_expect_success || m_expected_exception_type.has_value() || m_expected_message.has_value()) {
         return result.test_failure(test_name + " threw unexpected unknown exception");
      }
   }

   return result.test_success(test_name + " behaved as expected");
}

bool Test::Result::test_throws(const std::string& what, const std::function<void()>& fn) {
   return ThrowExpectations(fn).check(what, *this);
}

bool Test::Result::test_throws(const std::string& what, const std::string& expected, const std::function<void()>& fn) {
   return ThrowExpectations(fn).expect_message(expected).check(what, *this);
}

bool Test::Result::test_no_throw(const std::string& what, const std::function<void()>& fn) {
   return ThrowExpectations(fn).expect_success().check(what, *this);
}

bool Test::Result::test_success(const std::string& note) {
   if(Test::options().log_success()) {
      test_note(note);
   }
   ++m_tests_passed;
   return true;
}

bool Test::Result::test_failure(const std::string& what, const std::string& error) {
   return test_failure(who() + " " + what + " with error " + error);
}

void Test::Result::test_failure(const std::string& what, const uint8_t buf[], size_t buf_len) {
   test_failure(who() + ": " + what + " buf len " + std::to_string(buf_len) + " value " +
                Botan::hex_encode(buf, buf_len));
}

bool Test::Result::test_failure(const std::string& err) {
   m_fail_log.push_back(err);

   if(Test::options().abort_on_first_fail() && m_who != "Failing Test") {
      std::abort();
   }
   return false;
}

namespace {

bool same_contents(const uint8_t x[], const uint8_t y[], size_t len) {
   return (len == 0) ? true : std::memcmp(x, y, len) == 0;
}

}  // namespace

bool Test::Result::test_ne(const std::string& what,
                           const uint8_t produced[],
                           size_t produced_len,
                           const uint8_t expected[],
                           size_t expected_len) {
   if(produced_len == expected_len && same_contents(produced, expected, expected_len)) {
      return test_failure(who() + ": " + what + " produced matching");
   }
   return test_success();
}

bool Test::Result::test_eq(const char* producer,
                           const std::string& what,
                           const uint8_t produced[],
                           size_t produced_size,
                           const uint8_t expected[],
                           size_t expected_size) {
   if(produced_size == expected_size && same_contents(produced, expected, expected_size)) {
      return test_success();
   }

   std::ostringstream err;

   err << who();

   if(producer) {
      err << " producer '" << producer << "'";
   }

   err << " unexpected result for " << what;

   if(produced_size != expected_size) {
      err << " produced " << produced_size << " bytes expected " << expected_size;
   }

   std::vector<uint8_t> xor_diff(std::min(produced_size, expected_size));
   size_t bytes_different = 0;

   for(size_t i = 0; i != xor_diff.size(); ++i) {
      xor_diff[i] = produced[i] ^ expected[i];
      bytes_different += (xor_diff[i] > 0);
   }

   err << "\nProduced: " << Botan::hex_encode(produced, produced_size)
       << "\nExpected: " << Botan::hex_encode(expected, expected_size);

   if(bytes_different > 0) {
      err << "\nXOR Diff: " << Botan::hex_encode(xor_diff);
   }

   return test_failure(err.str());
}

bool Test::Result::test_is_nonempty(const std::string& what_is_it, const std::string& to_examine) {
   if(to_examine.empty()) {
      return test_failure(what_is_it + " was empty");
   }
   return test_success();
}

bool Test::Result::test_eq(const std::string& what, const std::string& produced, const std::string& expected) {
   return test_is_eq(what, produced, expected);
}

bool Test::Result::test_eq(const std::string& what, const char* produced, const char* expected) {
   return test_is_eq(what, std::string(produced), std::string(expected));
}

bool Test::Result::test_eq(const std::string& what, size_t produced, size_t expected) {
   return test_is_eq(what, produced, expected);
}

bool Test::Result::test_eq_sz(const std::string& what, size_t produced, size_t expected) {
   return test_is_eq(what, produced, expected);
}

bool Test::Result::test_eq(const std::string& what,
                           const Botan::OctetString& produced,
                           const Botan::OctetString& expected) {
   std::ostringstream out;
   out << m_who << " " << what;

   if(produced == expected) {
      out << " produced expected result " << produced.to_string();
      return test_success(out.str());
   } else {
      out << " produced unexpected result '" << produced.to_string() << "' expected '" << expected.to_string() << "'";
      return test_failure(out.str());
   }
}

bool Test::Result::test_lt(const std::string& what, size_t produced, size_t expected) {
   if(produced >= expected) {
      std::ostringstream err;
      err << m_who << " " << what;
      err << " unexpected result " << produced << " >= " << expected;
      return test_failure(err.str());
   }

   return test_success();
}

bool Test::Result::test_lte(const std::string& what, size_t produced, size_t expected) {
   if(produced > expected) {
      std::ostringstream err;
      err << m_who << " " << what << " unexpected result " << produced << " > " << expected;
      return test_failure(err.str());
   }

   return test_success();
}

bool Test::Result::test_gte(const std::string& what, size_t produced, size_t expected) {
   if(produced < expected) {
      std::ostringstream err;
      err << m_who;
      err << " " << what;
      err << " unexpected result " << produced << " < " << expected;
      return test_failure(err.str());
   }

   return test_success();
}

bool Test::Result::test_gt(const std::string& what, size_t produced, size_t expected) {
   if(produced <= expected) {
      std::ostringstream err;
      err << m_who;
      err << " " << what;
      err << " unexpected result " << produced << " <= " << expected;
      return test_failure(err.str());
   }

   return test_success();
}

bool Test::Result::test_ne(const std::string& what, const std::string& str1, const std::string& str2) {
   if(str1 != str2) {
      return test_success(str1 + " != " + str2);
   }

   return test_failure(who() + " " + what + " produced matching strings " + str1);
}

bool Test::Result::test_ne(const std::string& what, size_t produced, size_t expected) {
   if(produced != expected) {
      return test_success();
   }

   std::ostringstream err;
   err << who() << " " << what << " produced " << produced << " unexpected value";
   return test_failure(err.str());
}

#if defined(BOTAN_HAS_BIGINT)
bool Test::Result::test_eq(const std::string& what, const BigInt& produced, const BigInt& expected) {
   return test_is_eq(what, produced, expected);
}

bool Test::Result::test_ne(const std::string& what, const BigInt& produced, const BigInt& expected) {
   if(produced != expected) {
      return test_success();
   }

   std::ostringstream err;
   err << who() << " " << what << " produced " << produced << " prohibited value";
   return test_failure(err.str());
}
#endif

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
bool Test::Result::test_eq(const std::string& what, const Botan::EC_Point& a, const Botan::EC_Point& b) {
   //return test_is_eq(what, a, b);
   if(a == b) {
      return test_success();
   }

   std::ostringstream err;
   err << who() << " " << what << " a=(" << a.get_affine_x() << "," << a.get_affine_y() << ")"
       << " b=(" << b.get_affine_x() << "," << b.get_affine_y();
   return test_failure(err.str());
}
#endif

bool Test::Result::test_eq(const std::string& what, bool produced, bool expected) {
   return test_is_eq(what, produced, expected);
}

bool Test::Result::test_rc_init(const std::string& func, int rc) {
   if(rc == 0) {
      return test_success();
   } else {
      std::ostringstream msg;
      msg << m_who;
      msg << " " << func;

      // -40 is BOTAN_FFI_ERROR_NOT_IMPLEMENTED
      if(rc == -40) {
         msg << " returned not implemented";
      } else {
         msg << " unexpectedly failed with error code " << rc;
      }

      if(rc == -40) {
         this->test_note(msg.str());
      } else {
         this->test_failure(msg.str());
      }
      return false;
   }
}

bool Test::Result::test_rc(const std::string& func, int expected, int rc) {
   if(expected != rc) {
      std::ostringstream err;
      err << m_who;
      err << " call to " << func << " unexpectedly returned " << rc;
      err << " but expecting " << expected;
      return test_failure(err.str());
   }

   return test_success();
}

void Test::initialize(std::string test_name, CodeLocation location) {
   m_test_name = std::move(test_name);
   m_registration_location = std::move(location);
}

Botan::RandomNumberGenerator& Test::rng() const {
   if(!m_test_rng) {
      m_test_rng = Test::new_rng(m_test_name);
   }

   return *m_test_rng;
}

std::vector<std::string> Test::possible_providers(const std::string& /*unused*/) {
   return Test::provider_filter({"base"});
}

//static
std::string Test::format_time(uint64_t ns) {
   std::ostringstream o;

   if(ns > 1000000000) {
      o << std::setprecision(2) << std::fixed << ns / 1000000000.0 << " sec";
   } else {
      o << std::setprecision(2) << std::fixed << ns / 1000000.0 << " msec";
   }

   return o.str();
}

Test::Result::Result(std::string who, const std::vector<Result>& downstream_results) : Result(std::move(who)) {
   for(const auto& result : downstream_results) {
      merge(result, true /* ignore non-matching test names */);
   }
}

// TODO: this should move to `StdoutReporter`
std::string Test::Result::result_string() const {
   const bool verbose = Test::options().verbose();

   if(tests_run() == 0 && !verbose) {
      return "";
   }

   std::ostringstream report;

   report << who() << " ran ";

   if(tests_run() == 0) {
      report << "ZERO";
   } else {
      report << tests_run();
   }
   report << " tests";

   if(m_ns_taken > 0) {
      report << " in " << format_time(m_ns_taken);
   }

   if(tests_failed()) {
      report << " " << tests_failed() << " FAILED";
   } else {
      report << " all ok";
   }

   report << "\n";

   for(size_t i = 0; i != m_fail_log.size(); ++i) {
      report << "Failure " << (i + 1) << ": " << m_fail_log[i];
      if(m_where) {
         report << " (at " << m_where->path << ":" << m_where->line << ")";
      }
      report << "\n";
   }

   if(!m_fail_log.empty() || tests_run() == 0 || verbose) {
      for(size_t i = 0; i != m_log.size(); ++i) {
         report << "Note " << (i + 1) << ": " << m_log[i] << "\n";
      }
   }

   return report.str();
}

namespace {

class Test_Registry {
   public:
      static Test_Registry& instance() {
         static Test_Registry registry;
         return registry;
      }

      void register_test(const std::string& category,
                         const std::string& name,
                         bool smoke_test,
                         bool needs_serialization,
                         std::function<std::unique_ptr<Test>()> maker_fn) {
         if(m_tests.contains(name)) {
            throw Test_Error("Duplicate registration of test '" + name + "'");
         }

         if(m_tests.contains(category)) {
            throw Test_Error("'" + category + "' cannot be used as category, test exists");
         }

         if(m_categories.contains(name)) {
            throw Test_Error("'" + name + "' cannot be used as test name, category exists");
         }

         if(smoke_test) {
            m_smoke_tests.push_back(name);
         }

         if(needs_serialization) {
            m_mutexed_tests.push_back(name);
         }

         m_tests.emplace(name, std::move(maker_fn));
         m_categories.emplace(category, name);
      }

      std::unique_ptr<Test> get_test(const std::string& test_name) const {
         auto i = m_tests.find(test_name);
         if(i != m_tests.end()) {
            return i->second();
         }
         return nullptr;
      }

      std::set<std::string> registered_tests() const {
         std::set<std::string> s;
         for(auto&& i : m_tests) {
            s.insert(i.first);
         }
         return s;
      }

      std::set<std::string> registered_test_categories() const {
         std::set<std::string> s;
         for(auto&& i : m_categories) {
            s.insert(i.first);
         }
         return s;
      }

      std::vector<std::string> filter_registered_tests(const std::vector<std::string>& requested,
                                                       const std::set<std::string>& to_be_skipped) {
         std::vector<std::string> result;

         // TODO: this is O(n^2), but we have a relatively small number of tests.
         auto insert_if_not_exists_and_not_skipped = [&](const std::string& test_name) {
            if(!Botan::value_exists(result, test_name) && to_be_skipped.find(test_name) == to_be_skipped.end()) {
               result.push_back(test_name);
            }
         };

         if(requested.empty()) {
            /*
            If nothing was requested on the command line, run everything. First
            run the "essentials" to smoke test, then everything else in
            alphabetical order.
            */
            result = m_smoke_tests;
            for(const auto& [test_name, _] : m_tests) {
               insert_if_not_exists_and_not_skipped(test_name);
            }
         } else {
            for(const auto& r : requested) {
               if(m_tests.find(r) != m_tests.end()) {
                  insert_if_not_exists_and_not_skipped(r);
               } else if(auto elems = m_categories.equal_range(r); elems.first != m_categories.end()) {
                  for(; elems.first != elems.second; ++elems.first) {
                     insert_if_not_exists_and_not_skipped(elems.first->second);
                  }
               } else {
                  throw Test_Error("Unknown test suite or category: " + r);
               }
            }
         }

         return result;
      }

      bool needs_serialization(const std::string& test_name) const {
         return Botan::value_exists(m_mutexed_tests, test_name);
      }

   private:
      Test_Registry() = default;

   private:
      std::map<std::string, std::function<std::unique_ptr<Test>()>> m_tests;
      std::multimap<std::string, std::string> m_categories;
      std::vector<std::string> m_smoke_tests;
      std::vector<std::string> m_mutexed_tests;
};

}  // namespace

// static Test:: functions

//static
void Test::register_test(const std::string& category,
                         const std::string& name,
                         bool smoke_test,
                         bool needs_serialization,
                         std::function<std::unique_ptr<Test>()> maker_fn) {
   Test_Registry::instance().register_test(category, name, smoke_test, needs_serialization, std::move(maker_fn));
}

//static
uint64_t Test::timestamp() {
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

//static
std::vector<Test::Result> Test::flatten_result_lists(std::vector<std::vector<Test::Result>> result_lists) {
   std::vector<Test::Result> results;
   for(auto& result_list : result_lists) {
      for(auto& result : result_list) {
         results.emplace_back(std::move(result));
      }
   }
   return results;
}

//static
std::set<std::string> Test::registered_tests() {
   return Test_Registry::instance().registered_tests();
}

//static
std::set<std::string> Test::registered_test_categories() {
   return Test_Registry::instance().registered_test_categories();
}

//static
std::unique_ptr<Test> Test::get_test(const std::string& test_name) {
   return Test_Registry::instance().get_test(test_name);
}

//static
bool Test::test_needs_serialization(const std::string& test_name) {
   return Test_Registry::instance().needs_serialization(test_name);
}

//static
std::vector<std::string> Test::filter_registered_tests(const std::vector<std::string>& requested,
                                                       const std::set<std::string>& to_be_skipped) {
   return Test_Registry::instance().filter_registered_tests(requested, to_be_skipped);
}

//static
std::string Test::temp_file_name(const std::string& basename) {
   // TODO add a --tmp-dir option to the tests to specify where these files go

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)

   // POSIX only calls for 6 'X' chars but OpenBSD allows arbitrary amount
   std::string mkstemp_basename = "/tmp/" + basename + ".XXXXXXXXXX";

   int fd = ::mkstemp(&mkstemp_basename[0]);

   // error
   if(fd < 0) {
      return "";
   }

   ::close(fd);

   return mkstemp_basename;
#else
   // For now just create the temp in the current working directory
   return basename;
#endif
}

bool Test::copy_file(const std::string& from, const std::string& to) {
#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && defined(__cpp_lib_filesystem)
   std::error_code ec;  // don't throw, just return false on error
   return std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, ec);
#else
   // TODO: implement fallbacks to POSIX or WIN32
   // ... but then again: it's 2023 and we're using C++20 :o)
   BOTAN_UNUSED(from, to);
   throw Botan::No_Filesystem_Access();
#endif
}

std::string Test::read_data_file(const std::string& path) {
   const std::string fsname = Test::data_file(path);
   std::ifstream file(fsname.c_str());
   if(!file.good()) {
      throw Test_Error("Error reading from " + fsname);
   }

   return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

std::vector<uint8_t> Test::read_binary_data_file(const std::string& path) {
   const std::string fsname = Test::data_file(path);
   std::ifstream file(fsname.c_str(), std::ios::binary);
   if(!file.good()) {
      throw Test_Error("Error reading from " + fsname);
   }

   std::vector<uint8_t> contents;

   while(file.good()) {
      std::vector<uint8_t> buf(4096);
      file.read(reinterpret_cast<char*>(buf.data()), buf.size());
      const size_t got = static_cast<size_t>(file.gcount());

      if(got == 0 && file.eof()) {
         break;
      }

      contents.insert(contents.end(), buf.data(), buf.data() + got);
   }

   return contents;
}

// static member variables of Test

// NOLINTNEXTLINE(*-avoid-non-const-global-variables)
Test_Options Test::m_opts;
// NOLINTNEXTLINE(*-avoid-non-const-global-variables)
std::string Test::m_test_rng_seed;

//static
void Test::set_test_options(const Test_Options& opts) {
   m_opts = opts;
}

namespace {

/*
* This is a fast, simple, deterministic PRNG that's used for running
* the tests. It is not intended to be cryptographically secure.
*/
class Testsuite_RNG final : public Botan::RandomNumberGenerator {
   public:
      std::string name() const override { return "Testsuite_RNG"; }

      void clear() override { m_x = 0; }

      bool accepts_input() const override { return true; }

      bool is_seeded() const override { return true; }

      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
         for(const auto byte : input) {
            mix(byte);
         }

         for(auto& byte : output) {
            byte = mix();
         }
      }

      Testsuite_RNG(std::string_view seed, std::string_view test_name) {
         m_x = 0;

         for(char c : seed) {
            this->mix(static_cast<uint8_t>(c));
         }
         for(char c : test_name) {
            this->mix(static_cast<uint8_t>(c));
         }
      }

   private:
      uint8_t mix(uint8_t input = 0) {
         m_x ^= input;
         m_x *= 0xF2E16957;
         m_x += 0xE50B590F;
         return static_cast<uint8_t>(m_x >> 27);
      }

      uint64_t m_x;
};

}  // namespace

//static
void Test::set_test_rng_seed(std::span<const uint8_t> seed, size_t epoch) {
   m_test_rng_seed = Botan::fmt("seed={} epoch={}", Botan::hex_encode(seed), epoch);
}

//static
std::unique_ptr<Botan::RandomNumberGenerator> Test::new_rng(std::string_view test_name) {
   return std::make_unique<Testsuite_RNG>(m_test_rng_seed, test_name);
}

//static
std::shared_ptr<Botan::RandomNumberGenerator> Test::new_shared_rng(std::string_view test_name) {
   return std::make_shared<Testsuite_RNG>(m_test_rng_seed, test_name);
}

//static
std::string Test::data_file(const std::string& file) {
   return options().data_dir() + "/" + file;
}

//static
std::string Test::data_dir(const std::string& subdir) {
   return options().data_dir() + "/" + subdir;
}

//static
std::vector<std::string> Test::files_in_data_dir(const std::string& subdir) {
   auto fs = Botan::get_files_recursive(options().data_dir() + "/" + subdir);
   if(fs.empty()) {
      throw Test_Error("Test::files_in_data_dir encountered empty subdir " + subdir);
   }
   return fs;
}

//static
std::string Test::data_file_as_temporary_copy(const std::string& what) {
   auto tmp_basename = what;
   std::replace(tmp_basename.begin(), tmp_basename.end(), '/', '_');
   auto temp_file = temp_file_name("tmp-" + tmp_basename);
   if(temp_file.empty()) {
      return "";
   }
   if(!Test::copy_file(data_file(what), temp_file)) {
      return "";
   }
   return temp_file;
}

//static
std::vector<std::string> Test::provider_filter(const std::vector<std::string>& in) {
   if(m_opts.provider().empty()) {
      return in;
   }
   for(auto&& provider : in) {
      if(provider == m_opts.provider()) {
         return std::vector<std::string>{provider};
      }
   }
   return std::vector<std::string>{};
}

std::string Test::random_password(Botan::RandomNumberGenerator& rng) {
   const size_t len = 1 + rng.next_byte() % 32;
   return Botan::hex_encode(rng.random_vec(len));
}

size_t Test::random_index(Botan::RandomNumberGenerator& rng, size_t max) {
   return Botan::load_be(rng.random_array<8>()) % max;
}

std::vector<std::vector<uint8_t>> VarMap::get_req_bin_list(const std::string& key) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      throw Test_Error("Test missing variable " + key);
   }

   std::vector<std::vector<uint8_t>> bin_list;

   for(auto&& part : Botan::split_on(i->second, ',')) {
      try {
         bin_list.push_back(Botan::hex_decode(part));
      } catch(std::exception& e) {
         std::ostringstream oss;
         oss << "Bad input '" << part << "'"
             << " in binary list key " << key << " - " << e.what();
         throw Test_Error(oss.str());
      }
   }

   return bin_list;
}

std::vector<uint8_t> VarMap::get_req_bin(const std::string& key) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      throw Test_Error("Test missing variable " + key);
   }

   try {
      if(i->second.starts_with("0x")) {
         if(i->second.size() % 2 == 0) {
            return Botan::hex_decode(i->second.substr(2));
         } else {
            std::string z = i->second;
            std::swap(z[0], z[1]);  // swap 0x to x0 then remove x
            return Botan::hex_decode(z.substr(1));
         }
      } else {
         return Botan::hex_decode(i->second);
      }
   } catch(std::exception& e) {
      std::ostringstream oss;
      oss << "Bad input '" << i->second << "'"
          << " for key " << key << " - " << e.what();
      throw Test_Error(oss.str());
   }
}

std::string VarMap::get_opt_str(const std::string& key, const std::string& def_value) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      return def_value;
   }
   return i->second;
}

bool VarMap::get_req_bool(const std::string& key) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      throw Test_Error("Test missing variable " + key);
   }

   if(i->second == "true") {
      return true;
   } else if(i->second == "false") {
      return false;
   } else {
      throw Test_Error("Invalid boolean for key '" + key + "' value '" + i->second + "'");
   }
}

size_t VarMap::get_req_sz(const std::string& key) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      throw Test_Error("Test missing variable " + key);
   }
   return Botan::to_u32bit(i->second);
}

uint8_t VarMap::get_req_u8(const std::string& key) const {
   const size_t s = this->get_req_sz(key);
   if(s > 256) {
      throw Test_Error("Invalid " + key + " expected uint8_t got " + std::to_string(s));
   }
   return static_cast<uint8_t>(s);
}

uint32_t VarMap::get_req_u32(const std::string& key) const {
   return static_cast<uint32_t>(get_req_sz(key));
}

uint64_t VarMap::get_req_u64(const std::string& key) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      throw Test_Error("Test missing variable " + key);
   }
   try {
      return std::stoull(i->second);
   } catch(std::exception&) {
      throw Test_Error("Invalid u64 value '" + i->second + "'");
   }
}

size_t VarMap::get_opt_sz(const std::string& key, const size_t def_value) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      return def_value;
   }
   return Botan::to_u32bit(i->second);
}

uint64_t VarMap::get_opt_u64(const std::string& key, const uint64_t def_value) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      return def_value;
   }
   try {
      return std::stoull(i->second);
   } catch(std::exception&) {
      throw Test_Error("Invalid u64 value '" + i->second + "'");
   }
}

std::vector<uint8_t> VarMap::get_opt_bin(const std::string& key) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      return std::vector<uint8_t>();
   }

   try {
      return Botan::hex_decode(i->second);
   } catch(std::exception&) {
      throw Test_Error("Test invalid hex input '" + i->second + "'" + +" for key " + key);
   }
}

std::string VarMap::get_req_str(const std::string& key) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      throw Test_Error("Test missing variable " + key);
   }
   return i->second;
}

#if defined(BOTAN_HAS_BIGINT)
Botan::BigInt VarMap::get_req_bn(const std::string& key) const {
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      throw Test_Error("Test missing variable " + key);
   }

   try {
      return Botan::BigInt(i->second);
   } catch(std::exception&) {
      throw Test_Error("Test invalid bigint input '" + i->second + "' for key " + key);
   }
}

Botan::BigInt VarMap::get_opt_bn(const std::string& key, const Botan::BigInt& def_value) const

{
   auto i = m_vars.find(key);
   if(i == m_vars.end()) {
      return def_value;
   }

   try {
      return Botan::BigInt(i->second);
   } catch(std::exception&) {
      throw Test_Error("Test invalid bigint input '" + i->second + "' for key " + key);
   }
}
#endif

Text_Based_Test::Text_Based_Test(const std::string& data_src,
                                 const std::string& required_keys_str,
                                 const std::string& optional_keys_str) :
      m_data_src(data_src) {
   if(required_keys_str.empty()) {
      throw Test_Error("Invalid test spec");
   }

   std::vector<std::string> required_keys = Botan::split_on(required_keys_str, ',');
   std::vector<std::string> optional_keys = Botan::split_on(optional_keys_str, ',');

   m_required_keys.insert(required_keys.begin(), required_keys.end());
   m_optional_keys.insert(optional_keys.begin(), optional_keys.end());
   m_output_key = required_keys.at(required_keys.size() - 1);
}

std::string Text_Based_Test::get_next_line() {
   while(true) {
      if(m_cur == nullptr || m_cur->good() == false) {
         if(m_srcs.empty()) {
            if(m_first) {
               if(m_data_src.ends_with(".vec")) {
                  m_srcs.push_back(Test::data_file(m_data_src));
               } else {
                  const auto fs = Test::files_in_data_dir(m_data_src);
                  m_srcs.assign(fs.begin(), fs.end());
                  if(m_srcs.empty()) {
                     throw Test_Error("Error reading test data dir " + m_data_src);
                  }
               }

               m_first = false;
            } else {
               return "";  // done
            }
         }

         m_cur = std::make_unique<std::ifstream>(m_srcs[0]);
         m_cur_src_name = m_srcs[0];

         // Reinit cpuid on new file if needed
         if(m_cpu_flags.empty() == false) {
            m_cpu_flags.clear();
            Botan::CPUID::initialize();
         }

         if(!m_cur->good()) {
            throw Test_Error("Could not open input file '" + m_cur_src_name);
         }

         m_srcs.pop_front();
      }

      while(m_cur->good()) {
         std::string line;
         std::getline(*m_cur, line);

         if(line.empty()) {
            continue;
         }

         if(line[0] == '#') {
            if(line.starts_with("#test ")) {
               return line;
            } else {
               continue;
            }
         }

         return line;
      }
   }
}

namespace {

// strips leading and trailing but not internal whitespace
std::string strip_ws(const std::string& in) {
   const char* whitespace = " ";

   const auto first_c = in.find_first_not_of(whitespace);
   if(first_c == std::string::npos) {
      return "";
   }

   const auto last_c = in.find_last_not_of(whitespace);

   return in.substr(first_c, last_c - first_c + 1);
}

std::vector<uint64_t> parse_cpuid_bits(const std::vector<std::string>& tok) {
   std::vector<uint64_t> bits;
   for(size_t i = 1; i < tok.size(); ++i) {
      const std::vector<Botan::CPUID::CPUID_bits> more = Botan::CPUID::bit_from_string(tok[i]);
      bits.insert(bits.end(), more.begin(), more.end());
   }

   return bits;
}

}  // namespace

bool Text_Based_Test::skip_this_test(const std::string& /*header*/, const VarMap& /*vars*/) {
   return false;
}

std::vector<Test::Result> Text_Based_Test::run() {
   std::vector<Test::Result> results;

   std::string header, header_or_name = m_data_src;
   VarMap vars;
   size_t test_cnt = 0;

   while(true) {
      const std::string line = get_next_line();
      if(line.empty())  // EOF
      {
         break;
      }

      if(line.starts_with("#test ")) {
         std::vector<std::string> pragma_tokens = Botan::split_on(line.substr(6), ' ');

         if(pragma_tokens.empty()) {
            throw Test_Error("Empty pragma found in " + m_cur_src_name);
         }

         if(pragma_tokens[0] != "cpuid") {
            throw Test_Error("Unknown test pragma '" + line + "' in " + m_cur_src_name);
         }

         if(!Test_Registry::instance().needs_serialization(this->test_name())) {
            throw Test_Error(Botan::fmt("'{}' used cpuid control but is not serialized", this->test_name()));
         }

         m_cpu_flags = parse_cpuid_bits(pragma_tokens);

         continue;
      } else if(line[0] == '#') {
         throw Test_Error("Unknown test pragma '" + line + "' in " + m_cur_src_name);
      }

      if(line[0] == '[' && line[line.size() - 1] == ']') {
         header = line.substr(1, line.size() - 2);
         header_or_name = header;
         test_cnt = 0;
         vars.clear();
         continue;
      }

      const std::string test_id = "test " + std::to_string(test_cnt);

      auto equal_i = line.find_first_of('=');

      if(equal_i == std::string::npos) {
         results.push_back(Test::Result::Failure(header_or_name, "invalid input '" + line + "'"));
         continue;
      }

      std::string key = strip_ws(std::string(line.begin(), line.begin() + equal_i - 1));
      std::string val = strip_ws(std::string(line.begin() + equal_i + 1, line.end()));

      if(!m_required_keys.contains(key) && !m_optional_keys.contains(key)) {
         auto r = Test::Result::Failure(header_or_name, Botan::fmt("{} failed unknown key {}", test_id, key));
         results.push_back(r);
      }

      vars.add(key, val);

      if(key == m_output_key) {
         try {
            for(auto& req_key : m_required_keys) {
               if(!vars.has_key(req_key)) {
                  auto r =
                     Test::Result::Failure(header_or_name, Botan::fmt("{} missing required key {}", test_id, req_key));
                  results.push_back(r);
               }
            }

            if(skip_this_test(header, vars)) {
               continue;
            }

            ++test_cnt;

            uint64_t start = Test::timestamp();

            Test::Result result = run_one_test(header, vars);
            if(!m_cpu_flags.empty()) {
               for(const auto& cpuid_u64 : m_cpu_flags) {
                  Botan::CPUID::CPUID_bits cpuid_bit = static_cast<Botan::CPUID::CPUID_bits>(cpuid_u64);
                  if(Botan::CPUID::has_cpuid_bit(cpuid_bit)) {
                     Botan::CPUID::clear_cpuid_bit(cpuid_bit);
                     // now re-run the test
                     result.merge(run_one_test(header, vars));
                  }
               }
               Botan::CPUID::initialize();
            }
            result.set_ns_consumed(Test::timestamp() - start);

            if(result.tests_failed()) {
               std::ostringstream oss;
               oss << "Test # " << test_cnt << " ";
               if(!header.empty()) {
                  oss << header << " ";
               }
               oss << "failed ";

               for(const auto& k : m_required_keys) {
                  oss << k << "=" << vars.get_req_str(k) << " ";
               }

               result.test_note(oss.str());
            }
            results.push_back(result);
         } catch(std::exception& e) {
            std::ostringstream oss;
            oss << "Test # " << test_cnt << " ";
            if(!header.empty()) {
               oss << header << " ";
            }

            for(const auto& k : m_required_keys) {
               oss << k << "=" << vars.get_req_str(k) << " ";
            }

            oss << "failed with exception '" << e.what() << "'";

            results.push_back(Test::Result::Failure(header_or_name, oss.str()));
         }

         if(clear_between_callbacks()) {
            vars.clear();
         }
      }
   }

   if(results.empty()) {
      return results;
   }

   try {
      std::vector<Test::Result> final_tests = run_final_tests();
      results.insert(results.end(), final_tests.begin(), final_tests.end());
   } catch(std::exception& e) {
      results.push_back(Test::Result::Failure(header_or_name, "run_final_tests exception " + std::string(e.what())));
   }

   m_first = true;

   return results;
}

std::map<std::string, std::string> Test_Options::report_properties() const {
   std::map<std::string, std::string> result;

   for(const auto& prop : m_report_properties) {
      const auto colon = prop.find(':');
      // props without a colon separator or without a name are not allowed
      if(colon == std::string::npos || colon == 0) {
         throw Test_Error("--report-properties should be of the form <key>:<value>,<key>:<value>,...");
      }

      result.insert_or_assign(prop.substr(0, colon), prop.substr(colon + 1, prop.size() - colon - 1));
   }

   return result;
}

}  // namespace Botan_Tests

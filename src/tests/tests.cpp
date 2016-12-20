/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <sstream>
#include <iomanip>
#include <botan/hex.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/stl_util.h>

namespace Botan_Tests {

Test::Registration::Registration(const std::string& name, Test* test)
   {
   if(Test::global_registry().count(name) == 0)
      {
      Test::global_registry().insert(std::make_pair(name, std::unique_ptr<Test>(test)));
      }
   else
      {
      throw Test_Error("Duplicate registration of test '" + name + "'");
      }
   }

void Test::Result::merge(const Result& other)
   {
   if(who() != other.who())
      throw Test_Error("Merging tests from different sources");

   m_ns_taken += other.m_ns_taken;
   m_tests_passed += other.m_tests_passed;
   m_fail_log.insert(m_fail_log.end(), other.m_fail_log.begin(), other.m_fail_log.end());
   m_log.insert(m_log.end(), other.m_log.begin(), other.m_log.end());
   }

void Test::Result::start_timer()
   {
   if(m_started == 0)
      {
      m_started = Test::timestamp();
      }
   }

void Test::Result::end_timer()
   {
   if(m_started > 0)
      {
      m_ns_taken += Test::timestamp() - m_started;
      m_started = 0;
      }
   }

void Test::Result::test_note(const std::string& note, const char* extra)
   {
   if(note != "")
      {
      std::ostringstream out;
      out << who() << " " << note;
      if(extra)
         out << ": " << extra;
      m_log.push_back(out.str());
      }
   }

void Test::Result::note_missing(const std::string& whatever)
   {
   static std::set<std::string> s_already_seen;

   if(s_already_seen.count(whatever) == 0)
      {
      test_note("Skipping tests due to missing " + whatever);
      s_already_seen.insert(whatever);
      }
   }

bool Test::Result::test_throws(const std::string& what, std::function<void ()> fn)
   {
   try {
      fn();
      return test_failure(what + " failed to throw expected exception");
   }
   catch(std::exception& e)
      {
      return test_success(what + " threw exception " + e.what());
      }
   catch(...)
      {
      return test_success(what + " threw unknown exception");
      }
   }

bool Test::Result::test_throws(const std::string& what, const std::string& expected, std::function<void ()> fn)
   {
   try {
      fn();
      return test_failure(what + " failed to throw expected exception");
   }
   catch(std::exception& e)
      {
      if(expected == e.what()) 
         {
         return test_success(what + " threw exception " + e.what());
         }
      else 
         {
         return test_failure(what + " failed to throw an exception with the expected text:\n  Expected: " + expected + "\n  Got: " + e.what());
         }
      }
   catch(...)
      {
      return test_failure(what + " failed to throw an exception with the expected text:\n  Expected: " + expected);
      }
   }

bool Test::Result::test_success(const std::string& note)
   {
   if(Test::log_success())
      {
      test_note(note);
      }
   ++m_tests_passed;
   return true;
   }

bool Test::Result::test_failure(const std::string& what, const std::string& error)
   {
   return test_failure(who() + " " + what + " with error " + error);
   }

void Test::Result::test_failure(const std::string& what, const uint8_t buf[], size_t buf_len)
   {
   test_failure(who() + ": " + what +
                " buf len " + std::to_string(buf_len) +
                " value " + Botan::hex_encode(buf, buf_len));
   }

bool Test::Result::test_failure(const std::string& err)
   {
   m_fail_log.push_back(err);
   return false;
   }

bool Test::Result::test_ne(const std::string& what,
                           const uint8_t produced[], size_t produced_len,
                           const uint8_t expected[], size_t expected_len)
   {
   if(produced_len == expected_len && Botan::same_mem(produced, expected, expected_len))
      return test_failure(who() + ": " + what + " produced matching");
   return test_success();
   }

bool Test::Result::test_eq(const char* producer, const std::string& what,
                           const uint8_t produced[], size_t produced_size,
                           const uint8_t expected[], size_t expected_size)
   {
   if(produced_size == expected_size && Botan::same_mem(produced, expected, expected_size))
      return test_success();

   std::ostringstream err;

   err << who();

   if(producer)
      {
      err << " producer '" << producer << "'";
      }

   err << " unexpected result for " << what;

   if(produced_size != expected_size)
      {
      err << " produced " << produced_size << " bytes expected " << expected_size;
      }

   std::vector<uint8_t> xor_diff(std::min(produced_size, expected_size));
   size_t bits_different = 0;

   for(size_t i = 0; i != xor_diff.size(); ++i)
      {
      xor_diff[i] = produced[i] ^ expected[i];
      bits_different += Botan::hamming_weight(xor_diff[i]);
      }

   err << "\nProduced: " << Botan::hex_encode(produced, produced_size)
       << "\nExpected: " << Botan::hex_encode(expected, expected_size);

   if(bits_different > 0)
      {
      err << "\nXOR Diff: " << Botan::hex_encode(xor_diff)
          << " (" << bits_different << " bits different)";
      }

   return test_failure(err.str());
   }

bool Test::Result::test_is_nonempty(const std::string& what_is_it, const std::string& to_examine)
   {
   if(to_examine.empty())
      return test_failure(what_is_it + " was empty");
   return test_success();
   }

bool Test::Result::test_eq(const std::string& what, const std::string& produced, const std::string& expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_eq(const std::string& what, const char* produced, const char* expected)
   {
   return test_is_eq(what, std::string(produced), std::string(expected));
   }

bool Test::Result::test_eq(const std::string& what, size_t produced, size_t expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_eq(const std::string& what, OctetString produced, OctetString expected)
   {
   std::ostringstream out;
   out << m_who << " " << what;

   if(produced == expected)
      {
      out << " produced expected result " << produced.as_string();
      return test_success(out.str());
      }
   else
      {
      out << " produced unexpected result '" << produced.as_string() << "' expected '" << expected.as_string() << "'";
      return test_failure(out.str());
      }
   }

bool Test::Result::test_lt(const std::string& what, size_t produced, size_t expected)
   {
   if(produced >= expected)
      {
      std::ostringstream err;
      err << m_who << " " << what;
      err << " unexpected result " << produced << " >= " << expected;
      return test_failure(err.str());
      }

   return test_success();
   }

bool Test::Result::test_lte(const std::string& what, size_t produced, size_t expected)
   {
   if(produced > expected)
      {
      std::ostringstream err;
      err << m_who << " " << what << " unexpected result " << produced << " > " << expected;
      return test_failure(err.str());
      }

   return test_success();
   }

bool Test::Result::test_gte(const std::string& what, size_t produced, size_t expected)
   {
   if(produced < expected)
      {
      std::ostringstream err;
      err << m_who;
      err << " " << what;
      err << " unexpected result " << produced << " < " << expected;
      return test_failure(err.str());
      }

   return test_success();
   }

bool Test::Result::test_ne(const std::string& what, const std::string& str1, const std::string& str2)
   {
   if(str1 != str2)
      {
      return test_success(str1 + " != " + str2);
      }

   return test_failure(who() + " " + what + " produced matching strings " + str1);
   }

bool Test::Result::test_ne(const std::string& what, size_t produced, size_t expected)
   {
   if(produced != expected)
      {
      return test_success();
      }

   std::ostringstream err;
   err << who() << " " << what << " produced " << produced << " unexpected value";
   return test_failure(err.str());
   }

#if defined(BOTAN_HAS_BIGINT)
bool Test::Result::test_eq(const std::string& what, const BigInt& produced, const BigInt& expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_ne(const std::string& what, const BigInt& produced, const BigInt& expected)
   {
   if(produced != expected)
      return test_success();

   std::ostringstream err;
   err << who() << " " << what << " produced " << produced << " prohibited value";
   return test_failure(err.str());
   }
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
bool Test::Result::test_eq(const std::string& what,
                           const Botan::PointGFp& a, const Botan::PointGFp& b)
   {
   //return test_is_eq(what, a, b);
   if(a == b)
      return test_success();

   std::ostringstream err;
   err << who() << " " << what << " a=(" << a.get_affine_x() << "," << a.get_affine_y() << ")"
       << " b=(" << b.get_affine_x() << "," << b.get_affine_y();
   return test_failure(err.str());
   }
#endif

bool Test::Result::test_eq(const std::string& what, bool produced, bool expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_rc(const std::string& func, int expected, int rc)
   {
   if(expected != rc)
      {
      std::ostringstream err;
      err << m_who;
      err << " call to " << func << " unexpectedly returned " << rc;
      err << " but expecting " << expected;
      return test_failure(err.str());
      }

   return test_success();
   }

//static
std::string Test::format_time(uint64_t ns)
   {
   std::ostringstream o;

   if(ns > 1000000000)
      {
      o << std::setprecision(2) << std::fixed << ns/1000000000.0 << " sec";
      }
   else
      {
      o << std::setprecision(2) << std::fixed << ns/1000000.0 << " msec";
      }

   return o.str();
   }

std::string Test::Result::result_string(bool verbose) const
   {
   if(tests_run() == 0 && !verbose)
      return "";

   std::ostringstream report;

   report << who() << " ran ";

   if(tests_run() == 0)
      {
      report << "ZERO";
      }
   else
      {
      report << tests_run();
      }
   report << " tests";

   if(m_ns_taken > 0)
      {
      report << " in " << format_time(m_ns_taken);
      }

   if(tests_failed())
      {
      report << " " << tests_failed() << " FAILED";
      }
   else
      {
      report << " all ok";
      }

   report << "\n";

   for(size_t i = 0; i != m_fail_log.size(); ++i)
      {
      report << "Failure " << (i+1) << ": " << m_fail_log[i] << "\n";
      }

   if(m_fail_log.size() > 0 || tests_run() == 0)
      {
      for(size_t i = 0; i != m_log.size(); ++i)
         {
         report << "Note " << (i+1) << ": " << m_log[i] << "\n";
         }
      }

   return report.str();
   }

// static Test:: functions
//static
std::map<std::string, std::unique_ptr<Test>>& Test::global_registry()
   {
   static std::map<std::string, std::unique_ptr<Test>> g_test_registry;
   return g_test_registry;
   }

//static
uint64_t Test::timestamp()
   {
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

//static
std::set<std::string> Test::registered_tests()
   {
   return Botan::map_keys_as_set(Test::global_registry());
   }

//static
Test* Test::get_test(const std::string& test_name)
   {
   auto i = Test::global_registry().find(test_name);
   if(i != Test::global_registry().end())
      return i->second.get();
   return nullptr;
   }

//static
std::vector<Test::Result> Test::run_test(const std::string& test_name, bool fail_if_missing)
   {
   std::vector<Test::Result> results;

   try
      {
      if(Test* test = get_test(test_name))
         {
         std::vector<Test::Result> test_results = test->run();
         results.insert(results.end(), test_results.begin(), test_results.end());
         }
      else
         {
         Test::Result result(test_name);
         if(fail_if_missing)
            result.test_failure("Test missing or unavailable");
         else
            result.test_note("Test missing or unavailable");
         results.push_back(result);
         }
      }
   catch(std::exception& e)
      {
      results.push_back(Test::Result::Failure(test_name, e.what()));
      }
   catch(...)
      {
      results.push_back(Test::Result::Failure(test_name, "unknown exception"));
      }

   return results;
   }

// static member variables of Test
Botan::RandomNumberGenerator* Test::m_test_rng = nullptr;
std::string Test::m_data_dir;
bool Test::m_log_success = false;
bool Test::m_run_online_tests = false;
bool Test::m_run_long_tests = false;
std::string Test::m_pkcs11_lib;

//static
void Test::setup_tests(bool log_success,
                       bool run_online,
                       bool run_long,
                       const std::string& data_dir,
                       const std::string& pkcs11_lib,
                       Botan::RandomNumberGenerator* rng)
   {
   m_data_dir = data_dir;
   m_log_success = log_success;
   m_run_online_tests = run_online;
   m_run_long_tests = run_long;
   m_test_rng = rng;
   m_pkcs11_lib = pkcs11_lib;
   }

//static
std::string Test::data_file(const std::string& what)
   {
   return Test::data_dir() + "/" + what;
   }

//static
const std::string& Test::data_dir()
   {
   return m_data_dir;
   }

//static
bool Test::log_success()
   {
   return m_log_success;
   }

//static
bool Test::run_online_tests()
   {
   return m_run_online_tests;
   }

//static
bool Test::run_long_tests()
   {
   return m_run_long_tests;
   }

//static
std::string Test::pkcs11_lib()
   {
   return m_pkcs11_lib;
   }

//static
Botan::RandomNumberGenerator& Test::rng()
   {
   if(!m_test_rng)
      throw Test_Error("Test RNG not initialized");
   return *m_test_rng;
   }

std::string Test::random_password()
   {
   const size_t len = 1 + Test::rng().next_byte() % 32;
   return Botan::hex_encode(Test::rng().random_vec(len));
   }

Text_Based_Test::Text_Based_Test(const std::string& data_src,
                                 const std::string& required_keys_str,
                                 const std::string& optional_keys_str) :
   m_data_src(data_src)
   {
   if(required_keys_str.empty())
      throw Test_Error("Invalid test spec");

   std::vector<std::string> required_keys = Botan::split_on(required_keys_str, ',');
   std::vector<std::string> optional_keys = Botan::split_on(optional_keys_str, ',');

   m_required_keys.insert(required_keys.begin(), required_keys.end());
   m_optional_keys.insert(optional_keys.begin(), optional_keys.end());
   m_output_key = required_keys.at(required_keys.size() - 1);
   }

std::vector<uint8_t> Text_Based_Test::get_req_bin(const VarMap& vars,
                                                  const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw Test_Error("Test missing variable " + key);

   try
      {
      return Botan::hex_decode(i->second);
      }
   catch(std::exception&)
      {
      throw Test_Error("Test invalid hex input '" + i->second + "'" +
                       + " for key " + key);
      }
   }

std::string Text_Based_Test::get_opt_str(const VarMap& vars,
                                         const std::string& key, const std::string& def_value) const

   {
   auto i = vars.find(key);
   if(i == vars.end())
      return def_value;
   return i->second;
   }

bool Text_Based_Test::get_req_bool(const VarMap& vars, const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw Test_Error("Test missing variable " + key);

   if(i->second == "true")
      return true;
   else if(i->second == "false")
      return false;
   else
      throw Test_Error("Invalid boolean for key '" + key + "' value '" + i->second + "'");
   }

size_t Text_Based_Test::get_req_sz(const VarMap& vars, const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw Test_Error("Test missing variable " + key);
   return Botan::to_u32bit(i->second);
   }

size_t Text_Based_Test::get_opt_sz(const VarMap& vars, const std::string& key, const size_t def_value) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      return def_value;
   return Botan::to_u32bit(i->second);
   }

std::vector<uint8_t> Text_Based_Test::get_opt_bin(const VarMap& vars,
                                                  const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      return std::vector<uint8_t>();

   try
      {
      return Botan::hex_decode(i->second);
      }
   catch(std::exception&)
      {
      throw Test_Error("Test invalid hex input '" + i->second + "'" +
                               + " for key " + key);
      }
   }

std::string Text_Based_Test::get_req_str(const VarMap& vars, const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw Test_Error("Test missing variable " + key);
   return i->second;
   }

#if defined(BOTAN_HAS_BIGINT)
Botan::BigInt Text_Based_Test::get_req_bn(const VarMap& vars,
                                          const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw Test_Error("Test missing variable " + key);

   try
      {
      return Botan::BigInt(i->second);
      }
   catch(std::exception&)
      {
      throw Test_Error("Test invalid bigint input '" + i->second + "' for key " + key);
      }
   }

Botan::BigInt Text_Based_Test::get_opt_bn(const VarMap& vars,
                                        const std::string& key,
                                        const Botan::BigInt& def_value) const

   {
   auto i = vars.find(key);
   if(i == vars.end())
      {
      return def_value;
      }

   try
      {
      return Botan::BigInt(i->second);
      }
   catch(std::exception&)
      {
      throw Test_Error("Test invalid bigint input '" + i->second + "' for key " + key);
      }
   }
#endif

std::string Text_Based_Test::get_next_line()
   {
   while(true)
      {
      if(m_cur == nullptr || m_cur->good() == false)
         {
         if(m_srcs.empty())
            {
            if(m_first)
               {
               const std::string full_path = Test::data_dir() + "/" + m_data_src;
               if(full_path.find(".vec") != std::string::npos)
                  {
                  m_srcs.push_back(full_path);
                  }
               else
                  {
                  const auto fs = Botan::get_files_recursive(full_path);
                  m_srcs.assign(fs.begin(), fs.end());
                  if(m_srcs.empty())
                     throw Test_Error("Error reading test data dir " + full_path);
                  }

               m_first = false;
               }
            else
               {
               return ""; // done
               }
            }

         m_cur.reset(new std::ifstream(m_srcs[0]));
         m_cur_src_name = m_srcs[0];

         // Reinit cpuid on new file if needed
         if(m_cpu_flags.empty() == false)
            {
            m_cpu_flags.clear();
            Botan::CPUID::initialize();
            }

         if(!m_cur->good())
            throw Test_Error("Could not open input file '" + m_cur_src_name);

         m_srcs.pop_front();
         }

      while(m_cur->good())
         {
         std::string line;
         std::getline(*m_cur, line);

         if(line.empty())
            continue;

         if(line[0] == '#')
            {
            if(line.compare(0, 6, "#test ") == 0)
               return line;
            else
               continue;
            }

         return line;
         }
      }
   }

namespace {

// strips leading and trailing but not internal whitespace
std::string strip_ws(const std::string& in)
   {
   const char* whitespace = " ";

   const auto first_c = in.find_first_not_of(whitespace);
   if(first_c == std::string::npos)
      return "";

   const auto last_c = in.find_last_not_of(whitespace);

   return in.substr(first_c, last_c - first_c + 1);
   }

std::vector<Botan::CPUID::CPUID_bits> map_cpuid_string(const std::string& tok)
   {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   if(tok == "sse2" || tok == "simd")
      return {Botan::CPUID::CPUID_SSE2_BIT};
   if(tok == "ssse3")
      return {Botan::CPUID::CPUID_SSSE3_BIT};
   if(tok == "aesni")
      return {Botan::CPUID::CPUID_AESNI_BIT};
   if(tok == "clmul")
      return {Botan::CPUID::CPUID_CLMUL_BIT};
   if(tok == "avx2")
      return {Botan::CPUID::CPUID_AVX2_BIT};
#endif

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   if(tok == "altivec" || tok == "simd")
      return {Botan::CPUID::CPUID_ALTIVEC_BIT};
#endif

   return {};
   }

std::vector<Botan::CPUID::CPUID_bits>
parse_cpuid_bits(const std::vector<std::string>& tok)
   {
   std::vector<Botan::CPUID::CPUID_bits> bits;
   for(size_t i = 1; i < tok.size(); ++i)
      {
      const std::vector<Botan::CPUID::CPUID_bits> more = map_cpuid_string(tok[i]);
      bits.insert(bits.end(), more.begin(), more.end());
      }

   return bits;
   }

}

bool Text_Based_Test::skip_this_test(const std::string& /*header*/,
                                     const VarMap& /*vars*/)
   {
   return false;
   }

std::vector<Test::Result> Text_Based_Test::run()
   {
   std::vector<Test::Result> results;

   std::string header, header_or_name = m_data_src;
   VarMap vars;
   size_t test_cnt = 0;

   while(true)
      {
      const std::string line = get_next_line();
      if(line.empty()) // EOF
         break;

      if(line.compare(0, 6, "#test ") == 0)
         {
         std::vector<std::string> pragma_tokens = Botan::split_on(line.substr(6), ' ');

         if(pragma_tokens.empty())
            throw Test_Error("Empty pragma found in " + m_cur_src_name);

         if(pragma_tokens[0] != "cpuid")
            throw Test_Error("Unknown test pragma '" + line + "' in " + m_cur_src_name);

         m_cpu_flags = parse_cpuid_bits(pragma_tokens);

         continue;
         }
      else if(line[0] == '#')
         {
         throw Test_Error("Unknown test pragma '" + line + "' in " + m_cur_src_name);
         }

      if(line[0] == '[' && line[line.size()-1] == ']')
         {
         header = line.substr(1, line.size() - 2);
         header_or_name = header;
         test_cnt = 0;
         continue;
         }

      const std::string test_id = "test " + std::to_string(test_cnt);

      auto equal_i = line.find_first_of('=');

      if(equal_i == std::string::npos)
         {
         results.push_back(Test::Result::Failure(header_or_name,
                                                 "invalid input '" + line + "'"));
         continue;
         }

      std::string key = strip_ws(std::string(line.begin(), line.begin() + equal_i - 1));
      std::string val = strip_ws(std::string(line.begin() + equal_i + 1, line.end()));

      if(m_required_keys.count(key) == 0 && m_optional_keys.count(key) == 0)
         results.push_back(Test::Result::Failure(header_or_name,
                                                 test_id + " failed unknown key " + key));

      vars[key] = val;

      if(key == m_output_key)
         {
         try
            {
            if(skip_this_test(header, vars))
               {
               continue;
               }

            ++test_cnt;

            uint64_t start = Test::timestamp();

            Test::Result result = run_one_test(header, vars);
            if(m_cpu_flags.size() > 0)
               {
               for(auto&& cpuid_bit : m_cpu_flags)
                  {
                  if(Botan::CPUID::has_cpuid_bit(cpuid_bit))
                     {
                     Botan::CPUID::clear_cpuid_bit(cpuid_bit);
                     // now re-run the test
                     result.merge(run_one_test(header, vars));
                     }
                  }
               Botan::CPUID::initialize();
               }
            result.set_ns_consumed(Test::timestamp() - start);

            if(result.tests_failed())
               result.test_note("Test #" + std::to_string(test_cnt) + " failed");
            results.push_back(result);
            }
         catch(std::exception& e)
            {
            results.push_back(Test::Result::Failure(header_or_name,
                                                    "test " + std::to_string(test_cnt) +
                                                    " failed with exception '" + e.what() + "'"));
            }

         if(clear_between_callbacks())
            {
            vars.clear();
            }
         }
      }

   try
      {
      std::vector<Test::Result> final_tests = run_final_tests();
      results.insert(results.end(), final_tests.begin(), final_tests.end());
      }
   catch(std::exception& e)
      {
      results.push_back(Test::Result::Failure(header_or_name,
                                              "run_final_tests exception " + std::string(e.what())));
      }

   return results;
   }

}


/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <sstream>
#include <iomanip>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/bit_ops.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

namespace Botan_Tests {

void Test::Result::merge(const Result& other)
   {
   if(who() != other.who())
      throw std::runtime_error("Merging tests from different sources");

   m_ns_taken += other.m_ns_taken;
   m_tests_passed += other.m_tests_passed;
   m_fail_log.insert(m_fail_log.end(), other.m_fail_log.begin(), other.m_fail_log.end());
   m_log.insert(m_log.end(), other.m_log.begin(), other.m_log.end());
   }

void Test::Result::test_note(const std::string& note)
   {
   m_log.push_back(who() + " " + note);
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

bool Test::Result::test_success()
   {
   ++m_tests_passed;
   return true;
   }

bool Test::Result::test_failure(const char* what, const char* error)
   {
   return test_failure(who() + " " + what + " with error " + error);
   }

void Test::Result::test_failure(const char* what, const uint8_t buf[], size_t buf_len)
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

bool Test::Result::test_ne(const char* what,
                           const uint8_t produced[], size_t produced_len,
                           const uint8_t expected[], size_t expected_len)
   {
   if(produced_len == expected_len && Botan::same_mem(produced, expected, expected_len))
      return test_failure(who() + ":" + what + " produced matching");
   return test_success();
   }

bool Test::Result::test_eq(const char* producer, const char* what,
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

   err << " unexpected result";

   if(what)
      {
      err << " for " << what;
      }

   if(produced_size != expected_size)
      {
      err << " produced " << produced_size << " bytes expected " << expected_size;
      }

   err << "\n";

   std::vector<uint8_t> xor_diff(std::min(produced_size, expected_size));
   size_t bits_different = 0;

   for(size_t i = 0; i != xor_diff.size(); ++i)
      {
      xor_diff[i] = produced[i] ^ expected[i];
      bits_different += Botan::hamming_weight(xor_diff[i]);
      }

   err << "Produced: " << Botan::hex_encode(produced, produced_size) << "\n";
   err << "Expected: " << Botan::hex_encode(expected, expected_size) << "\n";
   if(bits_different > 0)
      {
      err << "XOR Diff: " << Botan::hex_encode(xor_diff)
          << " (" << bits_different << " bits different)\n";
      }

   return test_failure(err.str());
   }

bool Test::Result::test_eq(const char* what, const std::string& produced, const std::string& expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_eq(const char* what, const char* produced, const char* expected)
   {
   return test_is_eq(what, std::string(produced), std::string(expected));
   }

bool Test::Result::test_eq(const char* what, uint32_t produced, uint32_t expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_eq(const char* what, size_t produced, size_t expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_lt(const char* what, size_t produced, size_t expected)
   {
   if(produced >= expected)
      {
      std::ostringstream err;
      err << m_who;
      if(what)
         err << " " << what;
      err << " unexpected result " << produced << " >= " << expected << "\n";
      return test_failure(err.str());
      }

   return test_success();
   }

bool Test::Result::test_gte(const char* what, size_t produced, size_t expected)
   {
   if(produced < expected)
      {
      std::ostringstream err;
      err << m_who;
      if(what)
         err << " " << what;
      err << " unexpected result " << produced << " < " << expected << "\n";
      return test_failure(err.str());
      }

   return test_success();
   }

#if defined(BOTAN_HAS_BIGINT)
bool Test::Result::test_eq(const char* what, const BigInt& produced, const BigInt& expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_ne(const char* what, const BigInt& produced, const BigInt& expected)
   {
   if(produced != expected)
      return test_success();

   std::ostringstream err;
   err << who() << " " << what << " produced " << produced << " prohibited value";
   return test_failure(err.str());
   }
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
bool Test::Result::test_eq(const char* what, const Botan::PointGFp& a, const Botan::PointGFp& b)
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

bool Test::Result::test_eq(const char* what, bool produced, bool expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_rc_ok(const char* what, int rc)
   {
   if(rc != 0)
      {
      std::ostringstream err;
      err << m_who;
      if(what)
         err << " " << what;
      err << " unexpectedly failed with error code " << rc << "\n";
      return test_failure(err.str());
      }

   return test_success();
   }

bool Test::Result::test_rc_fail(const char* func, const char* why, int rc)
   {
   if(rc == 0)
      {
      std::ostringstream err;
      err << m_who;
      if(func)
         err << " call to " << func << " unexpectedly succeeded";
      if(why)
         err << " expecting failure because " << why;
      err << "\n";
      return test_failure(err.str());
      }

   return test_success();
   }

namespace {

std::string format_time(uint64_t ns)
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

}

std::string Test::Result::result_string() const
   {
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
std::map<std::string, Test*>& Test::global_registry()
   {
   static std::map<std::string, Test*> g_test_registry;
   return g_test_registry;
   }

namespace {

template<typename K, typename V>
std::set<K> map_keys_as_set(const std::map<K, V>& kv)
   {
   std::set<K> s;
   for(auto&& i : kv)
      {
      s.insert(i.first);
      }
   return s;
   }

uint64_t timestamp()
   {
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

}

std::set<std::string> Botan_Tests::Test::registered_tests()
   {
   return map_keys_as_set(Test::global_registry());
   }

//static
Test* Test::get_test(const std::string& test_name)
   {
   auto i = Test::global_registry().find(test_name);
   if(i != Test::global_registry().end())
      return i->second;
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

//static
size_t Test::run_tests(const std::vector<std::string>& requested,
                       bool run_all_tests,
                       std::ostream& out)
   {
   std::vector<std::string> tests_to_run = requested;
   size_t tests_ran = 0, tests_failed = 0;

   if(run_all_tests)
      {
      std::set<std::string> all_others = Botan_Tests::Test::registered_tests();

      for(auto r : requested)
         all_others.erase(r);

      tests_to_run.insert(tests_to_run.end(), all_others.begin(), all_others.end());
      }

   for(auto&& test_name : tests_to_run)
      {
      std::vector<Test::Result> results = Test::run_test(test_name, false);

      std::map<std::string, Test::Result> combined;
      for(auto&& result : results)
         {
         const std::string who = result.who();
         auto i = combined.find(who);
         if(i == combined.end())
            {
            combined[who] = Test::Result(who);
            i = combined.find(who);
            }

         i->second.merge(result);
         }

      for(auto&& result : combined)
         {
         out << result.second.result_string();
         tests_failed += result.second.tests_failed();
         tests_ran += result.second.tests_run();
         }

      out << std::flush; // Nice when output is redirected to file
      }

   out << "Tests complete ran " << tests_ran << " tests ";

   if(tests_failed > 0)
      {
      out << tests_failed << " tests failed";
      }
   else if(tests_ran > 0)
      {
      out << "all tests ok";
      }

   out << std::endl;

   return tests_failed;
   }

//static
std::string Test::data_dir(const std::string& what)
   {
   return std::string(TEST_DATA_DIR) + "/" + what;
   }

//static
std::string Test::data_file(const std::string& what)
   {
   return std::string(TEST_DATA_DIR) + "/" + what;
   }

//static
size_t Test::soak_level()
   {
   // TODO: make configurable
   return 5;
   }

//static
Botan::RandomNumberGenerator& Test::rng()
   {
   // TODO: replace by HMAC_DRBG with fixed seed
#if defined(BOTAN_HAS_SYSTEM_RNG)
   return Botan::system_rng();
#else
   static Botan::AutoSeeded_RNG rng;
   return rng;
#endif
   }

std::string Test::random_password()
   {
   const size_t len = 1 + Test::rng().next_byte() % 32;
   return Botan::hex_encode(Test::rng().random_vec(len));
   }

Text_Based_Test::Text_Based_Test(const std::string& data_dir,
                                 const std::vector<std::string>& required_keys,
                                 const std::vector<std::string>& optional_keys) :
   m_data_dir(data_dir)
   {
   if(required_keys.empty())
      throw std::runtime_error("Invalid test spec");

   m_required_keys.insert(required_keys.begin(), required_keys.end());
   m_optional_keys.insert(optional_keys.begin(), optional_keys.end());
   m_output_key = required_keys.at(required_keys.size() - 1);
   }

Text_Based_Test::Text_Based_Test(const std::string& algo,
                                 const std::string& data_dir,
                                 const std::vector<std::string>& required_keys,
                                 const std::vector<std::string>& optional_keys) :
   m_algo(algo),
   m_data_dir(data_dir)
   {
   if(required_keys.empty())
      throw std::runtime_error("Invalid test spec");

   m_required_keys.insert(required_keys.begin(), required_keys.end());
   m_optional_keys.insert(optional_keys.begin(), optional_keys.end());
   m_output_key = required_keys.at(required_keys.size() - 1);
   }

std::vector<uint8_t> Text_Based_Test::get_req_bin(const VarMap& vars,
                                                  const std::string& key) const
      {
      auto i = vars.find(key);
      if(i == vars.end())
         throw std::runtime_error("Test missing variable " + key);

      try
         {
         return Botan::hex_decode(i->second);
         }
      catch(std::exception& e)
         {
         throw std::runtime_error("Test invalid hex input " + key);
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

size_t Text_Based_Test::get_req_sz(const VarMap& vars, const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw std::runtime_error("Test missing variable " + key);
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
   catch(std::exception& e)
      {
      throw std::runtime_error("Test invalid hex input " + key);
      }
   }

std::string Text_Based_Test::get_req_str(const VarMap& vars, const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw std::runtime_error("Test missing variable " + key);
   return i->second;
   }

#if defined(BOTAN_HAS_BIGINT)
Botan::BigInt Text_Based_Test::get_req_bn(const VarMap& vars,
                                          const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw std::runtime_error("Test missing variable " + key);

   try
      {
      return Botan::BigInt(i->second);
      }
   catch(std::exception& e)
      {
      throw std::runtime_error("Test invalid bigint input " + key);
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
               std::vector<std::string> fs = Botan::get_files_recursive(m_data_dir);

               if(fs.empty() && m_data_dir.find(".vec") != std::string::npos)
                  {
                  m_srcs.push_back(m_data_dir);
                  }
               else
                  {
                  m_srcs.assign(fs.begin(), fs.end());
                  }

               m_first = false;
               }
            else
               {
               return ""; // done
               }
            }

         m_cur.reset(new std::ifstream(m_srcs[0]));

         if(!m_cur->good())
            throw std::runtime_error("Could not open input file '" + m_srcs[0]);

         m_srcs.pop_front();
         }

      while(m_cur->good())
         {
         std::string line;
         std::getline(*m_cur, line);

         if(line == "")
            continue;

         if(line[0] == '#')
            continue;

         return line;
         }
      }
   }

std::vector<Test::Result> Text_Based_Test::run()
   {
   std::vector<Test::Result> results;

   std::string who;
   VarMap vars;
   size_t test_cnt = 0;

   while(true)
      {
      std::string line = get_next_line();
      if(line == "")
         break;

      if(line[0] == '[' && line[line.size()-1] == ']')
         {
         who = line.substr(1, line.size() - 2);
         test_cnt = 0;
         continue;
         }

      const std::string test_id = "test " + std::to_string(test_cnt);

      const std::string key = line.substr(0, line.find_first_of(' '));
      const std::string val = line.substr(line.find_last_of(' ') + 1, std::string::npos);

      if(m_required_keys.count(key) == 0 && m_optional_keys.count(key) == 0)
         results.push_back(Test::Result::Failure(who, test_id + " failed unknown key " + key));

      vars[key] = val;

      if(key == m_output_key)
         {
         try
            {
            ++test_cnt;

            uint64_t start = timestamp();
            Test::Result result = run_one_test(who, vars);
            result.set_ns_consumed(timestamp() - start);

            if(result.tests_failed())
               result.test_note("Test #" + std::to_string(test_cnt) + " failed");
            results.push_back(result);
            }
         catch(std::exception& e)
            {
            results.push_back(Test::Result::Failure(who, "test " + std::to_string(test_cnt) + " failed with exception '" + e.what() + "'"));
            }

         if(clear_between_callbacks())
            {
            vars.clear();
            }
         }
      }

   return results;
   }

}


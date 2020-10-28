/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <sstream>
#include <fstream>
#include <iomanip>
#include <botan/hex.h>
#include <botan/parsing.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/stl_util.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
   #include <botan/point_gfp.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <stdlib.h>
   #include <unistd.h>
#endif

namespace Botan_Tests {

void Test::Result::merge(const Result& other)
   {
   if(who() != other.who())
      {
      throw Test_Error("Merging tests from different sources");
      }

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
         {
         out << ": " << extra;
         }
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
   try
      {
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
   try
      {
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
         return test_failure(what + " failed to throw an exception with the expected text:\n  Expected: " + expected +
                             "\n  Got: " + e.what());
         }
      }
   catch(...)
      {
      return test_failure(what + " failed to throw an exception with the expected text:\n  Expected: " + expected);
      }
   }

bool Test::Result::test_success(const std::string& note)
   {
   if(Test::options().log_success())
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

   if(Test::options().abort_on_first_fail() && m_who != "Failing Test")
      {
      std::abort();
      }
   return false;
   }

bool Test::Result::test_ne(const std::string& what,
                           const uint8_t produced[], size_t produced_len,
                           const uint8_t expected[], size_t expected_len)
   {
   if(produced_len == expected_len && Botan::same_mem(produced, expected, expected_len))
      {
      return test_failure(who() + ": " + what + " produced matching");
      }
   return test_success();
   }

bool Test::Result::test_eq(const char* producer, const std::string& what,
                           const uint8_t produced[], size_t produced_size,
                           const uint8_t expected[], size_t expected_size)
   {
   if(produced_size == expected_size && Botan::same_mem(produced, expected, expected_size))
      {
      return test_success();
      }

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
   size_t bytes_different = 0;

   for(size_t i = 0; i != xor_diff.size(); ++i)
      {
      xor_diff[i] = produced[i] ^ expected[i];
      bytes_different += (xor_diff[i] > 0);
      }

   err << "\nProduced: " << Botan::hex_encode(produced, produced_size)
       << "\nExpected: " << Botan::hex_encode(expected, expected_size);

   if(bytes_different > 0)
      {
      err << "\nXOR Diff: " << Botan::hex_encode(xor_diff);
      }

   return test_failure(err.str());
   }

bool Test::Result::test_is_nonempty(const std::string& what_is_it, const std::string& to_examine)
   {
   if(to_examine.empty())
      {
      return test_failure(what_is_it + " was empty");
      }
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

bool Test::Result::test_eq_sz(const std::string& what, size_t produced, size_t expected)
   {
   return test_is_eq(what, produced, expected);
   }

bool Test::Result::test_eq(const std::string& what,
                           Botan::OctetString produced,
                           Botan::OctetString expected)
   {
   std::ostringstream out;
   out << m_who << " " << what;

   if(produced == expected)
      {
      out << " produced expected result " << produced.to_string();
      return test_success(out.str());
      }
   else
      {
      out << " produced unexpected result '" << produced.to_string() << "' expected '" << expected.to_string() << "'";
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

bool Test::Result::test_gt(const std::string& what, size_t produced, size_t expected)
   {
   if(produced <= expected)
      {
      std::ostringstream err;
      err << m_who;
      err << " " << what;
      err << " unexpected result " << produced << " <= " << expected;
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
      {
      return test_success();
      }

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
      {
      return test_success();
      }

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

std::vector<std::string> Test::possible_providers(const std::string&)
   {
   return Test::provider_filter({ "base" });
   }

//static
std::string Test::format_time(uint64_t ns)
   {
   std::ostringstream o;

   if(ns > 1000000000)
      {
      o << std::setprecision(2) << std::fixed << ns / 1000000000.0 << " sec";
      }
   else
      {
      o << std::setprecision(2) << std::fixed << ns / 1000000.0 << " msec";
      }

   return o.str();
   }

std::string Test::Result::result_string() const
   {
   const bool verbose = Test::options().verbose();

   if(tests_run() == 0 && !verbose)
      {
      return "";
      }

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
      report << "Failure " << (i + 1) << ": " << m_fail_log[i] << "\n";
      }

   if(m_fail_log.size() > 0 || tests_run() == 0 || verbose)
      {
      for(size_t i = 0; i != m_log.size(); ++i)
         {
         report << "Note " << (i + 1) << ": " << m_log[i] << "\n";
         }
      }

   return report.str();
   }

// static Test:: functions
//static
std::map<std::string, std::function<Test* ()>>& Test::global_registry()
   {
   static std::map<std::string, std::function<Test* ()>> g_test_registry;
   return g_test_registry;
   }

//static
void Test::register_test(const std::string& category,
                         const std::string& name,
                         std::function<Test* ()> maker_fn)
   {
   BOTAN_UNUSED(category);
   if(Test::global_registry().count(name) != 0)
      throw Test_Error("Duplicate registration of test '" + name + "'");

   Test::global_registry().insert(std::make_pair(name, maker_fn));
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
std::unique_ptr<Test> Test::get_test(const std::string& test_name)
   {
   auto i = Test::global_registry().find(test_name);
   if(i != Test::global_registry().end())
      {
      return std::unique_ptr<Test>(i->second());
      }
   return nullptr;
   }

//static
std::string Test::temp_file_name(const std::string& basename)
   {
   // TODO add a --tmp-dir option to the tests to specify where these files go

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)

   // POSIX only calls for 6 'X' chars but OpenBSD allows arbitrary amount
   std::string mkstemp_basename = "/tmp/" + basename + ".XXXXXXXXXX";

   int fd = ::mkstemp(&mkstemp_basename[0]);

   // error
   if(fd < 0)
      {
      return "";
      }

   ::close(fd);

   return mkstemp_basename;
#else
   // For now just create the temp in the current working directory
   return basename;
#endif
   }

std::string Test::read_data_file(const std::string& path)
   {
   const std::string fsname = Test::data_file(path);
   std::ifstream file(fsname.c_str());
   if(!file.good())
      {
      throw Test_Error("Error reading from " + fsname);
      }

   return std::string((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
   }

std::vector<uint8_t> Test::read_binary_data_file(const std::string& path)
   {
   const std::string fsname = Test::data_file(path);
   std::ifstream file(fsname.c_str(), std::ios::binary);
   if(!file.good())
      {
      throw Test_Error("Error reading from " + fsname);
      }

   std::vector<uint8_t> contents;

   while(file.good())
      {
      std::vector<uint8_t> buf(4096);
      file.read(reinterpret_cast<char*>(buf.data()), buf.size());
      const size_t got = static_cast<size_t>(file.gcount());

      if(got == 0 && file.eof())
         {
         break;
         }

      contents.insert(contents.end(), buf.data(), buf.data() + got);
      }

   return contents;
   }

// static member variables of Test

Test_Options Test::m_opts;
std::unique_ptr<Botan::RandomNumberGenerator> Test::m_test_rng;

//static
void Test::set_test_options(const Test_Options& opts)
   {
   m_opts = opts;
   }

//static
void Test::set_test_rng(std::unique_ptr<Botan::RandomNumberGenerator> rng)
   {
   m_test_rng.reset(rng.release());
   }

//static
std::string Test::data_file(const std::string& what)
   {
   return Test::data_dir() + "/" + what;
   }

//static
std::vector<std::string> Test::provider_filter(const std::vector<std::string>& in)
   {
   if(m_opts.provider().empty())
      {
      return in;
      }
   for(auto&& provider : in)
      {
      if(provider == m_opts.provider())
         {
         return std::vector<std::string> { provider };
         }
      }
   return std::vector<std::string> {};
   }

//static
Botan::RandomNumberGenerator& Test::rng()
   {
   if(!m_test_rng)
      {
      throw Test_Error("Test requires RNG but no RNG set with Test::set_test_rng");
      }
   return *m_test_rng;
   }

std::string Test::random_password()
   {
   const size_t len = 1 + Test::rng().next_byte() % 32;
   return Botan::hex_encode(Test::rng().random_vec(len));
   }

std::vector<std::vector<uint8_t>> VarMap::get_req_bin_list(const std::string& key) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      throw Test_Error("Test missing variable " + key);
      }

   std::vector<std::vector<uint8_t>> bin_list;

   for(auto&& part : Botan::split_on(i->second, ','))
      {
      try
         {
         bin_list.push_back(Botan::hex_decode(part));
         }
      catch(std::exception& e)
         {
         std::ostringstream oss;
         oss << "Bad input '" << part << "'" << " in binary list key " << key << " - " << e.what();
         throw Test_Error(oss.str());
         }
      }

   return bin_list;
   }

std::vector<uint8_t> VarMap::get_req_bin(const std::string& key) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      throw Test_Error("Test missing variable " + key);
      }

   try
      {
      return Botan::hex_decode(i->second);
      }
   catch(std::exception& e)
      {
      std::ostringstream oss;
      oss << "Bad input '" << i->second << "'" << " for key " << key << " - " << e.what();
      throw Test_Error(oss.str());
      }
   }

std::string VarMap::get_opt_str(const std::string& key, const std::string& def_value) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      return def_value;
      }
   return i->second;
   }

bool VarMap::get_req_bool(const std::string& key) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      throw Test_Error("Test missing variable " + key);
      }

   if(i->second == "true")
      {
      return true;
      }
   else if(i->second == "false")
      {
      return false;
      }
   else
      {
      throw Test_Error("Invalid boolean for key '" + key + "' value '" + i->second + "'");
      }
   }

size_t VarMap::get_req_sz(const std::string& key) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      throw Test_Error("Test missing variable " + key);
      }
   return Botan::to_u32bit(i->second);
   }

uint8_t VarMap::get_req_u8(const std::string& key) const
   {
   const size_t s = this->get_req_sz(key);
   if(s > 256)
      {
      throw Test_Error("Invalid " + key + " expected uint8_t got " + std::to_string(s));
      }
   return static_cast<uint8_t>(s);
   }

uint32_t VarMap::get_req_u32(const std::string& key) const
   {
   return static_cast<uint32_t>(get_req_sz(key));
   }

uint64_t VarMap::get_req_u64(const std::string& key) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      throw Test_Error("Test missing variable " + key);
      }
   try
      {
      return std::stoull(i->second);
      }
   catch(std::exception&)
      {
      throw Test_Error("Invalid u64 value '" + i->second + "'");
      }
   }

size_t VarMap::get_opt_sz(const std::string& key, const size_t def_value) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      return def_value;
      }
   return Botan::to_u32bit(i->second);
   }

uint64_t VarMap::get_opt_u64(const std::string& key, const uint64_t def_value) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      return def_value;
      }
   try
      {
      return std::stoull(i->second);
      }
   catch(std::exception&)
      {
      throw Test_Error("Invalid u64 value '" + i->second + "'");
      }
   }

std::vector<uint8_t> VarMap::get_opt_bin(const std::string& key) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      return std::vector<uint8_t>();
      }

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

std::string VarMap::get_req_str(const std::string& key) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      throw Test_Error("Test missing variable " + key);
      }
   return i->second;
   }

#if defined(BOTAN_HAS_BIGINT)
Botan::BigInt VarMap::get_req_bn(const std::string& key) const
   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
      {
      throw Test_Error("Test missing variable " + key);
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

Botan::BigInt VarMap::get_opt_bn(const std::string& key,
                                 const Botan::BigInt& def_value) const

   {
   auto i = m_vars.find(key);
   if(i == m_vars.end())
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

Text_Based_Test::Text_Based_Test(const std::string& data_src,
                                 const std::string& required_keys_str,
                                 const std::string& optional_keys_str) :
   m_data_src(data_src)
   {
   if(required_keys_str.empty())
      {
      throw Test_Error("Invalid test spec");
      }

   std::vector<std::string> required_keys = Botan::split_on(required_keys_str, ',');
   std::vector<std::string> optional_keys = Botan::split_on(optional_keys_str, ',');

   m_required_keys.insert(required_keys.begin(), required_keys.end());
   m_optional_keys.insert(optional_keys.begin(), optional_keys.end());
   m_output_key = required_keys.at(required_keys.size() - 1);
   }

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
                     {
                     throw Test_Error("Error reading test data dir " + full_path);
                     }
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
            {
            throw Test_Error("Could not open input file '" + m_cur_src_name);
            }

         m_srcs.pop_front();
         }

      while(m_cur->good())
         {
         std::string line;
         std::getline(*m_cur, line);

         if(line.empty())
            {
            continue;
            }

         if(line[0] == '#')
            {
            if(line.compare(0, 6, "#test ") == 0)
               {
               return line;
               }
            else
               {
               continue;
               }
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
      {
      return "";
      }

   const auto last_c = in.find_last_not_of(whitespace);

   return in.substr(first_c, last_c - first_c + 1);
   }

std::vector<uint64_t>
parse_cpuid_bits(const std::vector<std::string>& tok)
   {
   std::vector<uint64_t> bits;
   for(size_t i = 1; i < tok.size(); ++i)
      {
      const std::vector<Botan::CPUID::CPUID_bits> more = Botan::CPUID::bit_from_string(tok[i]);
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
         {
         break;
         }

      if(line.compare(0, 6, "#test ") == 0)
         {
         std::vector<std::string> pragma_tokens = Botan::split_on(line.substr(6), ' ');

         if(pragma_tokens.empty())
            {
            throw Test_Error("Empty pragma found in " + m_cur_src_name);
            }

         if(pragma_tokens[0] != "cpuid")
            {
            throw Test_Error("Unknown test pragma '" + line + "' in " + m_cur_src_name);
            }

         m_cpu_flags = parse_cpuid_bits(pragma_tokens);

         continue;
         }
      else if(line[0] == '#')
         {
         throw Test_Error("Unknown test pragma '" + line + "' in " + m_cur_src_name);
         }

      if(line[0] == '[' && line[line.size() - 1] == ']')
         {
         header = line.substr(1, line.size() - 2);
         header_or_name = header;
         test_cnt = 0;
         vars.clear();
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

      vars.add(key, val);

      if(key == m_output_key)
         {
         try
            {
            if(skip_this_test(header, vars))
               continue;

            ++test_cnt;

            uint64_t start = Test::timestamp();

            Test::Result result = run_one_test(header, vars);
            if(m_cpu_flags.size() > 0)
               {
               for(auto const& cpuid_u64 : m_cpu_flags)
                  {
                  Botan::CPUID::CPUID_bits cpuid_bit = static_cast<Botan::CPUID::CPUID_bits>(cpuid_u64);
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
               {
               std::ostringstream oss;
               oss << "Test # " << test_cnt << " ";
               if(!header.empty())
                  oss << header << " ";
               oss << " failed [Key=" << vars.get_req_str(m_output_key) << "]";

               result.test_note(oss.str());
               }
            results.push_back(result);
            }
         catch(std::exception& e)
            {
            std::ostringstream oss;
            oss << "Test # " << test_cnt << " ";
            if(!header.empty())
               oss << header << " ";
            oss << " failed with exception '" << e.what() << "'";
            oss << " [Key=" << vars.get_req_str(m_output_key) << "]";

            results.push_back(Test::Result::Failure(header_or_name, oss.str()));
            }

         if(clear_between_callbacks())
            {
            vars.clear();
            }
         }
      }

   if(results.empty())
      {
      return results;
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

   m_first = true;

   return results;
   }

}

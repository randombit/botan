/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <iostream>
#include <fstream>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/bit_ops.h>

#define CATCH_CONFIG_RUNNER
#define CATCH_CONFIG_CONSOLE_WIDTH 60
#define CATCH_CONFIG_COLOUR_NONE
#include "catchy/catch.hpp"

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

using namespace Botan;


namespace Botan_Tests {

void Test::Result::merge(const Result& other)
   {
   if(who() != other.who())
      throw std::runtime_error("Merging tests from different sources");

   m_tests_passed += other.m_tests_passed;
   m_fail_log.insert(m_fail_log.end(), other.m_fail_log.begin(), other.m_fail_log.end());
   m_log.insert(m_log.end(), other.m_log.begin(), other.m_log.end());
   }

void Test::Result::test_note(const std::string& note)
   {
   m_log.push_back(who() + " " + note);
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
   if(produced_len == expected_len && same_mem(produced, expected, expected_len))
      return test_failure(who() + ":" + what + " produced matching");
   return test_success();
   }

bool Test::Result::test_eq(const char* producer, const char* what,
                           const uint8_t produced[], size_t produced_len,
                           const uint8_t expected[], size_t expected_len)
   {
   const std::string res = test_buffers_equal(m_who, producer, what,
                                              produced, produced_len,
                                              expected, expected_len);

   if(!res.empty())
      return test_failure(res);

   return test_success();
   }

bool Test::Result::test_eq(const char* what, size_t produced, size_t expected)
   {
   if(produced != expected)
      {
      std::ostringstream err;
      err << m_who;
      if(what)
         err << " " << what;
      err << " unexpected result produced " << produced << " expected " << expected << "\n";
      return test_failure(err);
      }

   return test_success();
   }

bool Test::Result::test_eq(const char* what, bool produced, bool expected)
   {
   if(produced != expected)
      {
      std::ostringstream err;
      err << m_who;
      if(what)
         err << " " << what;
      err << " unexpected result produced " << produced << " expected " << expected << "\n";
      return test_failure(err);
      }

   return test_success();
   }

std::string Test::Result::result_string() const
   {
   std::ostringstream report;
   report << who() << " ran " << tests_run() << " tests";

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

   if(m_fail_log.size() > 0)
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

//static
Test* Test::get_test(const std::string& test_name)
   {
   auto i = Test::global_registry().find(test_name);
   if(i != Test::global_registry().end())
      return i->second;
   return nullptr;
   }

//static
std::vector<Test::Result> Test::run_test(const std::string& what)
   {
   if(Test* test = get_test(what))
      return test->run();

   Test::Result missing(what);
   missing.test_note("No test found, possibly compiled out?");
   return std::vector<Test::Result>{missing};
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

//static
void Test::summarize(const std::vector<Test::Result>& results, std::string& report_out, size_t& fail_cnt)
   {
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

   size_t failures = 0;
   std::ostringstream report;
   for(auto&& result : combined)
      {
      report << result.second.result_string();

      // ADD test notes
      //report << result.second.result_string();
      failures += result.second.tests_failed();
      }

   fail_cnt = failures;
   report_out = report.str();
   }

Text_Based_Test::Text_Based_Test(const std::string& data_dir,
                                 const std::vector<std::string>& required_keys,
                                 const std::vector<std::string>& optional_keys,
                                 bool clear_between) :
   m_data_dir(data_dir),
   m_clear_between_cb(clear_between)
   {
   if(required_keys.empty())
      throw std::runtime_error("Invalid test spec");

   m_required_keys.insert(required_keys.begin(), required_keys.end());
   m_optional_keys.insert(optional_keys.begin(), optional_keys.end());
   m_output_key = required_keys.at(required_keys.size() - 1);
   }

std::vector<uint8_t> Text_Based_Test::get_req_bin(const std::map<std::string, std::string>& vars,
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

std::string Text_Based_Test::get_opt_str(const std::map<std::string, std::string>& vars,
                                         const std::string& key, const std::string& def_value) const

   {
   auto i = vars.find(key);
   if(i == vars.end())
      return def_value;
   return i->second;
   }

std::vector<uint8_t> Text_Based_Test::get_opt_bin(const std::map<std::string, std::string>& vars,
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

std::string Text_Based_Test::get_req_str(const std::map<std::string, std::string>& vars, const std::string& key) const
   {
   auto i = vars.find(key);
   if(i == vars.end())
      throw std::runtime_error("Test missing variable " + key);
   return i->second;
   }

#if defined(BOTAN_HAS_BIGINT)
Botan::BigInt Text_Based_Test::get_req_bn(const std::map<std::string, std::string>& vars,
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

               if(fs.empty())
                  m_srcs.push_back(m_data_dir);
               else
                  m_srcs.assign(fs.begin(), fs.end());

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
   std::map<std::string, std::string> vars;
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

            Test::Result result = run_one_test(who, vars);
            result.set_test_number(test_cnt);

            if(result.tests_failed() > 0)
               {
               //result.test_note(who + " test " + std::to_string(test_cnt) + " failed");
               }

            results.push_back(result);
            }
         catch(std::exception& e)
            {
            results.push_back(Test::Result::Failure(who, "test " + std::to_string(test_cnt) + " failed with exception '" + e.what() + "'"));
            }

         if(m_clear_between_cb)
            {
            vars.clear();
            }
         }
      }

   return results;
   }

size_t basic_error_report(const std::string& test)
   {
   std::vector<Test::Result> results = Test::run_test(test);

   std::string report;
   size_t fail_cnt = 0;
   Test::summarize(results, report, fail_cnt);

   std::cout << report;
   return fail_cnt;
   }

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

void check_invalid_signatures(Test::Result& result,
                              Botan::PK_Verifier& verifier,
                              const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& signature)
   {
   const std::vector<uint8_t> zero_sig(signature.size());
   result.test_eq("all zero signature invalid", verifier.verify_message(message, zero_sig), false);

   std::vector<uint8_t> bad_sig = signature;
   for(size_t i = 0; i <= Test::soak_level(); ++i)
      {
      size_t offset = Test::rng().get_random<uint16_t>() % bad_sig.size();
      bad_sig[offset] ^= Test::rng().next_nonzero_byte();

      if(!result.test_eq("incorrect signature invalid", verifier.verify_message(message, bad_sig), false))
         {
         result.test_note("Accepted invalid signature " + Botan::hex_encode(bad_sig));
         }
      }
   }

void check_invalid_ciphertexts(Test::Result& result,
                               Botan::PK_Decryptor& decryptor,
                               const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& ciphertext)
   {
   std::vector<uint8_t> bad_ctext = ciphertext;

   size_t ciphertext_accepted = 0, ciphertext_rejected = 0;

   for(size_t i = 0; i <= Test::soak_level(); ++i)
      {
      size_t offset = Test::rng().get_random<uint16_t>() % bad_ctext.size();
      bad_ctext[offset] ^= Test::rng().next_nonzero_byte();

      try
         {
         const Botan::secure_vector<uint8_t> decrypted = decryptor.decrypt(bad_ctext);
         ++ciphertext_accepted;

         if(!result.test_ne("incorrect ciphertext different", decrypted, plaintext))
            {
            result.test_note("used corrupted ciphertext " + Botan::hex_encode(bad_ctext));
            }

         }
      catch(std::exception& e)
         {
         ++ciphertext_rejected;
         }
      }

   result.test_note("Accepted " + std::to_string(ciphertext_accepted) +
                    " invalid ciphertexts, rejected " + std::to_string(ciphertext_rejected));
   }
#endif

}



Botan::RandomNumberGenerator& test_rng()
   {
   return Botan_Tests::Test::rng();
   }

size_t warn_about_missing(const std::string& whatever)
   {
   static std::set<std::string> s_already_seen;

   if(s_already_seen.count(whatever) == 0)
      {
      std::cout << "Skipping tests due to missing " << whatever << "\n";
      s_already_seen.insert(whatever);
      }

   return 0;
   }

std::string test_buffers_equal(const std::string& who,
                               const char* provider,
                               const char* what,
                               const uint8_t produced[],
                               size_t produced_size,
                               const uint8_t expected[],
                               size_t expected_size)
   {
   if(produced_size == expected_size && same_mem(produced, expected, expected_size))
      return "";

   std::ostringstream err;

   err << who;

   if(provider)
      {
      err << " provider " << provider;
      }
   if(what)
      {
      err << " " << what;
      }

   err << " unexpected result";

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
      bits_different += hamming_weight(xor_diff[i]);
      }

   err << "Produced: " << hex_encode(produced, produced_size) << "\n";
   err << "Expected: " << hex_encode(expected, expected_size) << "\n";
   if(bits_different > 0)
      {
      err << "XOR Diff: " << hex_encode(xor_diff)
          << " (" << bits_different << " bits different)\n";
      }

   return err.str();
   }

size_t run_tests_in_dir(const std::string& dir, std::function<size_t (const std::string&)> fn)
   {
   size_t fails = 0;

   try
      {
      auto files = get_files_recursive(dir);

      if (files.empty())
         std::cout << "Warning: No test files found in '" << dir << "'" << std::endl;

      for(const auto file: files)
         fails += fn(file);
      }
   catch(No_Filesystem_Access)
      {
      std::cout << "Warning: No filesystem access available to read test files in '" << dir << "'" << std::endl;
      }

   return fails;
   }

size_t run_tests(const std::vector<std::pair<std::string, test_fn>>& tests)
   {
   size_t fails = 0;

   for(const auto& row : tests)
      {
      auto name = row.first;
      auto test = row.second;
      try
         {
         fails += test();
         }
      catch(std::exception& e)
         {
         std::cout << name << ": Exception escaped test: " << e.what() << std::endl;
         ++fails;
         }
      catch(...)
         {
         std::cout << name << ": Exception escaped test" << std::endl;
         ++fails;
         }
      }

   // Summary for test suite
   std::cout << "===============" << std::endl;
   test_report("Tests", 0, fails);

   return fails;
   }

void test_report(const std::string& name, size_t ran, size_t failed)
   {
   std::cout << name;

   if(ran > 0)
      std::cout << " " << ran << " tests";

   if(failed)
      std::cout << " " << failed << " FAILs" << std::endl;
   else
      std::cout << " all ok" << std::endl;
   }

size_t run_tests_bb(std::istream& src,
                    const std::string& name_key,
                    const std::string& output_key,
                    bool clear_between_cb,
                    std::function<size_t (std::map<std::string, std::string>)> cb)
   {
   if(!src.good())
      {
      std::cout << "Could not open input file for " << name_key << std::endl;
      return 1;
      }

   std::map<std::string, std::string> vars;
   size_t test_fails = 0, algo_fail = 0;
   size_t test_count = 0, algo_count = 0;

   std::string fixed_name;

   while(src.good())
      {
      std::string line;
      std::getline(src, line);

      if(line == "")
         continue;

      if(line[0] == '#')
         continue;

      if(line[0] == '[' && line[line.size()-1] == ']')
         {
         if(fixed_name != "")
            test_report(fixed_name, algo_count, algo_fail);

         test_count += algo_count;
         test_fails += algo_fail;
         algo_count = 0;
         algo_fail = 0;
         fixed_name = line.substr(1, line.size() - 2);
         vars[name_key] = fixed_name;
         continue;
         }

      const std::string key = line.substr(0, line.find_first_of(' '));
      const std::string val = line.substr(line.find_last_of(' ') + 1, std::string::npos);

      vars[key] = val;

      if(key == name_key)
         fixed_name.clear();

      if(key == output_key)
         {
         //std::cout << vars[name_key] << " " << algo_count << std::endl;
         ++algo_count;
         try
            {
            const size_t fails = cb(vars);

            if(fails)
               {
               std::cout << vars[name_key] << " test " << algo_count << ": " << fails << " failure" << std::endl;
               algo_fail += fails;
               }
            }
         catch(std::exception& e)
            {
            std::cout << vars[name_key] << " test " << algo_count << " failed: " << e.what() << std::endl;
            ++algo_fail;
            }

         if(clear_between_cb)
            {
            vars.clear();
            vars[name_key] = fixed_name;
            }
         }
      }

   test_count += algo_count;
   test_fails += algo_fail;

   if(fixed_name != "" && (algo_count > 0 || algo_fail > 0))
      test_report(fixed_name, algo_count, algo_fail);
   else
      test_report(name_key, test_count, test_fails);

   return test_fails;
   }

size_t run_tests(const std::string& filename,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb)
   {
   std::ifstream vec(filename);

   if(!vec)
      {
      std::cout << "Failure opening " << filename << std::endl;
      return 1;
      }

   return run_tests(vec, name_key, output_key, clear_between_cb, cb);
   }

size_t run_tests(std::istream& src,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb)
   {
   return run_tests_bb(src, name_key, output_key, clear_between_cb,
                [name_key,output_key,cb](std::map<std::string, std::string> vars)
                {
                const std::string got = cb(vars);
                if(got != vars[output_key])
                   {
                   std::cout << name_key << ' ' << vars[name_key] << " got " << got
                             << " expected " << vars[output_key] << std::endl;
                   return 1;
                   }
                return 0;
                });
   }

namespace {

int help(char* argv0)
   {
   std::cout << "Usage: " << argv0 << " [suite]" << std::endl;
   std::cout << "Suites: all (default), block, hash, bigint, rsa, ecdsa, ..." << std::endl;
   return 1;
   }

int test_catchy()
   {
   // drop arc and arv for now
   int catchy_result = Catch::Session().run();
   if (catchy_result != 0)
      {
      std::exit(EXIT_FAILURE);
      }
   return 0;
   }

}

int main(int argc, char* argv[])
   {
   if(argc != 1 && argc != 2)
      return help(argv[0]);

   std::string target = "all";

   if(argc == 2)
      target = argv[1];

   if(target == "-h" || target == "--help" || target == "help")
      return help(argv[0]);

   std::vector<std::pair<std::string, test_fn>> tests;

#define DEF_TEST(test) do { if(target == "all" || target == #test) \
      tests.push_back(std::make_pair(#test, test_ ## test));       \
   } while(0)

   // unittesting framework in sub-folder tests/catchy
   DEF_TEST(catchy);

   //DEF_TEST(block);
   DEF_TEST(modes);
   DEF_TEST(aead);
   DEF_TEST(ocb);

   DEF_TEST(stream);
   DEF_TEST(hash);
   DEF_TEST(mac);
   DEF_TEST(pbkdf);
   DEF_TEST(kdf);
   DEF_TEST(keywrap);
   DEF_TEST(transform);
   DEF_TEST(rngs);
   DEF_TEST(passhash9);
   DEF_TEST(bcrypt);
   DEF_TEST(cryptobox);
   DEF_TEST(tss);
   DEF_TEST(rfc6979);
   DEF_TEST(srp6);

   DEF_TEST(bigint);

   DEF_TEST(rsa);
   DEF_TEST(rw);
   DEF_TEST(dsa);
   DEF_TEST(nr);
   DEF_TEST(dh);
   DEF_TEST(dlies);
   DEF_TEST(elgamal);
   DEF_TEST(ecc_pointmul);
   DEF_TEST(ecdsa);
   DEF_TEST(gost_3410);
   DEF_TEST(curve25519);
   DEF_TEST(gf2m);
   DEF_TEST(mceliece);
   DEF_TEST(mce);

   DEF_TEST(ecc_unit);
   DEF_TEST(ecc_randomized);
   DEF_TEST(ecdsa_unit);
   DEF_TEST(ecdh_unit);
   DEF_TEST(pk_keygen);
   DEF_TEST(cvc);
   DEF_TEST(x509);
   DEF_TEST(x509_x509test);
   DEF_TEST(nist_x509);
   DEF_TEST(tls);
   DEF_TEST(compression);
   DEF_TEST(fuzzer);

   if(tests.empty())
      {
      std::cout << "No tests selected by target '" << target << "'" << std::endl;
      return 1;
      }

   return run_tests(tests);
   }

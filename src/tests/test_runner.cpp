/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_runner.h"
#include "tests.h"

#include <botan/version.h>
#include <botan/rotate.h>
#include <botan/loadstor.h>

namespace Botan_Tests {

Test_Runner::Test_Runner(std::ostream& out) : m_output(out) {}

namespace {

/*
* This is a fast, simple, deterministic PRNG that's used for running
* the tests. It is not intended to be cryptographically secure.
*/
class Testsuite_RNG final : public Botan::RandomNumberGenerator
   {
   public:
      std::string name() const override { return "Testsuite_RNG"; }

      void clear() override
         {
         m_a = m_b = m_c = m_d = 0;
         }

      void add_entropy(const uint8_t data[], size_t len) override
         {
         for(size_t i = 0; i != len; ++i)
            {
            m_a ^= data[i];
            m_b ^= i;
            mix();
            }
         }

      bool is_seeded() const override
         {
         return true;
         }

      void randomize(uint8_t out[], size_t len) override
         {
         for(size_t i = 0; i != len; ++i)
            {
            out[i] = static_cast<uint8_t>(m_a);
            mix();
            }
         }

      Testsuite_RNG(const std::string& drbg_seed, size_t test_counter = 0)
         {
         m_d = static_cast<uint32_t>(test_counter);

         add_entropy(reinterpret_cast<const uint8_t*>(drbg_seed.data()),
                     drbg_seed.size());
         }
   private:
      void mix()
         {
         const size_t ROUNDS = 3;

         for(size_t i = 0; i != ROUNDS; ++i)
            {
            m_a += i;

            m_a = Botan::rotl<9>(m_a);
            m_b ^= m_a;
            m_d ^= m_c;

            m_a += m_d;
            m_c += m_b;
            m_c = Botan::rotl<23>(m_c);
            }
         }

      uint32_t m_a = 0, m_b = 0, m_c = 0, m_d = 0;
   };

}

int Test_Runner::run(const std::vector<std::string>& requested_tests,
                     const std::string& data_dir,
                     const std::string& pkcs11_lib,
                     const std::string& provider,
                     bool log_success,
                     bool run_online_tests,
                     bool run_long_tests,
                     const std::string& drbg_seed,
                     size_t runs)
   {
   std::vector<std::string> req = requested_tests;

   if(req.empty())
      {
      /*
      If nothing was requested on the command line, run everything. First
      run the "essentials" to smoke test, then everything else in
      alphabetical order.
      */
      req = {"block", "stream", "hash", "mac", "modes", "aead"
             "kdf", "pbkdf", "hmac_drbg", "util"
      };

      std::set<std::string> all_others = Botan_Tests::Test::registered_tests();

      if(pkcs11_lib.empty())
         {
         // do not run pkcs11 tests by default unless pkcs11-lib set
         for(std::set<std::string>::iterator iter = all_others.begin(); iter != all_others.end();)
            {
            if((*iter).find("pkcs11") != std::string::npos)
               {
               iter = all_others.erase(iter);
               }
            else
               {
               ++iter;
               }
            }
         }

      for(auto f : req)
         {
         all_others.erase(f);
         }

      req.insert(req.end(), all_others.begin(), all_others.end());
      }
   else if(req.size() == 1 && req.at(0) == "pkcs11")
      {
      req = {"pkcs11-manage", "pkcs11-module", "pkcs11-slot", "pkcs11-session", "pkcs11-object", "pkcs11-rsa",
             "pkcs11-ecdsa", "pkcs11-ecdh", "pkcs11-rng", "pkcs11-x509"
      };
      }
   else
      {
      std::set<std::string> all = Botan_Tests::Test::registered_tests();
      for(auto const& r : req)
         {
         if(all.find(r) == all.end())
            {
            throw Botan_Tests::Test_Error("Unknown test suite: " + r);
            }
         }
      }

   output() << "Testing " << Botan::version_string() << "\n";
   output() << "Starting tests";

   if(!pkcs11_lib.empty())
      {
      output() << " pkcs11 library:" << pkcs11_lib;
      }

   Botan_Tests::Provider_Filter pf;
   if(!provider.empty())
      {
      output() << " provider:" << provider;
      pf.set(provider);
      }

   std::vector<uint8_t> seed = Botan::hex_decode(drbg_seed);
   if(seed.empty())
      {
      const uint64_t ts = Botan_Tests::Test::timestamp();
      seed.resize(8);
      Botan::store_be(ts, seed.data());
      }

   output() << " drbg_seed:" << Botan::hex_encode(seed) << "\n";

   Botan_Tests::Test::set_test_options(log_success,
                                       run_online_tests,
                                       run_long_tests,
                                       data_dir,
                                       pkcs11_lib,
                                       pf);

   for(size_t i = 0; i != runs; ++i)
      {
      std::unique_ptr<Botan::RandomNumberGenerator> rng =
         std::unique_ptr<Botan::RandomNumberGenerator>(new Testsuite_RNG(drbg_seed, i));

      Botan_Tests::Test::set_test_rng(std::move(rng));

      const size_t failed = run_tests(req, i, runs);
      if(failed > 0)
         return failed;
      }

   return 0;
   }

namespace {

std::string report_out(const std::vector<Botan_Tests::Test::Result>& results,
                       size_t& tests_failed,
                       size_t& tests_ran)
   {
   std::ostringstream out;

   std::map<std::string, Botan_Tests::Test::Result> combined;
   for(auto const& result : results)
      {
      const std::string who = result.who();
      auto i = combined.find(who);
      if(i == combined.end())
         {
         combined.insert(std::make_pair(who, Botan_Tests::Test::Result(who)));
         i = combined.find(who);
         }

      i->second.merge(result);
      }

   for(auto const& result : combined)
      {
      const bool verbose = false;
      out << result.second.result_string(verbose);
      tests_failed += result.second.tests_failed();
      tests_ran += result.second.tests_run();
      }

   return out.str();
   }

}

size_t Test_Runner::run_tests(const std::vector<std::string>& tests_to_run,
                              size_t test_run,
                              size_t tot_test_runs)
   {
   size_t tests_ran = 0, tests_failed = 0;

   const uint64_t start_time = Botan_Tests::Test::timestamp();

   for(auto const& test_name : tests_to_run)
      {
      output() << test_name << ':' << std::endl;

      std::vector<Test::Result> results;

      try
         {
         if(Test* test = Test::get_test(test_name))
            {
            std::vector<Test::Result> test_results = test->run();
            results.insert(results.end(), test_results.begin(), test_results.end());
            }
         else
            {
            results.push_back(Test::Result::Note(test_name, "Test missing or unavailable"));
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

      output() << report_out(results, tests_failed, tests_ran) << std::flush;
      }

   const uint64_t total_ns = Botan_Tests::Test::timestamp() - start_time;

   if(test_run == 0 && tot_test_runs == 1)
      output() << "Tests";
   else
      output() << "Test run " << (1+test_run) << "/" << tot_test_runs;

   output() << " complete ran " << tests_ran << " tests in "
            << Botan_Tests::Test::format_time(total_ns) << " ";

   if(tests_failed > 0)
      {
      output() << tests_failed << " tests failed";
      }
   else if(tests_ran > 0)
      {
      output() << "all tests ok";
      }

   output() << std::endl;

   return tests_failed;
   }

}


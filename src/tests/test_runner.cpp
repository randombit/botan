/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_runner.h"
#include "tests.h"

#include <botan/version.h>
#include <botan/loadstor.h>
#include <botan/mac.h>

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

namespace Botan_Tests {

Test_Runner::Test_Runner(std::ostream& out) : m_output(out) {}

namespace {

std::unique_ptr<Botan::RandomNumberGenerator>
create_test_rng(const std::string& drbg_seed, std::ostream& output)
   {
   std::unique_ptr<Botan::RandomNumberGenerator> rng;

#if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_AUTO_RNG_HMAC)

   std::vector<uint8_t> seed = Botan::hex_decode(drbg_seed);
   if(seed.empty())
      {
      const uint64_t ts = Botan_Tests::Test::timestamp();
      seed.resize(8);
      Botan::store_be(ts, seed.data());
      }

   output << " rng:HMAC_DRBG(" << BOTAN_AUTO_RNG_HMAC << ") with seed '" << Botan::hex_encode(seed) << "'\n";

   // Expand out the seed with a hash to make the DRBG happy
   std::unique_ptr<Botan::MessageAuthenticationCode> mac =
      Botan::MessageAuthenticationCode::create(BOTAN_AUTO_RNG_HMAC);

   mac->set_key(seed);
   seed.resize(mac->output_length());
   mac->final(seed.data());

   std::unique_ptr<Botan::HMAC_DRBG> drbg(new Botan::HMAC_DRBG(std::move(mac)));
   drbg->initialize_with(seed.data(), seed.size());

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   rng.reset(new Botan::Serialized_RNG(drbg.release()));
#else
   rng = std::move(drbg);
#endif

#endif

   if(!rng && drbg_seed != "")
      throw Botan_Tests::Test_Error("HMAC_DRBG disabled in build, cannot specify DRBG seed");

#if defined(BOTAN_HAS_SYSTEM_RNG)
   if(!rng)
      {
      output << " rng:system\n";
      rng.reset(new Botan::System_RNG);
      }
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   if(!rng)
      {
      output << " rng:autoseeded\n";
#if defined(BOTAN_TARGET_OS_HAS_THREADS)
      rng.reset(new Botan::Serialized_RNG(new Botan::AutoSeeded_RNG));
#else
      rng.reset(new Botan::AutoSeeded_RNG);
#endif

      }
#endif

   if(!rng)
      {
      // last ditch fallback for RNG-less build
      class Bogus_Fallback_RNG final : public Botan::RandomNumberGenerator
         {
         public:
            std::string name() const override { return "Bogus_Fallback_RNG"; }

            void clear() override { /* ignored */ }
            void add_entropy(const uint8_t[], size_t) override { /* ignored */ }
            bool is_seeded() const override { return true; }

            void randomize(uint8_t out[], size_t len) override
               {
               for(size_t i = 0; i != len; ++i)
                  {
                  m_x = (m_x * 31337 + 42);
                  out[i] = static_cast<uint8_t>(m_x >> 7);
                  }
               }

            Bogus_Fallback_RNG() : m_x(1) {}
         private:
            uint32_t m_x;
         };

      output << " rng:bogus\n";
      rng.reset(new Bogus_Fallback_RNG);
      }

   return rng;
   }

}

std::string Test_Runner::help_text() const
   {
   std::ostringstream err;

   err << "Usage: botan-test "
       << "--run-long-tests --run-online-tests --test-runs=1 --drbg-seed= --data-dir= --pkcs11-lib= --provider= --log-success"
       << "\n\nAvailable test suites\n"
       << "----------------\n";

   size_t line_len = 0;

   for(auto const& test : Botan_Tests::Test::registered_tests())
      {
      err << test << " ";
      line_len += test.size() + 1;

      if(line_len > 64)
         {
         err << "\n";
         line_len = 0;
         }
      }

   if(line_len > 0)
      {
      err << "\n";
      }

   return err.str();
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

   std::unique_ptr<Botan::RandomNumberGenerator> rng = create_test_rng(drbg_seed, output());

   Botan_Tests::Test::setup_tests(log_success, run_online_tests, run_long_tests,
                                  data_dir, pkcs11_lib, pf, rng.get());

   for(size_t i = 0; i != runs; ++i)
      {
      const size_t failed = run_tests(req);

      // Throw so main returns an error
      if(failed)
         {
         return failed;
         }
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

size_t Test_Runner::run_tests(const std::vector<std::string>& tests_to_run)
   {
   size_t tests_ran = 0, tests_failed = 0;

   const uint64_t start_time = Botan_Tests::Test::timestamp();

   for(auto const& test_name : tests_to_run)
      {
      try
         {
         output() << test_name << ':' << std::endl;
         const auto results = Botan_Tests::Test::run_test(test_name, false);
         output() << report_out(results, tests_failed, tests_ran) << std::flush;
         }
      catch(std::exception& e)
         {
         output() << "Test " << test_name << " failed with exception " << e.what() << std::flush;
         }
      }

   const uint64_t total_ns = Botan_Tests::Test::timestamp() - start_time;
   output() << "Tests complete ran " << tests_ran << " tests in "
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


/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../tests.h"

#include "test_runner.h"
#include "test_stdout_reporter.h"

#include <botan/version.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/cpuid.h>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
   #include <botan/internal/rwlock.h>
#endif

namespace Botan_Tests {

Test_Runner::Test_Runner(std::ostream& out) : m_output(out) {}
Test_Runner::~Test_Runner() = default;

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
         m_x = 0;
         }

      bool accepts_input() const override { return true; }

      void add_entropy(const uint8_t data[], size_t len) override
         {
         for(size_t i = 0; i != len; ++i)
            {
            mix(data[i]);
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
            out[i] = mix();
            }
         }

      Testsuite_RNG(const std::vector<uint8_t>& seed, uint64_t test_counter)
         {
         m_x = ~test_counter;
         add_entropy(seed.data(), seed.size());
         }
   private:
      uint8_t mix(uint8_t input = 0)
         {
         m_x ^= input;
         m_x *= 0xF2E16957;
         m_x += 0xE50B590F;
         return static_cast<uint8_t>(m_x >> 27);
         }

      uint64_t m_x;
   };

}

bool Test_Runner::run(const Test_Options& opts)
   {
   std::vector<std::string> req = opts.requested_tests();
   const std::set<std::string>& to_skip = opts.skip_tests();

   m_reporters.emplace_back(std::make_unique<StdoutReporter>(opts, output()));

   if(req.empty())
      {
      /*
      If nothing was requested on the command line, run everything. First
      run the "essentials" to smoke test, then everything else in
      alphabetical order.
      */

      std::vector<std::string> default_first = {
         "block", "stream", "hash", "mac", "aead",
         "modes", "kdf", "pbkdf", "hmac_drbg", "util"
      };

      for(const auto& s : default_first)
         {
         if(to_skip.count(s) == 0)
            req.push_back(s);
         }

      std::set<std::string> all_others = Botan_Tests::Test::registered_tests();

      if(opts.pkcs11_lib().empty())
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

      for(const auto& f : req)
         {
         all_others.erase(f);
         }

      for(const std::string& f : to_skip)
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

   std::vector<uint8_t> seed = Botan::hex_decode(opts.drbg_seed());
   if(seed.empty())
      {
      const uint64_t ts = Botan_Tests::Test::timestamp();
      seed.resize(8);
      Botan::store_be(ts, seed.data());
      }

   for(auto& reporter : m_reporters)
      {
      const std::string cpuid = Botan::CPUID::to_string();
      if(!cpuid.empty())
         reporter->set_property("CPU flags", cpuid);

      if(!opts.pkcs11_lib().empty())
         reporter->set_property("pkcs11 library", opts.pkcs11_lib());

      if(!opts.provider().empty())
         reporter->set_property("provider", opts.provider());

      reporter->set_property("drbg_seed", Botan::hex_encode(seed));
      }

   Botan_Tests::Test::set_test_options(opts);

   for(size_t i = 0; i != opts.test_runs(); ++i)
      {
      auto rng = std::make_unique<Testsuite_RNG>(seed, i);

      Botan_Tests::Test::set_test_rng(std::move(rng));

      for(const auto& reporter : m_reporters)
         {
         reporter->next_test_run();
         }

      const bool passed =
         (opts.test_threads() == 1)
            ? run_tests(req)
            : run_tests_multithreaded(req, opts.test_threads());

      for(const auto& reporter : m_reporters)
         {
         reporter->render();
         }

      if(!passed)
         return false;
      }

   return true;
   }

namespace {

std::vector<Test::Result> run_a_test(const std::string& test_name)
   {
   std::vector<Test::Result> results;

   try
      {
      if(test_name == "simd_32" && Botan::CPUID::has_simd_32() == false)
         {
         results.push_back(Test::Result::Note(test_name, "SIMD not available on this platform"));
         }
      else if(std::unique_ptr<Test> test = Test::get_test(test_name))
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

   return results;
   }

#if defined(BOTAN_HAS_THREAD_UTILS)

bool needs_serialization(const std::string& test_name)
   {
   if(test_name.substr(0, 6) == "pkcs11")
      return true;
   if(test_name == "block" || test_name == "hash" || test_name == "mac" || test_name == "stream" || test_name == "aead")
      return true;
   if(test_name == "ecc_unit")
      return false;
   return false;
   }

#endif

bool all_passed(const std::vector<Test::Result>& results)
   {
   return std::all_of(results.begin(), results.end(),
                      [](const auto& r) { return r.tests_failed() == 0; });
   }

}

bool Test_Runner::run_tests_multithreaded(const std::vector<std::string>& tests_to_run,
                                          size_t test_threads)
   {
   // If 0 then we let thread pool select the count
   BOTAN_ASSERT_NOMSG(test_threads != 1);

#if !defined(BOTAN_HAS_THREAD_UTILS)
   output() << "Running tests in multiple threads not enabled in this build\n";
   return run_tests(tests_to_run);

#else
   Botan::Thread_Pool pool(test_threads);
   Botan::RWLock rwlock;

   std::vector<std::future<std::vector<Test::Result>>> m_fut_results;

   auto run_test_exclusive = [&](const std::string& test_name) {
      rwlock.lock();
      std::vector<Test::Result> results = run_a_test(test_name);
      rwlock.unlock();
      return results;
   };

   auto run_test_shared = [&](const std::string& test_name) {
      rwlock.lock_shared();
      std::vector<Test::Result> results = run_a_test(test_name);
      rwlock.unlock_shared();
      return results;
   };

   for(auto const& test_name : tests_to_run)
      {
      if(needs_serialization(test_name))
         {
         m_fut_results.push_back(pool.run(run_test_exclusive, test_name));
         }
      else
         {
         m_fut_results.push_back(pool.run(run_test_shared, test_name));
         }
      }

   bool passed = true;
   for(size_t i = 0; i != m_fut_results.size(); ++i)
      {
      const auto results = m_fut_results[i].get();
      for(auto& reporter : m_reporters)
         {
         reporter->record(tests_to_run[i], results);
         }
      passed &= all_passed(results);
      }

   pool.shutdown();

   return passed;
#endif
   }

bool Test_Runner::run_tests(const std::vector<std::string>& tests_to_run)
   {
   bool passed = true;
   for(auto const& test_name : tests_to_run)
      {
      const auto results = run_a_test(test_name);

      for(auto& reporter : m_reporters)
         {
         reporter->record(test_name, results);
         }
      passed &= all_passed(results);
      }

   return passed;
   }

}

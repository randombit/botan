/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_runner.h"
#include "tests.h"

#include <botan/version.h>
#include <botan/loadstor.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
   #include <botan/internal/rwlock.h>
#endif

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

      bool accepts_input() const override { return true; }

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

      Testsuite_RNG(const std::vector<uint8_t>& seed, size_t test_counter = 0)
         {
         m_d = static_cast<uint32_t>(test_counter);

         add_entropy(seed.data(), seed.size());
         }
   private:
      void mix()
         {
         const size_t ROUNDS = 3;

         for(size_t i = 0; i != ROUNDS; ++i)
            {
            m_a += static_cast<uint32_t>(i ^ 0x5555);

            m_a *= 0x9e3779b9;
            m_b ^= m_a;
            m_d ^= m_c;

            m_a += m_d;
            m_c += m_b;

            m_c += (m_c >> 17);
            }
         }

      uint32_t m_a = 0, m_b = 0, m_c = 0, m_d = 0;
   };

}

int Test_Runner::run(const Test_Options& opts)
   {
   std::vector<std::string> req = opts.requested_tests();
   const std::set<std::string> to_skip = opts.skip_tests();

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

      for(auto s : default_first)
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

      for(auto f : req)
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

   output() << "Testing " << Botan::version_string() << "\n";

   const std::string cpuid = Botan::CPUID::to_string();
   if(cpuid.size() > 0)
      output() << "CPU flags: " << cpuid << "\n";
   output() << "Starting tests";

   if(!opts.pkcs11_lib().empty())
      {
      output() << " pkcs11 library:" << opts.pkcs11_lib();
      }

   if(!opts.provider().empty())
      {
      output() << " provider:" << opts.provider();
      }

   std::vector<uint8_t> seed = Botan::hex_decode(opts.drbg_seed());
   if(seed.empty())
      {
      const uint64_t ts = Botan_Tests::Test::timestamp();
      seed.resize(8);
      Botan::store_be(ts, seed.data());
      }

   output() << " drbg_seed:" << Botan::hex_encode(seed) << "\n";

   Botan_Tests::Test::set_test_options(opts);

   for(size_t i = 0; i != opts.test_runs(); ++i)
      {
      std::unique_ptr<Botan::RandomNumberGenerator> rng =
         std::unique_ptr<Botan::RandomNumberGenerator>(new Testsuite_RNG(seed, i));

      Botan_Tests::Test::set_test_rng(std::move(rng));

      const size_t failed = run_tests(req, opts.test_threads(), i, opts.test_runs());
      if(failed > 0)
         return static_cast<int>(failed);
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
      out << result.second.result_string();
      tests_failed += result.second.tests_failed();
      tests_ran += result.second.tests_run();
      }

   return out.str();
   }

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

std::string test_summary(size_t test_run, size_t tot_test_runs, uint64_t total_ns,
                         size_t tests_ran, size_t tests_failed)
   {
   std::ostringstream oss;

   if(test_run == 0 && tot_test_runs == 1)
      oss << "Tests";
   else
      oss << "Test run " << (1+test_run) << "/" << tot_test_runs;

   oss << " complete ran " << tests_ran << " tests in "
            << Botan_Tests::Test::format_time(total_ns) << " ";

   if(tests_failed > 0)
      {
      oss << tests_failed << " tests failed";
      }
   else if(tests_ran > 0)
      {
      oss << "all tests ok";
      }

   oss << "\n";
   return oss.str();
   }

#if defined(BOTAN_HAS_THREAD_UTILS)

bool needs_serialization(const std::string& test_name)
   {
   if(test_name.substr(0, 6) == "pkcs11")
      return true;
   if(test_name == "block" || test_name == "hash" || test_name == "mac" || test_name == "stream" || test_name == "aead")
      return true;
   return false;
   }

#endif

}

size_t Test_Runner::run_tests(const std::vector<std::string>& tests_to_run,
                              size_t test_threads,
                              size_t test_run,
                              size_t tot_test_runs)
   {
   size_t tests_ran = 0, tests_failed = 0;
   const uint64_t start_time = Botan_Tests::Test::timestamp();

#if defined(BOTAN_HAS_THREAD_UTILS)
   if(test_threads != 1)
      {
      // If 0 then we let thread pool select the count
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

      for(size_t i = 0; i != m_fut_results.size(); ++i)
         {
         output() << tests_to_run[i] << ':' << std::endl;
         const std::vector<Test::Result> results = m_fut_results[i].get();
         output() << report_out(results, tests_failed, tests_ran) << std::flush;
         }

      pool.shutdown();

      const uint64_t total_ns = Botan_Tests::Test::timestamp() - start_time;

      output() << test_summary(test_run, tot_test_runs, total_ns, tests_ran, tests_failed);

      return tests_failed;
      }
#else
   if(test_threads > 1)
      {
      output() << "Running tests in multiple threads not enabled in this build\n";
      }
#endif

   for(auto const& test_name : tests_to_run)
      {
      output() << test_name << ':' << std::endl;
      const std::vector<Test::Result> results = run_a_test(test_name);
      output() << report_out(results, tests_failed, tests_ran) << std::flush;
      }

   const uint64_t total_ns = Botan_Tests::Test::timestamp() - start_time;

   output() << test_summary(test_run, tot_test_runs, total_ns, tests_ran, tests_failed);

   return tests_failed;
   }

}


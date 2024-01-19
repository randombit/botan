/*
* (C) 2017 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../tests.h"

#include "test_runner.h"
#include "test_stdout_reporter.h"
#include "test_xml_reporter.h"

#include <botan/version.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/loadstor.h>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/rwlock.h>
   #include <botan/internal/thread_pool.h>
#endif

#include <shared_mutex>

namespace Botan_Tests {

Test_Runner::Test_Runner(std::ostream& out) : m_output(out) {}

Test_Runner::~Test_Runner() = default;

bool Test_Runner::run(const Test_Options& opts) {
   if(!opts.no_stdout()) {
      m_reporters.emplace_back(std::make_unique<StdoutReporter>(opts, output()));
   }
   if(!opts.xml_results_dir().empty()) {
#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      m_reporters.emplace_back(std::make_unique<XmlReporter>(opts, opts.xml_results_dir()));
#else
      output() << "Generating test report files is not supported on this platform\n";
#endif
   }

   auto req = Botan_Tests::Test::filter_registered_tests(opts.requested_tests(), opts.skip_tests());

   // TODO: Test runner should not be aware of certain test's environmental requirements.
   if(opts.pkcs11_lib().empty()) {
      // do not run pkcs11 tests by default unless pkcs11-lib set
      for(auto iter = req.begin(); iter != req.end();) {
         if((*iter).find("pkcs11") != std::string::npos) {
            iter = req.erase(iter);
         } else {
            ++iter;
         }
      }
   }

   if(req.empty()) {
      throw Test_Error("No tests to run");
   }

   std::vector<uint8_t> seed = Botan::hex_decode(opts.drbg_seed());
   if(seed.empty()) {
      const uint64_t ts = Botan_Tests::Test::timestamp();
      seed.resize(8);
      Botan::store_be(ts, seed.data());
   }

   for(auto& reporter : m_reporters) {
      const std::string cpuid = Botan::CPUID::to_string();
      if(!cpuid.empty()) {
         reporter->set_property("CPU flags", cpuid);
      }

      if(!opts.pkcs11_lib().empty()) {
         reporter->set_property("pkcs11 library", opts.pkcs11_lib());
      }

      if(!opts.provider().empty()) {
         reporter->set_property("provider", opts.provider());
      }

      reporter->set_property("drbg_seed", Botan::hex_encode(seed));
   }

   Botan_Tests::Test::set_test_options(opts);

   for(size_t i = 0; i != opts.test_runs(); ++i) {
      Botan_Tests::Test::set_test_rng_seed(seed, i);

      for(const auto& reporter : m_reporters) {
         reporter->next_test_run();
      }

      const bool passed =
         (opts.test_threads() == 1) ? run_tests(req) : run_tests_multithreaded(req, opts.test_threads());

      for(const auto& reporter : m_reporters) {
         reporter->render();
      }

      if(!passed) {
         return false;
      }
   }

   return true;
}

namespace {

std::vector<Test::Result> run_a_test(const std::string& test_name) {
   std::vector<Test::Result> results;

   try {
      if(test_name == "simd_32" && Botan::CPUID::has_simd_32() == false) {
         results.push_back(Test::Result::Note(test_name, "SIMD not available on this platform"));
      } else if(std::unique_ptr<Test> test = Test::get_test(test_name)) {
         std::vector<Test::Result> test_results = test->run();
         for(auto& result : test_results) {
            if(!result.code_location() && test->registration_location()) {
               // If a test result has no specific code location associated to it,
               // we fall back to the test case's registration location.
               result.set_code_location(test->registration_location().value());
            }
         }
         results.insert(results.end(), test_results.begin(), test_results.end());
      } else {
         results.push_back(Test::Result::Note(test_name, "Test missing or unavailable"));
      }
   } catch(std::exception& e) {
      results.push_back(Test::Result::Failure(test_name, e.what()));
   } catch(...) {
      results.push_back(Test::Result::Failure(test_name, "unknown exception"));
   }

   return results;
}

bool all_passed(const std::vector<Test::Result>& results) {
   return std::all_of(results.begin(), results.end(), [](const auto& r) { return r.tests_failed() == 0; });
}

}  // namespace

bool Test_Runner::run_tests_multithreaded(const std::vector<std::string>& tests_to_run, size_t test_threads) {
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
      std::unique_lock lk(rwlock);
      return run_a_test(test_name);
   };

   auto run_test_shared = [&](const std::string& test_name) {
      std::shared_lock lk(rwlock);
      return run_a_test(test_name);
   };

   for(const auto& test_name : tests_to_run) {
      if(Test::test_needs_serialization(test_name)) {
         m_fut_results.push_back(pool.run(run_test_exclusive, test_name));
      } else {
         m_fut_results.push_back(pool.run(run_test_shared, test_name));
      }
   }

   bool passed = true;
   for(size_t i = 0; i != m_fut_results.size(); ++i) {
      const auto results = m_fut_results[i].get();
      for(auto& reporter : m_reporters) {
         reporter->record(tests_to_run[i], results);
      }
      passed &= all_passed(results);
   }

   pool.shutdown();

   return passed;
#endif
}

bool Test_Runner::run_tests(const std::vector<std::string>& tests_to_run) {
   bool passed = true;
   for(const auto& test_name : tests_to_run) {
      const auto results = run_a_test(test_name);

      for(auto& reporter : m_reporters) {
         reporter->record(test_name, results);
      }
      passed &= all_passed(results);
   }

   return passed;
}

}  // namespace Botan_Tests

/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../cli/cli.h"
#include "tests.h"
#include <iostream>
#include <sstream>
#include <string>
#include <set>
#include <deque>
#include <thread>
#include <future>

#include <botan/version.h>
#include <botan/loadstor.h>
#include <botan/hash.h>

#if defined(BOTAN_HAS_HMAC_DRBG)
#include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
#include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
  #include <botan/auto_rng.h>
#endif

namespace {

class Test_Runner : public Botan_CLI::Command
   {
   public:
      Test_Runner() : Command("test --threads=0 --soak=5 --drbg-seed= --data-dir= --pkcs11-lib= --log-success *suites") {}

      std::string help_text() const override
         {
         std::ostringstream err;

         const std::string& spec = cmd_spec();

         err << "Usage: botan-test"
             << spec.substr(spec.find_first_of(' '), std::string::npos)
             << "\n\nAvailable test suites\n"
             << "----------------\n";

         size_t line_len = 0;

         for(auto&& test : Botan_Tests::Test::registered_tests())
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

      void go() override
         {
         const size_t threads = get_arg_sz("threads");
         const size_t soak_level = get_arg_sz("soak");
         const std::string drbg_seed = get_arg("drbg-seed");
         const bool log_success = flag_set("log-success");
         const std::string data_dir = get_arg_or("data-dir", "src/tests/data");
         const std::string pkcs11_lib = get_arg("pkcs11-lib");

         std::vector<std::string> req = get_arg_list("suites");

         if(req.empty())
            {
            /*
            If nothing was requested on the command line, run everything. First
            run the "essentials" to smoke test, then everything else in
            alphabetical order.
            */
            req = {"block", "stream", "hash", "mac", "modes", "aead"
                   "kdf", "pbkdf", "hmac_drbg", "x931_rng", "util"};

            std::set<std::string> all_others = Botan_Tests::Test::registered_tests();

            // do not run pkcs11 tests by default
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

            for(auto f : req)
               {
               all_others.erase(f);
               }

            req.insert(req.end(), all_others.begin(), all_others.end());
            }
         else if(req.size() == 1 && req.at(0) == "pkcs11")
            {
            req = {"pkcs11-manage", "pkcs11-module", "pkcs11-slot", "pkcs11-session", "pkcs11-object", "pkcs11-rsa",
                    "pkcs11-ecdsa", "pkcs11-ecdh", "pkcs11-rng", "pkcs11-x509"};
            }

         output() << "Testing " << Botan::version_string() << "\n";
         output() << "Starting tests";

         if(threads > 1)
            output() << " threads:" << threads;

         output() << " soak level:" << soak_level;

         if(! pkcs11_lib.empty())
            {
            output() << " pkcs11 library:" << pkcs11_lib;
            }

         std::unique_ptr<Botan::RandomNumberGenerator> rng;

#if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_HAS_SHA2_64)
         std::vector<uint8_t> seed = Botan::hex_decode(drbg_seed);
         if(seed.empty())
            {
            const uint64_t ts = Botan_Tests::Test::timestamp();
            seed.resize(8);
            Botan::store_be(ts, seed.data());
            }

         output() << " rng:HMAC_DRBG with seed '" << Botan::hex_encode(seed) << "'";

         // Expand out the seed to 512 bits to make the DRBG happy
         std::unique_ptr<Botan::HashFunction> sha512(Botan::HashFunction::create("SHA-512"));
         sha512->update(seed);
         seed.resize(sha512->output_length());
         sha512->final(seed.data());

         std::unique_ptr<Botan::HMAC_DRBG> drbg(new Botan::HMAC_DRBG("SHA-384"));
         drbg->initialize_with(seed.data(), seed.size());
         rng.reset(new Botan::Serialized_RNG(drbg.release()));

#else

         if(drbg_seed != "")
            throw Botan_Tests::Test_Error("HMAC_DRBG disabled in build, cannot specify DRBG seed");

#if defined(BOTAN_HAS_SYSTEM_RNG)
         output() << " rng:system";
         rng.reset(new Botan::System_RNG);
#elif defined(BOTAN_HAS_AUTO_SEEDING_RNG)
         output() << " rng:autoseeded";
         rng.reset(new Botan::Serialized_RNG(new Botan::AutoSeeded_RNG));
#endif

#endif
         output() << "\n";

         if(rng.get() == nullptr)
             {
             throw Botan_Tests::Test_Error("No usable RNG enabled in build, aborting tests");
             }

         Botan_Tests::Test::setup_tests(soak_level, log_success, data_dir, pkcs11_lib, rng.get());

         const size_t failed = run_tests(req, output(), threads);

         // Throw so main returns an error
         if(failed)
            throw Botan_Tests::Test_Error("Test suite failure");
         }

   private:

      std::string report_out(const std::vector<Botan_Tests::Test::Result>& results,
                             size_t& tests_failed,
                             size_t& tests_ran)
         {
         std::ostringstream out;

         std::map<std::string, Botan_Tests::Test::Result> combined;
         for(auto&& result : results)
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

         for(auto&& result : combined)
            {
            out << result.second.result_string(verbose());
            tests_failed += result.second.tests_failed();
            tests_ran += result.second.tests_run();
            }

         return out.str();
         }


      size_t run_tests(const std::vector<std::string>& tests_to_run,
                       std::ostream& out,
                       size_t threads)
         {
         size_t tests_ran = 0, tests_failed = 0;

         if(threads <= 1)
            {
            for(auto&& test_name : tests_to_run)
               {
               const auto results = Botan_Tests::Test::run_test(test_name, false);
               out << report_out(results, tests_failed, tests_ran) << std::flush;
               }
            }
         else
            {

            /*
            We're not doing this in a particularly nice way, and variance in time is
            high so commonly we'll 'run dry' by blocking on the first future. But
            plain C++11 <thread> is missing a lot of tools we'd need (like
            wait_for_any on a set of futures) and there is no point pulling in an
            additional dependency just for this. In any case it helps somewhat
            (50-100% speedup) and provides a proof of concept for parallel testing.
            */

            typedef std::future<std::vector<Botan_Tests::Test::Result>> FutureResults;
            std::deque<FutureResults> fut_results;

            for(auto&& test_name : tests_to_run)
               {
               auto run_it = [test_name] {
                  return Botan_Tests::Test::run_test(test_name, false);
               };

               fut_results.push_back(std::async(std::launch::async, run_it));

               while(fut_results.size() > threads)
                  {
                  out << report_out(fut_results[0].get(), tests_failed, tests_ran) << std::flush;
                  fut_results.pop_front();
                  }
               }

            while(fut_results.size() > 0)
               {
               out << report_out(fut_results[0].get(), tests_failed, tests_ran) << std::flush;
               fut_results.pop_front();
               }
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


   };

BOTAN_REGISTER_COMMAND("test", Test_Runner);

}

int main(int argc, char* argv[])
   {
   std::cerr << Botan::runtime_version_check(BOTAN_VERSION_MAJOR,
                                             BOTAN_VERSION_MINOR,
                                             BOTAN_VERSION_PATCH);

   std::unique_ptr<Botan_CLI::Command> cmd(Botan_CLI::Command::get_cmd("test"));

   if(!cmd)
      {
      std::cout << "Unable to retrieve testing helper (program bug)\n"; // WTF
      return 1;
      }

   std::vector<std::string> args(argv + 1, argv + argc);
   return cmd->run(args);
   }

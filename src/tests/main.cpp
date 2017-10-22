/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../cli/argparse.h"
#include "test_runner.h"
#include <iostream>
#include <vector>
#include <string>

#include <botan/version.h>

#if defined(BOTAN_HAS_OPENSSL)
   #include <botan/internal/openssl.h>
#endif

int main(int argc, char* argv[])
   {
   std::cerr << Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

   try
      {
      Botan_CLI::Argument_Parser parser("test --data-dir= --pkcs11-lib= --provider= --log-success "
                                        "--verbose --help --run-long-tests --run-online-tests --test-runs=1 --drbg-seed= "
                                        "*suites");

      parser.parse_args(std::vector<std::string>(argv + 1, argv + argc));

      const std::string data_dir = parser.get_arg_or("data-dir", "src/tests/data");
      const std::string pkcs11_lib = parser.get_arg("pkcs11-lib");
      const std::string provider = parser.get_arg("provider");
      const std::string drbg_seed = parser.get_arg("drbg-seed");

      const bool log_success = parser.flag_set("log-success");
      const bool run_long_tests = parser.flag_set("run-long-tests");
      const bool run_online_tests = parser.flag_set("run-online-tests");
      const size_t test_runs = parser.get_arg_sz("test-runs");

      const std::vector<std::string> suites = parser.get_arg_list("suites");

#if defined(BOTAN_HAS_OPENSSL)
      if(provider.empty() || provider == "openssl")
         {
         ::ERR_load_crypto_strings();
         }
#endif

      Botan_Tests::Test_Runner tests(std::cout);

      return tests.run(suites, data_dir, pkcs11_lib, provider,
                       log_success, run_online_tests, run_long_tests,
                       drbg_seed, test_runs);
      }
   catch(std::exception& e)
      {
      std::cerr << "Exiting with error: " << e.what() << std::endl;
      }
   catch(...)
      {
      std::cerr << "Exiting with unknown exception" << std::endl;
      }
   return 2;
   }

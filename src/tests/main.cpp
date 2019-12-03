/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../cli/argparse.h"
#include "test_runner.h"
#include "tests.h"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

#include <botan/version.h>

#if defined(BOTAN_HAS_OPENSSL)
   #include <botan/internal/openssl.h>
#endif

namespace {

std::string help_text(const std::string& spec)
   {
   std::ostringstream err;

   err << "Usage: " << spec << "\n\n"
       << "Available test suites\n"
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

}

int main(int argc, char* argv[])
   {
   std::cerr << Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

   try
      {
      const std::string arg_spec =
         "botan-test --verbose --help --data-dir= --pkcs11-lib= --provider= "
         "--log-success --abort-on-first-fail --no-avoid-undefined --skip-tests= "
         "--test-threads=0 --run-long-tests --run-online-tests --test-runs=1 --drbg-seed= "
         "*suites";

      Botan_CLI::Argument_Parser parser(arg_spec);

      parser.parse_args(std::vector<std::string>(argv + 1, argv + argc));

      if(parser.flag_set("help"))
         {
         std::cout << help_text(arg_spec);
         return 0;
         }

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_HAS_THREAD_UTILS)
      /*
      The mlock pool becomes a major contention point when many threads are running,
      so disable it unless it was explicitly asked for via setting the env variable
      */
      if(parser.get_arg_sz("test-threads") != 1)
         {
         ::setenv("BOTAN_MLOCK_POOL_SIZE", "0", /*overwrite=*/0);
         }
#endif

      const Botan_Tests::Test_Options opts(
         parser.get_arg_list("suites"),
         parser.get_arg_list("skip-tests"),
         parser.get_arg_or("data-dir", "src/tests/data"),
         parser.get_arg("pkcs11-lib"),
         parser.get_arg("provider"),
         parser.get_arg("drbg-seed"),
         parser.get_arg_sz("test-runs"),
         parser.get_arg_sz("test-threads"),
         parser.flag_set("verbose"),
         parser.flag_set("log-success"),
         parser.flag_set("run-online-tests"),
         parser.flag_set("run-long-tests"),
         parser.flag_set("abort-on-first-fail"));

#if defined(BOTAN_HAS_OPENSSL)
      if(opts.provider().empty() || opts.provider() == "openssl")
         {
         ::ERR_load_crypto_strings();
         }
#endif

      Botan_Tests::Test_Runner tests(std::cout);

      int rc = tests.run(opts);

#if defined(BOTAN_HAS_OPENSSL) && defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x01010000)
      if(opts.provider().empty() || opts.provider() == "openssl")
         {
         ERR_free_strings();
         ::ERR_remove_thread_state(nullptr);
         }
#endif

      return rc;
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

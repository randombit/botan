/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../cli/argparse.h"
#include "runner/test_runner.h"
#include "tests.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <botan/version.h>
#include <botan/internal/target_info.h>

namespace {

void print_item_list(std::ostringstream& err, const std::set<std::string>& list) {
   size_t line_len = 0;

   for(const auto& item : list) {
      err << item << " ";
      line_len += item.size() + 1;

      if(line_len > 64) {
         err << "\n";
         line_len = 0;
      }
   }

   if(line_len > 0) {
      err << "\n";
   }
}

std::string help_text(const std::string& spec) {
   std::ostringstream err;

   err << "Usage: " << spec << "\n\n"
       << "Available test suites\n"
       << "----------------\n";

   print_item_list(err, Botan_Tests::Test::registered_tests());

   err << '\n'
       << "Available test categories\n"
       << "----------------\n";

   print_item_list(err, Botan_Tests::Test::registered_test_categories());

   return err.str();
}

}  // namespace

int main(int argc, char* argv[]) {
   std::cerr << Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

   try {
      const std::string arg_spec =
         "botan-test --verbose --help --data-dir= --pkcs11-lib= --provider= "
         "--tpm2-tcti-name=disabled --tpm2-tcti-conf= --tpm2-persistent-rsa-handle=0x81000008 "
         "--tpm2-persistent-ecc-handle=0x81000010 --tpm2-persistent-auth-value=password "
         "--log-success --abort-on-first-fail --no-stdout --no-avoid-undefined "
         "--skip-tests= --test-threads=0 --test-results-dir= --run-long-tests "
         "--run-memory-intensive-tests --run-online-tests --test-runs=1 "
         "--drbg-seed= --report-properties= --list-tests *suites";

      Botan_CLI::Argument_Parser parser(arg_spec);

      parser.parse_args(std::vector<std::string>(argv + 1, argv + argc));

      if(parser.flag_set("help")) {
         std::cout << help_text(arg_spec);
         return 0;
      }

      if(parser.flag_set("list-tests")) {
         for(const auto& test_name : Botan_Tests::Test::registered_tests()) {
            std::cout << test_name << "\n";
         }
         return 0;
      }

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_HAS_THREAD_UTILS)
      /*
      The mlock pool becomes a major contention point when many threads are running,
      so disable it unless it was explicitly asked for via setting the env variable
      */
      if(parser.get_arg_sz("test-threads") != 1) {
         ::setenv("BOTAN_MLOCK_POOL_SIZE", "0", /*overwrite=*/0);
      }
#endif

      const Botan_Tests::Test_Options opts(parser.get_arg_list("suites"),
                                           parser.get_arg_list("skip-tests"),
                                           parser.get_arg_or("data-dir", "src/tests/data"),
                                           parser.get_arg("pkcs11-lib"),
                                           parser.get_arg("provider"),
                                           parser.get_arg("tpm2-tcti-name"),
                                           parser.get_arg("tpm2-tcti-conf"),
                                           parser.get_arg_hex_sz_or("tpm2-persistent-rsa-handle", "0x81000008"),
                                           parser.get_arg_hex_sz_or("tpm2-persistent-ecc-handle", "0x81000010"),
                                           parser.get_arg_or("tpm2-persistent-auth-value", "password"),
                                           parser.get_arg("drbg-seed"),
                                           parser.get_arg("test-results-dir"),
                                           parser.get_arg_list("report-properties"),
                                           parser.get_arg_sz("test-runs"),
                                           parser.get_arg_sz("test-threads"),
                                           parser.flag_set("verbose"),
                                           parser.flag_set("log-success"),
                                           parser.flag_set("run-online-tests"),
                                           parser.flag_set("run-long-tests"),
                                           parser.flag_set("run-memory-intensive-tests"),
                                           parser.flag_set("abort-on-first-fail"),
                                           parser.flag_set("no-stdout"));

      Botan_Tests::Test_Runner tests(std::cout);

      return tests.run(opts) ? 0 : 1;
   } catch(std::exception& e) {
      std::cerr << "Exiting with error: " << e.what() << std::endl;
   } catch(...) {
      std::cerr << "Exiting with unknown exception" << std::endl;
   }
   return 2;
}

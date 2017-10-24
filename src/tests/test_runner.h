/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_RUNNER_H_
#define BOTAN_TEST_RUNNER_H_

#include <iosfwd>
#include <string>
#include <vector>

namespace Botan_Tests {

class Test_Runner final
   {
   public:
      Test_Runner(std::ostream& out);

      int run(const std::vector<std::string>& requested_tests,
              const std::string& data_dir,
              const std::string& pkcs11_lib,
              const std::string& provider,
              bool log_success,
              bool run_online_tests,
              bool run_long_tests,
              const std::string& drbg_seed,
              size_t runs);

   private:
      std::ostream& output() const { return m_output; }

      size_t run_tests(const std::vector<std::string>& tests_to_run);

      std::ostream& m_output;
   };

}

#endif

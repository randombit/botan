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
#include <memory>

namespace Botan_Tests {

class Test_Options;

class Test_Runner final
   {
   public:
      Test_Runner(std::ostream& out);

      int run(const Test_Options& options);

   private:
      std::ostream& output() const { return m_output; }

      size_t run_tests(const std::vector<std::string>& tests_to_run,
                       size_t test_threads,
                       size_t test_run,
                       size_t tot_test_runs);

      std::ostream& m_output;
   };

}

#endif

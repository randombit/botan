/*
* (C) 2017 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_RUNNER_H_
#define BOTAN_TEST_RUNNER_H_

#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Botan_Tests {

class Test_Options;
class Reporter;

class Test_Runner final {
   public:
      Test_Runner(std::ostream& out);
      ~Test_Runner();

      /// @return true iff all tests have passed
      bool run(const Test_Options& options);

   private:
      std::ostream& output() const { return m_output; }

      /// @return true iff all tests passed
      bool run_tests(const std::vector<std::string>& tests_to_run);
      bool run_tests_multithreaded(const std::vector<std::string>& tests_to_run, size_t test_threads);

      std::ostream& m_output;
      std::vector<std::unique_ptr<Reporter>> m_reporters;
};

}  // namespace Botan_Tests

#endif

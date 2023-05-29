/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_STDOUT_REPORTER_H_
#define BOTAN_TEST_STDOUT_REPORTER_H_

#include "test_reporter.h"

namespace Botan_Tests {

class StdoutReporter : public Reporter {
   public:
      StdoutReporter(const Test_Options& opts, std::ostream& output_stream);

      void next_testsuite(const std::string& name) override;
      void record(const std::string& name, const Test::Result& result) override;
      void render() const override;

   protected:
      void clear();
      void next_run() override;

   private:
      void render_preamble() const;
      void render_summary() const;

   private:
      bool m_verbose;
      std::ostream& m_out;

      std::set<std::string> m_tests_failed_names;
      size_t m_tests_failed;
      size_t m_tests_run;
};

}  // namespace Botan_Tests

#endif

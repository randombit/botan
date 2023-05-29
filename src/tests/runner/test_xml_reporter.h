/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_XML_REPORTER_H_
#define BOTAN_TEST_XML_REPORTER_H_

#include <botan/types.h>
#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   #include "test_reporter.h"

   #include <fstream>
   #include <optional>

namespace Botan_Tests {

/**
 * XML JUnit exporter for test results
 *
 * JUnit schema follows:
 *   https://github.com/junit-team/junit5/blob/main/platform-tests/src/test/resources/jenkins-junit.xsd
 */
class XmlReporter : public Reporter {
   public:
      XmlReporter(const Test_Options& opts, std::string output_dir);

      void render() const override;

      void next_run() override;

   private:
      std::string get_unique_output_filename() const;

      void render_preamble(std::ostream& out) const;
      void render_properties(std::ostream& out) const;
      void render_testsuites(std::ostream& out) const;
      void render_testsuite(std::ostream& out, const Testsuite& suite) const;
      void render_testcase(std::ostream& out, const TestSummary& test) const;
      void render_failures_and_stdout(std::ostream& out, const TestSummary& test) const;

   private:
      std::string m_output_dir;

      mutable std::optional<std::ofstream> m_outfile;
};

}  // namespace Botan_Tests

#endif  // defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

#endif  // BOTAN_TEST_XML_REPORTER_H_

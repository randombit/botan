/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_stdout_reporter.h"

#include <botan/version.h>

namespace Botan_Tests {

StdoutReporter::StdoutReporter(const Test_Options& opts, std::ostream& output_stream) :
      Reporter(opts), m_verbose(opts.verbose()), m_out(output_stream), m_tests_failed(0), m_tests_run(0) {}

void StdoutReporter::next_run() {
   if(current_test_run() == 1) {
      render_preamble();
   }
   clear();
}

void StdoutReporter::next_testsuite(const std::string& name) {
   m_out << name << ":\n";
}

void StdoutReporter::record(const std::string& name, const Test::Result& result) {
   m_out << result.result_string();
   m_out << std::flush;
   m_tests_run += result.tests_run();

   const size_t failed = result.tests_failed();
   if(failed > 0) {
      m_tests_failed += failed;
      m_tests_failed_names.insert(name);
   }
}

void StdoutReporter::render() const {
   render_summary();
}

void StdoutReporter::clear() {
   m_tests_failed_names.clear();
   m_tests_failed = 0;
   m_tests_run = 0;
}

void StdoutReporter::render_preamble() const {
   m_out << "Testing " << Botan::version_string() << "\n";

   if(!properties().empty()) {
      m_out << "Properties:\n";

      for(const auto& prop : properties()) {
         m_out << "  " << prop.first << ": " << prop.second << "\n";
      }
   }
}

void StdoutReporter::render_summary() const {
   const auto total_ns = elapsed_time();

   if(total_test_runs() == 1) {
      m_out << "Tests";
   } else {
      m_out << "Test run " << current_test_run() << "/" << total_test_runs();
   }

   m_out << " complete ran " << m_tests_run << " tests in " << Botan_Tests::Test::format_time(total_ns) << " ";

   if(m_tests_failed > 0) {
      m_out << m_tests_failed << " tests failed (in ";

      bool first = true;
      for(const auto& test : m_tests_failed_names) {
         if(!first) {
            m_out << " ";
         }
         first = false;
         m_out << test;
      }

      m_out << ")";
   } else if(m_tests_run > 0) {
      m_out << "all tests ok";
   }

   m_out << "\n";
}

}  // namespace Botan_Tests

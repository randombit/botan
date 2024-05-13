/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_xml_reporter.h"

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   #include <botan/build.h>
   #include <botan/version.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/os_utils.h>

   #include <iomanip>
   #include <numeric>
   #include <sstream>

namespace Botan_Tests {

namespace {

std::string full_compiler_version_string() {
   #if defined(__VERSION__)
   return __VERSION__;

   #elif defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   // See https://learn.microsoft.com/en-us/cpp/preprocessor/predefined-macros
   //    If the version number of the Microsoft C/C++ compiler is 15.00.20706.01,
   //    the _MSC_FULL_VER macro evaluates to 150020706.
   constexpr int major = _MSC_FULL_VER / 10000000;
   constexpr int minor = (_MSC_FULL_VER % 10000000) / 100000;
   constexpr int patch = _MSC_FULL_VER % 100000;
   constexpr int build = _MSC_BUILD;

   std::ostringstream oss;

   oss << std::setfill('0') << std::setw(2) << major << "." << std::setw(2) << minor << "." << std::setw(5) << patch
       << "." << std::setw(2) << build << std::endl;

   return oss.str();
   #else
   return "unknown";
   #endif
}

std::string full_compiler_name_string() {
   #if defined(BOTAN_BUILD_COMPILER_IS_XCODE)
   return "xcode";
   #elif defined(BOTAN_BUILD_COMPILER_IS_CLANG)
   return "clang";
   #elif defined(BOTAN_BUILD_COMPILER_IS_GCC)
   return "gcc";
   #elif defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   return "Microsoft Visual C++";
   #else
   return "unknown";
   #endif
}

/// formats a given time point in ISO 8601 format (with time zone)
std::string format(const std::chrono::system_clock::time_point& tp) {
   auto seconds_since_epoch = std::chrono::system_clock::to_time_t(tp);
   return Botan::OS::format_time(seconds_since_epoch, "%FT%T%z");
}

std::string format(const std::chrono::nanoseconds& dur) {
   const float secs = static_cast<float>(dur.count()) / 1000000000;

   std::ostringstream out;
   out.precision(3);
   out << std::fixed << secs;
   return out.str();
}

}  // namespace

XmlReporter::XmlReporter(const Test_Options& opts, std::string output_dir) :
      Reporter(opts), m_output_dir(std::move(output_dir)) {
   set_property("architecture", BOTAN_TARGET_ARCH);
   set_property("compiler", full_compiler_name_string());
   set_property("compiler_version", full_compiler_version_string());
   set_property("timestamp", format(std::chrono::system_clock::now()));
   auto custom_props = opts.report_properties();
   for(const auto& prop : custom_props) {
      set_property(prop.first, prop.second);
   }
}

void XmlReporter::render() const {
   BOTAN_STATE_CHECK(m_outfile.has_value() && m_outfile->good());

   render_preamble(m_outfile.value());
   render_testsuites(m_outfile.value());
}

std::string XmlReporter::get_unique_output_filename() const {
   const uint64_t ts = Botan_Tests::Test::timestamp();
   std::vector<uint8_t> seed(8);
   Botan::store_be(ts, seed.data());

   std::stringstream ss;
   ss << m_output_dir << "/"
      << "Botan-" << Botan::short_version_string() << "-tests-" << Botan::hex_encode(seed, false) << ".xml";

   return ss.str();
}

void XmlReporter::next_run() {
   if(m_outfile.has_value()) {
      m_outfile.reset();
   }

   set_property("current test run", std::to_string(current_test_run()));
   set_property("total test runs", std::to_string(total_test_runs()));
   const auto file = get_unique_output_filename();
   m_outfile = std::ofstream(file, std::ofstream::out | std::ofstream::trunc);

   if(!m_outfile->good()) {
      std::stringstream ss;
      ss << "Failed to open '" << file << "' for writing JUnit report.";
      throw Botan::System_Error(ss.str());
   }
}

// == == == == == == == == == == == == == == == == == == == == == == == == == ==
// XML Rendering
// == == == == == == == == == == == == == == == == == == == == == == == == == ==

namespace {

void replace(std::string& str, const std::string& from, const std::string& to) {
   if(from.empty()) {
      return;
   }

   for(size_t offset = 0, pos = 0; (pos = str.find(from, offset)) != std::string::npos; offset = pos + to.size()) {
      str.replace(pos, from.size(), to);
   }
}

std::string escape(std::string str) {
   replace(str, "&", "&amp;");
   replace(str, "<", "&lt;");
   replace(str, ">", "&gt;");
   replace(str, "\"", "&quot;");
   replace(str, "'", "&apos;");
   return str;
}

std::string format_cdata(std::string str) {
   // XML CDATA payloads are not evaluated, hence no special character encoding
   // is needed.
   // Though the termination sequence (i.e. ']]>') must not appear in
   // a CDATA payload frame. The only way to escape it is to terminate the CDATA
   // sequence and break the payload's termination sequence into the adjacent
   // CDATA frames.
   //
   //   See: https://stackoverflow.com/a/223782
   replace(str, "]]>", "]]]><![CDATA[]>");
   //            ^^^ -> ^~~~~~~~~~~~~^^

   // wrap the (escaped) payload into a CDATA frame
   std::ostringstream out;
   out << "<![CDATA[" << str << "]]>";
   return out.str();
}

}  // namespace

void XmlReporter::render_preamble(std::ostream& out) const {
   out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
}

void XmlReporter::render_properties(std::ostream& out) const {
   if(properties().empty()) {
      return;
   }

   out << "<properties>\n";
   for(const auto& prop : properties()) {
      out << "<property"
          << " name=\"" << escape(prop.first) << "\""
          << " value=\"" << escape(prop.second) << "\""
          << " />\n";
   }
   out << "</properties>\n";
}

void XmlReporter::render_testsuites(std::ostream& out) const {
   // render an empty testsuites tag even if no tests were run
   out << "<testsuites"
       << " tests=\"" << tests_run() << "\""
       << " failures=\"" << tests_failed() << "\""
       << " time=\"" << format(elapsed_time()) << "\">\n";

   // Note: In the JUnit .xsd spec, <properties> appear only in individual
   //       test cases. This deviation from the spec allows us to embed
   //       specific platform information about this particular test run.
   render_properties(out);

   for(const auto& suite : testsuites()) {
      render_testsuite(out, suite.second);
   }

   out << "</testsuites>\n";
}

void XmlReporter::render_testsuite(std::ostream& out, const Testsuite& suite) const {
   out << "<testsuite"
       << " name=\"" << escape(suite.name()) << "\""
       << " tests=\"" << suite.tests_run() << "\""
       << " failures=\"" << suite.tests_failed() << "\""
       << " timestamp=\"" << format(suite.timestamp()) << "\"";

   const auto elapsed = suite.elapsed_time();
   if(elapsed.has_value()) {
      out << " time=\"" << format(elapsed.value()) << "\"";
   }

   if(suite.results().empty()) {
      out << " />\n";
   } else {
      out << ">\n";

      for(const auto& result : suite.results()) {
         render_testcase(out, result);
      }

      out << "</testsuite>\n";
   }
}

void XmlReporter::render_testcase(std::ostream& out, const TestSummary& test) const {
   out << "<testcase"
       << " name=\"" << escape(test.name) << "\""
       << " assertions=\"" << test.assertions << "\""
       << " timestamp=\"" << format(test.timestamp) << "\"";

   if(test.elapsed_time.has_value()) {
      out << " time=\"" << format(test.elapsed_time.value()) << "\"";
   }

   if(test.code_location.has_value()) {
      out << " file=\"" << escape(test.code_location->path) << "\""
          << " line=\"" << test.code_location->line << "\"";
   }

   if(test.failures.empty() && test.notes.empty()) {
      out << " />\n";
   } else {
      out << ">\n";
      render_failures_and_stdout(out, test);
      out << "</testcase>\n";
   }
}

void XmlReporter::render_failures_and_stdout(std::ostream& out, const TestSummary& test) const {
   for(const auto& failure : test.failures) {
      out << "<failure>\n"
          << format_cdata(failure) << "\n"
          << "</failure>\n";
   }

   // xUnit format does not have a special tag for test notes, hence we
   // render it into the freetext 'system-out'
   if(!test.notes.empty()) {
      out << "<system-out>\n";
      for(const auto& note : test.notes) {
         out << format_cdata(note) << '\n';
      }
      out << "</system-out>\n";
   }
}

}  // namespace Botan_Tests

#endif  // defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_xml_reporter.h"

#include <botan/internal/loadstor.h>
#include <botan/version.h>

#include <filesystem>
#include <ctime>
#include <iomanip>
#include <numeric>

namespace Botan_Tests {

XmlReporter::XmlReporter(const Test_Options& opts, std::string output_dir)
   : Reporter(opts)
   , m_output_dir(std::move(output_dir)) {}

XmlReporter::~XmlReporter()
   {
   if(m_outfile.has_value() && m_outfile->good())
      {
      m_outfile->close();
      }
   }

void XmlReporter::render() const
   {
   BOTAN_STATE_CHECK(m_outfile.has_value() && m_outfile->good());

   render_preamble(m_outfile.value());
   render_properties(m_outfile.value());
   render_testsuites(m_outfile.value());
   }

namespace fs = std::filesystem;

std::string XmlReporter::get_unique_output_filename() const
   {
   fs::path path(m_output_dir);
   fs::create_directories(path);

   const uint64_t ts = Botan_Tests::Test::timestamp();
   std::vector<uint8_t> seed(8);
   Botan::store_be(ts, seed.data());

   std::stringstream ss;
   ss << "Botan-"
      << Botan::short_version_string()
      << "-tests-"
      << Botan::hex_encode(seed, false)
      << ".xml";

   return (path / ss.str()).string();
   }

void XmlReporter::next_run()
   {
   if(m_outfile.has_value() && m_outfile->good())
      {
      m_outfile->close();
      m_outfile.reset();
      }

   set_property("current test run", std::to_string(current_test_run()));
   set_property("total test runs", std::to_string(total_test_runs()));
   m_outfile = std::ofstream(get_unique_output_filename(),
                             std::ofstream::out |  std::ofstream::trunc);
   }


// == == == == == == == == == == == == == == == == == == == == == == == == == ==
// XML Rendering
// == == == == == == == == == == == == == == == == == == == == == == == == == ==


namespace {

void replace(std::string& str, const std::string& from, const std::string& to)
   {
   if(from.empty())
      { return; }

   for(size_t offset = 0, pos = 0;
       (pos = str.find(from, offset)) != std::string::npos;
       offset = pos + to.size())
      {
      str.replace(pos, from.size(), to);
      }
   }

std::string escape(std::string str)
   {
   replace(str, "&",  "&amp;");
   replace(str, "<",  "&lt;");
   replace(str, ">",  "&gt;");
   replace(str, "\"", "&quot;");
   replace(str, "'",  "&apos;");
   return str;
   }

std::string format_cdata(std::string str)
   {
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
   out << "<![CDATA["
       << str
       << "]]>";
   return out.str();
   }

/// formats a given time point in ISO 8601 format (with time zone)
std::string format(const std::chrono::system_clock::time_point& tp)
   {
   auto seconds_since_epoch = std::chrono::system_clock::to_time_t(tp);

   std::ostringstream out;
   out << std::put_time(std::localtime(&seconds_since_epoch), "%FT%T%z");
   return out.str();
   }

std::string format(const std::chrono::nanoseconds& dur)
   {
   const float secs = static_cast<float>(dur.count()) / 1000000000;

   std::ostringstream out;
   out.precision(3);
   out << std::fixed << secs;
   return out.str();
   }

}

void XmlReporter::render_preamble(std::ostream& out) const
   {
   out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
   }

void XmlReporter::render_properties(std::ostream& out) const
   {
   if(properties().empty())
      {
      return;
      }

   out << "<properties>\n";
   for(const auto& prop : properties())
      {
      out << "<property"
          << " name=\"" << escape(prop.first) << "\""
          << " value=\"" << escape(prop.second) << "\""
          << " />\n";
      }
   out << "</properties>\n";
   }

void XmlReporter::render_testsuites(std::ostream& out) const
   {
   // render an empty testsuites tag even if no tests were run
   out << "<testsuites"
       << " tests=\"" << tests_run() << "\""
       << " failures=\"" << tests_failed() << "\""
       << " time=\"" << format(elapsed_time()) << "\">\n";

   for(const auto& suite : testsuites())
      {
      render_testsuite(out, suite.second);
      }

   out << "</testsuites>\n";
   }

void XmlReporter::render_testsuite(std::ostream& out, const Testsuite& suite) const
   {
   out << "<testsuite"
       << " name=\"" << escape(suite.name()) << "\""
       << " tests=\"" << suite.tests_run() << "\""
       << " failures=\"" << suite.tests_failed() << "\""
       << " timestamp=\"" << format(suite.timestamp()) << "\"";

   const auto elapsed = suite.elapsed_time();
   if(elapsed.has_value())
      {
      out << " time=\"" << format(elapsed.value()) << "\"";
      }

   if(suite.results().empty())
      {
      out << " />\n";
      }
   else
      {
      out << ">\n";

      for(const auto& result : suite.results())
         {
         render_testcase(out, result);
         }

      out << "</testsuite>\n";
      }
   }

void XmlReporter::render_testcase(std::ostream& out, const TestSummary& test) const
   {
   out << "<testcase"
      << " name=\"" << escape(test.name) << "\""
      << " assertions=\"" << test.assertions << "\""
      << " timestamp=\"" << format(test.timestamp) << "\"";

   if(test.elapsed_time.has_value())
      {
      out << " time=\"" << format(test.elapsed_time.value()) << "\"";
      }

   if(test.failures.empty() && test.notes.empty())
      {
      out << " />\n";
      }
   else
      {
      out << ">\n";
      render_failures_and_stdout(out, test);
      out << "</testcase>\n";
      }
   }

void XmlReporter::render_failures_and_stdout(std::ostream& out, const TestSummary& test) const
   {
   for(const auto& failure : test.failures)
      {
      out << "<failure>\n"
          << format_cdata(failure) << "\n"
          << "</failure>\n";
      }

   // xUnit format does not have a special tag for test notes, hence we
   // render it into the freetext 'system-out'
   if(!test.notes.empty())
      {
      out << "<system-out>\n";
      for(const auto& note : test.notes)
         {
         out << format_cdata(note) << '\n';
         }
      out << "</system-out>\n";
      }
   }

}

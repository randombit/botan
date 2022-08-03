/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_xml_reporter.h"

#include <iostream>
#include <ctime>
#include <iomanip>
#include <numeric>

namespace Botan_Tests {

namespace {

template <typename T>
constexpr std::optional<T>
operator+(const std::optional<T>& a, const std::optional<T>& b)
   {
   if(!a.has_value() || !b.has_value())
      {
      return std::nullopt;
      }

   return a.value() + b.value();
   }

class XmlTest
   {
   public:
      XmlTest(const Test::Result& result)
         : m_name(result.who())
         , m_notes(result.notes())
         , m_failures(result.failures())
         , m_assertions(result.tests_run())
         , m_timestamp(result.timestamp())
         , m_elapsed(result.elapsed_time()) {}

      bool passed() const { return m_failures.empty(); }
      bool failed() const { return !m_failures.empty(); }
      decltype(auto) timestamp() const { return m_timestamp; }
      decltype(auto) elapsed_time() const { return m_elapsed; }

      void render(std::ostream& os) const;

   private:
      void render_failures_and_notes(std::ostream& os) const;

   private:
      const std::string m_name;

      const std::vector<std::string> m_notes;
      const std::vector<std::string> m_failures;

      const size_t m_assertions;

      const std::chrono::system_clock::time_point m_timestamp;
      const std::optional<std::chrono::nanoseconds> m_elapsed;
   };

class XmlTestsuite
   {
   public:
      XmlTestsuite(std::string name) : m_name(std::move(name)) {}

      void record(const Test::Result& result)
         {
         m_results.emplace_back(result);
         }

      void render(std::ostream& os) const;

      size_t tests() const { return m_results.size(); }

      size_t passed() const
         {
         return std::count_if(m_results.begin(), m_results.end(),
                              [](const auto& r) { return r.passed(); });
         }

      size_t failed() const
         {
         return std::count_if(m_results.begin(), m_results.end(),
                              [](const auto& r) { return r.failed(); });
         }

      /// Returns the oldest time stamp in all contained test cases
      std::chrono::system_clock::time_point timestamp() const
         {
         return std::transform_reduce(
            m_results.begin(), m_results.end(),
            std::chrono::system_clock::time_point::max(),
            [](const auto& a, const auto& b) { return std::min(a, b); },
            [](const auto& result) { return result.timestamp(); });
         }

      /// Returns the cumulative elapsed time of all contained test cases
      std::optional<std::chrono::nanoseconds> elapsed_time() const
         {
         return std::transform_reduce(
            m_results.begin(), m_results.end(),
            std::make_optional(std::chrono::nanoseconds::zero()),
            [](const auto& a, const auto& b) { return a + b; },
            [](const auto& result) { return result.elapsed_time(); });
         }

   private:
      const std::string m_name;
      std::vector<XmlTest> m_results;
   };

}


struct XmlReporterInternal
   {
   XmlReporterInternal()
      : start_time(std::chrono::high_resolution_clock::now()) {}

   std::map<std::string, XmlTestsuite> testsuites;
   std::chrono::high_resolution_clock::time_point start_time;
   };


XmlReporter::XmlReporter(std::string output_dir)
   : m_output_dir(std::move(output_dir))
   , m_internal(std::make_unique<XmlReporterInternal>()) {}


XmlReporter::~XmlReporter() = default;


void XmlReporter::record(const std::string& name, const Test::Result& result)
   {
   auto& suite = m_internal->testsuites.try_emplace(name, name).first->second;
   suite.record(result);
   }


size_t XmlReporter::tests() const
   {
   return std::transform_reduce(
      m_internal->testsuites.begin(), m_internal->testsuites.end(),
      size_t(0), std::plus{},
      [](const auto& testsuite) { return testsuite.second.tests(); });
   }


size_t XmlReporter::passed() const
   {
   return std::transform_reduce(
      m_internal->testsuites.begin(), m_internal->testsuites.end(),
      size_t(0), std::plus{},
      [](const auto& testsuite) { return testsuite.second.passed(); });
   }


size_t XmlReporter::failed() const
   {
   return std::transform_reduce(
      m_internal->testsuites.begin(), m_internal->testsuites.end(),
      size_t(0), std::plus{},
      [](const auto& testsuite) { return testsuite.second.failed(); });
   }


std::chrono::nanoseconds XmlReporter::elapsed_time() const
   {
   return std::chrono::high_resolution_clock::now() - m_internal->start_time;
   }


//
// = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
// Rendering
// = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
//


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


void XmlReporter::render(std::ostream& os) const
   {
   os << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
   os << "<testsuites"
      << " tests=\"" << tests() << "\""
      << " failures=\"" << failed() << "\""
      << " time=\"" << format(elapsed_time()) << "\">\n";

   for(const auto& suite : m_internal->testsuites)
      {
      suite.second.render(os);
      }

   os << "</testsuites>\n";
   }


void XmlTestsuite::render(std::ostream& os) const
   {
   os << "<testsuite"
      << " name=\"" << escape(m_name) << "\""
      << " tests=\"" << tests() << "\""
      << " failures=\"" << failed() << "\""
      << " errors=\"0\"" // we cannot currently distinguish that
      << " skipped=\"0\"" // we do not currently track that
      << " timestamp=\"" << format(timestamp()) << "\"";

   const auto elapsed = elapsed_time();
   if(elapsed)
      {
      os << " time=\"" << format(elapsed.value()) << "\"";
      }

   if(m_results.empty())
      {
      os << " />\n";
      }
   else
      {
      os << ">\n";

      for(const auto& result : m_results)
         {
         result.render(os);
         }

      os << "</testsuite>\n";
      }
   }


void XmlTest::render(std::ostream& os) const
   {
   os << "<testcase"
      << " name=\"" << escape(m_name) << "\""
      << " assertions=\"" << m_assertions << "\""
      << " timestamp=\"" << format(m_timestamp) << "\"";

   auto elapsed = elapsed_time();
   if(elapsed)
      {
      os << " time=\"" << format(elapsed.value()) << "\"";
      }

   if(m_failures.empty() && m_notes.empty())
      {
      os << " />\n";
      }
   else
      {
      os << ">\n";
      render_failures_and_notes(os);
      os << "</testcase>\n";
      }
   }


void XmlTest::render_failures_and_notes(std::ostream& os) const
   {
   for(const auto& failure : m_failures)
      {
      os << "<failure>\n"
         << format_cdata(failure) << "\n"
         << "</failure>\n";
      }

   // xUnit format does not have a special tag for test notes, hence we
   // render it into the freetext 'system-out'
   if(!m_notes.empty())
      {
      os << "<system-out>\n";
      for(unsigned int i = 0; i < m_notes.size(); ++i)
         {
         os << format_cdata(m_notes[i]) << '\n';
         }
      os << "</system-out>\n";
      }
   }

}

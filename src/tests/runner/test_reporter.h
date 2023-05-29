/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_REPORTER_H_
#define BOTAN_TEST_REPORTER_H_

#include "../tests.h"

namespace Botan_Tests {

/**
 * Summary data holder for an individual test (i.e. one `Test::Result` instance)
 */
class TestSummary final {
   public:
      TestSummary(const Test::Result& result);

      bool passed() const { return failures.empty(); }

      bool failed() const { return !failures.empty(); }

   public:
      const std::string name;
      const std::optional<CodeLocation> code_location;

      const size_t assertions;
      const std::vector<std::string> notes;
      const std::vector<std::string> failures;

      const std::chrono::system_clock::time_point timestamp;
      const std::optional<std::chrono::nanoseconds> elapsed_time;
};

/**
 * Summary data holder for a test suite containing potentially many test cases
 */
class Testsuite final {
   public:
      Testsuite(std::string name);

      void record(const Test::Result& result);

      size_t tests_run() const { return m_results.size(); }

      size_t tests_passed() const;
      size_t tests_failed() const;

      /// Returns the oldest time stamp in all contained test cases
      std::chrono::system_clock::time_point timestamp() const;

      /// Returns the cumulative elapsed time of all contained test cases
      std::optional<std::chrono::nanoseconds> elapsed_time() const;

      const std::string& name() const { return m_name; }

      const std::vector<TestSummary>& results() const { return m_results; }

   private:
      const std::string m_name;
      std::vector<TestSummary> m_results;
};

/**
 * @brief Base class for Botan's test result reporting facility
 *
 * Note that this class is currently not thread safe.
 */
class Reporter {
   public:
      using TestsuiteMap = std::map<std::string, Testsuite>;
      using PropertyMap = std::map<std::string, std::string>;

   public:
      explicit Reporter(const Test_Options& opts);

      virtual ~Reporter() = default;
      Reporter(const Reporter&) = delete;
      Reporter& operator=(const Reporter&) = delete;
      Reporter(Reporter&&) = delete;
      Reporter& operator=(Reporter&&) = delete;

      /**
       * @brief Sets test-specific properties to be added to the report
       *
       * The reporter will usually not evaluate or use those properties but
       * simply add them to the report output for reference.
       *
       * Setting the same property name twice will overwrite the first value.
       *
       * @param name   The name of the property
       * @param value  The content of the property (in printable encoding)
       */
      void set_property(const std::string& name, const std::string& value);

      /**
       * @brief Called when a new test run is started
       *
       * This prepare the reporter for the next run and calls \p next_run() to
       * allow subclasses to (e.g.) reset internal counters or flush data of the
       * previous run).
       *
       * Usually this is called exactly once (with number = 0), except if the
       * user requested multiple test execution runs.
       */
      void next_test_run();

      /**
       * @brief Reports a single test result
       *
       * The default implementation records the result as `Testsuite` and
       * `TestSummary` objects but doesn't do any reporting.
       *
       * Subclasses should override this method to add custom handling and/or
       * replace the test summary recording entirely. Note that the protected
       * accessor methods won't work as expected if this method isn't up-called.
       *
       * @param name    The name of the test case the result was created in
       *                Note that multiple results can be reported under the
       *                same name. The `Reporter` will coalesce those.
       * @param result  The test result data structure of a finished test case
       */
      virtual void record(const std::string& name, const Test::Result& result);

      /**
       * @brief Reports a list of test results for a given test suite
       *
       * Note that this merges test results with the same name
       */
      void record(const std::string& test_name, const std::vector<Botan_Tests::Test::Result>& results);

      /**
       * Called once all test results have been reported for a single run.
       * Some reporter might render a summary or their entire output here.
       */
      virtual void render() const {}

   protected:
      /**
       * @brief Announce that a new test suite was reached
       *
       * This information is an artifact of the serial test execution nature and
       * won't be used by this base class.
       *
       * @param name  the name of the test suite that is going to start
       */
      virtual void next_testsuite(const std::string& name) { BOTAN_UNUSED(name); }

      /**
       * @brief Prepare the reporter for the next test run
       */
      virtual void next_run() = 0;

      size_t tests_run() const;
      size_t tests_passed() const;
      size_t tests_failed() const;

      std::chrono::nanoseconds elapsed_time() const;

      const PropertyMap& properties() const { return m_properties; }

      const TestsuiteMap& testsuites() const { return m_testsuites; }

      size_t current_test_run() const { return m_current_test_run; }

      size_t total_test_runs() const { return m_total_test_runs; }

   private:
      const size_t m_total_test_runs;
      size_t m_current_test_run;

      PropertyMap m_properties;

      TestsuiteMap m_testsuites;
      std::chrono::high_resolution_clock::time_point m_start_time;
};

}  // namespace Botan_Tests

#endif

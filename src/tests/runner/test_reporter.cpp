/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_reporter.h"

#include <algorithm>
#include <numeric>

namespace Botan_Tests {

namespace {

template <typename T>
constexpr std::optional<T> operator+(const std::optional<T>& a, const std::optional<T>& b) {
   if(!a.has_value() || !b.has_value()) {
      return std::nullopt;
   }

   return a.value() + b.value();
}

}  // namespace

TestSummary::TestSummary(const Test::Result& result) :
      name(result.who()),
      code_location(result.code_location()),
      assertions(result.tests_run()),
      notes(result.notes()),
      failures(result.failures()),
      timestamp(result.timestamp()),
      elapsed_time(result.elapsed_time()) {}

Testsuite::Testsuite(std::string name) : m_name(std::move(name)) {}

void Testsuite::record(const Test::Result& result) {
   m_results.emplace_back(result);
}

size_t Testsuite::tests_passed() const {
   return std::count_if(m_results.begin(), m_results.end(), [](const auto& r) { return r.passed(); });
}

size_t Testsuite::tests_failed() const {
   return std::count_if(m_results.begin(), m_results.end(), [](const auto& r) { return r.failed(); });
}

std::chrono::system_clock::time_point Testsuite::timestamp() const {
   return std::transform_reduce(
      m_results.begin(),
      m_results.end(),
      std::chrono::system_clock::time_point::max(),
      [](const auto& a, const auto& b) { return std::min(a, b); },
      [](const auto& result) { return result.timestamp; });
}

std::optional<std::chrono::nanoseconds> Testsuite::elapsed_time() const {
   return std::transform_reduce(
      m_results.begin(),
      m_results.end(),
      std::make_optional(std::chrono::nanoseconds::zero()),
      [](const auto& a, const auto& b) { return a + b; },
      [](const auto& result) { return result.elapsed_time; });
}

Reporter::Reporter(const Test_Options& opts) : m_total_test_runs(opts.test_runs()), m_current_test_run(0) {}

void Reporter::set_property(const std::string& name, const std::string& value) {
   m_properties.insert_or_assign(name, value);
}

void Reporter::next_test_run() {
   m_start_time = std::chrono::high_resolution_clock::now();
   ++m_current_test_run;
   m_testsuites.clear();

   next_run();
}

void Reporter::record(const std::string& name, const Test::Result& result) {
   auto& suite = m_testsuites.try_emplace(name, name).first->second;
   suite.record(result);
}

void Reporter::waiting_for_next_results(const std::string& test_name) {
   next_testsuite(test_name);
}

void Reporter::record(const std::string& testsuite_name, const std::vector<Botan_Tests::Test::Result>& results) {
   std::map<std::string, Botan_Tests::Test::Result> combined;
   for(const auto& result : results) {
      const auto& who = result.who();
      auto i = combined.find(who);
      if(i == combined.end()) {
         combined.insert(std::make_pair(who, Botan_Tests::Test::Result(who)));
         i = combined.find(who);
      }

      i->second.merge(result);
   }

   for(const auto& result : combined) {
      record(testsuite_name, result.second);
   }
}

size_t Reporter::tests_run() const {
   return std::transform_reduce(
      m_testsuites.begin(), m_testsuites.end(), size_t(0), std::plus{}, [](const auto& testsuite) {
         return testsuite.second.tests_run();
      });
}

size_t Reporter::tests_passed() const {
   return std::transform_reduce(
      m_testsuites.begin(), m_testsuites.end(), size_t(0), std::plus{}, [](const auto& testsuite) {
         return testsuite.second.tests_passed();
      });
}

size_t Reporter::tests_failed() const {
   return std::transform_reduce(
      m_testsuites.begin(), m_testsuites.end(), size_t(0), std::plus{}, [](const auto& testsuite) {
         return testsuite.second.tests_failed();
      });
}

std::chrono::nanoseconds Reporter::elapsed_time() const {
   return std::chrono::high_resolution_clock::now() - m_start_time;
}

}  // namespace Botan_Tests

/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_reporter.h"

#include <numeric>

namespace Botan_Tests {

Reporter::Reporter(const Test_Options& opts)
   : m_total_test_runs(opts.test_runs())
   , m_current_test_run(0)
   {}

void Reporter::set_property(const std::string& name, const std::string& value)
   {
   m_properties.insert_or_assign(name, value);
   }

void Reporter::next_test_run()
   {
   m_start_time = std::chrono::high_resolution_clock::now();
   ++m_current_test_run;

   next_run();
   }

void Reporter::record(const std::string& testsuite_name,
                      const std::vector<Botan_Tests::Test::Result>& results)
   {
   // TODO: Is that still required or could it be modernized?
   std::map<std::string, Botan_Tests::Test::Result> combined;
   for(auto const& result : results)
      {
      const std::string who = result.who();
      auto i = combined.find(who);
      if(i == combined.end())
         {
         combined.insert(std::make_pair(who, Botan_Tests::Test::Result(who)));
         i = combined.find(who);
         }

      i->second.merge(result);
      }

   next_testsuite(testsuite_name);
   for(auto const& result : combined)
      {
      record(testsuite_name, result.second);
      }
   }

std::chrono::nanoseconds Reporter::elapsed_time() const
   {
   return std::chrono::high_resolution_clock::now() - m_start_time;
   }

}

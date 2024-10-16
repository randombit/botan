/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"
#include "cli_exceptions.h"
#include <map>

namespace Botan_CLI {

PerfTest::Registration::Registration(const std::string& name, const PerfTest::pt_maker_fn& maker_fn) {
   std::map<std::string, PerfTest::pt_maker_fn>& reg = PerfTest::global_registry();

   if(reg.contains(name)) {
      throw CLI_Error("Duplicated registration of command " + name);
   }

   reg.insert(std::make_pair(name, maker_fn));
}

//static
std::map<std::string, PerfTest::pt_maker_fn>& PerfTest::global_registry() {
   static std::map<std::string, PerfTest::pt_maker_fn> g_perf_tests;
   return g_perf_tests;
}

//static
std::unique_ptr<PerfTest> PerfTest::get(const std::string& name) {
   const auto& reg = PerfTest::global_registry();

   auto i = reg.find(name);
   if(i != reg.end()) {
      return i->second();
   }

   return PerfTest::get_sym(name);
}

std::string PerfTest::format_name(const std::string& alg, const std::string& param) const {
   if(param.empty()) {
      return alg;
   }
   if(param.starts_with(alg)) {
      return param;
   }
   return Botan::fmt("{}-{}", alg, param);
}

}  // namespace Botan_CLI

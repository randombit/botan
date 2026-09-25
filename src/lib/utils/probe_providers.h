/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PROBE_PROVIDERS_H_
#define BOTAN_PROBE_PROVIDERS_H_

#include <string>
#include <string_view>
#include <vector>

namespace Botan {

/**
* Return those of the possible providers for which T::create succeeds
*/
template <typename T>
std::vector<std::string> probe_providers_of(std::string_view algo_spec,
                                            const std::vector<std::string>& possible = {"base"}) {
   std::vector<std::string> providers;
   for(auto&& prov : possible) {
      auto o = T::create(algo_spec, prov);
      if(o) {
         providers.push_back(prov);  // available
      }
   }
   return providers;
}

}  // namespace Botan

#endif

/**
SCAN Name Abstraction
(C) 2008 Jack Lloyd
*/

#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <stdexcept>

namespace Botan {

SCAN_Name::SCAN_Name(const std::string& algo_spec,
                     const std::string& prov_names)
   {
   orig_algo_spec = algo_spec;
   orig_providers = prov_names;

   name = parse_algorithm_name(algo_spec);
   for(u32bit i = 0; i != name.size(); ++i)
      name[i] = global_state().deref_alias(name[i]);

   if(prov_names.find(',') != std::string::npos)
      {
      std::vector<std::string> prov_names_vec = split_on(prov_names, ',');
      for(u32bit i = 0; i != prov_names_vec.size(); ++i)
         providers.insert(prov_names_vec[i]);
      }
   else if(prov_names != "")
      providers.insert(prov_names);
   }

bool SCAN_Name::provider_allowed(const std::string& provider) const
   {
   // If not providers were specified by the user, then allow any;
   // usually the source order will try to perfer one of the better
   // ones first.

   // The core provider is always enabled
   if(provider == "core" || providers.empty())
      return true;

   return (providers.find(provider) != providers.end());
   }

std::string SCAN_Name::argument(u32bit i) const
   {
   if(i > arg_count())
      throw std::range_error("SCAN_Name::argument");
   return name[i+1];
   }

u32bit SCAN_Name::argument_as_u32bit(u32bit i, u32bit def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return to_u32bit(name[i+1]);
   }

}

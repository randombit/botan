/**
SCAN Name Abstraction
(C) 2008 Jack Lloyd
*/

#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <stdexcept>

namespace Botan {

SCAN_Name::SCAN_Name(const std::string& algo_spec)
   {
   name = parse_algorithm_name(algo_spec);

   for(u32bit i = 0; i != name.size(); ++i)
      name[i] = global_state().deref_alias(name[i]);
   }

std::string SCAN_Name::argument(u32bit i)
   {
   if(i > arg_count())
      throw std::range_error("SCAN_Name::argument");
   return name[i+1];
   }

u32bit SCAN_Name::argument_as_u32bit(u32bit i, u32bit def_value)
   {
   if(i >= arg_count())
      return def_value;
   return to_u32bit(name[i+1]);
   }

}

/**
SCAN Name Abstraction
(C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <stdexcept>

namespace Botan {

namespace {

std::vector<std::string>
parse_and_deref_aliases(const std::string& algo_spec)
   {
   std::vector<std::string> parts = parse_algorithm_name(algo_spec);
   std::vector<std::string> out;

   for(size_t i = 0; i != parts.size(); ++i)
      {
      std::string part_i = global_state().deref_alias(parts[i]);

      if(i == 0 && part_i.find_first_of(",()") != std::string::npos)
         {
         std::vector<std::string> parts_i = parse_and_deref_aliases(part_i);

         for(size_t j = 0; j != parts_i.size(); ++j)
            out.push_back(parts_i[j]);
         }
      else
         out.push_back(part_i);
      }

   return out;
   }

}

SCAN_Name::SCAN_Name(const std::string& algo_spec)
   {
   orig_algo_spec = algo_spec;

   name = parse_and_deref_aliases(algo_spec);

   if(name.size() == 0)
      throw Decoding_Error("Bad SCAN name " + algo_spec);
   }

std::string SCAN_Name::arg(u32bit i) const
   {
   if(i >= arg_count())
      throw std::range_error("SCAN_Name::argument");
   return name[i+1];
   }

std::string SCAN_Name::arg(u32bit i, const std::string& def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return name[i+1];
   }

u32bit SCAN_Name::arg_as_u32bit(u32bit i, u32bit def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return to_u32bit(name[i+1]);
   }

}

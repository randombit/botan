/**
SCAN Name Abstraction
(C) 2008 Jack Lloyd
*/

#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <stdexcept>

#include <iostream>

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

SCAN_Name::SCAN_Name(const std::string& algo_spec,
                     const std::string& provider)
   {
   orig_algo_spec = algo_spec;
   m_provider = provider;

   name = parse_and_deref_aliases(algo_spec);

   if(name.size() == 0)
      throw Decoding_Error("Bad SCAN name " + algo_spec);
   }

SCAN_Name SCAN_Name::arg(u32bit i) const
   {
   if(i > arg_count())
      throw std::range_error("SCAN_Name::argument");

   return SCAN_Name(name[i+1], m_provider);
   }

std::string SCAN_Name::arg_as_string(u32bit i) const
   {
   if(i > arg_count())
      throw std::range_error("SCAN_Name::argument");
   return name[i+1];
   }

u32bit SCAN_Name::arg_as_u32bit(u32bit i, u32bit def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return to_u32bit(name[i+1]);
   }

}

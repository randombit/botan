/**
* SCAN Name Abstraction
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <botan/exceptn.h>
#include <stdexcept>

namespace Botan {

namespace {

std::string make_arg(
   const std::vector<std::pair<u32bit, std::string> >& name, u32bit start)
   {
   std::string output = name[start].second;
   u32bit level = name[start].first;

   u32bit paren_depth = 0;

   for(u32bit i = start + 1; i != name.size(); ++i)
      {
      if(name[i].first <= name[start].first)
         break;

      if(name[i].first > level)
         {
         output += '(' + name[i].second;
         ++paren_depth;
         }
      else if(name[i].first < level)
         {
         output += ")," + name[i].second;
         --paren_depth;
         }
      else
         {
         if(output[output.size() - 1] != '(')
            output += ",";
         output += name[i].second;
         }

      level = name[i].first;
      }

   for(u32bit i = 0; i != paren_depth; ++i)
      output += ')';

   return output;
   }

std::pair<u32bit, std::string>
deref_aliases(const std::pair<u32bit, std::string>& in)
   {
   return std::make_pair(in.first,
                         global_state().deref_alias(in.second));
   }

}

SCAN_Name::SCAN_Name(const std::string& algo_spec)
   {
   orig_algo_spec = algo_spec;

   std::vector<std::pair<u32bit, std::string> > name;
   u32bit level = 0;
   std::pair<u32bit, std::string> accum = std::make_pair(level, "");

   for(u32bit i = 0; i != algo_spec.size(); ++i)
      {
      char c = algo_spec[i];

      if(c == '/' || c == ',' || c == '(' || c == ')')
         {
         if(c == '(')
            ++level;
         else if(c == ')')
            {
            if(level == 0)
               throw Decoding_Error("Bad SCAN name " + algo_spec);
            --level;
            }

         if(c == '/' && level > 0)
            accum.second.push_back(c);
         else
            {
            if(accum.second != "")
               name.push_back(deref_aliases(accum));
            accum = std::make_pair(level, "");
            }
         }
      else
         accum.second.push_back(c);
      }

   if(accum.second != "")
      name.push_back(deref_aliases(accum));

   if(level != 0 || name.size() == 0)
      throw Decoding_Error("Bad SCAN name " + algo_spec);

   alg_name = name[0].second;

   bool in_modes = false;

   for(u32bit i = 1; i != name.size(); ++i)
      {
      if(name[i].first == 0)
         {
         mode_info.push_back(make_arg(name, i));
         in_modes = true;
         }
      else if(name[i].first == 1 && !in_modes)
         args.push_back(make_arg(name, i));
      }
   }

std::string SCAN_Name::algo_name_and_args() const
   {
   std::string out;

   out = algo_name();

   if(arg_count())
      {
      out += '(';
      for(u32bit i = 0; i != arg_count(); ++i)
         {
         out += arg(i);
         if(i != arg_count() - 1)
            out += ',';
         }
      out += ')';

      }

   return out;
   }

std::string SCAN_Name::arg(u32bit i) const
   {
   if(i >= arg_count())
      throw std::range_error("SCAN_Name::argument");
   return args[i];
   }

std::string SCAN_Name::arg(u32bit i, const std::string& def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return args[i];
   }

u32bit SCAN_Name::arg_as_u32bit(u32bit i, u32bit def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return to_u32bit(args[i]);
   }

}

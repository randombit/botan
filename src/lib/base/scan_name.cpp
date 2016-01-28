/*
* SCAN Name Abstraction
* (C) 2008-2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {

std::string make_arg(
   const std::vector<std::pair<size_t, std::string> >& name, size_t start)
   {
   std::string output = name[start].second;
   size_t level = name[start].first;

   size_t paren_depth = 0;

   for(size_t i = start + 1; i != name.size(); ++i)
      {
      if(name[i].first <= name[start].first)
         break;

      if(name[i].first > level)
         {
         output += "(" + name[i].second;
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

   for(size_t i = 0; i != paren_depth; ++i)
      output += ")";

   return output;
   }

std::pair<size_t, std::string>
deref_aliases(const std::pair<size_t, std::string>& in)
   {
   return std::make_pair(in.first,
                         SCAN_Name::deref_alias(in.second));
   }

}

SCAN_Name::SCAN_Name(std::string algo_spec, const std::string& extra) : SCAN_Name(algo_spec)
   {
   m_alg_name += extra;
   }

SCAN_Name::SCAN_Name(const char* algo_spec) : SCAN_Name(std::string(algo_spec))
   {
   }

SCAN_Name::SCAN_Name(std::string algo_spec) : m_orig_algo_spec(algo_spec), m_alg_name(), m_args(), m_mode_info()
   {
   std::vector<std::pair<size_t, std::string> > name;
   size_t level = 0;
   std::pair<size_t, std::string> accum = std::make_pair(level, "");

   const std::string decoding_error = "Bad SCAN name '" + algo_spec + "': ";

   algo_spec = SCAN_Name::deref_alias(algo_spec);

   for(size_t i = 0; i != algo_spec.size(); ++i)
      {
      char c = algo_spec[i];

      if(c == '/' || c == ',' || c == '(' || c == ')')
         {
         if(c == '(')
            ++level;
         else if(c == ')')
            {
            if(level == 0)
               throw Decoding_Error(decoding_error + "Mismatched parens");
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

   if(level != 0)
      throw Decoding_Error(decoding_error + "Missing close paren");

   if(name.size() == 0)
      throw Decoding_Error(decoding_error + "Empty name");

   m_alg_name = name[0].second;

   bool in_modes = false;

   for(size_t i = 1; i != name.size(); ++i)
      {
      if(name[i].first == 0)
         {
         m_mode_info.push_back(make_arg(name, i));
         in_modes = true;
         }
      else if(name[i].first == 1 && !in_modes)
         m_args.push_back(make_arg(name, i));
      }
   }

std::string SCAN_Name::all_arguments() const
   {
   std::string out;
   if(arg_count())
      {
      out += "(";
      for(size_t i = 0; i != arg_count(); ++i)
         {
         out += arg(i);
         if(i != arg_count() - 1)
            out += ",";
         }
      out += ")";
      }
   return out;
   }

std::string SCAN_Name::arg(size_t i) const
   {
   if(i >= arg_count())
      throw Invalid_Argument("SCAN_Name::arg " + std::to_string(i) +
                             " out of range for '" + as_string() + "'");
   return m_args[i];
   }

std::string SCAN_Name::arg(size_t i, const std::string& def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return m_args[i];
   }

size_t SCAN_Name::arg_as_integer(size_t i, size_t def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return to_u32bit(m_args[i]);
   }

std::mutex SCAN_Name::g_alias_map_mutex;
std::map<std::string, std::string> SCAN_Name::g_alias_map = {
   { "3DES",            "TripleDES" },
   { "ARC4",            "RC4" },
   { "CAST5",           "CAST-128" },
   { "DES-EDE",         "TripleDES" },
   { "EME-OAEP",        "OAEP" },
   { "EME-PKCS1-v1_5",  "PKCS1v15" },
   { "EME1",            "OAEP" },
   { "EMSA-PKCS1-v1_5", "EMSA_PKCS1" },
   { "EMSA-PSS",        "PSSR" },
   { "EMSA2",           "EMSA_X931" },
   { "EMSA3",           "EMSA_PKCS1" },
   { "EMSA4",           "PSSR" },
   { "GOST-34.11",      "GOST-R-34.11-94" },
   { "MARK-4",          "RC4(256)" },
   { "OMAC",            "CMAC" },
   { "PSS-MGF1",        "PSSR" },
   { "SHA-1",           "SHA-160" },
   { "SHA1",            "SHA-160" },
   { "X9.31",           "EMSA2" }
};

void SCAN_Name::add_alias(const std::string& alias, const std::string& basename)
   {
   std::lock_guard<std::mutex> lock(g_alias_map_mutex);

   if(g_alias_map.find(alias) == g_alias_map.end())
      g_alias_map[alias] = basename;
   }

std::string SCAN_Name::deref_alias(const std::string& alias)
   {
   std::lock_guard<std::mutex> lock(g_alias_map_mutex);

   std::string name = alias;

   for(auto i = g_alias_map.find(name); i != g_alias_map.end(); i = g_alias_map.find(name))
      name = i->second;

   return name;
   }

}

/*
* Simple config/test file reader
* (C) 2013,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/parsing.h>
#include <ctype.h>

namespace Botan {

void lex_cfg(std::istream& is,
             std::function<void (std::string)> cb)
   {
   while(is.good())
      {
      std::string s;

      std::getline(is, s);

      while(is.good() && s.back() == '\\')
         {
         while(s.size() && (s.back() == '\\' || s.back() == '\n'))
            s.resize(s.size()-1);

         std::string x;
         std::getline(is, x);

         size_t i = 0;

         while(i < x.size() && (::isspace(x[i])))
            ++i;

         s += x.substr(i);
         }

      auto comment = s.find('#');
      if(comment)
         s = s.substr(0, comment);

      if(s.empty())
         continue;

      auto parts = split_on_pred(s, [](char c) { return ::isspace(c); });

      for(auto& p : parts)
         {
         if(p.empty())
            continue;

         auto eq = p.find("=");

         if(eq == std::string::npos || p.size() < 2)
            {
            cb(p);
            }
         else if(eq == 0)
            {
            cb("=");
            cb(p.substr(1, std::string::npos));
            }
         else if(eq == p.size() - 1)
            {
            cb(p.substr(0, p.size() - 1));
            cb("=");
            }
         else if(eq != std::string::npos)
            {
            cb(p.substr(0, eq));
            cb("=");
            cb(p.substr(eq + 1, std::string::npos));
            }
         }
      }
   }

void lex_cfg_w_headers(std::istream& is,
                       std::function<void (std::string)> cb,
                       std::function<void (std::string)> hdr_cb)
   {
   auto intercept = [cb,hdr_cb](const std::string& s)
      {
      if(s[0] == '[' && s[s.length()-1] == ']')
         hdr_cb(s.substr(1, s.length()-2));
      else
         cb(s);
      };

   lex_cfg(is, intercept);
   }

std::map<std::string, std::map<std::string, std::string>>
   parse_cfg(std::istream& is)
   {
   std::string header = "default";
   std::map<std::string, std::map<std::string, std::string>> vals;
   std::string key;

   auto header_cb = [&header](const std::string i) { header = i; };
   auto cb = [&header,&key,&vals](const std::string s)
      {
      if(s == "=")
         {
         BOTAN_ASSERT(!key.empty(), "Valid assignment in config");
         }
      else if(key.empty())
         key = s;
      else
         {
         vals[header][key] = s;
         key = "";
         }
      };

   lex_cfg_w_headers(is, cb, header_cb);

   return vals;
   }

}

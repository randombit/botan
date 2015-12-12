/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CHECK_GETOPT_H__
#define BOTAN_CHECK_GETOPT_H__

#include <string>
#include <vector>
#include <map>

#include <botan/parsing.h>

class OptionParser
   {
   public:
      std::vector<std::string> arguments() const { return leftover; }

      bool is_set(const std::string& key) const
         {
         return (options.find(key) != options.end());
         }

      std::string value(const std::string& key) const
         {
         std::map<std::string, std::string>::const_iterator i = options.find(key);
         if(i == options.end())
            throw std::runtime_error("Option '" + key + "' not set");
         return i->second;
         }

      std::string value_if_set(const std::string& key) const
         {
         return value_or_else(key, "");
         }

      std::string value_or_else(const std::string& key,
                                const std::string& or_else) const
         {
         return is_set(key) ? value(key) : or_else;
         }

      size_t int_value_or_else(const std::string& key, size_t or_else) const
         {
         return is_set(key) ? Botan::to_u32bit(value(key)) : or_else;
         }

      void help(std::ostream& o, const std::string &appname)
         {
         o << "Usage: " << appname << " ";

         for(auto flag : flags)
            {
            o << "--" << flag.name();
            if(flag.takes_arg())
               o << "=";
            o << " ";
            }

         o << std::endl;
         }

      void parse(const std::vector<std::string> &args);

      OptionParser(const std::string& opt_string)
         {
         std::vector<std::string> opts = Botan::split_on(opt_string, '|');

         for(size_t j = 0; j != opts.size(); j++)
            flags.push_back(OptionFlag(opts[j]));
         }

   private:
      class OptionFlag
         {
         public:
            std::string name() const { return opt_name; }
            bool takes_arg() const { return opt_takes_arg; }

            OptionFlag(const std::string& opt_string)
               {
               std::string::size_type mark = opt_string.find('=');
               opt_name = opt_string.substr(0, mark);
               opt_takes_arg = (mark != std::string::npos);
               }
         private:
            std::string opt_name;
            bool opt_takes_arg;
         };

      OptionFlag find_option(const std::string& name) const
         {
         for(size_t j = 0; j != flags.size(); j++)
            if(flags[j].name() == name)
               return flags[j];
         throw std::runtime_error("Unknown option " + name);
         }

      std::vector<OptionFlag> flags;
      std::map<std::string, std::string> options;
      std::vector<std::string> leftover;
   };

#endif

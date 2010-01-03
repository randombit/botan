/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CHECK_GETOPT_H__
#define BOTAN_CHECK_GETOPT_H__

#include <string>
#include <vector>
#include <stdexcept>
#include <map>

#include <botan/parsing.h>

class OptionParser
   {
   public:
      std::vector<std::string> leftovers() const { return leftover; }

      bool is_set(const std::string& key) const
         {
         return (options.find(key) != options.end());
         }

      std::string value(const std::string& key) const
         {
         std::map<std::string, std::string>::const_iterator i = options.find(key);
         if(i == options.end())
            throw std::runtime_error("Option " + key + " not found");
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

      void parse(char* argv[])
         {
         std::vector<std::string> args;
         for(int j = 1; argv[j]; j++)
            args.push_back(argv[j]);

         for(size_t j = 0; j != args.size(); j++)
            {
            std::string arg = args[j];

            if(arg.size() > 2 && arg[0] == '-' && arg[1] == '-')
               {
               const std::string opt_name = arg.substr(0, arg.find('='));

               arg = arg.substr(2);

               std::string::size_type mark = arg.find('=');
               OptionFlag opt = find_option(arg.substr(0, mark));

               if(opt.takes_arg())
                  {
                  if(mark == std::string::npos)
                     throw std::runtime_error("Option " + opt_name +
                                              " requires an argument");

                  std::string name = arg.substr(0, mark);
                  std::string value = arg.substr(mark+1);

                  options[name] = value;
                  }
               else
                  {
                  if(mark != std::string::npos)
                     throw std::runtime_error("Option " + opt_name +
                                              " does not take an argument");

                  options[arg] = "";
                  }
               }
            else
               leftover.push_back(arg);
            }
         }

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

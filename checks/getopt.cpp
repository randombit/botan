
#include "getopt.h"

#include <botan/parsing.h>
#include <botan/exceptn.h>

OptionParser::OptionParser(const std::string& opt_string)
   {
   std::vector<std::string> opts = Botan::split_on(opt_string, '|');

   for(size_t j = 0; j != opts.size(); j++)
      flags.push_back(OptionFlag(opts[j]));
   }

OptionParser::OptionFlag
OptionParser::find_option(const std::string& name) const
   {
   for(size_t j = 0; j != flags.size(); j++)
      if(flags[j].name() == name)
         return flags[j];
   throw Botan::Exception("Unknown option " + name);
   }

bool OptionParser::is_set(const std::string& key) const
   {
   return (options.find(key) != options.end());
   }

std::string OptionParser::value(const std::string& key) const
   {
   std::map<std::string, std::string>::const_iterator i = options.find(key);
   if(i == options.end())
      throw Botan::Exception("Option " + key + " not found");
   return i->second;
   }

std::string OptionParser::value_if_set(const std::string& key) const
   {
   return is_set(key) ? value(key) : "";
   }

void OptionParser::parse(char* argv[])
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
               throw Botan::Exception("Option " + opt_name +
                                      " requires an argument");

            std::string name = arg.substr(0, mark);
            std::string value = arg.substr(mark+1);

            options[name] = value;
            }
         else
            {
            if(mark != std::string::npos)
               throw Botan::Exception("Option " + opt_name +
                                      " does not take an argument");

            options[arg] = "";
            }
         }
      else
         leftover.push_back(arg);
      }
   }

/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "getopt.h"
#include <iostream>

void OptionParser::parse(const std::vector<std::string> &args)
   {
   const std::string appname = args[0];

   // ship first, args[0] is the app name
   for(size_t j = 1; j != args.size(); j++)
      {
      std::string arg = args[j];

      // FIXME: cli app must manually query if user requested help
      // in order to be able to stop the cpp. At the moment e.g.
      // `./botan keygen --help` generates keys.
      if(arg == "help" || arg == "--help" || arg == "-h")
         {
         help(std::cout, appname);
         return;
         }

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
               throw std::runtime_error("Option " + opt_name + " does not take an argument");

            options[arg] = "";
            }
         }
      else
         leftover.push_back(arg);
      }
   }

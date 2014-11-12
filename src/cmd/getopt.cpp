#include "getopt.h"
#include <iostream>

void OptionParser::parse(char* argv[])
   {
   std::vector<std::string> args;
   for(int j = 1; argv[j]; j++)
      args.push_back(argv[j]);

   for(size_t j = 0; j != args.size(); j++)
      {
      std::string arg = args[j];

      if(arg == "help" || arg == "--help" || arg == "-h")
         return help(std::cout, argv[0]);

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


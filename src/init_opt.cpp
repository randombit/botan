/*************************************************
* Initialization Options Source File             *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/init.h>
#include <botan/parsing.h>

namespace Botan {

namespace Init {

/*************************************************
* Check for an arbitrary boolean-valued option   *
*************************************************/
bool InitializerOptions::boolean_arg(const std::string& option_name) const
   {
   return (args.find(option_name) != args.end());
   }

/*************************************************
* Check if thread safety was requested           *
*************************************************/
bool InitializerOptions::thread_safe() const
   {
   return boolean_arg("thread_safe");
   }

/*************************************************
* Check if using engines was requested           *
*************************************************/
bool InitializerOptions::use_engines() const
   {
   return boolean_arg("use_engines");
   }

/*************************************************
* Check if RNG seeding should be disabled        *
*************************************************/
bool InitializerOptions::seed_rng() const
   {
   return !boolean_arg("no_rng_seed");
   }

/*************************************************
* Return the config file to load, if any         *
*************************************************/
std::string InitializerOptions::config_file() const
   {
   std::map<std::string, std::string>::const_iterator i =
      args.find("config");

   return (i != args.end()) ? i->second : "";
   }

/*************************************************
* Setup an InitializerOptions                    *
*************************************************/
InitializerOptions::InitializerOptions(const std::string& arg_string)
   {
   std::vector<std::string> arg_list = split_on(arg_string, ' ');
   for(u32bit j = 0; j != arg_list.size(); ++j)
      {
      if(arg_list[j].find('=') == std::string::npos)
         args[arg_list[j]] = "";
      else
         {
         std::vector<std::string> name_and_value = split_on(arg_list[j], '=');
         args[name_and_value[0]] = name_and_value[1];
         }
      }
   }

}

}

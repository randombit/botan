/*************************************************
* Initialization Options Source File             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/init.h>
#include <botan/parsing.h>
#include <botan/stl_util.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {

/*************************************************
* Check for an arbitrary boolean-valued option   *
*************************************************/
bool boolean_arg(const std::map<std::string, std::string>& args,
                 const std::string& key, bool not_found = false)
   {
   std::map<std::string, std::string>::const_iterator i = args.find(key);
   if(i == args.end())
      return not_found;

   std::string value = i->second;

   if(value == "1" || value == "true" || value == "yes" || value == "on")
      return true;
   if(value == "0" || value == "false" || value == "no" || value == "off")
      return false;
   if(value == "default")
      return not_found;

   throw Invalid_Argument("InitializerOptions: Bad argument for boolean " +
                          key + " of '" + value + "'");
   }

}

/*************************************************
* Check if thread safety was requested           *
*************************************************/
bool InitializerOptions::thread_safe() const
   {
   return boolean_arg(args, "thread_safe");
   }

/*************************************************
* Check if secure allocation was requested       *
*************************************************/
bool InitializerOptions::secure_memory() const
   {
   return boolean_arg(args, "secure_memory");
   }

/*************************************************
* Check if using engines was requested           *
*************************************************/
bool InitializerOptions::use_engines() const
   {
   return boolean_arg(args, "use_engines");
   }

/*************************************************
* Check if RNG seeding should be enabled         *
*************************************************/
bool InitializerOptions::seed_rng() const
   {
   return boolean_arg(args, "seed_rng", true);
   }

/*************************************************
* Check if FIPS mode was requested               *
*************************************************/
bool InitializerOptions::fips_mode() const
   {
   return boolean_arg(args, "fips140");
   }

/*************************************************
* Check if startup self tests were requested     *
*************************************************/
bool InitializerOptions::self_test() const
   {
   return boolean_arg(args, "selftest", true);
   }

/*************************************************
* Return the config file to load, if any         *
*************************************************/
std::string InitializerOptions::config_file() const
   {
   std::map<std::string, std::string>::const_iterator i = args.find("config");
   return (i != args.end()) ? i->second : "";
   }

/*************************************************
* Setup an InitializerOptions                    *
*************************************************/
InitializerOptions::InitializerOptions(const std::string& arg_string)
   {
   const std::vector<std::string> arg_list = split_on(arg_string, ' ');

   for(u32bit j = 0; j != arg_list.size(); ++j)
      {
      if(arg_list[j].size() == 0)
         continue;

      if(arg_list[j].find('=') == std::string::npos)
         args[arg_list[j]] = "true";
      else
         {
         std::vector<std::string> name_and_value = split_on(arg_list[j], '=');
         args[name_and_value[0]] = name_and_value[1];
         }
      }
   }

}

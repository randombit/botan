/*************************************************
* Configuration Handling Source File             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/config.h>
#include <botan/libstate.h>
#include <botan/lookup.h>
#include <botan/charset.h>
#include <botan/parsing.h>
#include <botan/stl_util.h>
#include <botan/mutex.h>
#include <string>

namespace Botan {

/*************************************************
* Get the global configuration object            *
*************************************************/
Config& global_config()
   {
   return global_state().config();
   }

/*************************************************
* Get a configuration value                      *
*************************************************/
std::string Config::get(const std::string& section,
                        const std::string& key) const
   {
   Named_Mutex_Holder lock("config");

   return search_map<std::string, std::string>(settings,
                                               section + "/" + key, "");
   }

/*************************************************
* See if a particular option has been set        *
*************************************************/
bool Config::is_set(const std::string& section,
                    const std::string& key) const
   {
   Named_Mutex_Holder lock("config");

   return search_map(settings, section + "/" + key, false, true);
   }

/*************************************************
* Set a configuration value                      *
*************************************************/
void Config::set(const std::string& section, const std::string& key,
                 const std::string& value, bool overwrite)
   {
   Named_Mutex_Holder lock("config");

   std::string full_key = section + "/" + key;

   std::map<std::string, std::string>::const_iterator i =
      settings.find(full_key);

   if(overwrite || i == settings.end() || i->second == "")
      settings[full_key] = value;
   }

/*************************************************
* Add an alias                                   *
*************************************************/
void Config::add_alias(const std::string& key, const std::string& value)
   {
   set("alias", key, value);
   }

/*************************************************
* Dereference an alias to a fixed name           *
*************************************************/
std::string Config::deref_alias(const std::string& key) const
   {
   std::string result = key;
   while(is_set("alias", result))
      result = get("alias", result);
   return result;
   }

/*************************************************
* Set/Add an option                              *
*************************************************/
void Config::set_option(const std::string key, const std::string& value)
   {
   set("conf", key, value);
   }

/*************************************************
* Get an option value                            *
*************************************************/
std::string Config::option(const std::string& key) const
   {
   return get("conf", key);
   }

/*************************************************
* Get the config setting as a list of strings    *
*************************************************/
std::vector<std::string> Config::option_as_list(const std::string& key) const
   {
   return split_on(option(key), ':');
   }

/*************************************************
* Get the config setting as a u32bit             *
*************************************************/
u32bit Config::option_as_u32bit(const std::string& key) const
   {
   return parse_expr(option(key));
   }

/*************************************************
* Get the config setting as a time               *
*************************************************/
u32bit Config::option_as_time(const std::string& key) const
   {
   const std::string timespec = option(key);
   if(timespec == "")
      return 0;

   const char suffix = timespec[timespec.size()-1];
   std::string value = timespec.substr(0, timespec.size()-1);

   u32bit scale = 1;

   if(Charset::is_digit(suffix))
      value += suffix;
   else if(suffix == 's')
      scale = 1;
   else if(suffix == 'm')
      scale = 60;
   else if(suffix == 'h')
      scale = 60 * 60;
   else if(suffix == 'd')
      scale = 24 * 60 * 60;
   else if(suffix == 'y')
      scale = 365 * 24 * 60 * 60;
   else
      throw Decoding_Error(
         "Config::option_as_time: Unknown time value " + value
         );

   return scale * to_u32bit(value);
   }

/*************************************************
* Get the config setting as a boolean            *
*************************************************/
bool Config::option_as_bool(const std::string& key) const
   {
   const std::string value = option(key);
   if(value == "0" || value == "false")
      return false;
   if(value == "1" || value == "true")
      return true;

   throw Decoding_Error(
      "Config::option_as_bool: Unknown boolean value " + value
      );
   }

/*************************************************
* Choose the signature format for a PK algorithm *
*************************************************/
void Config::choose_sig_format(const std::string& algo_name,
                               std::string& padding,
                               Signature_Format& format)
   {
   if(algo_name == "RSA")
      {
      std::string hash = global_state().config().option("x509/ca/rsa_hash");

      if(hash == "")
         throw Invalid_State("No value set for x509/ca/rsa_hash");

      hash = global_state().config().deref_alias(hash);

      padding = "EMSA3(" + hash + ")";
      format = IEEE_1363;
      }
   else if(algo_name == "DSA")
      {
      std::string hash = global_state().config().deref_alias("SHA-1");
      padding = "EMSA1(" + hash + ")";
      format = DER_SEQUENCE;
      }
   else
      throw Invalid_Argument("Unknown X.509 signing key type: " + algo_name);
   }

/*************************************************
* Dereference an alias                           *
*************************************************/
std::string deref_alias(const std::string& name)
   {
   return global_config().deref_alias(name);
   }

}

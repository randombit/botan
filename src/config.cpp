/*************************************************
* Configuration Handling Source File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/config.h>
#include <botan/libstate.h>
#include <botan/mutex.h>
#include <botan/stl_util.h>
#include <botan/lookup.h>
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
* Dereference an alias                           *
*************************************************/
std::string deref_alias(const std::string& name)
   {
   return global_state().config().deref_alias(name);
   }

/*************************************************
* Get a configuration value                      *
*************************************************/
Config::Config()
   {
   mutex = global_state().get_mutex();
   }

/*************************************************
* Get a configuration value                      *
*************************************************/
Config::~Config()
   {
   delete mutex;
   }

/*************************************************
* Get a configuration value                      *
*************************************************/
std::string Config::get(const std::string& section,
                        const std::string& key) const
   {
   Mutex_Holder lock(mutex);

   return search_map<std::string, std::string>(settings,
                                               section + "/" + key, "");
   }

/*************************************************
* See if a particular option has been set        *
*************************************************/
bool Config::is_set(const std::string& section,
                    const std::string& key) const
   {
   Mutex_Holder lock(mutex);

   return search_map(settings, section + "/" + key, false, true);
   }

/*************************************************
* Set a configuration value                      *
*************************************************/
void Config::set(const std::string& section, const std::string& key,
                 const std::string& value, bool overwrite)
   {
   Mutex_Holder lock(mutex);

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

}

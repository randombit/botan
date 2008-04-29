/*************************************************
* Configuration Handling Header File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_POLICY_CONF_H__
#define BOTAN_POLICY_CONF_H__

#include <botan/mutex.h>
#include <string>
#include <vector>
#include <map>

namespace Botan {

/*************************************************
* Library Configuration Settings                 *
*************************************************/
class BOTAN_DLL Config
   {
   public:
      Config();
      ~Config();

      void load_defaults();

      std::string get(const std::string&, const std::string&) const;
      bool is_set(const std::string&, const std::string&) const;
      void set(const std::string&, const std::string&,
               const std::string&, bool = true);

      std::string option(const std::string&) const;
      u32bit option_as_time(const std::string&) const;

      void set_option(const std::string, const std::string&);

      void add_alias(const std::string&, const std::string&);
      std::string deref_alias(const std::string&) const;

      void load_inifile(const std::string&);
   private:
      Config(const Config&) {}
      Config& operator=(const Config&) { return (*this); }

      std::map<std::string, std::string> settings;
      Mutex* mutex;
   };

/*************************************************
* Hook for the global config                     *
*************************************************/
BOTAN_DLL Config& global_config();

}

#endif

/*************************************************
* Configuration Handling Header File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_POLICY_CONF_H__
#define BOTAN_POLICY_CONF_H__

#include <botan/mutex.h>
#include <botan/enums.h>
#include <string>
#include <vector>
#include <map>

namespace Botan {

/*************************************************
* Library Configuration Settings                 *
*************************************************/
class Config
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
      u32bit option_as_u32bit(const std::string&) const;
      u32bit option_as_time(const std::string&) const;
      std::vector<std::string> option_as_list(const std::string&) const;

      void set_option(const std::string, const std::string&);

      void add_alias(const std::string&, const std::string&);
      std::string deref_alias(const std::string&) const;

      void load_inifile(const std::string&);

      static void choose_sig_format(const std::string&, std::string&,
                                    Signature_Format&);
   private:
      Config(const Config&) {}
      Config& operator=(const Config&) { return (*this); }

      std::map<std::string, std::string> settings;
      Mutex* mutex;
   };

/*************************************************
* Hook for the global config                     *
*************************************************/
Config& global_config();

}

#endif

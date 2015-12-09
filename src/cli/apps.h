/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>
#include <functional>
#include <string>
#include <set>
#include <botan/build.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include "getopt.h"

using namespace Botan;

typedef std::function<int (std::vector<std::string>)> app_fn;

class AppRegistrations
   {
   public:
      void add(const std::string& name, app_fn fn)
         {
         m_apps[name] = fn;
         }

      bool has(const std::string& cmd) const
         {
         return m_apps.count(cmd) > 0;
         }

      std::set<std::string> all_appnames() const
         {
         std::set<std::string> apps;
         for(auto i : m_apps)
            apps.insert(i.first);
         return apps;
         }

      // TODO: Remove redundancy cmd == args[0]
      int run(const std::string& cmd, std::vector<std::string> args) const
         {
         const auto app = m_apps.find(cmd);
         if(app != m_apps.end())
            return app->second(args);
         return -1;
         }

      static AppRegistrations& instance()
         {
         static AppRegistrations s_apps;
         return s_apps;
         }

      class AppRegistration
         {
         public:
            AppRegistration(const std::string& name, app_fn fn)
               {
               AppRegistrations::instance().add(name, fn);
               }
         };

   private:
      AppRegistrations() {}

      std::map<std::string, app_fn> m_apps;
   };

#define REGISTER_APP(nm) AppRegistrations::AppRegistration g_ ## nm ## _registration(#nm, nm)

#if defined(BOTAN_TARGET_OS_IS_WINDOWS) || defined(BOTAN_TARGET_OS_IS_MINGW)
  #undef BOTAN_TARGET_OS_HAS_SOCKETS
#else
  #define BOTAN_TARGET_OS_HAS_SOCKETS
#endif

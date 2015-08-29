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

typedef std::function<int (int, char*[])> main_fn;

class AppRegistrations
   {
   public:
      void add(const std::string& name, main_fn fn)
         {
         m_cmds[name] = fn;
         }

      bool has(const std::string& cmd) const
         {
         return m_cmds.count(cmd) > 0;
         }

      std::set<std::string> all_apps() const
         {
         std::set<std::string> apps;
         for(auto i : m_cmds)
            apps.insert(i.first);
         return apps;
         }

      int run(const std::string& cmd, int argc, char* argv[]) const
         {
         auto i = m_cmds.find(cmd);
         if(i != m_cmds.end())
            return i->second(argc, argv);
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
            AppRegistration(const std::string& name, main_fn fn)
               {
               AppRegistrations::instance().add(name, fn);
               }
         };

   private:
      AppRegistrations() {}

      std::map<std::string, main_fn> m_cmds;
   };

#define REGISTER_APP(nm) AppRegistrations::AppRegistration g_ ## nm ## _registration(#nm, nm)

#if defined(BOTAN_TARGET_OS_IS_WINDOWS) || defined(BOTAN_TARGET_OS_IS_MINGW)
  #undef BOTAN_TARGET_OS_HAS_SOCKETS
#else
  #define BOTAN_TARGET_OS_HAS_SOCKETS
#endif

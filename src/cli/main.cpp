/*
* (C) 2009,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <vector>
#include <string>

#include <iostream>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>

#include <botan/version.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_HTTP_UTIL)
#include <botan/http_util.h>
#endif

using namespace Botan;

#include "apps.h"

namespace {

int help(const std::vector<std::string> &args)
   {
   std::cout << "Usage: " << args[0] << " [subcommand] [subcommand-options]" << std::endl;

   std::set<std::string> apps = AppRegistrations::instance().all_appnames();

   std::cout << "Available commands:" << std::endl;

   size_t idx = 1;
   for(auto&& app: apps)
      {
      std::cout << app;

      if(idx % 3 == 0)
         std::cout << std::endl;
      else
         std::cout << std::string(18-app.size(), ' ');

      ++idx;
      }
   std::cout << std::endl;

   return 1;
   }

int config(const std::vector<std::string> &args)
   {
   if(args.size() != 2)
      {
      std::cout << "Usage: " << args[0] << " <what>\n"
                << "   prefix: Print install prefix\n"
                << "   cflags: Print include params\n"
                << "   ldflags: Print linker params\n"
                << "   libs: Print libraries" << std::endl;
      return 1;
      }

   const std::string arg = args[1];

   if(arg == "prefix")
      std::cout << BOTAN_INSTALL_PREFIX << std::endl;

   else if(arg == "cflags")
      std::cout << "-I" << BOTAN_INSTALL_PREFIX << "/" << BOTAN_INSTALL_HEADER_DIR << std::endl;

   else if(arg == "ldflags")
      std::cout << "-L" << BOTAN_INSTALL_PREFIX << "/" << BOTAN_INSTALL_LIB_DIR << std::endl;

   else if(arg == "libs")
      std::cout << "-lbotan-" << version_major() << "." << version_minor()
                << " " << BOTAN_LIB_LINK << std::endl;

   else
      {
      std::cerr << "Unknown option " << arg << " to botan config" << std::endl;
      return 1;
      }

   return 0;
   }
REGISTER_APP(config);

int version(const std::vector<std::string> &args)
   {
   if(BOTAN_VERSION_MAJOR != version_major() ||
      BOTAN_VERSION_MINOR != version_minor() ||
      BOTAN_VERSION_PATCH != version_patch())
      {
      std::cerr << "Warning: linked version ("
                << version_major() << '.'
                << version_minor() << '.'
                << version_patch()
                << ") does not match version built against ("
                << BOTAN_VERSION_MAJOR << '.'
                << BOTAN_VERSION_MINOR << '.'
                << BOTAN_VERSION_PATCH << ")" << std::endl;
      }

   if(args.size() == 1)
      {
      std::cout << Botan::version_major() << "."
                << Botan::version_minor() << "."
                << Botan::version_patch() << std::endl;
      }
   else if(args.size() == 2 && args[1] == "--full")
      {
      std::cout << Botan::version_string() << std::endl;
      }
   else
      {
      std::cout << "Usage: " << args[0] << " version [--full]" << std::endl;
      return 1;
      }

   return 0;
   }
REGISTER_APP(version);

int cpuid(const std::vector<std::string> &args)
   {
   BOTAN_UNUSED(args);
   CPUID::print(std::cout);
   return 0;
   }
REGISTER_APP(cpuid);

#if defined(BOTAN_HAS_HTTP_UTIL)
int http_get(const std::vector<std::string> &args)
   {
   if(args.size() != 2)
      {
      std::cout << "Usage " << args[0] << " <url>" << std::endl;
      return 1;
      }

   auto resp = HTTP::GET_sync(args[1]);
   std::cout << resp << std::endl;
   return 0;
   }
REGISTER_APP(http_get);

#endif

}

int main(int argc, char* argv[])
   {
   const std::vector<std::string> args(argv, argv + argc);

   try
      {
      if(args.size() < 2)
         return help(args);

      const std::string cmd = args[1];

      if(cmd == "help" || cmd == "-h")
         return help(args);

      AppRegistrations& apps = AppRegistrations::instance();
      if(apps.has(cmd))
         return apps.run(cmd, std::vector<std::string>(args.begin()+1, args.end()));

      std::cerr << "Unknown command " << cmd << std::endl;
      return help(args);
      }
   catch(std::exception& e)
      {
      std::cerr << e.what() << std::endl;
      return 1;
      }
   catch(...)
      {
      std::cerr << "Unknown exception caught" << std::endl;
      return 1;
      }

   return 0;
   }

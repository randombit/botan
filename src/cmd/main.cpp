/*
* (C) 2009,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <vector>
#include <string>

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>

#include <botan/init.h>
#include <botan/version.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_HTTP_UTIL)
#include <botan/http_util.h>
#endif

using namespace Botan;

#include "apps.h"

namespace {

int help(int , char* argv[])
   {
   std::cout << "Usage: " << argv[0] << " [subcommand] [subcommand-options]\n";

   std::set<std::string> apps = AppRegistrations::instance().all_apps();

   std::cout << "Available commands:\n";

   size_t idx = 1;
   for(auto&& app: apps)
      {
      std::cout << app;

      if(idx % 3 == 0)
         std::cout << "\n";
      else
         std::cout << std::string(18-app.size(), ' ');

      ++idx;
      }
   std::cout << "\n";

   return 1;
   }

int config(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage: " << argv[0] << " <what>\n"
                << "   prefix: Print install prefix\n"
                << "   cflags: Print include params\n"
                << "   ldflags: Print linker params\n"
                << "   libs: Print libraries\n";
      return 1;
      }

   const std::string arg = argv[1];

   if(arg == "prefix")
      std::cout << BOTAN_INSTALL_PREFIX << "\n";

   else if(arg == "cflags")
      std::cout << "-I" << BOTAN_INSTALL_PREFIX << "/" << BOTAN_INSTALL_HEADER_DIR << "\n";

   else if(arg == "ldflags")
      std::cout << "-L" << BOTAN_INSTALL_PREFIX << "/" << BOTAN_INSTALL_LIB_DIR << "\n";

   else if(arg == "libs")
      std::cout << "-lbotan-" << version_major() << "." << version_minor()
                << " " << BOTAN_LIB_LINK << "\n";

   else
      {
      std::cerr << "Unknown option " << arg << " to botan-config\n";
      return 1;
      }

   return 0;
   }
REGISTER_APP(config);

int version(int argc, char* argv[])
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
                << BOTAN_VERSION_PATCH << ")\n";
      }

   if(argc == 1)
      {
      std::cout << Botan::version_major() << "."
                << Botan::version_minor() << "."
                << Botan::version_patch() << "\n";
      }
   else if(argc == 2 && std::string(argv[1]) == "--full")
      {
      std::cout << Botan::version_string() << "\n";
      }
   else
      {
      std::cout << "Usage: " << argv[0] << " version [--full]\n";
      return 1;
      }

   return 0;
   }
REGISTER_APP(version);

int cpuid(int, char*[])
   {
   CPUID::print(std::cout);
   return 0;
   }
REGISTER_APP(cpuid);

#if defined(BOTAN_HAS_HTTP_UTIL)
int http_get(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage " << argv[0] << " <url>\n";
      return 1;
      }

   auto resp = HTTP::GET_sync(argv[2]);
   std::cout << resp << "\n";
   return 0;
   }
REGISTER_APP(http_get);

#endif

}

int main(int argc, char* argv[])
   {
   try
      {
      Botan::LibraryInitializer init;

      if(argc < 2)
         return help(argc, argv);

      const std::string cmd = argv[1];

      if(cmd == "help" || cmd == "-h")
         return help(argc, argv);

      AppRegistrations& apps = AppRegistrations::instance();
      if(apps.has(cmd))
         return apps.run(cmd, argc - 1, argv + 1);

      std::cerr << "Unknown command " << cmd << std::endl;
      return help(argc, argv);
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


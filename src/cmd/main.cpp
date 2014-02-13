/*
* (C) 2009,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
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
   std::cout << "Usage: " << argv[0] << " [subcommand]\n";
   std::cout << "version config speed cpuid bcrypt x509 factor tls_client tls_server asn1 base64 hash self_sig ...\n";
   return 1;
   }

int config_main(int argc, char* argv[])
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

int version_main(int argc, char* argv[])
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
      std::cout << "Usage: " << argv[0] << " [--full]\n";
      return 1;
      }

   return 0;
   }

}

int unimplemented(int , char* argv[], const char* what)
   {
   std::cout << argv[0] << " command not implemented - library missing " << what << "\n";
   return 1;
   }

int main(int argc, char* argv[])
   {
   try
      {
      Botan::LibraryInitializer init;

      if(argc < 2)
         return help(argc, argv);

      const std::string cmd = argv[1];

      if(cmd == "help")
         return help(argc, argv);

      if(cmd == "config" && argc > 1)
         return config_main(argc - 1, argv + 1);

      if(cmd == "version" && argc > 1)
         return version_main(argc - 1, argv + 1);

      if(cmd == "cpuid")
         {
         CPUID::print(std::cout);
         return 0;
         }

#if defined(BOTAN_HAS_HTTP_UTIL)
      if(cmd == "http_get")
         {
         auto resp = HTTP::GET_sync(argv[2]);
         std::cout << resp << "\n";
         }
#endif

#define CALL_APP(cmdsym)                           \
   do { if(cmd == #cmdsym) { return cmdsym ##_main (argc - 1, argv + 1); } } while(0)

      CALL_APP(asn1);
      CALL_APP(base64);
      CALL_APP(bcrypt);
      CALL_APP(bzip);
      CALL_APP(dsa_sign);
      CALL_APP(dsa_verify);
      CALL_APP(factor);
      CALL_APP(fpe);
      CALL_APP(hash);
      CALL_APP(keygen);
      CALL_APP(read_ssh);
      CALL_APP(speed);

#if defined(BOTAN_HAS_TLS)
      CALL_APP(tls_client);
      CALL_APP(tls_server);
      CALL_APP(tls_server_asio);
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES)
      CALL_APP(ca);
      CALL_APP(pkcs10);
      CALL_APP(self_sig);
      CALL_APP(x509);
#endif

      std::cout << "Unknown command " << cmd << "\n";
      return help(argc, argv);
      }
   catch(std::exception& e)
      {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
      }
   catch(...)
      {
      std::cerr << "Unknown (...) exception caught" << std::endl;
      return 1;
      }

   return 0;
   }


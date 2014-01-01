/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
 * Test Driver for Botan
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
#include <botan/auto_rng.h>
#include <botan/cpuid.h>
#include <botan/http_util.h>

using namespace Botan;

#include "common.h"
#include "speed/speed.h"
#include "tests/tests.h"
#include "apps/apps.h"

// from common.h
void strip_comments(std::string& line)
   {
   if(line.find('#') != std::string::npos)
      line = line.erase(line.find('#'), std::string::npos);
   }

void strip_newlines(std::string& line)
   {
   while(line.find('\n') != std::string::npos)
      line = line.erase(line.find('\n'), 1);
   }

/* Strip comments, whitespace, etc */
void strip(std::string& line)
   {
   strip_comments(line);

#if 0
   while(line.find(' ') != std::string::npos)
      line = line.erase(line.find(' '), 1);
#endif

   while(line.find('\t') != std::string::npos)
      line = line.erase(line.find('\t'), 1);
   }

std::vector<std::string> parse(const std::string& line)
   {
   const char DELIMITER = ':';
   std::vector<std::string> substr;
   std::string::size_type start = 0, end = line.find(DELIMITER);
   while(end != std::string::npos)
      {
      substr.push_back(line.substr(start, end-start));
      start = end+1;
      end = line.find(DELIMITER, start);
      }
   if(line.size() > start)
      substr.push_back(line.substr(start));
   while(substr.size() <= 4) // at least 5 substr, some possibly empty
      substr.push_back("");
   return substr;
   }

namespace {

int help(int , char* argv[])
   {
   std::cout << "Usage: " << argv[0] << " subcommand\n";
   std::cout << "Common commands: help version test speed\n";
   std::cout << "Other commands: cpuid bcrypt x509 factor tls_client asn1 base64 hash self_sig\n";
   return 1;
   }

}

int main(int argc, char* argv[])
   {
   if(BOTAN_VERSION_MAJOR != version_major() ||
      BOTAN_VERSION_MINOR != version_minor() ||
      BOTAN_VERSION_PATCH != version_patch())
      {
      std::cout << "Warning: linked version ("
                << version_major() << '.'
                << version_minor() << '.'
                << version_patch()
                << ") does not match version built against ("
                << BOTAN_VERSION_MAJOR << '.'
                << BOTAN_VERSION_MINOR << '.'
                << BOTAN_VERSION_PATCH << ")\n";
      }

   try
      {
      Botan::LibraryInitializer init;

      if(argc < 2)
         return help(argc, argv);

      const std::string cmd = argv[1];

      if(cmd == "help")
         return help(argc, argv);

      if(cmd == "version")
         {
         std::cout << Botan::version_string() << "\n";
         return 0;
         }

      if(cmd == "cpuid")
         {
         CPUID::print(std::cout);
         return 0;
         }

      if(cmd == "test")
         {
         const size_t failures = run_all_tests();
         return failures ? 1 : 0;
         }

      if(cmd == "speed")
         return speed_main(argc - 1, argv + 1);

      if(cmd == "http_get")
         {
         auto resp = HTTP::GET_sync(argv[2]);
         std::cout << resp << "\n";
         }

#define CALL_CMD(cmdsym)                           \
      do { if(cmd == #cmdsym) { return cmdsym (argc - 1, argv + 1); } } while(0)

      CALL_CMD(asn1);
      CALL_CMD(base64);
      CALL_CMD(bcrypt);
      CALL_CMD(bzip);
      CALL_CMD(ca);
      CALL_CMD(factor);
      CALL_CMD(fpe);
      CALL_CMD(hash);
      CALL_CMD(keygen);
      CALL_CMD(pkcs10);
      CALL_CMD(read_ssh);
      CALL_CMD(self_sig);
      CALL_CMD(tls_client);
      CALL_CMD(tls_server);
      CALL_CMD(x509);
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


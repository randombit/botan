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

using namespace Botan;

#include "common.h"
#include "speed/speed.h"
#include "tests/tests.h"

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
      OptionParser opts("help|test|validate|"
                        "algo=|seconds=|buf-size=");
      opts.parse(argv);

      Botan::LibraryInitializer init;

      if(opts.is_set("help") || argc < 2)
         {
         std::cout << "Commands: test version time\n";
         return 1;
         }

      const std::string cmd = argv[1];

      if(cmd == "version")
         {
         std::cout << Botan::version_string() << "\n";
         return 0;
         }

      if(cmd == "test")
         {
         const size_t failures = run_all_tests();
         return failures ? 1 : 0;
         }

      if(cmd == "speed")
         {
         double seconds = 5;
         u32bit buf_size = 16;

         if(opts.is_set("seconds"))
            {
            seconds = std::atof(opts.value("seconds").c_str());
            if(seconds < 0.1 || seconds > (5 * 60))
               {
               std::cout << "Invalid argument to --seconds\n";
               return 2;
               }
            }

         if(opts.is_set("buf-size"))
            {
            buf_size = std::atoi(opts.value("buf-size").c_str());
            if(buf_size == 0 || buf_size > 1024)
               {
               std::cout << "Invalid argument to --buf-size\n";
               return 2;
               }
            }

         if(opts.is_set("--algo"))
            {
            AutoSeeded_RNG rng;
            for(auto alg: Botan::split_on(opts.value("algo"), ','))
               bench_algo(alg, rng, seconds, buf_size);
            }
         /*
         else
            benchmark(seconds, buf_size);
         */
         }
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


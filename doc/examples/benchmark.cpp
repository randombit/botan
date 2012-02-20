/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/benchmark.h>

#include <iostream>
#include <string>
#include <map>
#include <cstdlib>

int main(int argc, char* argv[])
   {
   if(argc <= 2)
      {
      std::cout << "Usage: " << argv[0] << " seconds <algo1> <algo2> ...\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   Botan::AutoSeeded_RNG rng;

   Botan::Algorithm_Factory& af = Botan::global_state().algorithm_factory();

   double ms = 1000 * std::atof(argv[1]);

   for(size_t i = 2; argv[i]; ++i)
      {
      std::string algo = argv[i];

      std::map<std::string, double> results =
         algorithm_benchmark(algo, af, rng, ms, 16);

      std::cout << algo << ":\n";
      for(std::map<std::string, double>::iterator r = results.begin();
          r != results.end(); ++r)
         {
         std::cout << "  " << r->first << ": " << r->second << " MiB/s\n";
         }
      std::cout << "\n";
      }
   }

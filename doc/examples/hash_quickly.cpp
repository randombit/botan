/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
Try to find the fastest SHA-1 implementation and use it to hash
files. In most programs this isn't worth the bother and
overhead. However with large amount of input, it is worth it. On tests
on a Core2 system with the SHA-1 SSE2 code enabled, over a few hundred
Mb or so the overhead paid for itself.

Of course you could also just do this once and save it as an
application config, which is probably the smart thing to do.
*/

#include <botan/botan.h>
#include <botan/benchmark.h>
#include <botan/filters.h>

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <cstdlib>

namespace {

void set_fastest_implementation(const std::string& algo,
                                Botan::RandomNumberGenerator& rng,
                                double ms = 30)
   {
   Botan::Algorithm_Factory& af = Botan::global_state().algorithm_factory();

   std::map<std::string, double> results =
      Botan::algorithm_benchmark(algo, af, rng, ms, 16);

   std::string fastest_provider = "";
   double best_res = 0;

   for(std::map<std::string, double>::iterator r = results.begin();
       r != results.end(); ++r)
      {
      std::cout << r->first << " @ " << r->second << " MiB/sec\n";

      if(fastest_provider == "" || r->second > best_res)
         {
         fastest_provider = r->first;
         best_res = r->second;
         }
      }

   std::cout << "Using " << fastest_provider << "\n";

   af.set_preferred_provider(algo, fastest_provider);
   }

}

int main(int argc, char* argv[])
   {
   if(argc <= 1)
      {
      std::cout << "Usage: " << argv[0] << " <file> <file> ...\n";
      return 1;
      }

   Botan::LibraryInitializer init;
   Botan::AutoSeeded_RNG rng;

   const std::string hash = "SHA-1";

   set_fastest_implementation(hash, rng);

   // Here we intentionally use the 'old style' lookup interface
   // which will also respect the provider settings. Or can use:
   //   global_state().algorithm_factory().make_hash_function(hash)
   Botan::Pipe pipe(
      new Botan::Hash_Filter(Botan::get_hash(hash)),
      new Botan::Hex_Encoder
      );

   for(size_t i = 1; argv[i]; ++i)
      {
      std::ifstream in(argv[i], std::ios::binary);
      if(!in)
         continue;

      pipe.start_msg();
      in >> pipe;
      pipe.end_msg();

      std::cout << argv[i] << " = "
                << pipe.read_all_as_string(Botan::Pipe::LAST_MESSAGE) << "\n";

      }
   }

#include "tests.h"

#include <botan/libstate.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

bool hash_test(const std::string& algo,
              const std::string& in_hex,
              const std::string& out_hex)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   const auto providers = af.providers_of(algo);
   size_t fails = 0;

   for(auto provider: providers)
      {
      auto proto = af.prototype_hash_function(algo, provider);

      if(!proto)
         {
         std::cout << "Unable to get " << algo << " from " << provider << "\n";
         ++fails;
         continue;
         }

      std::unique_ptr<HashFunction> hash(proto->clone());

      hash->update(hex_decode(in_hex));

      auto h = hash->final();

      if(h != hex_decode_locked(out_hex))
         {
         std::cout << algo << " " << provider << " got " << hex_encode(h) << " != " << out_hex << "\n";
         ++fails;
         }
      }

   return (fails == 0);
   }

}

size_t test_hash()
   {
   std::ifstream vec("checks/hash.vec");

   return run_tests_bb(vec, "Hash", "Out", true,
             [](std::map<std::string, std::string> m) -> bool
             {
             return hash_test(m["Hash"], m["In"], m["Out"]);
             });
   }

#include "tests.h"

#include <botan/libstate.h>
#include <botan/mac.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

bool mac_test(const std::string& algo,
              const std::string& key_hex,
              const std::string& in_hex,
              const std::string& out_hex)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   const auto providers = af.providers_of(algo);
   size_t fails = 0;

   for(auto provider: providers)
      {
      auto proto = af.prototype_mac(algo, provider);

      if(!proto)
         {
         std::cout << "Unable to get " << algo << " from " << provider << "\n";
         ++fails;
         continue;
         }

      std::unique_ptr<MessageAuthenticationCode> mac(proto->clone());

      mac->set_key(hex_decode(key_hex));
      mac->update(hex_decode(in_hex));

      auto h = mac->final();

      if(h != hex_decode_locked(out_hex))
         {
         std::cout << algo << " " << provider << " got " << hex_encode(h) << " != " << out_hex << "\n";
         ++fails;
         }
      }

   return (fails == 0);
   }

}

size_t test_mac()
   {
   std::ifstream vec(CHECKS_DIR "/mac.vec");

   return run_tests_bb(vec, "Mac", "Out", true,
             [](std::map<std::string, std::string> m) -> bool
             {
             return mac_test(m["Mac"], m["Key"], m["In"], m["Out"]);
             });
   }

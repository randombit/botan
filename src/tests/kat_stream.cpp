#include "tests.h"

#include <botan/libstate.h>
#include <botan/stream_cipher.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t stream_test(const std::string& algo,
                   const std::string& key_hex,
                   const std::string& in_hex,
                   const std::string& out_hex,
                   const std::string& nonce_hex)
   {
   const secure_vector<byte> key = hex_decode_locked(key_hex);
   const secure_vector<byte> pt = hex_decode_locked(in_hex);
   const secure_vector<byte> ct = hex_decode_locked(out_hex);
   const secure_vector<byte> nonce = hex_decode_locked(nonce_hex);

   Algorithm_Factory& af = global_state().algorithm_factory();

   const auto providers = af.providers_of(algo);
   size_t fails = 0;

   for(auto provider: providers)
      {
      const StreamCipher* proto = af.prototype_stream_cipher(algo, provider);

      if(!proto)
         {
         std::cout << "Unable to get " << algo << " from " << provider << "\n";
         ++fails;
         continue;
         }

      std::unique_ptr<StreamCipher> cipher(proto->clone());
      cipher->set_key(key);

      if(nonce.size())
         cipher->set_iv(&nonce[0], nonce.size());

      secure_vector<byte> buf = pt;

      cipher->encrypt(buf);

      if(buf != ct)
         {
         std::cout << algo << " " << provider << " enc " << hex_encode(buf) << " != " << out_hex << "\n";
         ++fails;
         }
      }

   return fails;
   }

}

size_t test_stream()
   {
   auto test = [](const std::string& input)
      {
      std::ifstream vec(input);

      return run_tests_bb(vec, "StreamCipher", "Out", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return stream_test(m["StreamCipher"], m["Key"], m["In"], m["Out"], m["Nonce"]);
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "/stream", test);
   }

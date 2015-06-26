/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_STREAM_CIPHER)

#include <botan/stream_cipher.h>
#include <botan/lookup.h>
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

   const std::vector<std::string> providers = get_stream_cipher_providers(algo);
   size_t fails = 0;

   if(providers.empty())
      {
      std::cout << "Unknown stream cipher " << algo << std::endl;
      ++fails;
      }

   for(auto provider: providers)
      {
      std::unique_ptr<StreamCipher> cipher(get_stream_cipher(algo, provider));

      if(!cipher)
         {
         std::cout << "Unable to get " << algo << " from " << provider << std::endl;
         ++fails;
         continue;
         }

      cipher->set_key(key);

      if(nonce.size())
         cipher->set_iv(nonce.data(), nonce.size());

      secure_vector<byte> buf = pt;

      cipher->encrypt(buf);

      if(buf != ct)
         {
         std::cout << algo << " " << provider << " enc " << hex_encode(buf) << " != " << out_hex << std::endl;
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

#else

SKIP_TEST(stream);

#endif // BOTAN_HAS_STREAM_CIPHER

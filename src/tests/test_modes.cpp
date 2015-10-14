/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MODES)

#include <botan/hex.h>
#include <botan/cipher_mode.h>
#include <iostream>
#include <fstream>
#include <memory>

using namespace Botan;

namespace {

secure_vector<byte> run_mode(const std::string& algo,
                             Cipher_Dir dir,
                             const secure_vector<byte>& pt,
                             const secure_vector<byte>& nonce,
                             const secure_vector<byte>& key)
   {
   std::unique_ptr<Cipher_Mode> cipher(get_cipher_mode(algo, dir));
   if(!cipher)
      throw std::runtime_error("No cipher " + algo + " enabled in build");

   cipher->set_key(key);
   cipher->start(nonce);

   secure_vector<byte> ct = pt;
   cipher->finish(ct);
   return ct;
   }

size_t mode_test(const std::string& algo,
                 const std::string& pt,
                 const std::string& ct,
                 const std::string& key_hex,
                 const std::string& nonce_hex)
   {
   auto nonce = hex_decode_locked(nonce_hex);
   auto key = hex_decode_locked(key_hex);

   size_t fails = 0;

   const std::string ct2 = hex_encode(run_mode(algo,
                                               ENCRYPTION,
                                               hex_decode_locked(pt),
                                               nonce,
                                               key));

   if(ct != ct2)
      {
      std::cout << algo << " got ct " << ct2 << " expected " << ct << std::endl;
      ++fails;
      }

   const std::string pt2 = hex_encode(run_mode(algo,
                                               DECRYPTION,
                                               hex_decode_locked(ct),
                                               nonce,
                                               key));

   if(pt != pt2)
      {
      std::cout << algo << " got pt " << pt2 << " expected " << pt << std::endl;
      ++fails;
      }

   return fails;
   }

}

size_t test_modes()
   {
   auto test = [](const std::string& input)
      {
      std::ifstream vec(input);

      return run_tests_bb(vec, "Mode", "Out", true,
             [](std::map<std::string, std::string> m)
             {
             return mode_test(m["Mode"], m["In"], m["Out"], m["Key"], m["Nonce"]);
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "/modes", test);
   }

#else

SKIP_TEST(modes);

#endif // BOTAN_HAS_MODES

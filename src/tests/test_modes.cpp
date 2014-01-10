#include "tests.h"

#include <botan/hex.h>
#include <botan/lookup.h>
#include <botan/cipher_mode.h>
#include <botan/filters.h>
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
#if 0
   std::unique_ptr<Cipher_Mode> cipher(get_cipher(algo, dir));

   cipher->set_key(key);
   cipher->start_vec(nonce);

   secure_vector<byte> ct = pt;
   cipher->finish(ct);
#endif

   Pipe pipe(get_cipher(algo, SymmetricKey(key), InitializationVector(nonce), dir));

   pipe.process_msg(pt);

   return pipe.read_all();
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
      std::cout << algo << " got ct " << ct2 << " expected " << ct << "\n";
      ++fails;
      }

   const std::string pt2 = hex_encode(run_mode(algo,
                                               DECRYPTION,
                                               hex_decode_locked(ct),
                                               nonce,
                                               key));

   if(pt != pt2)
      {
      std::cout << algo << " got pt " << pt2 << " expected " << pt << "\n";
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

   return run_tests_in_dir(TEST_DATA_DIR "modes", test);
   }

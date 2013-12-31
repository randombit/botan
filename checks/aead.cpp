#include "tests.h"

#include <botan/hex.h>
#include <botan/siv.h>
#include <botan/aead.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

secure_vector<byte> aead(const std::string& algo,
                         Cipher_Dir dir,
                         const secure_vector<byte>& pt,
                         const secure_vector<byte>& nonce,
                         const secure_vector<byte>& ad,
                         const secure_vector<byte>& key)
   {
   std::unique_ptr<AEAD_Mode> aead(get_aead(algo, dir));

   aead->set_key(&key[0], key.size());
   aead->start_vec(nonce);
   aead->set_associated_data_vec(ad);

   secure_vector<byte> ct = pt;
   aead->finish(ct);

   return ct;
   }

bool aead_test(const std::string& algo,
               const std::string& pt,
               const std::string& ct,
               const std::string& nonce_hex,
               const std::string& ad_hex,
               const std::string& key_hex)
   {
   auto nonce = hex_decode_locked(nonce_hex);
   auto ad = hex_decode_locked(ad_hex);
   auto key = hex_decode_locked(key_hex);

   const std::string ct2 = hex_encode(aead(algo,
                                           ENCRYPTION,
                                           hex_decode_locked(pt),
                                           nonce,
                                           ad,
                                           key));

   if(ct != ct2)
      std::cout << algo << " got ct " << ct2 << " expected " << ct << "\n";

   const std::string pt2 = hex_encode(aead(algo,
                                           DECRYPTION,
                                           hex_decode_locked(ct),
                                           nonce,
                                           ad,
                                           key));

   if(pt != pt2)
      std::cout << algo << " got pt " << pt2 << " expected " << pt << "\n";

   return (ct == ct2) && (pt == pt2);
   }

}

size_t test_aead()
   {
   std::ifstream vec("checks/aead.vec");

   return run_tests_bb(vec, "AEAD", "Ciphertext", true,
             [](std::map<std::string, std::string> m)
             {
             return aead_test(m["AEAD"], m["Plaintext"], m["Ciphertext"],
                              m["Nonce"], m["AD"], m["Key"]);
             });
   }

/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/hex.h>
#include <botan/aead.h>
#include <iostream>
#include <fstream>
#include <memory>

using namespace Botan;

namespace {

size_t aead_test(const std::string& algo,
                 const std::string& input,
                 const std::string& expected,
                 const std::string& nonce_hex,
                 const std::string& ad_hex,
                 const std::string& key_hex)
   {
   const auto nonce = hex_decode_locked(nonce_hex);
   const auto ad = hex_decode_locked(ad_hex);
   const auto key = hex_decode_locked(key_hex);

   std::unique_ptr<Cipher_Mode> enc(get_aead(algo, ENCRYPTION));
   std::unique_ptr<Cipher_Mode> dec(get_aead(algo, DECRYPTION));

   if(!enc || !dec)
      throw std::runtime_error("Unknown AEAD " + algo);

   enc->set_key(key);
   dec->set_key(key);

   if(auto aead_enc = dynamic_cast<AEAD_Mode*>(enc.get()))
      aead_enc->set_associated_data_vec(ad);
   if(auto aead_dec = dynamic_cast<AEAD_Mode*>(dec.get()))
      aead_dec->set_associated_data_vec(ad);

   size_t fail = 0;

   const auto pt = hex_decode_locked(input);
   const auto expected_ct = hex_decode_locked(expected);

   auto vec = pt;
   enc->start(nonce);
   // should first update if possible
   enc->finish(vec);

   if(vec != expected_ct)
      {
      std::cout << algo << " got ct " << hex_encode(vec) << " expected " << expected << "\n";
      std::cout << algo << "\n";
      ++fail;
      }

   vec = expected_ct;

   dec->start(nonce);
   dec->finish(vec);

   if(vec != pt)
      {
      std::cout << algo << " got pt " << hex_encode(vec) << " expected " << input << "\n";
      ++fail;
      }

   if(enc->authenticated())
      {
      vec = expected_ct;
      vec[0] ^= 1;
      dec->start(nonce);
      try
         {
         dec->finish(vec);
         std::cout << algo << " accepted message with modified message\n";
         ++fail;
         }
      catch(...) {}

      if(nonce.size())
         {
         auto bad_nonce = nonce;
         bad_nonce[0] ^= 1;
         vec = expected_ct;

         dec->start(bad_nonce);

         try
            {
            dec->finish(vec);
            std::cout << algo << " accepted message with modified nonce\n";
            ++fail;
            }
         catch(...) {}
         }

      if(auto aead_dec = dynamic_cast<AEAD_Mode*>(dec.get()))
         {
         auto bad_ad = ad;

         if(ad.size())
            bad_ad[0] ^= 1;
         else
            bad_ad.push_back(0);

         aead_dec->set_associated_data_vec(bad_ad);

         vec = expected_ct;
         dec->start(nonce);

         try
            {
            dec->finish(vec);
            std::cout << algo << " accepted message with modified AD\n";
            ++fail;
            }
         catch(...) {}
         }
      }

   return fail;
   }

}

size_t test_aead()
   {
   auto test = [](const std::string& input)
      {
      std::ifstream vec(input);

      return run_tests_bb(vec, "AEAD", "Out", true,
             [](std::map<std::string, std::string> m)
             {
             return aead_test(m["AEAD"], m["In"], m["Out"],
                              m["Nonce"], m["AD"], m["Key"]);
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "aead", test);
   }

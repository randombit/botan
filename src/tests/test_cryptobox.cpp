/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <iostream>

#if defined(BOTAN_HAS_CRYPTO_BOX)
  #include <botan/cryptobox.h>
#endif

using namespace Botan;

size_t test_cryptobox()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_CRYPTO_BOX)
   auto& rng = test_rng();

   const byte msg[] = { 0xAA, 0xBB, 0xCC };
   std::string ciphertext = CryptoBox::encrypt(msg, sizeof(msg),
                                               "secret password",
                                               rng);

   try
      {
      std::string plaintext = CryptoBox::decrypt(ciphertext,
                                                 "secret password");

      if(plaintext.size() != sizeof(msg) ||
         !same_mem(reinterpret_cast<const byte*>(plaintext.data()), msg, sizeof(msg)))
         ++fails;

      }
   catch(std::exception& e)
      {
      std::cout << "Error during Cryptobox test " << e.what() << "\n";
      ++fails;
      }

   test_report("Cryptobox", 1, fails);
#endif

   return fails;
   }


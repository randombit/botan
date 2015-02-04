/*
* PBKDF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pbkdf_utils.h>
#include <botan/pbkdf1.h>
#include <botan/exceptn.h>

namespace Botan {

BOTAN_REGISTER_PBKDF_1HASH(PKCS5_PBKDF1, "PBKDF1")

/*
* Return a PKCS#5 PBKDF1 derived key
*/
std::pair<size_t, OctetString>
PKCS5_PBKDF1::key_derivation(size_t key_len,
                             const std::string& passphrase,
                             const byte salt[], size_t salt_len,
                             size_t iterations,
                             std::chrono::milliseconds msec) const
   {
   if(key_len > hash->output_length())
      throw Invalid_Argument("PKCS5_PBKDF1: Requested output length too long");

   hash->update(passphrase);
   hash->update(salt, salt_len);
   secure_vector<byte> key = hash->final();

   const auto start = std::chrono::high_resolution_clock::now();
   size_t iterations_performed = 1;

   while(true)
      {
      if(iterations == 0)
         {
         if(iterations_performed % 10000 == 0)
            {
            auto time_taken = std::chrono::high_resolution_clock::now() - start;
            auto msec_taken = std::chrono::duration_cast<std::chrono::milliseconds>(time_taken);
            if(msec_taken > msec)
               break;
            }
         }
      else if(iterations_performed == iterations)
         break;

      hash->update(key);
      hash->final(&key[0]);

      ++iterations_performed;
      }

   return std::make_pair(iterations_performed,
                         OctetString(&key[0], std::min(key_len, key.size())));
   }

}

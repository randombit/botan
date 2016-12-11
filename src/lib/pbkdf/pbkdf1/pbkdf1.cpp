/*
* PBKDF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbkdf1.h>
#include <botan/exceptn.h>

namespace Botan {

size_t PKCS5_PBKDF1::pbkdf(uint8_t output_buf[], size_t output_len,
                           const std::string& passphrase,
                           const uint8_t salt[], size_t salt_len,
                           size_t iterations,
                           std::chrono::milliseconds msec) const
   {
   if(output_len > m_hash->output_length())
      throw Invalid_Argument("PKCS5_PBKDF1: Requested output length too long");

   m_hash->update(passphrase);
   m_hash->update(salt, salt_len);
   secure_vector<uint8_t> key = m_hash->final();

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

      m_hash->update(key);
      m_hash->final(key.data());

      ++iterations_performed;
      }

   copy_mem(output_buf, key.data(), output_len);
   return iterations_performed;
   }

}

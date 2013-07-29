/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pbkdf2.h>
#include <botan/get_byte.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/rounding.h>

namespace Botan {

/*
* Return a PKCS #5 PBKDF2 derived key
*/
std::pair<size_t, OctetString>
PKCS5_PBKDF2::key_derivation(size_t key_len,
                             const std::string& passphrase,
                             const byte salt[], size_t salt_len,
                             size_t iterations,
                             std::chrono::milliseconds msec) const
   {
   if(key_len == 0)
      return std::make_pair(iterations, OctetString());

   try
      {
      mac->set_key(reinterpret_cast<const byte*>(passphrase.data()),
                   passphrase.length());
      }
   catch(Invalid_Key_Length)
      {
      throw Exception(name() + " cannot accept passphrases of length " +
                      to_string(passphrase.length()));
      }

   secure_vector<byte> key(key_len);

   byte* T = &key[0];

   secure_vector<byte> U(mac->output_length());

   const size_t blocks_needed = round_up(key_len, mac->output_length()) / mac->output_length();

   std::chrono::microseconds usec_per_block =
      std::chrono::duration_cast<std::chrono::microseconds>(msec) / blocks_needed;

   u32bit counter = 1;
   while(key_len)
      {
      size_t T_size = std::min<size_t>(mac->output_length(), key_len);

      mac->update(salt, salt_len);
      mac->update_be(counter);
      mac->final(&U[0]);

      xor_buf(T, &U[0], T_size);

      if(iterations == 0)
         {
         /*
         If no iterations set, run the first block to calibrate based
         on how long hashing takes on whatever machine we're running on.
         */

         const auto start = std::chrono::high_resolution_clock::now();

         iterations = 1; // the first iteration we did above

         while(true)
            {
            mac->update(U);
            mac->final(&U[0]);
            xor_buf(T, &U[0], T_size);
            iterations++;

            /*
            Only break on relatively 'even' iterations. For one it
            avoids confusion, and likely some broken implementations
            break on getting completely randomly distributed values
            */
            if(iterations % 10000 == 0)
               {
               auto time_taken = std::chrono::high_resolution_clock::now() - start;
               auto usec_taken = std::chrono::duration_cast<std::chrono::microseconds>(time_taken);
               if(usec_taken > usec_per_block)
                  break;
               }
            }
         }
      else
         {
         for(size_t i = 1; i != iterations; ++i)
            {
            mac->update(U);
            mac->final(&U[0]);
            xor_buf(T, &U[0], T_size);
            }
         }

      key_len -= T_size;
      T += T_size;
      ++counter;
      }

   return std::make_pair(iterations, key);
   }

}

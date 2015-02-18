/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pbkdf_utils.h>
#include <botan/pbkdf2.h>
#include <botan/get_byte.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/rounding.h>

namespace Botan {

BOTAN_REGISTER_NAMED_T(PBKDF, "PBKDF2", PKCS5_PBKDF2, PKCS5_PBKDF2::make);

PKCS5_PBKDF2* PKCS5_PBKDF2::make(const Spec& spec)
   {
   if(auto mac = make_a<MessageAuthenticationCode>(spec.arg(0)))
      return new PKCS5_PBKDF2(mac);

   if(auto mac = make_a<MessageAuthenticationCode>("HMAC(" + spec.arg(0) + ")"))
      return new PKCS5_PBKDF2(mac);

   return nullptr;
   }

size_t
pbkdf2(MessageAuthenticationCode& prf,
       byte out[],
       size_t out_len,
       const std::string& passphrase,
       const byte salt[], size_t salt_len,
       size_t iterations,
       std::chrono::milliseconds msec)
   {
   clear_mem(out, out_len);

   if(out_len == 0)
      return 0;

   try
      {
      prf.set_key(reinterpret_cast<const byte*>(passphrase.data()), passphrase.size());
      }
   catch(Invalid_Key_Length)
      {
      throw std::runtime_error("PBKDF2 with " + prf.name() +
                               " cannot accept passphrases of length " +
                               std::to_string(passphrase.size()));
      }

   const size_t prf_sz = prf.output_length();
   secure_vector<byte> U(prf_sz);

   const size_t blocks_needed = round_up(out_len, prf_sz) / prf_sz;

   std::chrono::microseconds usec_per_block =
      std::chrono::duration_cast<std::chrono::microseconds>(msec) / blocks_needed;

   u32bit counter = 1;
   while(out_len)
      {
      const size_t prf_output = std::min<size_t>(prf_sz, out_len);

      prf.update(salt, salt_len);
      prf.update_be(counter++);
      prf.final(&U[0]);

      xor_buf(out, &U[0], prf_output);

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
            prf.update(U);
            prf.final(&U[0]);
            xor_buf(out, &U[0], prf_output);
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
            prf.update(U);
            prf.final(&U[0]);
            xor_buf(out, &U[0], prf_output);
            }
         }

      out_len -= prf_output;
      out += prf_output;
      }

   return iterations;
   }

size_t
PKCS5_PBKDF2::pbkdf(byte key[], size_t key_len,
                    const std::string& passphrase,
                    const byte salt[], size_t salt_len,
                    size_t iterations,
                    std::chrono::milliseconds msec) const
   {
   return pbkdf2(*mac.get(), key, key_len, passphrase, salt, salt_len, iterations, msec);
   }


}

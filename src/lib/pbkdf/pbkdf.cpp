/*
* PBKDF
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbkdf.h>
#include <stdexcept>

namespace Botan {

void PBKDF::pbkdf_timed(byte out[], size_t out_len,
                        const std::string& passphrase,
                        const byte salt[], size_t salt_len,
                        std::chrono::milliseconds msec,
                        size_t& iterations) const
   {
   iterations = pbkdf(out, out_len, passphrase, salt, salt_len, 0, msec);
   }

void PBKDF::pbkdf_iterations(byte out[], size_t out_len,
                             const std::string& passphrase,
                             const byte salt[], size_t salt_len,
                             size_t iterations) const
   {
   if(iterations == 0)
      throw std::invalid_argument(name() + ": Invalid iteration count");

   const size_t iterations_run = pbkdf(out, out_len, passphrase,
                                       salt, salt_len, iterations,
                                       std::chrono::milliseconds(0));
   BOTAN_ASSERT_EQUAL(iterations, iterations_run, "Expected PBKDF iterations");
   }

secure_vector<byte> PBKDF::pbkdf_iterations(size_t out_len,
                                            const std::string& passphrase,
                                            const byte salt[], size_t salt_len,
                                            size_t iterations) const
   {
   secure_vector<byte> out(out_len);
   pbkdf_iterations(&out[0], out_len, passphrase, salt, salt_len, iterations);
   return out;
   }

secure_vector<byte> PBKDF::pbkdf_timed(size_t out_len,
                                       const std::string& passphrase,
                                       const byte salt[], size_t salt_len,
                                       std::chrono::milliseconds msec,
                                       size_t& iterations) const
   {
   secure_vector<byte> out(out_len);
   pbkdf_timed(&out[0], out_len, passphrase, salt, salt_len, msec, iterations);
   return out;
   }

}

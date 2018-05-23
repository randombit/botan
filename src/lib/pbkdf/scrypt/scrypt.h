/**
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SCRYPT_H_
#define BOTAN_SCRYPT_H_

#include <botan/types.h>
#include <chrono>
#include <string>

namespace Botan {

class Scrypt_Params
   {
   public:
      Scrypt_Params(size_t N, size_t r, size_t p);

      Scrypt_Params(std::chrono::milliseconds msec);

      Scrypt_Params(size_t iterations);

      size_t N() const { return m_N; }
      size_t r() const { return m_r; }
      size_t p() const { return m_p; }
   private:
      size_t m_N, m_r, m_p;
   };

/**
* Scrypt key derivation function (RFC 7914)
*
* @param output the output will be placed here
* @param output_len length of output
* @param password the user password
* @param salt the salt
* @param salt_len length of salt
* @param N the CPU/Memory cost parameter, must be power of 2
* @param r the block size parameter
* @param p the parallelization parameter
*
* Suitable parameters for most uses would be N = 16384, r = 8, p = 1
*
* Scrypt uses approximately (p + N + 1) * 128 * r bytes of memory
*/
void BOTAN_UNSTABLE_API scrypt(uint8_t output[], size_t output_len,
                               const std::string& password,
                               const uint8_t salt[], size_t salt_len,
                               size_t N, size_t r, size_t p);

void BOTAN_UNSTABLE_API scrypt(uint8_t output[], size_t output_len,
                               const std::string& password,
                               const uint8_t salt[], size_t salt_len,
                               const Scrypt_Params& params);

}

#endif

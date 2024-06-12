/*
* Passhash9 Password Hashing
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PASSHASH9_H_
#define BOTAN_PASSHASH9_H_

#include <botan/types.h>
#include <string>

namespace Botan {

class RandomNumberGenerator;

/**
* Create a password hash using PBKDF2
*
* Functions much like generate_bcrypt(). The last parameter,
* @p alg_id, specifies which PRF to use. Currently defined values are:
*
* - 0: HMAC(SHA-1)
* - 1: HMAC(SHA-256)
* - 2: CMAC(Blowfish)
* - 3: HMAC(SHA-384)
* - 4: HMAC(SHA-512)
*
* The @p work_factor must be greater than zero and less than 512. This performs
* 10000 * @p work_factor PBKDF2 iterations, using 96 bits of salt taken from
* @p rng. Using work factor of 10 or more is recommended.
*
* @param password the password
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
* @param alg_id specifies which PRF to use with PBKDF2 0 is HMAC(SHA-1) 1 is
*        HMAC(SHA-256) 2 is CMAC(Blowfish) 3 is HMAC(SHA-384) 4 is HMAC(SHA-512)
*        all other values are currently undefined
*/
std::string BOTAN_PUBLIC_API(2, 0) generate_passhash9(std::string_view password,
                                                      RandomNumberGenerator& rng,
                                                      uint16_t work_factor = 15,
                                                      uint8_t alg_id = 4);

/**
* Check a previously created password hash
* @param password the password to check against
* @param hash the stored hash to check against
*/
bool BOTAN_PUBLIC_API(2, 0) check_passhash9(std::string_view password, std::string_view hash);

/**
* Check if the PRF used with PBKDF2 is supported
* @param alg_id alg_id used in generate_passhash9()
*/
bool BOTAN_PUBLIC_API(2, 3) is_passhash9_alg_supported(uint8_t alg_id);

}  // namespace Botan

#endif

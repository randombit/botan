/**
* (C) 2018,2019,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ARGON2_FMT_H_
#define BOTAN_ARGON2_FMT_H_

#include <botan/types.h>
#include <string>

namespace Botan {

class RandomNumberGenerator;

/**
* Generate an Argon2 hash of the specified @p password. The @p y parameter
* specifies the variant: 0 for Argon2d, 1 for Argon2i, and 2 for Argon2id.
*/
std::string BOTAN_PUBLIC_API(2, 11) argon2_generate_pwhash(const char* password,
                                                           size_t password_len,
                                                           RandomNumberGenerator& rng,
                                                           size_t p,
                                                           size_t M,
                                                           size_t t,
                                                           uint8_t y = 2,
                                                           size_t salt_len = 16,
                                                           size_t output_len = 32);

/**
* Check a previously created password hash
*
* Verify an Argon2 password @p hash against the provided @p password. Returns
* false if the input hash seems malformed or if the computed hash does not
* match.
*
* @param password the password to check against
* @param password_len the length of password
* @param hash the stored hash to check against
*/
bool BOTAN_PUBLIC_API(2, 11) argon2_check_pwhash(const char* password, size_t password_len, std::string_view hash);

}  // namespace Botan

#endif

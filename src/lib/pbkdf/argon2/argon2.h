/**
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ARGON2_H_
#define BOTAN_ARGON2_H_

#include <botan/types.h>

namespace Botan {

/**
* Argon2 key derivation function
*
* @param output the output will be placed here
* @param output_len length of output
* @param password the user password
* @param salt the salt
* @param salt_len length of salt
* @param y the Argon2 variant (0 = Argon2d, 1 = Argon2i, 2 = Argon2id)
* @param p the parallelization parameter
* @param M the amount of memory to use in Kb
* @param t the number of iterations to use
*/
void BOTAN_PUBLIC_API(2,11) argon2(uint8_t output[], size_t output_len,
                                   const char* password, size_t password_len,
                                   const uint8_t salt[], size_t salt_len,
                                   const uint8_t key[], size_t key_len,
                                   const uint8_t ad[], size_t ad_len,
                                   size_t y, size_t p, size_t M, size_t t);

}

#endif

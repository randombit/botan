/*
* Password Hashing
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PASSHASH_H__
#define BOTAN_PASSHASH_H__

#include <botan/rng.h>

namespace Botan {

/**
* Create a password hash using PBKDF2
* @param password the password
* @param rng a random number generator
* @Param work_factor how much work to do to slow down guessing attacks
*/
std::string BOTAN_DLL password_hash(const std::string& password,
                                    RandomNumberGenerator& rng,
                                    u16bit work_factor = 10);

/**
* Check a previously created password hash
* @param password the password to check against
* @param hash the stored hash to check against
*/
bool BOTAN_DLL password_hash_ok(const std::string& password,
                                const std::string& hash);

}

#endif

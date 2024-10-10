/*
* Bcrypt Password Hashing
* (C) 2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BCRYPT_H_
#define BOTAN_BCRYPT_H_

#include <botan/types.h>
#include <string>

namespace Botan {

class RandomNumberGenerator;

/**
* Create a password hash using Bcrypt
*
* Takes the @p password to hash, a @p rng, and a @p work_factor. The resulting
* password hash is returned as a string.
*
* Higher work factors increase the amount of time the algorithm runs, increasing
* the cost of cracking attempts. The increase is exponential, so a work factor
* of 12 takes roughly twice as long as work factor 11. The default work factor
* was set to 10 up until the 2.8.0 release.
*
* It is recommended to set the work factor as high as your system can tolerate
* (from a performance and latency perspective) since higher work factors greatly
* improve the security against GPU-based attacks.  For example, for protecting
* high value administrator passwords, consider using work factor 15 or 16; at
* these work factors each bcrypt computation takes several seconds. Since admin
* logins will be relatively uncommon, it might be acceptable for each login
* attempt to take some time. As of 2018, a good password cracking rig (with 8
* NVIDIA 1080 cards) can attempt about 1 billion bcrypt computations per month
* for work factor 13. For work factor 12, it can do twice as many.  For work
* factor 15, it can do only one quarter as many attempts.
*
* Due to bugs affecting various implementations of bcrypt, several different
* variants of the algorithm are defined. As of 2.7.0 Botan supports generating
* (or checking) the 2a, 2b, and 2y variants.  Since Botan has never been
* affected by any of the bugs which necessitated these version upgrades, all
* three versions are identical beyond the version identifier. Which variant to
* use is controlled by the @p version argument.
*
* The bcrypt @p work_factor must be at least 4 (though at this work factor
* bcrypt is not very secure). The bcrypt format allows up to 31, but Botan
* currently rejects all work factors greater than 18 since even that work factor
* requires roughly 15 seconds of computation on a fast machine.
*
* @warning The password is truncated at at most 72 characters; characters after
*          that do not have any effect on the resulting hash. To support longer
*          passwords, consider pre-hashing the password, for example by using
*          the hex encoding of SHA-256 of the password as the input to bcrypt.
*
* @param password the password.
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
* @param version which version to emit (may be 'a', 'b', or 'y' all of which
*        have identical behavior in this implementation).
*
* @see https://www.usenix.org/events/usenix99/provos/provos_html/
*
* TODO(Botan4) Convert work_factor to a size_t
*/
std::string BOTAN_PUBLIC_API(2, 0) generate_bcrypt(std::string_view password,
                                                   RandomNumberGenerator& rng,
                                                   uint16_t work_factor = 12,
                                                   char version = 'a');

/**
* Check a previously created password hash
*
* Takes a @p password and a bcrypt @p hash and returns true if the password is
* the same as the one that was used to generate the bcrypt hash.
*
* @param password the password to check against
* @param hash the stored hash to check against
*/
bool BOTAN_PUBLIC_API(2, 0) check_bcrypt(std::string_view password, std::string_view hash);

}  // namespace Botan

#endif

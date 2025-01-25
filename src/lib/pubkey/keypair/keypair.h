/*
* Keypair Checks
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KEYPAIR_CHECKS_H_
#define BOTAN_KEYPAIR_CHECKS_H_

#include <botan/pk_keys.h>

namespace Botan::KeyPair {

/**
* Tests whether the key is consistent for encryption; whether
* encrypting and then decrypting gives to the original plaintext.
* @param rng the rng to use
* @param private_key the key to test
* @param public_key the key to test
* @param padding the encryption padding method to use
* @return true if consistent otherwise false
*/
bool encryption_consistency_check(RandomNumberGenerator& rng,
                                  const Private_Key& private_key,
                                  const Public_Key& public_key,
                                  std::string_view padding);

/**
* Tests whether the key is consistent for signatures; whether a
* signature can be created and then verified
* @param rng the rng to use
* @param private_key the key to test
* @param public_key the key to test
* @param padding the signature padding method to use
* @return true if consistent otherwise false
*/
bool signature_consistency_check(RandomNumberGenerator& rng,
                                 const Private_Key& private_key,
                                 const Public_Key& public_key,
                                 std::string_view padding);

/**
* Tests whether the key is consistent for encryption; whether
* encrypting and then decrypting gives to the original plaintext.
* @param rng the rng to use
* @param sk the key to test
* @param padding the encryption padding method to use
* @return true if consistent otherwise false
*/
inline bool encryption_consistency_check(RandomNumberGenerator& rng, const Private_Key& sk, std::string_view padding) {
   auto pk = sk.public_key();
   return encryption_consistency_check(rng, sk, *pk, padding);
}

/**
* Tests whether the key is consistent for signatures; whether a
* signature can be created and then verified
* @param rng the rng to use
* @param sk the key to test
* @param padding the signature padding method to use
* @return true if consistent otherwise false
*/
inline bool signature_consistency_check(RandomNumberGenerator& rng, const Private_Key& sk, std::string_view padding) {
   auto pk = sk.public_key();
   return signature_consistency_check(rng, sk, *pk, padding);
}

}  // namespace Botan::KeyPair

#endif

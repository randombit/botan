/*
* AES Key Wrap (RFC 3394)
* (C) 2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AES_KEY_WRAP_H__
#define BOTAN_AES_KEY_WRAP_H__

#include <botan/symkey.h>

namespace Botan {

/**
* Encrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* @param key the plaintext key to encrypt
* @param kek the key encryption key
* @return key encrypted under kek
*/
secure_vector<byte> BOTAN_DLL rfc3394_keywrap(const secure_vector<byte>& key,
                                              const SymmetricKey& kek);

/**
* Decrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* @param key the encrypted key to decrypt
* @param kek the key encryption key
* @param af an algorithm factory
* @return key decrypted under kek
*/
secure_vector<byte> BOTAN_DLL rfc3394_keyunwrap(const secure_vector<byte>& key,
                                                const SymmetricKey& kek);

}

#endif

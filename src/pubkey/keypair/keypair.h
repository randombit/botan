/*
* Keypair Checks
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_KEYPAIR_H__
#define BOTAN_KEYPAIR_H__

#include <botan/pubkey.h>

namespace Botan {

namespace KeyPair {

/**
* Tests whether the specified encryptor and decryptor are related to each other,
* i.e. whether encrypting with the encryptor and consecutive decryption leads to
* the original plaintext.
* @param rng the rng to use
* @param enc the encryptor to test
* @param dec the decryptor to test
* @throw Self_Test_Failure if the arguments are not related to each other
*/
BOTAN_DLL void check_key(RandomNumberGenerator& rng,
                         PK_Encryptor* enc,
                         PK_Decryptor* dec);

/**
* Tests whether the specified signer and verifier are related to each other,
* i.e. whether a signature created with the signer and can be
* successfully verified with the verifier.
* @param rng the rng to use
* @param sig the signer to test
* @param ver the verifier to test
* @throw Self_Test_Failure if the arguments are not related to each other
*/
BOTAN_DLL void check_key(RandomNumberGenerator& rng,
                         PK_Signer* sig,
                         PK_Verifier* ver);

}

}

#endif

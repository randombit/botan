/*************************************************
* Keypair Checks Header File                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_KEYPAIR_H__
#define BOTAN_KEYPAIR_H__

#include <botan/pubkey.h>

namespace Botan {

namespace KeyPair {

/**
* Tests whether the specified encryptor and decryptor are related to each other,
* i.e. whether encrypting with the encryptor and consecutive decryption leads to
* the original plaintext.
* @param enc the encryptor to test
* @param dec the decryptor to test
* @throw Self_Test_Failure if the arguments are not related to each other
*/
BOTAN_DLL void check_key(RandomNumberGenerator&, PK_Encryptor*, PK_Decryptor*);

/**
* Tests whether the specified signer and verifier are related to each other,
* i.e. whether a signature created with the signer and can be
* successfully verified with the verifier.
* @param sig the signer to test
* @param ver the verifier to test
* @throw Self_Test_Failure if the arguments are not related to each other
*/
BOTAN_DLL void check_key(RandomNumberGenerator&, PK_Signer*, PK_Verifier*);

}

}

#endif

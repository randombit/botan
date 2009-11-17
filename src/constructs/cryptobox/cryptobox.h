/*
* Cryptobox Message Routines
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CRYPTOBOX_H__
#define BOTAN_CRYPTOBOX_H__

#include <string>
#include <botan/rng.h>

namespace Botan {

namespace CryptoBox {

/**
* Encrypt a message
* @param input the input data
* @param input_len the length of input in bytes
* @param passphrase the passphrase used to encrypt the message
* @param rng a ref to a random number generator, such as AutoSeeded_RNG
*/
BOTAN_DLL std::string encrypt(const byte input[], u32bit input_len,
                              const std::string& passphrase,
                              RandomNumberGenerator& rng);

/**
* Decrypt a message encrypted with CryptoBox::encrypt
* @param input the input data
* @param input_len the length of input in bytes
* @param passphrase the passphrase used to encrypt the message
*/
BOTAN_DLL std::string decrypt(const byte input[], u32bit input_len,
                              const std::string& passphrase);

}

}

#endif

/*
* Rivest's Package Tranform
*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AONT_PACKAGE_TRANSFORM_H__
#define BOTAN_AONT_PACKAGE_TRANSFORM_H__

#include <botan/block_cipher.h>
#include <botan/rng.h>

namespace Botan {

/**
* Rivest's Package Tranform
* @arg rng the random number generator to use
* @arg cipher the block cipher to use
* @arg input the input data buffer
* @arg input_len the length of the input data in bytes
* @arg output the output data buffer (must be at least
*      input_len + cipher->BLOCK_SIZE bytes long)
*/
void BOTAN_DLL aont_package(RandomNumberGenerator& rng,
                            BlockCipher* cipher,
                            const byte input[], u32bit input_len,
                            byte output[]);

/**
* Rivest's Package Tranform (Inversion)
* @arg rng the random number generator to use
* @arg cipher the block cipher to use
* @arg input the input data buffer
* @arg input_len the length of the input data in bytes
* @arg output the output data buffer (must be at least
*      input_len - cipher->BLOCK_SIZE bytes long)
*/
void BOTAN_DLL aont_unpackage(BlockCipher* cipher,
                              const byte input[], u32bit input_len,
                              byte output[]);

}

#endif

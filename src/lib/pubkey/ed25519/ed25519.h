/*
* Ed25519
* (C) 2017 Ribose Inc
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ED25519_H__
#define BOTAN_ED25519_H__

#include <botan/types.h>

namespace Botan {

int ed25519_gen_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);

int ed25519_sign(uint8_t sig[64],
                 const uint8_t msg[],
                 size_t msg_len,
                 const uint8_t sk[64]);

int ed25519_verify(const uint8_t msg[],
                   size_t msg_len,
                   const uint8_t sig[64],
                   const uint8_t pk[32]);

}

#endif

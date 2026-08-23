/*
* Ed25519
* (C) 2017 Ribose Inc
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ED25519_INT_H_
#define BOTAN_ED25519_INT_H_

#include <botan/internal/ed25519_scalar.h>
#include <span>

namespace Botan {

void ed25519_basepoint_mul(std::span<uint8_t, 32> out, const Ed25519_Scalar& scalar);

bool ed25519_check_signature(std::span<const uint8_t, 32> pk,
                             const Ed25519_Scalar& h,
                             const uint8_t r[32],
                             const Ed25519_Scalar& s);

/**
* Check that this is a valid public key point encoding: it must decode,
* must not be the identity or the point of order 2, and must lie within
* the prime order subgroup
*/
bool ed25519_valid_public_key_point(std::span<const uint8_t, 32> pk);

}  // namespace Botan

#endif

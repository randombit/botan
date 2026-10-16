/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X25519_INTERNAL_H_
#define BOTAN_X25519_INTERNAL_H_

#include <botan/types.h>
#include <span>

namespace Botan {

/**
* X25519 scalar multiplication (RFC 7748 Section 5)
*
* Clamps the scalar and writes the u-coordinate of [k]P to out, where P is
* the point with u-coordinate u. The output is all zero if P has low order;
* callers that want to reject such points must check for this themselves.
*/
void x25519_scalarmult(std::span<uint8_t, 32> out, std::span<const uint8_t, 32> scalar, std::span<const uint8_t, 32> u);

/**
* X25519 public key derivation
*
* Clamps the scalar and writes the u-coordinate of [k]B to out, where B is the
* X25519 base point with u = 9.
*/
void x25519_basepoint(std::span<uint8_t, 32> out, std::span<const uint8_t, 32> scalar);

}  // namespace Botan

#endif

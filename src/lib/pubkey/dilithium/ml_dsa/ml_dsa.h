/*
 * Module-Lattice-Based Digital Signature Standard (ML-DSA)
 *
 * (C) 2024 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ML_DSA_H_
#define BOTAN_ML_DSA_H_

// This is a bridge into a future where we don't support Dilithium anymore to
// keep the API stable for users of the ML-DSA algorithm. We recommend new
// users to use the type-aliases declared in this header as the Dilithium API
// might be deprecated and eventually removed in future releases.

#include <botan/dilithium.h>

namespace Botan {

using ML_DSA_Mode = DilithiumMode;
using ML_DSA_PublicKey = Dilithium_PublicKey;
using ML_DSA_PrivateKey = Dilithium_PrivateKey;

}  // namespace Botan

#endif
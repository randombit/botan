/*
 * Module Lattice Key Encapsulation Mechanism
 *
 * (C) 2024 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ML_KEM_H_
#define BOTAN_ML_KEM_H_

// This is a bridge into a future where we don't support Kyber anymore to
// keep the API stable for users of the ML-KEM algorithm. We recommend new
// users to use the type-aliases declared in this header as the Kyber API
// might be deprecated and eventually removed in future releases.

#include <botan/kyber.h>

namespace Botan {

using ML_KEM_Mode = KyberMode;
using ML_KEM_PublicKey = Kyber_PublicKey;
using ML_KEM_PrivateKey = Kyber_PrivateKey;

}  // namespace Botan

#endif

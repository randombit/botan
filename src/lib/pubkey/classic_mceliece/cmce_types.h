/*
 * Classic McEliece Types
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_TYPES_H_
#define BOTAN_CMCE_TYPES_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <botan/internal/bitvector.h>

namespace Botan {

/// Represents a GF(q) element
using CmceGfElem = Strong<uint16_t, struct CmceGfElem_>;

/// Represents a GF(q) modulus
using CmceGfMod = Strong<uint16_t, struct CmceGfMod_>;

/// Represents an element of a permuation (pi in spec). Used in field ordering creation.
using CmcePermutationElement = Strong<uint16_t, struct CmcePermutationElement_>;

/// Represents a permutation (pi in spec). Used in field ordering creation.
using CmcePermutation = Strong<secure_vector<uint16_t>, struct CmcePermutation_>;

/// Represents initial delta of keygen
using CmceInitialSeed = Strong<secure_vector<uint8_t>, struct CmceInitialSeed_>;

/// Represents a delta (can be altered; final value stored in private key)
using CmceKeyGenSeed = Strong<secure_vector<uint8_t>, struct CmceKeyGenSeed_>;

// Represents the sigma_2*q bits of E=PRG(delta) used by the field ordering algorithm (see CMCE ISO 8.3 Step 4)
using CmceOrderingBits = Strong<secure_vector<uint8_t>, struct CmceOrderingBits_>;

// Represents the sigma_1*t bits of E=PRG(delta) used by the irreducible algorithm (see CMCE ISO 8.3 Step 5)
using CmceIrreducibleBits = Strong<secure_vector<uint8_t>, struct CmceIrreducibleBits_>;

/// Represents s of private key
using CmceRejectionSeed = Strong<secure_vector<uint8_t>, struct CmceRejectionSeed_>;

/// Represents c of private key
using CmceColumnSelection = Strong<secure_bitvector, struct CmceColumnSelection_>;

/// Represents e of encapsulation
using CmceErrorVector = Strong<secure_bitvector, struct CmceErrorVector_>;

/// Represents C of decapsulation
using CmceCodeWord = Strong<secure_bitvector, struct CmceCodeWord_>;

}  // namespace Botan
#endif  // BOTAN_CMCE_TYPES_H_

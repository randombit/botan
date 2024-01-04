/*
 * FrodoKEM modes and constants
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_FRODOKEM_TYPES_H_
#define BOTAN_FRODOKEM_TYPES_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>

#include <array>
#include <vector>

namespace Botan {

// Bytes of seed_a
using FrodoSeedA = Strong<std::vector<uint8_t>, struct FrodoSeedA_>;

// Bytes of s
using FrodoSeedS = Strong<secure_vector<uint8_t>, struct FrodoSeedS_>;

// Bytes of seed_se
using FrodoSeedSE = Strong<secure_vector<uint8_t>, struct FrodoSeedSE_>;

// Bytes of z
using FrodoSeedZ = Strong<std::vector<uint8_t>, struct FrodoSeedZ_>;

// Bytes of an r^(i)
using FrodoSampleR = Strong<secure_vector<uint8_t>, struct FrodoSampleR_>;

// Bytes of pkh
using FrodoPublicKeyHash = Strong<std::vector<uint8_t>, struct FrodoPublicKeyHash_>;

// Bytes of a packed Matrix
using FrodoPackedMatrix = Strong<std::vector<uint8_t>, struct FrodoPackedMatrix_>;

// Bytes of a serialized Matrix
using FrodoSerializedMatrix = Strong<secure_vector<uint8_t>, struct FrodoSerializedMatrix_>;

// Constant byte 0x5F/0x96 given to SHAKE for domain separation
using FrodoDomainSeparator = Strong<std::array<uint8_t, 1>, struct FrodoDoaminSeparator_>;

// Bytes of u/u'
using FrodoPlaintext = Strong<secure_vector<uint8_t>, struct FrodoPlaintext_>;

// Bytes of salt
using FrodoSalt = Strong<std::vector<uint8_t>, struct FrodoSalt_>;

// Bytes of k/k' aka intermediate shared secret in FO transform
using FrodoIntermediateSharedSecret = Strong<secure_vector<uint8_t>, struct FrodoIntermediateSharedSecret_>;

}  // namespace Botan

#endif

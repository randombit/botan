/*
 * SPHINCS+ Strong Type Definitions
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_TYPES_H_
#define BOTAN_SP_TYPES_H_

#include <botan/strong_type.h>
#include <botan/secmem.h>

namespace Botan {

using SphincsHashedMessage = Strong<std::vector<uint8_t>, struct SphincsHashedMessage_>;
using SphincsPublicSeed = Strong<std::vector<uint8_t>, struct SphincsPublicSeed_>;
using SphincsSecretSeed = Strong<secure_vector<uint8_t>, struct SphincsSecretSeed_>;
using SphincsSecretPRF = Strong<secure_vector<uint8_t>, struct SphincsSecretPRF_>;
using SphincsOptionalRandomness = Strong<secure_vector<uint8_t>, struct SphincsOptionalRandomness_>;
using ForsPublicKey = Strong<std::vector<uint8_t>, struct ForsPublicKey_>;
using ForsSignature = Strong<std::vector<uint8_t>, struct ForsSignature_>;
using ForsIndices = Strong<std::vector<uint32_t>, struct ForsIndices_>;

using SphincsTreeRootSpan = Strong<std::span<uint8_t>, struct SphincsTreeRootSpan_>; // TODO:
using SphincsAuthPathSpan = Strong<std::span<uint8_t>, struct SphincsAuthPathSpan_>; //  how to use?

}

#endif

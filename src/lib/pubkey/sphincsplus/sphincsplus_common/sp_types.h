/*
 * SLH-DSA Strong Type Definitions
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_TYPES_H_
#define BOTAN_SP_TYPES_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>

namespace Botan {

/*
 * The following gives an overview about the different building blocks of
 * SLH-DSA and how they are connected. In general, we always consider sequences of bytes
 * that are interpreted in the following manner (flattening the || operation, i.e.,
 * mapping the byte sequence of a strong type onto the underlying byte sequence of the containing strong type).
 * Only FORS indices are not seen as byte sequences.
 *
 * SLH-DSA secret key is built up like the following:
 * [SphincsSecretSeed || SphincsSecretPRF || SphincsPublicSeed || SphincsTreeNode] (the last chunk is the root node of SLH-DSA' topmost XMSS tree)
 *
 * SLH-DSA public key is built up like the following:
 * [SphincsPublicSeed || SphincsTreeNode] (the last chunk is the root node of SLH-DSA's topmost XMSS tree)]
 *
 * SLH-DSA signature is built up like the following:
 * [SphincsMessageRandomness (n bytes) || ForsSignature (k(a+1)*n = fors_signature_bytes bytes) || SphincsHypertreeSignature]. SphincsHypertreeSignature contains a total of
 * d SphincsXMSSSignatures, with (h+d*len)*n = xmss_signature_bytes bytes each.
 *
 * ForsSignature is built up like the following:
 * [<Leaf Secret of FORS Subtree 1>(n bytes) || SphincsAuthenticationPath (Subtree 1, a*n bytes) || ... || <Leaf Secret of FORS Subtree k>(n bytes) || SphincsAuthenticationPath (Subtree k, a*n bytes)]
 * We define no special type for the leaf secret. The leaf secret is the secret PRF output that is hashed to create a FORS subtree's leaf.
 *
 * SphincsXmssSignature is built up like the following:
 * [WotsSignature || SphincsAuthenticationPath]
 *
 * WotsSignature is built up like the following:
 * [WotsNode || ... || WotsNode] contains len WotsNodes, each of length n bytes.
 */

/// The prefix appended to the message in [hash_]slh_sign and slh_verify.
/// E.g. for SLH-DSA (pure): 0x00 || |ctx| || ctx. Empty for SPHINCS+.
using SphincsMessagePrefix = Strong<std::vector<uint8_t>, struct SphincsMessagePrefix_>;
// The input to [hash_]slh_sign and [hash_]slh_verify
using SphincsInputMessage = Strong<std::vector<uint8_t>, struct SphincsInputMessage_>;

/// M' representation of FIPS 205 (the input to slh_sign_internal and slh_verify_internal)
struct SphincsMessageInternal {
      SphincsMessagePrefix prefix;
      SphincsInputMessage message;
};

using SphincsContext = Strong<std::vector<uint8_t>, struct SphincsContext_>;

using SphincsHashedMessage = Strong<std::vector<uint8_t>, struct SphincsHashedMessage_>;
using SphincsPublicSeed = Strong<std::vector<uint8_t>, struct SphincsPublicSeed_>;
using SphincsSecretSeed = Strong<secure_vector<uint8_t>, struct SphincsSecretSeed_>;
using SphincsSecretPRF = Strong<secure_vector<uint8_t>, struct SphincsSecretPRF_>;
using SphincsOptionalRandomness = Strong<secure_vector<uint8_t>, struct SphincsOptionalRandomness_>;
using SphincsMessageRandomness = Strong<secure_vector<uint8_t>, struct SphincsMessageRandomness_>;
using SphincsXmssSignature = Strong<std::vector<uint8_t>, struct SphincsXmssSignature_>;
using SphincsHypertreeSignature = Strong<std::vector<uint8_t>, struct SphincsXmssSignature_>;
using SphincsAuthenticationPath = Strong<std::vector<uint8_t>, struct SphincsAuthenticationPath_>;

/// Either an XMSS or FORS tree node or leaf
using SphincsTreeNode = Strong<std::vector<uint8_t>, struct SphincsTreeNode_>;
using ForsLeafSecret = Strong<secure_vector<uint8_t>, struct ForsLeafSecret_>;
using ForsSignature = Strong<std::vector<uint8_t>, struct ForsSignature_>;
using WotsPublicKey = Strong<std::vector<uint8_t>, struct WotsPublicKey_>;

/// End node of a WOTS+ chain (part of the WOTS+ public key)
using WotsPublicKeyNode = Strong<std::vector<uint8_t>, struct WotsPublicKeyNode_>;

/// Start (or intermediate) node of a WOTS+ chain
using WotsNode = Strong<secure_vector<uint8_t>, struct WotsNode_>;
using WotsSignature = Strong<secure_vector<uint8_t>, struct WotsSignature_>;

/// Index of the layer within a FORS/XMSS tree
using TreeLayerIndex = Strong<uint32_t, struct TreeLayerIndex_, EnableArithmeticWithPlainNumber>;

/// Index of a layer in the XMSS hyper-tree
using HypertreeLayerIndex = Strong<uint32_t, struct HypertreeLayerIndex_>;

/// Index of an XMSS tree (unique for just the local hyper-tree layer)
using XmssTreeIndexInLayer = Strong<uint64_t, struct XmssTreeIndexInLayer_, EnableArithmeticWithPlainNumber>;

/// Index of an individual node inside an XMSS or FORS tree
using TreeNodeIndex = Strong<uint32_t, struct TreeNodeIndex_, EnableArithmeticWithPlainNumber>;

/// Index of a WOTS chain within a single usage of WOTS
using WotsChainIndex = Strong<uint32_t, struct WotsChainIndex_>;

/// Index of a hash application inside a single WOTS chain (integers in "base_w")
using WotsHashIndex = Strong<uint8_t, struct WotsHashIndex_, EnableArithmeticWithPlainNumber>;

}  // namespace Botan

#endif
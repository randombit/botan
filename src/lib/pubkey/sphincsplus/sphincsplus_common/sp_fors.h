/*
 * FORS - Forest of Random Subsets (FIPS 205, Section 8)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_SPHINCS_PLUS_FORS_H_
#define BOTAN_SPHINCS_PLUS_FORS_H_

#include <botan/internal/sp_types.h>

namespace Botan {

class Sphincs_Address;
class Sphincs_Hash_Functions;
class Sphincs_Parameters;

/**
 * @brief FIPS 205, Algorithm 16: fors_sign (with simultaneous FORS pk generation)
 *
 * Implements a domain specific wrapper for the few-times signature scheme
 * FORS (Forest of Random Subsets). It is meant to be used inside SLH-DSA
 * and does not aim to be applicable for other use cases.
 */
BOTAN_TEST_API SphincsTreeNode fors_sign_and_pkgen(StrongSpan<ForsSignature> sig_out,
                                                   const SphincsHashedMessage& hashed_message,
                                                   const SphincsSecretSeed& secret_seed,
                                                   const Sphincs_Address& address,
                                                   const Sphincs_Parameters& params,
                                                   Sphincs_Hash_Functions& hashes);

/**
 * @brief FIPS 205, Algorithm 17: fors_pkFromSig
 *
 * Reconstructs the FORS public key from a given FORS @p signature and
 * @p message. This is tailored for the use case in the SLH-DSA implementation
 * and is not meant for general usability.
 */
BOTAN_TEST_API SphincsTreeNode fors_public_key_from_signature(const SphincsHashedMessage& hashed_message,
                                                              StrongSpan<const ForsSignature> signature,
                                                              const Sphincs_Address& address,
                                                              const Sphincs_Parameters& params,
                                                              Sphincs_Hash_Functions& hash);

}  // namespace Botan

#endif

/*
 * Ed448 Internals
 * (C) 2024 Jack Lloyd
 *     2024 René Meusel, Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ED448_INTERNAL_H_
#define BOTAN_ED448_INTERNAL_H_

#include <botan/internal/ed448_point.h>

namespace Botan {

/**
 * @brief Create a public key point from a secret key (RFC 8032 5.2.5)
 */
BOTAN_TEST_API std::array<uint8_t, ED448_LEN> create_pk_from_sk(std::span<const uint8_t, ED448_LEN> sk);

/**
 * @brief Sign a message using a keypair (RFC 8032 5.2.6)
 *
 * @param sk the secret key
 * @param pk the public key
 * @param f the prehash flag (true iff using Ed448ph)
 * @param context the context string
 * @param msg the message to sign
 * @return the signature
 */
std::array<uint8_t, 114> sign_message(std::span<const uint8_t, ED448_LEN> sk,
                                      std::span<const uint8_t, ED448_LEN> pk,
                                      bool f,
                                      std::span<const uint8_t> context,
                                      std::span<const uint8_t> msg);

/**
 * @brief Verify a signature(RFC 8032 5.2.7)
 *
 * @param pk the public key
 * @param phflag the prehash flag (true iff using Ed448ph)
 * @param context the context string
 * @param sig the signature
 * @param msg the message to verify
 *
 * @throw Decoding_Error if the public key or signature is malformed
 * @return true if the signature is valid
 */
bool verify_signature(std::span<const uint8_t, ED448_LEN> pk,
                      bool phflag,
                      std::span<const uint8_t> context,
                      std::span<const uint8_t> sig,
                      std::span<const uint8_t> msg);

/**
* Check that this is a valid public key point encoding: it must decode,
* must not be the identity or another point of small order, and must lie
* within the prime order subgroup
*
* @throw Decoding_Error if any of these checks fail
*/
void ed448_validate_public_key_point(std::span<const uint8_t, ED448_LEN> pk);

}  // namespace Botan

#endif  // BOTAN_ED448_INTERNAL_H_

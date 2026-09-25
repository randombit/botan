/*
 * C++ wrapper around the C API of the Rust crate rust-hqc
 *
 * (C) 2026 Falko Strenzke
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_HQC_FFI_H_
#define BOTAN_HQC_FFI_H_

#include <botan/hqc_mode.h>

#include <cstdint>
#include <span>

/**
 * Thin, exception-based wrapper around the four functions of the C API of the
 * Rust crate rust-hqc (hqc_c_api.h). This is the only place in Botan that
 * includes that header.
 *
 * The C API is stateless. Key generation and encapsulation are deterministic
 * given the @p seed, which the crate expands with SHAKE256; the caller draws
 * the seed from Botan's RNG.
 */
namespace Botan::HQC_FFI {

/// Number of seed bytes handed to the crate for key generation and encapsulation
constexpr size_t seed_length = 48;

/// Byte lengths of the objects of an HQC parameter set
struct Sizes {
      size_t ek = 0;  ///< encapsulation (public) key
      size_t dk = 0;  ///< decapsulation (private) key
      size_t ct = 0;  ///< ciphertext
      size_t ss = 0;  ///< shared secret
};

Sizes sizes(const HQC_Mode& mode);

void keypair(const HQC_Mode& mode, std::span<uint8_t> ek, std::span<uint8_t> dk, std::span<const uint8_t> seed);

void encaps(const HQC_Mode& mode,
            std::span<uint8_t> ct,
            std::span<uint8_t> ss,
            std::span<const uint8_t> ek,
            std::span<const uint8_t> seed);

/**
 * Decapsulates @p ct with @p dk into @p ss.
 *
 * HQC uses the Fujisaki-Okamoto transform with implicit rejection: an invalid
 * ciphertext yields a pseudo-random shared secret and is never reported.
 * This function only throws if the inputs are structurally wrong (lengths,
 * parameter set).
 */
void decaps(const HQC_Mode& mode, std::span<uint8_t> ss, std::span<const uint8_t> ct, std::span<const uint8_t> dk);

}  // namespace Botan::HQC_FFI

#endif

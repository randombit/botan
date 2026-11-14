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
 * Thin, exception-based wrapper around the functions of the C API of the
 * Rust crate rust-hqc (hqc_c_api.h). This is the only place in Botan that
 * includes that header.
 *
 * The C API is stateless and derandomized: key generation and encapsulation
 * take exactly the random bytes the HQC specification draws from the RNG
 * (the 32-byte master seed, which is the decapsulation key, resp. the message
 * followed by the salt), which the caller draws from Botan's RNG.
 */
namespace Botan::HQC_FFI {

/// Byte lengths of the objects of an HQC parameter set
struct Sizes {
      size_t ek = 0;                  ///< encapsulation (public) key
      size_t dk = 0;                  ///< decapsulation (private) key (the master seed)
      size_t ct = 0;                  ///< ciphertext
      size_t ss = 0;                  ///< shared secret
      size_t keypair_randomness = 0;  ///< random bytes consumed by keypair()
      size_t encaps_randomness = 0;   ///< random bytes consumed by encaps()
};

Sizes sizes(const HQC_Mode& mode);

/**
 * Generates a key pair from @p seed (Sizes::keypair_randomness bytes), which
 * becomes the decapsulation key @p dk.
 */
void keypair(const HQC_Mode& mode, std::span<uint8_t> ek, std::span<uint8_t> dk, std::span<const uint8_t> seed);

/**
 * Derives the encapsulation key @p ek belonging to the decapsulation key @p dk.
 * Throws Invalid_Argument if @p dk has the wrong length.
 */
void public_key(const HQC_Mode& mode, std::span<uint8_t> ek, std::span<const uint8_t> dk);

/**
 * Encapsulates to @p ek with @p randomness (Sizes::encaps_randomness bytes:
 * the message followed by the salt).
 */
void encaps(const HQC_Mode& mode,
            std::span<uint8_t> ct,
            std::span<uint8_t> ss,
            std::span<const uint8_t> ek,
            std::span<const uint8_t> randomness);

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

/*
* TPM 2 TSS crypto callbacks backend interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_CRYPTO_BACKEND_H_
#define BOTAN_TPM2_CRYPTO_BACKEND_H_

#include <botan/compiler.h>
#include <memory>

struct ESYS_CONTEXT;

namespace Botan {
class RandomNumberGenerator;
}

namespace Botan::TPM2 {

/**
 * This state object is available to all crypto callbacks.
 * Its lifetime must be managed by the caller for as long as the associated
 * ESYS_CONTEXT pointer is valid.
 */
struct CryptoCallbackState {
      std::shared_ptr<Botan::RandomNumberGenerator> rng;  // NOLINT(misc-non-private-member-variables-in-classes)
};

/**
 * Enable Botan's crypto callbacks in the TPM2-TSS for the given ESYS_CONTEXT
 * @p context. Use this if you do not plan to use Botan's TPM wrapper (rooted
 * in TPM2::Context) but still want to benefit from Botan's TPM crypto backend.
 * Otherwise, use TPM2::Context::use_botan_crypto_backend().
 *
 * This replaces all cryptographic functionality required for the communication
 * with the TPM by Botan's implementations. The TSS2 would otherwise use OpenSSL
 * or mbedTLS.
 *
 * Note that the provided @p rng should not be dependent on the TPM and that the
 * returned pointer to the CryptoCallbackState must be kept alive as long as the
 * associated ESYS_CONTEXT is valid and used.
 *
 * @param context  the ESYS_CONTEXT pointer to register the crypto backend on
 * @param rng      the (independent) random number generator to be used
 * @returns        a state object that must be kept alive by the caller for as
 *                 long as the associated ESYS_CONTEXT is valid.
 *
 * @throws Not_Implemented if the TPM2-TSS does not support crypto callbacks.
 */
[[nodiscard]] BOTAN_PUBLIC_API(3, 7) std::unique_ptr<CryptoCallbackState> use_botan_crypto_backend(
   ESYS_CONTEXT* context, const std::shared_ptr<Botan::RandomNumberGenerator>& rng);

/**
 * Checks if the TSS2 supports registering Botan's crypto backend at runtime.
 * Older versions of the TSS2 do not support this feature ( 4.0.0).
 * @returns true if the TSS2 supports Botan's crypto backend
 */
[[nodiscard]] BOTAN_PUBLIC_API(3, 7) bool supports_botan_crypto_backend() noexcept;

}  // namespace Botan::TPM2

#endif

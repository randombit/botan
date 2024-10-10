/*
* TPM 2 TSS crypto callbacks backend
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_CRYPTO_BACKEND_H_
#define BOTAN_TPM2_CRYPTO_BACKEND_H_

#include <memory>

namespace Botan {
class RandomNumberGenerator;
}

namespace Botan::TPM2 {

class Context;

/**
 * This state object is available to all crypto callbacks.
 * Its lifetime is managed by the TPM2::Context.
 */
struct CryptoCallbackState {
      CryptoCallbackState(std::shared_ptr<Botan::RandomNumberGenerator> rng_in) : rng(std::move(rng_in)) {}

      std::shared_ptr<Botan::RandomNumberGenerator> rng;  // NOLINT(misc-non-private-member-variables-in-classes)
};

/**
 * Enable Botan's crypto callbacks in the TPM2-TSS for the given @p context.
 * @throws Not_Implemented if the TPM2-TSS does not support crypto callbacks.
 */
void enable_crypto_callbacks(const std::shared_ptr<Context>& context);

}  // namespace Botan::TPM2

#endif

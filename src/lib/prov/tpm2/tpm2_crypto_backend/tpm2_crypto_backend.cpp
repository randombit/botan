/*
* TPM 2 TSS crypto callbacks backend interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_crypto_backend.h>

#include <botan/internal/tpm2_crypto_backend_impl.h>
#include <botan/internal/tpm2_util.h>

namespace Botan::TPM2 {

std::unique_ptr<CryptoCallbackState> use_botan_crypto_backend(
   ESYS_CONTEXT* context, const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
   auto crypto_callback_state = std::make_unique<CryptoCallbackState>(CryptoCallbackState{.rng = rng});
   set_crypto_callbacks(context, crypto_callback_state.get());
   return crypto_callback_state;
}

BOTAN_PUBLIC_API(3, 7) bool supports_botan_crypto_backend() noexcept {
#if defined(BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS)
   return true;
#else
   return false;
#endif
}

}  // namespace Botan::TPM2

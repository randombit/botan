/*
* TPM 2 TSS crypto callbacks backend implementation
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_CRYPTO_BACKEND_IMPL_H_
#define BOTAN_TPM2_CRYPTO_BACKEND_IMPL_H_

struct ESYS_CONTEXT;

namespace Botan::TPM2 {

/**
 * Enable Botan's crypto callbacks in the TPM2-TSS for the given @p context.
 * @throws Not_Implemented if the TPM2-TSS does not support crypto callbacks.
 */
void set_crypto_callbacks(ESYS_CONTEXT* context, void* callback_state);

}  // namespace Botan::TPM2

#endif

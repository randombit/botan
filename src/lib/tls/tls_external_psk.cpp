/*
 * TLS 1.3 Preshared Key Container
 * (C) 2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *     2025 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/tls_external_psk.h>

#include <botan/assert.h>
#include <utility>

namespace Botan::TLS {

secure_vector<uint8_t> ExternalPSK::extract_master_secret() {
   BOTAN_STATE_CHECK(!m_master_secret.empty());
   return std::exchange(m_master_secret, {});
}

}  // namespace Botan::TLS

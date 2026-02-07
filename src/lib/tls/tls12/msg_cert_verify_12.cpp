/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_12.h>

#include <botan/assert.h>
#include <botan/pk_keys.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/x509cert.h>
#include <botan/internal/target_info.h>
#include <botan/internal/tls_handshake_state.h>

namespace Botan::TLS {

/*
* Create a new Certificate Verify message for TLS 1.2
*/
Certificate_Verify_12::Certificate_Verify_12(Handshake_IO& io,
                                             Handshake_State& state,
                                             const Policy& policy,
                                             RandomNumberGenerator& rng,
                                             const Private_Key* priv_key) {
   BOTAN_ASSERT_NONNULL(priv_key);

   const std::pair<std::string, Signature_Format> format = state.choose_sig_format(*priv_key, m_scheme, true, policy);

   m_signature =
      state.callbacks().tls_sign_message(*priv_key, rng, format.first, format.second, state.hash().get_contents());

   state.hash().update(io.send(*this));
}

bool Certificate_Verify_12::verify(const X509_Certificate& cert,
                                   const Handshake_State& state,
                                   const Policy& policy) const {
   auto key = cert.subject_public_key();

   policy.check_peer_key_acceptable(*key);

   const std::pair<std::string, Signature_Format> format =
      state.parse_sig_format(*key, m_scheme, state.client_hello()->signature_schemes(), true, policy);

   const bool signature_valid =
      state.callbacks().tls_verify_message(*key, format.first, format.second, state.hash().get_contents(), m_signature);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   BOTAN_UNUSED(signature_valid);
   return true;

#else
   return signature_valid;

#endif
}

}  // namespace Botan::TLS

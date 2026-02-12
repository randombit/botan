/*
* Finished Message
* (C) 2021-2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_13.h>

#include <botan/internal/tls_cipher_state.h>

namespace Botan::TLS {

Finished_13::Finished_13(Cipher_State* cipher_state, const Transcript_Hash& transcript_hash) {
   m_verification_data = cipher_state->finished_mac(transcript_hash);
}

bool Finished_13::verify(Cipher_State* cipher_state, const Transcript_Hash& transcript_hash) const {
   return cipher_state->verify_peer_finished_mac(transcript_hash, m_verification_data);
}

}  // namespace Botan::TLS

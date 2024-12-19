/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/kdf.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/literals.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>

#if defined(BOTAN_HAS_TLS_13)
   #include <botan/internal/tls_cipher_state.h>
#endif

namespace Botan::TLS {

namespace {

/*
* Compute the verify_data for TLS 1.2
*/
std::vector<uint8_t> finished_compute_verify_12(const Handshake_State& state, Connection_Side side) {
   using namespace literals;

   constexpr auto TLS_CLIENT_LABEL = "636C69656E742066696E6973686564"_hex;
   constexpr auto TLS_SERVER_LABEL = "7365727665722066696E6973686564"_hex;

   auto prf = state.protocol_specific_prf();

   const auto input = state.hash().final(state.ciphersuite().prf_algo());
   const auto label = (side == Connection_Side::Client) ? TLS_CLIENT_LABEL : TLS_SERVER_LABEL;

   return prf->derive_key<std::vector<uint8_t>>(12, state.session_keys().master_secret(), input, label);
}

}  // namespace

std::vector<uint8_t> Finished::serialize() const {
   return m_verification_data;
}

Finished::Finished(const std::vector<uint8_t>& buf) : m_verification_data(buf) {}

std::vector<uint8_t> Finished::verify_data() const {
   return m_verification_data;
}

Finished_12::Finished_12(Handshake_IO& io, Handshake_State& state, Connection_Side side) {
   m_verification_data = finished_compute_verify_12(state, side);
   state.hash().update(io.send(*this));
}

bool Finished_12::verify(const Handshake_State& state, Connection_Side side) const {
   std::vector<uint8_t> computed_verify = finished_compute_verify_12(state, side);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   return true;
#else
   // first check the size:
   if(m_verification_data.size() != computed_verify.size()) {
      return false;
   }

   return CT::is_equal(m_verification_data.data(), computed_verify.data(), computed_verify.size()).as_bool();
#endif
}

#if defined(BOTAN_HAS_TLS_13)
Finished_13::Finished_13(Cipher_State* cipher_state, const Transcript_Hash& transcript_hash) {
   m_verification_data = cipher_state->finished_mac(transcript_hash);
}

bool Finished_13::verify(Cipher_State* cipher_state, const Transcript_Hash& transcript_hash) const {
   return cipher_state->verify_peer_finished_mac(transcript_hash, m_verification_data);
}
#endif
}  // namespace Botan::TLS

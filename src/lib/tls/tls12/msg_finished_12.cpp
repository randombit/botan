/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_12.h>

#include <botan/kdf.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/target_info.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>

namespace Botan::TLS {

namespace {

/*
* Compute the verify_data for TLS 1.2
*/
std::vector<uint8_t> finished_compute_verify_12(const Handshake_State& state, Connection_Side side) {
   auto prf = state.protocol_specific_prf();

   // RFC 5246 7.4.9
   //    finished_label
   //       For Finished messages sent by the client, the string
   //       "client finished".  For Finished messages sent by the server, the
   //       string "server finished".
   using namespace std::literals;
   const auto label = (side == Connection_Side::Client)  //
                         ? "client finished"sv
                         : "server finished"sv;
   const auto input = state.hash().final(state.ciphersuite().prf_algo());

   return prf->derive_key<std::vector<uint8_t>>(
      12, state.session_keys().master_secret(), input, as_span_of_bytes(label));
}

}  // namespace

Finished_12::Finished_12(Handshake_IO& io, Handshake_State& state, Connection_Side side) {
   m_verification_data = finished_compute_verify_12(state, side);
   state.hash().update(io.send(*this));
}

bool Finished_12::verify(const Handshake_State& state, Connection_Side side) const {
   std::vector<uint8_t> computed_verify = finished_compute_verify_12(state, side);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   return true;
#else
   return CT::is_equal<uint8_t>(m_verification_data, computed_verify).as_bool();
#endif
}

}  // namespace Botan::TLS

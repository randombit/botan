/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_finished_impl.h>
#include <botan/tls_messages.h>
#include <botan/kdf.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>


namespace Botan {

namespace TLS {

namespace {

/*
* Compute the verify_data
*/
std::vector<uint8_t> finished_compute_verify(const Handshake_State& state,
                                          Connection_Side side)
   {
   const uint8_t TLS_CLIENT_LABEL[] = {
      0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x69, 0x6E, 0x69,
      0x73, 0x68, 0x65, 0x64 };

   const uint8_t TLS_SERVER_LABEL[] = {
      0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6E, 0x69,
      0x73, 0x68, 0x65, 0x64 };

   auto prf = state.protocol_specific_prf();

   std::vector<uint8_t> input;
   std::vector<uint8_t> label;
   label += (side == CLIENT)
      ? std::make_pair(TLS_CLIENT_LABEL, sizeof(TLS_CLIENT_LABEL))
      : std::make_pair(TLS_SERVER_LABEL, sizeof(TLS_SERVER_LABEL));

   input += state.hash().final(state.ciphersuite().prf_algo());

   return unlock(prf->derive_key(12, state.session_keys().master_secret(), input, label));
   }

}

/*
* Create a new Finished message
*/
Finished_Impl::Finished_Impl(Handshake_IO& io,
                             Handshake_State& state,
                             Connection_Side side) :
   m_verification_data(finished_compute_verify( state, side ))
   {
   state.hash().update(io.send(*this));
   }

Handshake_Type Finished_Impl::type() const
   {
   return FINISHED;
   }

/*
* Serialize a Finished message
*/
std::vector<uint8_t> Finished_Impl::serialize() const
   {
   return m_verification_data;
   }

/*
* Deserialize a Finished message
*/
Finished_Impl::Finished_Impl(const std::vector<uint8_t>& buf) : m_verification_data(buf)
   {}

std::vector<uint8_t> Finished_Impl::verify_data() const
   {
   return m_verification_data;
   }

/*
* Verify a Finished message
*/
bool Finished_Impl::verify(const Handshake_State& state,
                           Connection_Side side) const
   {
   std::vector<uint8_t> computed_verify = finished_compute_verify(state, side);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   return true;
#else
   return (m_verification_data.size() == computed_verify.size()) &&
      constant_time_compare(m_verification_data.data(), computed_verify.data(), computed_verify.size());
#endif
   }

}

}

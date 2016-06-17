/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_handshake_io.h>

namespace Botan {

namespace TLS {

namespace {

/*
* Compute the verify_data
*/
std::vector<byte> finished_compute_verify(const Handshake_State& state,
                                          Connection_Side side)
   {
   const byte TLS_CLIENT_LABEL[] = {
      0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x69, 0x6E, 0x69,
      0x73, 0x68, 0x65, 0x64 };

   const byte TLS_SERVER_LABEL[] = {
      0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6E, 0x69,
      0x73, 0x68, 0x65, 0x64 };

   std::unique_ptr<KDF> prf(state.protocol_specific_prf());

   std::vector<byte> input;
   std::vector<byte> label;
   if(side == CLIENT)
      label += std::make_pair(TLS_CLIENT_LABEL, sizeof(TLS_CLIENT_LABEL));
   else
      label += std::make_pair(TLS_SERVER_LABEL, sizeof(TLS_SERVER_LABEL));

   input += state.hash().final(state.version(), state.ciphersuite().prf_algo());

   return unlock(prf->derive_key(12, state.session_keys().master_secret(), input, label));
   }

}

/*
* Create a new Finished message
*/
Finished::Finished(Handshake_IO& io,
                   Handshake_State& state,
                   Connection_Side side) : m_verification_data(finished_compute_verify( state, side ))
   {
   state.hash().update(io.send(*this));
   }

/*
* Serialize a Finished message
*/
std::vector<byte> Finished::serialize() const
   {
   return m_verification_data;
   }

/*
* Deserialize a Finished message
*/
Finished::Finished(const std::vector<byte>& buf) : m_verification_data(buf)
   {}

/*
* Verify a Finished message
*/
bool Finished::verify(const Handshake_State& state,
                      Connection_Side side) const
   {
   return (m_verification_data == finished_compute_verify(state, side));
   }

}

}

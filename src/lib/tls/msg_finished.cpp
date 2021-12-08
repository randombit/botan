/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/kdf.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/msg_finished_impl_12.h>
#include <botan/internal/msg_finished_impl.h>
#include <botan/internal/tls_message_factory.h>
#include <botan/tls_version.h>

namespace Botan {

namespace TLS {

/*
* Create a new Finished message
*/
Finished::Finished(Handshake_IO& io,
                   Handshake_State& state,
                   Connection_Side side) :
   m_impl(Message_Factory::create<Finished_Impl>(state.version(), io, state, side))
   {
   }

/*
* Serialize a Finished message
*/
std::vector<uint8_t> Finished::serialize() const
   {
   return m_impl->serialize();
   }

/*
* Deserialize a Finished message
*/
Finished::Finished(const Protocol_Version& protocol_version, const std::vector<uint8_t>& buf):
   m_impl(Message_Factory::create<Finished_Impl>(protocol_version, buf))
   {
   }

// Needed for std::unique_ptr<> m_impl member, as *_Impl type
// is available as a forward declaration in the header only.
Finished::~Finished() = default;


std::vector<uint8_t> Finished::verify_data() const
   {
   return m_impl->verify_data();
   }

/*
* Verify a Finished message
*/
bool Finished::verify(const Handshake_State& state,
                      Connection_Side side) const
   {
   return m_impl->verify(state, side);
   }
}

}

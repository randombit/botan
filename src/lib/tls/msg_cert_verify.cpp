/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/msg_cert_verify_impl_12.h>
#include <botan/internal/msg_cert_verify_impl.h>
#include <botan/internal/tls_message_factory.h>

namespace Botan {

namespace TLS {

/*
* Create a new Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(Handshake_IO& io,
                                       Handshake_State& state,
                                       const Policy& policy,
                                       RandomNumberGenerator& rng,
                                       const Private_Key* priv_key) :
   m_impl(Message_Factory::create<Certificate_Verify_Impl>(state.version(), io, state, policy, rng, priv_key))
   {
   }

/*
* Deserialize a Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(const Protocol_Version& protocol_version, const std::vector<uint8_t>& buf) :
   m_impl(Message_Factory::create<Certificate_Verify_Impl>(protocol_version, buf))
   {
   }

// Needed for std::unique_ptr<> m_impl member, as *_Impl type
// is available as a forward declaration in the header only.
Certificate_Verify::~Certificate_Verify() = default;

/*
* Serialize a Certificate Verify message
*/
std::vector<uint8_t> Certificate_Verify::serialize() const
   {
   return m_impl->serialize();
   }

/*
* Verify a Certificate Verify message
*/
bool Certificate_Verify::verify(const X509_Certificate& cert,
                                const Handshake_State& state,
                                const Policy& policy) const
   {
   return m_impl->verify(cert, state, policy);
   }

}

}

/*
* Certificate Request Message
* (C) 2004-2006,2012 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_message_factory.h>
#include <botan/internal/msg_cert_req_impl_12.h>
#include <botan/internal/msg_cert_req_impl.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

namespace TLS {

Handshake_Type Certificate_Req::type() const
   {
   return m_impl->type();
   }

const std::vector<std::string>& Certificate_Req::acceptable_cert_types() const
   {
   return m_impl->acceptable_cert_types();
   }

const std::vector<X509_DN>& Certificate_Req::acceptable_CAs() const
   {
   return m_impl->acceptable_CAs();
   }

const std::vector<Signature_Scheme>& Certificate_Req::signature_schemes() const
   {
   return m_impl->signature_schemes();
   }

/**
* Create a new Certificate Request message
*/
Certificate_Req::Certificate_Req(const Protocol_Version& protocol_version,
                                 Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 const std::vector<X509_DN>& ca_certs) :
   m_impl(Message_Factory::create<Certificate_Req_Impl>(protocol_version, io, hash, policy, ca_certs))
   {
   }

/**
* Deserialize a Certificate Request message
*/
Certificate_Req::Certificate_Req(const Protocol_Version& protocol_version, const std::vector<uint8_t>& buf) :
   m_impl(Message_Factory::create<Certificate_Req_Impl>(protocol_version, buf))
   {
   }

// Needed for std::unique_ptr<> m_impl member, as *_Impl type
// is available as a forward declaration in the header only.
Certificate_Req::~Certificate_Req() = default;

/**
* Serialize a Certificate Request message
*/
std::vector<uint8_t> Certificate_Req::serialize() const
   {
   return m_impl->serialize();
   }

}

}

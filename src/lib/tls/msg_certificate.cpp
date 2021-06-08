/*
* Certificate Message
* (C) 2004-2006,2012,2020 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_certificate_impl_12.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_message_factory.h>
#include <botan/internal/loadstor.h>
#include <botan/data_src.h>

namespace Botan {

namespace TLS {

Handshake_Type Certificate::type() const
   {
   return m_impl->type();
   }

const std::vector<X509_Certificate>& Certificate::cert_chain() const
   {
   return m_impl->cert_chain();
   }

size_t Certificate::count() const
   {
   return m_impl->count();
   }

bool Certificate::empty() const
   {
   return m_impl->empty();
   }

/**
* Create a new Certificate message
*/
Certificate::Certificate(const Protocol_Version& protocol_version,
                         Handshake_IO& io,
                         Handshake_Hash& hash,
                         const std::vector<X509_Certificate>& cert_list) :
   m_impl( protocol_version == Protocol_Version::TLS_V13
      ? TLS_Message_Factory::create<Certificate_Impl, Protocol_Version::TLS_V13>()
      : TLS_Message_Factory::create<Certificate_Impl, Protocol_Version::TLS_V12>(io, hash, cert_list))
   {
   }

/**
* Deserialize a Certificate message
*/
Certificate::Certificate(const Protocol_Version& protocol_version,
                         const std::vector<uint8_t>& buf, const Policy& policy) :
   m_impl( protocol_version == Protocol_Version::TLS_V13
      ? TLS_Message_Factory::create<Certificate_Impl, Protocol_Version::TLS_V13>()
      : TLS_Message_Factory::create<Certificate_Impl, Protocol_Version::TLS_V12>(buf, policy))
   {
   }

Certificate::~Certificate() = default;

/**
* Serialize a Certificate message
*/
std::vector<uint8_t> Certificate::serialize() const
   {
   return m_impl->serialize();
   }

}

}

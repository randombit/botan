/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_callbacks.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/msg_server_hello_impl.h>
#include <botan/internal/msg_server_hello_impl_12.h>
#include <botan/internal/tls_message_factory.h>

namespace Botan {

namespace TLS {

// New session case
Server_Hello::Server_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello& client_hello,
                           const Server_Hello::Settings& server_settings,
                           const std::string next_protocol) :
   m_impl(Message_Factory::create<Server_Hello_Impl>(client_hello.version(), io, hash, policy, cb, rng, reneg_info, client_hello, server_settings, next_protocol))
   {
   }

// Resuming
Server_Hello::Server_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello& client_hello,
                           Session& resumed_session,
                           bool offer_session_ticket,
                           const std::string& next_protocol) :
   m_impl(Message_Factory::create<Server_Hello_Impl>(client_hello.version(), io, hash, policy, cb, rng, reneg_info, client_hello, resumed_session, offer_session_ticket, next_protocol))
   {
   }

/*
* Deserialize a Server Hello message
*/
Server_Hello::Server_Hello(const std::vector<uint8_t>& buf)
   {
      m_impl = Message_Factory::create<Server_Hello_Impl>(Server_Hello_Impl(buf).supported_versions(), buf);
   }

// Needed for std::unique_ptr<> m_impl member, as *_Impl type
// is available as a forward declaration in the header only.
Server_Hello::~Server_Hello() = default;

Handshake_Type Server_Hello::type() const
   {
   return m_impl->type();
   }

Protocol_Version Server_Hello::version() const
   {
   return m_impl->version();
   }

const std::vector<uint8_t>& Server_Hello::random() const
   {
   return m_impl->random();
   }

const std::vector<uint8_t>& Server_Hello::session_id() const
   {
   return m_impl->session_id();
   }

uint16_t Server_Hello::ciphersuite() const
   {
   return m_impl->ciphersuite();
   }

uint8_t Server_Hello::compression_method() const
   {
   return m_impl->compression_method();
   }

bool Server_Hello::secure_renegotiation() const
   {
   return m_impl->secure_renegotiation();
   }

std::vector<uint8_t> Server_Hello::renegotiation_info() const
   {
   return m_impl->renegotiation_info();
   }

bool Server_Hello::supports_extended_master_secret() const
   {
   return m_impl->supports_extended_master_secret();
   }

bool Server_Hello::supports_encrypt_then_mac() const
   {
   return m_impl->supports_encrypt_then_mac();
   }

bool Server_Hello::supports_certificate_status_message() const
   {
   return m_impl->supports_certificate_status_message();
   }

bool Server_Hello::supports_session_ticket() const
   {
   return m_impl->supports_session_ticket();
   }

uint16_t Server_Hello::srtp_profile() const
   {
   return m_impl->srtp_profile();
   }

std::string Server_Hello::next_protocol() const
   {
   return m_impl->next_protocol();
   }

std::set<Handshake_Extension_Type> Server_Hello::extension_types() const
   {
   return m_impl->extension_types();
   }

const Extensions& Server_Hello::extensions() const
   {
   return m_impl->extensions();
   }

bool Server_Hello::prefers_compressed_ec_points() const
   {
   return m_impl->prefers_compressed_ec_points();
   }

bool Server_Hello::random_signals_downgrade() const
   {
   return m_impl->random_signals_downgrade();
   }

/*
* Serialize a Server Hello message
*/
std::vector<uint8_t> Server_Hello::serialize() const
   {
   return m_impl->serialize();
   }

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Handshake_IO& io,
                                     Handshake_Hash& hash)
   {
   hash.update(io.send(*this));
   }

/*
* Deserialize a Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(const std::vector<uint8_t>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }

/*
* Serialize a Server Hello Done message
*/
std::vector<uint8_t> Server_Hello_Done::serialize() const
   {
   return std::vector<uint8_t>();
   }
}

}

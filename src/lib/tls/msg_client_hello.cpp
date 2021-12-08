/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <botan/tls_messages.h>
#include <botan/tls_callbacks.h>
#include <botan/rng.h>
#include <botan/hash.h>
#include <botan/tls_version.h>

#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/msg_client_hello_impl.h>
#include <botan/internal/msg_client_hello_impl_12.h>
#include <botan/internal/tls_message_factory.h>

namespace Botan {

namespace TLS {

/*
* Create a new Hello Request message
*/
Hello_Request::Hello_Request(Handshake_IO& io)
   {
   io.send(*this);
   }

/*
* Deserialize a Hello Request message
*/
Hello_Request::Hello_Request(const std::vector<uint8_t>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Bad Hello_Request, has non-zero size");
   }

/*
* Serialize a Hello Request message
*/
std::vector<uint8_t> Hello_Request::serialize() const
   {
   return std::vector<uint8_t>();
   }

/*
* Create a new Client Hello message
*/
Client_Hello::Client_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello::Settings& client_settings,
                           const std::vector<std::string>& next_protocols) :
   m_impl(Message_Factory::create<Client_Hello_Impl>(client_settings.protocol_version(), io, hash, policy, cb, rng, reneg_info, client_settings, next_protocols))
   {
   }

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello::Client_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Session& session,
                           const std::vector<std::string>& next_protocols) :
   m_impl(Message_Factory::create<Client_Hello_Impl>(session.version(), io, hash, policy, cb, rng, reneg_info, session, next_protocols))
   {
   }

/*
* Read a counterparty client hello
*/
Client_Hello::Client_Hello(const std::vector<uint8_t>& buf)
   {
      auto supported_versions = Client_Hello_Impl(buf).supported_versions();

      const auto protocol_version =
         value_exists(supported_versions, Protocol_Version(Protocol_Version::TLS_V13))
            ? Protocol_Version::TLS_V13
            : Protocol_Version::TLS_V12;

      m_impl = Message_Factory::create<Client_Hello_Impl>(protocol_version, buf);
   }

// Needed for std::unique_ptr<> m_impl member, as *_Impl type
// is available as a forward declaration in the header only.
Client_Hello::~Client_Hello() = default;


void Client_Hello::update_hello_cookie(const Hello_Verify_Request& hello_verify)
   {
   m_impl->update_hello_cookie(hello_verify);
   }


const std::vector<uint8_t>& Client_Hello::cookie() const
   {
   return m_impl->cookie();
   }

/*
* Serialize a Client Hello message
*/
std::vector<uint8_t> Client_Hello::serialize() const
   {
   return m_impl->serialize();
   }

std::vector<uint8_t> Client_Hello::cookie_input_data() const
   {
   return m_impl->cookie_input_data();
   }

std::set<Handshake_Extension_Type> Client_Hello::extension_types() const
   {
   return m_impl->extension_types();
   }

const Extensions& Client_Hello::extensions() const
   {
   return m_impl->extensions();
   }

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(uint16_t ciphersuite) const
   {
   return m_impl->offered_suite(ciphersuite);
   }

std::vector<Signature_Scheme> Client_Hello::signature_schemes() const
   {
   return m_impl->signature_schemes();
   }

std::vector<Group_Params> Client_Hello::supported_ecc_curves() const
   {
   return m_impl->supported_ecc_curves();
   }

std::vector<Group_Params> Client_Hello::supported_dh_groups() const
   {
   return m_impl->supported_dh_groups();
   }

bool Client_Hello::prefers_compressed_ec_points() const
   {
   return m_impl->prefers_compressed_ec_points();
   }

std::string Client_Hello::sni_hostname() const
   {
   return m_impl->sni_hostname();
   }

bool Client_Hello::secure_renegotiation() const
   {
   return m_impl->secure_renegotiation();
   }

std::vector<uint8_t> Client_Hello::renegotiation_info() const
   {
   return m_impl->renegotiation_info();
   }

Handshake_Type Client_Hello::type() const
   {
   return m_impl->type();
   }

Protocol_Version Client_Hello::version() const
   {
   return m_impl->version();
   }

std::vector<Protocol_Version> Client_Hello::supported_versions() const
   {
   return m_impl->supported_versions();
   }

const std::vector<uint8_t>& Client_Hello::random() const
   {
   return m_impl->random();
   }

const std::vector<uint8_t>& Client_Hello::session_id() const
   {
   return m_impl->session_id();
   }

const std::vector<uint8_t>& Client_Hello::compression_methods() const
   {
   return m_impl->compression_methods();
   }

const std::vector<uint16_t>& Client_Hello::ciphersuites() const
   {
   return m_impl->ciphersuites();
   }

bool Client_Hello::supports_session_ticket() const
   {
   return m_impl->supports_session_ticket();
   }

std::vector<uint8_t> Client_Hello::session_ticket() const
   {
   return m_impl->session_ticket();
   }

bool Client_Hello::supports_alpn() const
   {
   return m_impl->supports_alpn();
   }

bool Client_Hello::supports_extended_master_secret() const
   {
   return m_impl->supports_extended_master_secret();
   }

bool Client_Hello::supports_cert_status_message() const
   {
   return m_impl->supports_cert_status_message();
   }

bool Client_Hello::supports_encrypt_then_mac() const
   {
   return m_impl->supports_encrypt_then_mac();
   }

bool Client_Hello::sent_signature_algorithms() const
   {
   return m_impl->sent_signature_algorithms();
   }

std::vector<std::string> Client_Hello::next_protocols() const
   {
   return m_impl->next_protocols();
   }

std::vector<uint16_t> Client_Hello::srtp_profiles() const
   {
   return m_impl->srtp_profiles();
   }

}

}

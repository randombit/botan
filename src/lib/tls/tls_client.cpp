/*
* TLS Client
* (C) 2004-2011,2012,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_client.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/stl_util.h>

#include <botan/internal/tls_client_impl_12.h>
#if defined(BOTAN_HAS_TLS_13)
  #include <botan/internal/tls_client_impl_13.h>
#endif

#include <iterator>
#include <sstream>

namespace Botan::TLS {

/*
* TLS Client Constructor
*/
Client::Client(Callbacks& callbacks,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const Server_Information& info,
               const Protocol_Version& offer_version,
               const std::vector<std::string>& next_protocols,
               size_t io_buf_sz)
   {
   Protocol_Version effective_version = offer_version;
#if defined(BOTAN_HAS_TLS_13)
   // downgrade to TLS 1.2 directly if we have a legacy session to resume
   if(effective_version == Protocol_Version::TLS_V13)
      {
      Session session;
      const bool found = session_manager.load_from_server_info(info, session);
      if(found && session.version().is_pre_tls_13())
         effective_version = session.version();
      }

   if(effective_version == Protocol_Version::TLS_V13)
      m_impl = std::make_unique<Client_Impl_13>(
                  callbacks, session_manager, creds, policy,
                  rng, info, next_protocols);
   else
#endif
      m_impl = std::make_unique<Client_Impl_12>(
                  callbacks, session_manager, creds, policy,
                  rng, info, effective_version.is_datagram_protocol(),
                  next_protocols, io_buf_sz);
   }

Client::~Client() = default;

size_t Client::received_data(const uint8_t buf[], size_t buf_size)
   {
   auto read = m_impl->received_data(buf, buf_size);

   if(m_impl->is_downgrading())
      {
      auto info = m_impl->extract_downgrade_info();
      m_impl = std::make_unique<Client_Impl_12>(*info);

      // replay peer data received so far
      read = m_impl->received_data(info->peer_transcript.data(), info->peer_transcript.size());
      }

   return read;
   }

bool Client::is_active() const
   {
   return m_impl->is_active();
   }

bool Client::is_closed() const
   {
   return m_impl->is_closed();
   }

std::vector<X509_Certificate> Client::peer_cert_chain() const
   {
   return m_impl->peer_cert_chain();
   }

SymmetricKey Client::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   return m_impl->key_material_export(label, context, length);
   }

void Client::renegotiate(bool force_full_renegotiation)
   {
   m_impl->renegotiate(force_full_renegotiation);
   }

void Client::update_traffic_keys(bool request_peer_update)
   {
   m_impl->update_traffic_keys(request_peer_update);
   }

bool Client::secure_renegotiation_supported() const
   {
   return m_impl->secure_renegotiation_supported();
   }

void Client::send(const uint8_t buf[], size_t buf_size)
   {
   m_impl->send(buf, buf_size);
   }

void Client::send_alert(const Alert& alert)
   {
   m_impl->send_alert(alert);
   }

void Client::send_warning_alert(Alert::Type type)
   {
   m_impl->send_warning_alert(type);
   }

void Client::send_fatal_alert(Alert::Type type)
   {
   m_impl->send_fatal_alert(type);
   }

void Client::close()
   {
   m_impl->close();
   }

bool Client::timeout_check()
   {
   return m_impl->timeout_check();
   }

std::string Client::application_protocol() const
   {
   return m_impl->application_protocol();
   }

}

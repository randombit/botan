/*
* TLS Server
* (C) 2004-2011,2012,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_server.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/stl_util.h>
#include <botan/tls_magic.h>

#include <botan/internal/tls_server_impl_12.h>
#if defined(BOTAN_HAS_TLS_13)
  #include <botan/internal/tls_server_impl_13.h>
#endif

namespace Botan::TLS {

/*
* TLS Server Constructor
*/
Server::Server(Callbacks& callbacks,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               bool is_datagram,
               size_t io_buf_sz)
   {
   const auto max_version = policy.latest_supported_version(is_datagram);

   if(!max_version.is_pre_tls_13())
      {
#if defined(BOTAN_HAS_TLS_13)
      m_impl = std::make_unique<Server_Impl_13>(
         callbacks, session_manager, creds, policy, rng);

      if(m_impl->expects_downgrade())
         { m_impl->set_io_buffer_size(io_buf_sz); }
#else
      throw Not_Implemented("TLS 1.3 server is not available in this build");
#endif
      }
   else
      {
      m_impl = std::make_unique<Server_Impl_12>(
         callbacks, session_manager, creds, policy, rng, is_datagram, io_buf_sz);
      }
   }

Server::~Server() = default;

size_t Server::received_data(const uint8_t buf[], size_t buf_size)
   {
   auto read = m_impl->received_data(buf, buf_size);

   if(m_impl->is_downgrading())
      {
      auto info = m_impl->extract_downgrade_info();
      m_impl = std::make_unique<Server_Impl_12>(*info);

      // replay peer data received so far
      read = m_impl->received_data(info->peer_transcript.data(), info->peer_transcript.size());
      }

   return read;
   }

bool Server::is_active() const
   {
   return m_impl->is_active();
   }

bool Server::is_closed() const
   {
   return m_impl->is_closed();
   }

bool Server::is_closed_for_reading() const
   {
   return m_impl->is_closed_for_reading();
   }

bool Server::is_closed_for_writing() const
   {
   return m_impl->is_closed_for_writing();
   }

std::vector<X509_Certificate> Server::peer_cert_chain() const
   {
   return m_impl->peer_cert_chain();
   }

SymmetricKey Server::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   return m_impl->key_material_export(label, context, length);
   }

void Server::renegotiate(bool force_full_renegotiation)
   {
   m_impl->renegotiate(force_full_renegotiation);
   }

bool Server::new_session_ticket_supported() const
   {
   return m_impl->new_session_ticket_supported();
   }

void Server::send_new_session_tickets(const size_t tickets)
   {
   m_impl->send_new_session_tickets(tickets);
   }

void Server::update_traffic_keys(bool request_peer_update)
   {
   m_impl->update_traffic_keys(request_peer_update);
   }

bool Server::secure_renegotiation_supported() const
   {
   return m_impl->secure_renegotiation_supported();
   }

void Server::send(const uint8_t buf[], size_t buf_size)
   {
   m_impl->send(buf, buf_size);
   }

void Server::send_alert(const Alert& alert)
   {
   m_impl->send_alert(alert);
   }

void Server::send_warning_alert(Alert::Type type)
   {
   m_impl->send_warning_alert(type);
   }

void Server::send_fatal_alert(Alert::Type type)
   {
   m_impl->send_fatal_alert(type);
   }

void Server::close()
   {
   m_impl->close();
   }

bool Server::timeout_check()
   {
   return m_impl->timeout_check();
   }

std::string Server::application_protocol() const
   {
   return m_impl->application_protocol();
   }
}

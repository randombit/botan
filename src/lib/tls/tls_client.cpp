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
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_state.h>

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
Client::Client(const std::shared_ptr<Callbacks>& callbacks,
               const std::shared_ptr<Session_Manager>& session_manager,
               const std::shared_ptr<Credentials_Manager>& creds,
               const std::shared_ptr<const Policy>& policy,
               const std::shared_ptr<RandomNumberGenerator>& rng,
               Server_Information info,
               Protocol_Version offer_version,
               const std::vector<std::string>& next_protocols,
               size_t io_buf_sz) {
   BOTAN_ARG_CHECK(policy->acceptable_protocol_version(offer_version),
                   "Policy does not allow to offer requested protocol version");

#if defined(BOTAN_HAS_TLS_13)
   if(offer_version == Protocol_Version::TLS_V13) {
      m_impl = std::make_unique<Client_Impl_13>(
         callbacks, session_manager, creds, policy, rng, std::move(info), next_protocols);

      if(m_impl->expects_downgrade()) {
         m_impl->set_io_buffer_size(io_buf_sz);
      }

      if(m_impl->is_downgrading()) {
         // TLS 1.3 implementation found a resumable TLS 1.2 session and
         // requested a downgrade right away.
         downgrade();
      }

      return;
   }
#endif

   m_impl = std::make_unique<Client_Impl_12>(callbacks,
                                             session_manager,
                                             creds,
                                             policy,
                                             rng,
                                             std::move(info),
                                             offer_version.is_datagram_protocol(),
                                             next_protocols,
                                             io_buf_sz);
}

Client::~Client() = default;

size_t Client::downgrade() {
   BOTAN_ASSERT_NOMSG(m_impl->is_downgrading());

   auto info = m_impl->extract_downgrade_info();
   m_impl = std::make_unique<Client_Impl_12>(*info);

   if(!info->peer_transcript.empty()) {
      // replay peer data received so far
      return m_impl->from_peer(info->peer_transcript);
   } else {
      // the downgrade happened due to a resumable TLS 1.2 session
      // before any data was transferred
      return 0;
   }
}

size_t Client::from_peer(std::span<const uint8_t> data) {
   auto read = m_impl->from_peer(data);

   if(m_impl->is_downgrading()) {
      read = downgrade();
   }

   return read;
}

bool Client::is_handshake_complete() const {
   return m_impl->is_handshake_complete();
}

bool Client::is_active() const {
   return m_impl->is_active();
}

bool Client::is_closed() const {
   return m_impl->is_closed();
}

bool Client::is_closed_for_reading() const {
   return m_impl->is_closed_for_reading();
}

bool Client::is_closed_for_writing() const {
   return m_impl->is_closed_for_writing();
}

std::vector<X509_Certificate> Client::peer_cert_chain() const {
   return m_impl->peer_cert_chain();
}

std::shared_ptr<const Public_Key> Client::peer_raw_public_key() const {
   return m_impl->peer_raw_public_key();
}

std::optional<std::string> Client::external_psk_identity() const {
   return m_impl->external_psk_identity();
}

SymmetricKey Client::key_material_export(std::string_view label, std::string_view context, size_t length) const {
   return m_impl->key_material_export(label, context, length);
}

void Client::renegotiate(bool force_full_renegotiation) {
   m_impl->renegotiate(force_full_renegotiation);
}

void Client::update_traffic_keys(bool request_peer_update) {
   m_impl->update_traffic_keys(request_peer_update);
}

bool Client::secure_renegotiation_supported() const {
   return m_impl->secure_renegotiation_supported();
}

void Client::to_peer(std::span<const uint8_t> data) {
   m_impl->to_peer(data);
}

void Client::send_alert(const Alert& alert) {
   m_impl->send_alert(alert);
}

void Client::send_warning_alert(Alert::Type type) {
   m_impl->send_warning_alert(type);
}

void Client::send_fatal_alert(Alert::Type type) {
   m_impl->send_fatal_alert(type);
}

void Client::close() {
   m_impl->close();
}

bool Client::timeout_check() {
   return m_impl->timeout_check();
}

std::string Client::application_protocol() const {
   return m_impl->application_protocol();
}

}  // namespace Botan::TLS

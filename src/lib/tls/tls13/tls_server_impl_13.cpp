/*
* TLS Server - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_server_impl_13.h>

#include <botan/credentials_manager.h>
#include <botan/rng.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_cipher_state.h>

namespace Botan::TLS {

Server_Impl_13::Server_Impl_13(const std::shared_ptr<Callbacks>& callbacks,
                               const std::shared_ptr<Session_Manager>& session_manager,
                               const std::shared_ptr<Credentials_Manager>& credentials_manager,
                               const std::shared_ptr<const Policy>& policy,
                               const std::shared_ptr<RandomNumberGenerator>& rng) :
      Channel_Impl_13(callbacks, session_manager, credentials_manager, rng, policy, true /* is_server */) {
#if defined(BOTAN_HAS_TLS_12)
   if(policy->allow_tls12()) {
      expect_downgrade({}, {});
   }
#endif

   m_transitions.set_expected_next(Handshake_Type::ClientHello);
}

std::string Server_Impl_13::application_protocol() const {
   if(is_handshake_complete()) {
      const auto& eee = m_handshake_state.encrypted_extensions().extensions();
      if(const auto alpn = eee.get<Application_Layer_Protocol_Notification>()) {
         return alpn->single_protocol();
      }
   }

   return "";
}

std::vector<X509_Certificate> Server_Impl_13::peer_cert_chain() const {
   if(m_handshake_state.has_client_certificate_msg() &&
      m_handshake_state.client_certificate().has_certificate_chain()) {
      return m_handshake_state.client_certificate().cert_chain();
   }

   if(m_resumed_session.has_value()) {
      return m_resumed_session->peer_certs();
   }

   return {};
}

std::shared_ptr<const Public_Key> Server_Impl_13::peer_raw_public_key() const {
   if(m_handshake_state.has_client_certificate_msg() && m_handshake_state.client_certificate().is_raw_public_key()) {
      return m_handshake_state.client_certificate().public_key();
   }

   if(m_resumed_session.has_value()) {
      return m_resumed_session->peer_raw_public_key();
   }

   return nullptr;
}

std::optional<std::string> Server_Impl_13::external_psk_identity() const {
   return m_psk_identity;
}

bool Server_Impl_13::new_session_ticket_supported() const {
   // RFC 8446 4.2.9
   //    This extension also restricts the modes for use with PSK resumption.
   //    Servers SHOULD NOT send NewSessionTicket with tickets that are not
   //    compatible with the advertised modes; however, if a server does so,
   //    the impact will just be that the client's attempts at resumption fail.
   //
   // Note: Applications can overrule this by calling send_new_session_tickets()
   //       regardless of this method indicating no support for tickets.
   //
   // TODO: Implement other PSK KE modes than PSK_DHE_KE
   return is_handshake_complete() && m_handshake_state.client_hello().extensions().has<PSK_Key_Exchange_Modes>() &&
          value_exists(m_handshake_state.client_hello().extensions().get<PSK_Key_Exchange_Modes>()->modes(),
                       PSK_Key_Exchange_Mode::PSK_DHE_KE);
}

size_t Server_Impl_13::send_new_session_tickets(const size_t tickets) {
   BOTAN_STATE_CHECK(is_handshake_complete());

   if(tickets == 0) {
      return 0;
   }

   auto flight = aggregate_post_handshake_messages();
   size_t tickets_created = 0;

   for(size_t i = 0; i < tickets; ++i) {
      auto nonce = m_cipher_state->next_ticket_nonce();
      const Session session(m_cipher_state->psk(nonce),
                            std::nullopt,  // early data not yet implemented
                            policy().session_ticket_lifetime(),
                            peer_cert_chain(),
                            peer_raw_public_key(),
                            m_handshake_state.client_hello(),
                            m_handshake_state.server_hello(),
                            callbacks(),
                            rng());

      if(callbacks().tls_should_persist_resumption_information(session)) {
         if(auto handle = session_manager().establish(session)) {
            flight.add(New_Session_Ticket_13(std::move(nonce), session, handle.value(), callbacks()));
            ++tickets_created;
         }
      }
   }

   if(flight.contains_messages()) {
      flight.send();
   }

   return tickets_created;
}

void Server_Impl_13::process_handshake_msg(Handshake_Message_13 message) {
   std::visit(
      [&](auto msg) {
         // first verify that the message was expected by the state machine...
         m_transitions.confirm_transition_to(msg.get().type());

         // ... then allow the library user to abort on their discretion
         callbacks().tls_inspect_handshake_msg(msg.get());

         // ... finally handle the message
         handle(msg.get());
      },
      m_handshake_state.received(std::move(message)));
}

void Server_Impl_13::process_post_handshake_msg(Post_Handshake_Message_13 message) {
   BOTAN_STATE_CHECK(is_handshake_complete());

   std::visit([&](auto msg) { handle(msg); }, m_handshake_state.received(std::move(message)));
}

void Server_Impl_13::process_dummy_change_cipher_spec() {
   // RFC 8446 5.
   //    If an implementation detects a change_cipher_spec record received before
   //    the first ClientHello message or after the peer's Finished message, it MUST be
   //    treated as an unexpected record type [("unexpected_message" alert)].
   if(!m_handshake_state.has_client_hello() || m_handshake_state.has_client_finished()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received an unexpected dummy Change Cipher Spec");
   }

   // RFC 8446 5.
   //    An implementation may receive an unencrypted record of type change_cipher_spec [...]
   //    at any time after the first ClientHello message has been sent or received
   //    and before the peer's Finished message has been received [...]
   //    and MUST simply drop it without further processing.
   //
   // ... no further processing.
}

bool Server_Impl_13::is_handshake_complete() const {
   return m_handshake_state.handshake_finished();
}

void Server_Impl_13::maybe_log_secret(std::string_view label, std::span<const uint8_t> secret) const {
   if(policy().allow_ssl_key_log_file()) {
      callbacks().tls_ssl_key_log_data(label, m_handshake_state.client_hello().random(), secret);
   }
}

void Server_Impl_13::downgrade() {
   BOTAN_ASSERT_NOMSG(expects_downgrade());

   request_downgrade();

   // After this, no further messages are expected here because this instance
   // will be replaced by a Server_Impl_12.
   m_transitions.set_expected_next({});
}

void Server_Impl_13::maybe_handle_compatibility_mode() {
   BOTAN_ASSERT_NOMSG(m_handshake_state.has_client_hello());
   BOTAN_ASSERT_NOMSG(m_handshake_state.has_hello_retry_request() || m_handshake_state.has_server_hello());

   // RFC 8446 Appendix D.4  (Middlebox Compatibility Mode)
   //    The server sends a dummy change_cipher_spec record immediately after
   //    its first handshake message. This may either be after a ServerHello or
   //    a HelloRetryRequest.
   //
   //    This "compatibility mode" is partially negotiated: the client can opt
   //    to provide a session ID or not, and the server has to echo it. Either
   //    side can send change_cipher_spec at any time during the handshake, as
   //    they must be ignored by the peer, but if the client sends a non-empty
   //    session ID, the server MUST send the change_cipher_spec as described
   //    [above].
   //
   // Technically, the usage of compatibility mode is fully up to the client
   // sending a non-empty session ID. Nevertheless, when the policy requests
   // it we send a CCS regardless. Note that this is perfectly legal and also
   // satisfies some BoGo tests that expect this behaviour.
   //
   // Send a CCS immediately after the _first_ handshake message. I.e. either
   // after Hello Retry Request (exclusively) or after a Server Hello that was
   // not preseded by a Hello Retry Request.
   const bool just_after_first_handshake_message =
      m_handshake_state.has_hello_retry_request() ^ m_handshake_state.has_server_hello();
   const bool client_requested_compatibility_mode = !m_handshake_state.client_hello().session_id().empty();

   if(just_after_first_handshake_message &&
      (policy().tls_13_middlebox_compatibility_mode() || client_requested_compatibility_mode)) {
      send_dummy_change_cipher_spec();
   }
}

void Server_Impl_13::handle_reply_to_client_hello(Server_Hello_13 server_hello) {
   const auto& client_hello = m_handshake_state.client_hello();
   const auto& exts = client_hello.extensions();

   const bool uses_psk = server_hello.extensions().has<PSK>();

   const auto cipher_opt = Ciphersuite::by_id(server_hello.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher_opt.has_value());
   const auto& cipher = cipher_opt.value();
   m_transcript_hash.set_algorithm(cipher.prf_algo());

   std::unique_ptr<Cipher_State> psk_cipher_state;
   if(uses_psk) {
      auto psk_extension = server_hello.extensions().get<PSK>();

      psk_cipher_state =
         std::visit(overloaded{[&, this](Session session) {
                                  m_resumed_session = std::move(session);
                                  return Cipher_State::init_with_psk(Connection_Side::Server,
                                                                     Cipher_State::PSK_Type::Resumption,
                                                                     m_resumed_session->extract_master_secret(),
                                                                     cipher.prf_algo());
                               },
                               [&, this](ExternalPSK psk) {
                                  m_psk_identity = psk.identity();
                                  return Cipher_State::init_with_psk(Connection_Side::Server,
                                                                     Cipher_State::PSK_Type::External,
                                                                     psk.extract_master_secret(),
                                                                     cipher.prf_algo());
                               }},
                    psk_extension->take_session_to_resume_or_psk());

      // RFC 8446 4.2.11
      //    Prior to accepting PSK key establishment, the server MUST validate
      //    the corresponding binder value (see Section 4.2.11.2 below). If this
      //    value is not present or does not validate, the server MUST abort the
      //    handshake.
      //    Servers SHOULD NOT attempt to validate multiple binders; rather,
      //    they SHOULD select a single PSK and validate solely the binder that
      //    corresponds to that PSK.
      //
      // Note: PSK selection was performed earlier, resulting in the existence
      //       of this extension in the first place.
      if(!exts.get<PSK>()->validate_binder(*psk_extension,
                                           psk_cipher_state->psk_binder_mac(m_transcript_hash.truncated()))) {
         throw TLS_Exception(Alert::DecryptError, "PSK binder does not check out");
      }

      // RFC 8446 4.2.10
      //   For PSKs provisioned via NewSessionTicket, a server MUST validate
      //   that the ticket age for the selected PSK identity [...] is within a
      //   small tolerance of the time since the ticket was issued. If it is
      //   not, the server SHOULD proceed with the handshake but reject 0-RTT,
      //   and SHOULD NOT take any other action that assumes that this
      //   ClientHello is fresh.
      //
      // TODO: When implementing Early Data (0-RTT) we should take the above
      //       paragraph into account. Note that there are BoGo tests that
      //       validate this behaviour. Namely: TLS13-TicketAgeSkew-*
   }

   // This sends the server_hello to the peer.
   // NOTE: the server_hello variable is moved into the handshake state. Later
   //       references to the Server Hello will need to consult the handshake
   //       state object!
   send_handshake_message(m_handshake_state.sending(std::move(server_hello)));
   maybe_handle_compatibility_mode();

   // Setup encryption for all the remaining handshake messages
   m_cipher_state = [&] {
      // Currently, PSK without DHE is not implemented...
      const auto my_keyshare = m_handshake_state.server_hello().extensions().get<Key_Share>();
      BOTAN_ASSERT_NONNULL(my_keyshare);

      if(uses_psk) {
         BOTAN_ASSERT_NONNULL(psk_cipher_state);
         psk_cipher_state->advance_with_client_hello(m_transcript_hash.previous(), *this);
         psk_cipher_state->advance_with_server_hello(
            cipher, my_keyshare->take_shared_secret(), m_transcript_hash.current(), *this);

         return std::move(psk_cipher_state);
      } else {
         return Cipher_State::init_with_server_hello(
            m_side, my_keyshare->take_shared_secret(), cipher, m_transcript_hash.current(), *this);
      }
   }();

   auto flight = aggregate_handshake_messages();
   flight.add(m_handshake_state.sending(Encrypted_Extensions(client_hello, policy(), callbacks())));

   if(!uses_psk) {
      // RFC 8446 4.3.2
      //    A server which is authenticating with a certificate MAY optionally
      //    request a certificate from the client. This message, if sent, MUST
      //    follow EncryptedExtensions.
      if(auto certificate_request =
            Certificate_Request_13::maybe_create(client_hello, credentials_manager(), callbacks(), policy())) {
         flight.add(m_handshake_state.sending(std::move(certificate_request.value())));
      }

      const auto& enc_exts = m_handshake_state.encrypted_extensions().extensions();

      // RFC 7250 4.2
      //   This client_certificate_type extension in the server hello then
      //   indicates the type of certificates the client is requested to provide
      //   in a subsequent certificate payload.
      //
      // Note: TLS 1.3 carries this extension in the Encrypted Extensions
      //       message instead of the Server Hello.
      if(auto client_cert_type = enc_exts.get<Client_Certificate_Type>()) {
         set_selected_certificate_type(client_cert_type->selected_certificate_type());
      }

      // RFC 8446 4.4.2
      //    If the corresponding certificate type extension [...]  was not
      //    negotiated in EncryptedExtensions, or the X.509 certificate type
      //    was negotiated, then each CertificateEntry contains a DER-encoded
      //    X.509 certificate.
      const auto cert_type = [&] {
         if(auto server_cert_type = enc_exts.get<Server_Certificate_Type>()) {
            return server_cert_type->selected_certificate_type();
         } else {
            return Certificate_Type::X509;
         }
      }();

      flight.add(m_handshake_state.sending(Certificate_13(client_hello, credentials_manager(), callbacks(), cert_type)))
         .add(m_handshake_state.sending(Certificate_Verify_13(m_handshake_state.server_certificate(),
                                                              client_hello.signature_schemes(),
                                                              client_hello.sni_hostname(),
                                                              m_transcript_hash.current(),
                                                              Connection_Side::Server,
                                                              credentials_manager(),
                                                              policy(),
                                                              callbacks(),
                                                              rng())));
   }

   flight.add(m_handshake_state.sending(Finished_13(m_cipher_state.get(), m_transcript_hash.current())));

   if(client_hello.extensions().has<Record_Size_Limit>() &&
      m_handshake_state.encrypted_extensions().extensions().has<Record_Size_Limit>()) {
      // RFC 8449 4.
      //    When the "record_size_limit" extension is negotiated, an endpoint
      //    MUST NOT generate a protected record with plaintext that is larger
      //    than the RecordSizeLimit value it receives from its peer.
      //    Unprotected messages are not subject to this limit.
      //
      // Hence, the limit is set just before we start sending encrypted records.
      //
      // RFC 8449 4.
      //     The record size limit only applies to records sent toward the
      //     endpoint that advertises the limit.  An endpoint can send records
      //     that are larger than the limit it advertises as its own limit.
      //
      // Hence, the "outgoing" limit is what the client requested and the
      // "incoming" limit is what we will request in the Encrypted Extensions.
      const auto outgoing_limit = client_hello.extensions().get<Record_Size_Limit>();
      const auto incoming_limit = m_handshake_state.encrypted_extensions().extensions().get<Record_Size_Limit>();
      set_record_size_limits(outgoing_limit->limit(), incoming_limit->limit());
   }

   flight.send();

   m_cipher_state->advance_with_server_finished(m_transcript_hash.current(), *this);

   if(m_handshake_state.has_certificate_request()) {
      // RFC 8446 4.4.2
      //    The client MUST send a Certificate message if and only if the server
      //    has requested client authentication via a CertificateRequest message
      //    [...]. If the server requests client authentication but no
      //    suitable certificate is available, the client MUST send a Certificate
      //    message containing no certificates [...].
      m_transitions.set_expected_next(Handshake_Type::Certificate);
   } else {
      m_transitions.set_expected_next(Handshake_Type::Finished);
   }
}

void Server_Impl_13::handle_reply_to_client_hello(Hello_Retry_Request hello_retry_request) {
   auto cipher = Ciphersuite::by_id(hello_retry_request.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we chose that suite

   send_handshake_message(m_handshake_state.sending(std::move(hello_retry_request)));
   maybe_handle_compatibility_mode();

   m_transcript_hash = Transcript_Hash_State::recreate_after_hello_retry_request(cipher->prf_algo(), m_transcript_hash);

   m_transitions.set_expected_next(Handshake_Type::ClientHello);
}

void Server_Impl_13::handle(const Client_Hello_12& ch) {
   // The detailed handling of the TLS 1.2 compliant Client Hello is left to
   // the TLS 1.2 server implementation.
   BOTAN_UNUSED(ch);

   // After we sent a Hello Retry Request we must not accept a downgrade.
   if(m_handshake_state.has_hello_retry_request()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received a TLS 1.2 Client Hello after Hello Retry Request");
   }

   // RFC 8446 Appendix D.2
   //    If the "supported_versions" extension is absent and the server only
   //    supports versions greater than ClientHello.legacy_version, the server
   //    MUST abort the handshake with a "protocol_version" alert.
   //
   // If we're not expecting a downgrade, we only support TLS 1.3.
   if(!expects_downgrade()) {
      throw TLS_Exception(Alert::ProtocolVersion, "Received a legacy Client Hello");
   }

   downgrade();
}

void Server_Impl_13::handle(const Client_Hello_13& client_hello) {
   const auto& exts = client_hello.extensions();

   const bool is_initial_client_hello = !m_handshake_state.has_hello_retry_request();

   if(is_initial_client_hello) {
      const auto preferred_version = client_hello.highest_supported_version(policy());
      if(!preferred_version) {
         throw TLS_Exception(Alert::ProtocolVersion, "No shared TLS version");
      }

      // RFC 8446 4.2.2
      //   Clients MUST NOT use cookies in their initial ClientHello in subsequent
      //   connections.
      if(exts.has<Cookie>()) {
         throw TLS_Exception(Alert::IllegalParameter, "Received a Cookie in the initial client hello");
      }
   }

   // TODO: Implement support for PSK. For now, we ignore any such extensions
   //       and always revert to a standard key exchange.
   if(!exts.has<Supported_Groups>()) {
      throw Not_Implemented("PSK-only handshake NYI");
   }

   // RFC 8446 9.2
   //    If containing a "supported_groups" extension, [Client Hello] MUST
   //    also contain a "key_share" extension, and vice versa.
   //
   // This was validated before in the Client_Hello_13 constructor.
   BOTAN_ASSERT_NOMSG(exts.has<Key_Share>());

   if(!is_initial_client_hello) {
      const auto& hrr_exts = m_handshake_state.hello_retry_request().extensions();
      const auto offered_groups = exts.get<Key_Share>()->offered_groups();
      const auto selected_group = hrr_exts.get<Key_Share>()->selected_group();
      if(offered_groups.size() != 1 || offered_groups.at(0) != selected_group) {
         throw TLS_Exception(Alert::IllegalParameter, "Client did not comply with the requested key exchange group");
      }
   }

   callbacks().tls_examine_extensions(exts, Connection_Side::Client, client_hello.type());
   std::visit([this](auto msg) { handle_reply_to_client_hello(std::move(msg)); },
              Server_Hello_13::create(client_hello,
                                      is_initial_client_hello,
                                      session_manager(),
                                      credentials_manager(),
                                      rng(),
                                      policy(),
                                      callbacks()));
}

void Server_Impl_13::handle(const Certificate_13& certificate_msg) {
   // RFC 8446 4.3.2
   //    certificate_request_context:  [...] This field SHALL be zero length
   //    unless used for the post-handshake authentication exchanges [...].
   if(!is_handshake_complete() && !certificate_msg.request_context().empty()) {
      throw TLS_Exception(Alert::DecodeError, "Received a client certificate message with non-empty request context");
   }

   // RFC 8446 4.4.2
   //    Extensions in the Certificate message from the client MUST correspond
   //    to extensions in the CertificateRequest message from the server.
   certificate_msg.validate_extensions(m_handshake_state.certificate_request().extensions().extension_types(),
                                       callbacks());

   // RFC 8446 4.4.2.4
   //   If the client does not send any certificates (i.e., it sends an empty
   //   Certificate message), the server MAY at its discretion either continue
   //   the handshake without client authentication or abort the handshake with
   //   a "certificate_required" alert.
   if(certificate_msg.empty()) {
      if(policy().require_client_certificate_authentication()) {
         throw TLS_Exception(Alert::CertificateRequired, "Policy requires client send a certificate, but it did not");
      }

      // RFC 8446 4.4.2
      //    A Finished message MUST be sent regardless of whether the
      //    Certificate message is empty.
      m_transitions.set_expected_next(Handshake_Type::Finished);
   } else {
      // RFC 8446 4.4.2.4
      //    [...], if some aspect of the certificate chain was unacceptable
      //    (e.g., it was not signed by a known, trusted CA), the server MAY at
      //    its discretion either continue the handshake (considering the client
      //    unauthenticated) or abort the handshake.
      //
      // TODO: We could make this dependent on Policy::require_client_auth().
      //       Though, apps may also override Callbacks::tls_verify_cert_chain()
      //       and 'ignore' validation issues to a certain extent.
      certificate_msg.verify(callbacks(),
                             policy(),
                             credentials_manager(),
                             m_handshake_state.client_hello().sni_hostname(),
                             m_handshake_state.client_hello().extensions().has<Certificate_Status_Request>());

      // RFC 8446 4.4.3
      //    Clients MUST send this message whenever authenticating via a
      //    certificate (i.e., when the Certificate message
      //    is non-empty). When sent, this message MUST appear immediately after
      //    the Certificate message [...].
      m_transitions.set_expected_next(Handshake_Type::CertificateVerify);
   }
}

void Server_Impl_13::handle(const Certificate_Verify_13& certificate_verify_msg) {
   // RFC 8446 4.4.3
   //    If sent by a client, the signature algorithm used in the signature
   //    MUST be one of those present in the supported_signature_algorithms
   //    field of the "signature_algorithms" extension in the
   //    CertificateRequest message.
   const auto offered = m_handshake_state.certificate_request().signature_schemes();
   if(!value_exists(offered, certificate_verify_msg.signature_scheme())) {
      throw TLS_Exception(Alert::IllegalParameter,
                          "We did not offer the usage of " + certificate_verify_msg.signature_scheme().to_string() +
                             " as a signature scheme");
   }

   BOTAN_ASSERT_NOMSG(m_handshake_state.has_client_certificate_msg() &&
                      !m_handshake_state.client_certificate().empty());
   bool sig_valid = certificate_verify_msg.verify(
      *m_handshake_state.client_certificate().public_key(), callbacks(), m_transcript_hash.previous());

   // RFC 8446 4.4.3
   //   If the verification fails, the receiver MUST terminate the handshake
   //   with a "decrypt_error" alert.
   if(!sig_valid) {
      throw TLS_Exception(Alert::DecryptError, "Client certificate verification failed");
   }

   m_transitions.set_expected_next(Handshake_Type::Finished);
}

void Server_Impl_13::handle(const Finished_13& finished_msg) {
   // RFC 8446 4.4.4
   //    Recipients of Finished messages MUST verify that the contents are
   //    correct and if incorrect MUST terminate the connection with a
   //    "decrypt_error" alert.
   if(!finished_msg.verify(m_cipher_state.get(), m_transcript_hash.previous())) {
      throw TLS_Exception(Alert::DecryptError, "Finished message didn't verify");
   }

   // Give the application a chance for a final veto before fully
   // establishing the connection.
   callbacks().tls_session_established(
      Session_Summary(m_handshake_state.server_hello(),
                      Connection_Side::Server,
                      peer_cert_chain(),
                      peer_raw_public_key(),
                      m_psk_identity,
                      m_resumed_session.has_value(),
                      Server_Information(m_handshake_state.client_hello().sni_hostname()),
                      callbacks().tls_current_timestamp()));

   m_cipher_state->advance_with_client_finished(m_transcript_hash.current());

   // no more handshake messages expected
   m_transitions.set_expected_next({});

   callbacks().tls_session_activated();

   if(new_session_ticket_supported()) {
      send_new_session_tickets(policy().new_session_tickets_upon_handshake_success());
   }
}

}  // namespace Botan::TLS

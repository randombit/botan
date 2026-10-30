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
#include <botan/tls_callbacks.h>
#include <botan/tls_extensions_13.h>
#include <botan/tls_policy.h>
#include <botan/x509cert.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_channel_io.h>
#include <botan/internal/tls_cipher_state.h>

namespace Botan::TLS {

std::shared_ptr<Server_Impl_13> Server_Impl_13::create(const std::shared_ptr<Callbacks>& callbacks,
                                                       const std::shared_ptr<Session_Manager>& session_manager,
                                                       const std::shared_ptr<Credentials_Manager>& credentials_manager,
                                                       const std::shared_ptr<const Policy>& policy,
                                                       const std::shared_ptr<RandomNumberGenerator>& rng,
                                                       TLS_Flavor flavor) {
   auto self =
      std::make_shared<Server_Impl_13>(Private{}, callbacks, session_manager, credentials_manager, policy, rng, flavor);

#if defined(BOTAN_HAS_TLS_12)
   if((flavor == TLS_Flavor::TLS) ? policy->allow_tls12() : policy->allow_dtls12()) {
      self->expect_downgrade({}, {});
   }
#endif

   if(!self->expects_downgrade()) {
      // If we don't expect to downgrade, we can already enable all DTLS-only
      // features (e.g. record ACKing), because we know that we won't ever
      // talk to a legacy peer and succeed a handshake.
      self->m_channel_io->notify_protocol_version_committed();
   }

   self->m_handshake->transitions.set_expected_next(Handshake_Type::ClientHello);

   return self;
}

std::string Server_Impl_13::application_protocol() const {
   if(m_active_state.has_value()) {
      return m_active_state->application_protocol();
   }

   return "";
}

std::vector<X509_Certificate> Server_Impl_13::peer_cert_chain() const {
   if(m_active_state.has_value()) {
      return m_active_state->peer_certs();
   }

   if(m_handshake) {
      if(m_handshake->state.has_client_certificate_msg() &&
         m_handshake->state.client_certificate().has_certificate_chain()) {
         return m_handshake->state.client_certificate().cert_chain();
      }

      if(m_handshake->resumed_session.has_value()) {
         return m_handshake->resumed_session->peer_certs();
      }
   }

   return {};
}

std::shared_ptr<const Public_Key> Server_Impl_13::peer_raw_public_key() const {
   if(m_active_state.has_value()) {
      return m_active_state->peer_raw_public_key();
   }

   if(m_handshake) {
      if(m_handshake->state.has_client_certificate_msg() &&
         m_handshake->state.client_certificate().is_raw_public_key()) {
         return m_handshake->state.client_certificate().public_key();
      }

      if(m_handshake->resumed_session.has_value()) {
         return m_handshake->resumed_session->peer_raw_public_key();
      }
   }

   return nullptr;
}

std::optional<std::string> Server_Impl_13::external_psk_identity() const {
   if(m_active_state.has_value()) {
      return m_active_state->psk_identity();
   } else if(m_handshake) {
      return m_handshake->psk_identity;
   } else {
      return std::nullopt;
   }
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
   return is_handshake_complete() && m_active_state.has_value() && m_active_state->peer_supports_psk_dhe_ke();
}

size_t Server_Impl_13::send_new_session_tickets(const size_t tickets) {
   BOTAN_STATE_CHECK(is_handshake_complete());

   if(tickets == 0) {
      return 0;
   }

   if(!m_channel_io->can_send_post_handshake_messages()) {
      // In DTLS 1.3 KeyUpdate messages must be acknowledged by the peer. Before
      // that, we don't allow any other post-handshake messages to be sent for
      // compatibility with BoringSSL which enforces this restriction even
      // though the RFC does not require it explicitly.
      throw Invalid_State(
         "Cannot send NewSessionTicket messages right now. "
         "Probably you're using DTLS and a KeyUpdate is currently pending. "
         "Please try again later.");
   }

   auto flight = PostHandshakeFlight(callbacks());
   size_t tickets_created = 0;

   BOTAN_STATE_CHECK(m_active_state.has_value());
   auto* cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);

   for(size_t i = 0; i < tickets; ++i) {
      auto nonce = cs->next_ticket_nonce();
      const uint32_t ticket_age_add = load_be(rng().random_array<4>());
      const Session session(cs->psk(nonce),
                            std::nullopt,  // early data not yet implemented
                            ticket_age_add,
                            policy().session_ticket_lifetime(),
                            m_active_state->version(),
                            m_active_state->ciphersuite_code(),
                            Connection_Side::Server,
                            peer_cert_chain(),
                            peer_raw_public_key(),
                            Server_Information(m_active_state->sni_hostname()),
                            m_active_state->srtp_profile(),
                            callbacks().tls_current_timestamp());

      if(callbacks().tls_should_persist_resumption_information(session)) {
         if(auto handle = session_manager().establish(session)) {
            flight.add(New_Session_Ticket_13(std::move(nonce), session, handle.value(), callbacks()));
            ++tickets_created;
         }
      }
   }

   if(tickets_created > 0) {
      send_flight(flight.commit());
   }

   return tickets_created;
}

void Server_Impl_13::process_handshake_msg(Handshake_Message_13 message) {
   BOTAN_STATE_CHECK(m_handshake != nullptr);

   // first verify that the message was expected by the state machine
   // (and only then store it in the handshake state)
   m_handshake->transitions.confirm_transition_to(std::visit([](const auto& msg) { return msg.type(); }, message));

   std::visit(
      [&](auto msg) {
         // ... then allow the library user to abort on their discretion
         callbacks().tls_inspect_handshake_msg(msg.get());

         // ... finally handle the message
         handle(msg.get());
      },
      m_handshake->state.received(std::move(message)));
}

void Server_Impl_13::process_post_handshake_msg(Post_Handshake_Message_13 message) {
   BOTAN_STATE_CHECK(is_handshake_complete());

   const auto msg = specialize_to<Client_Post_Handshake_13_Message>(std::move(message));
   if(!msg) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received an unexpected post-handshake message");
   }

   std::visit([&](auto&& m) { handle(m); }, *msg);
}

void Server_Impl_13::process_dummy_change_cipher_spec() {
   // RFC 8446 5.
   //    If an implementation detects a change_cipher_spec record received before
   //    the first ClientHello message or after the peer's Finished message, it MUST be
   //    treated as an unexpected record type [("unexpected_message" alert)].
   if(!m_handshake || !m_handshake->state.has_client_hello() || m_handshake->state.has_client_finished()) {
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
   return m_active_state.has_value() || (m_handshake != nullptr && m_handshake->state.handshake_finished());
}

void Server_Impl_13::maybe_log_secret(std::string_view label, std::span<const uint8_t> secret) const {
   if(policy().allow_ssl_key_log_file()) {
      if(m_active_state.has_value()) {
         callbacks().tls_ssl_key_log_data(label, m_active_state->client_random(), secret);
      } else {
         callbacks().tls_ssl_key_log_data(label, m_handshake->state.client_hello().random(), secret);
      }
   }
}

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)

void Server_Impl_13::downgrade() {
   BOTAN_ASSERT_NOMSG(expects_downgrade());

   request_downgrade();

   // After this, no further messages are expected here because this instance
   // will be replaced by a Server_Impl_12.
   m_handshake->transitions.set_expected_next({});
}

#endif

bool Server_Impl_13::compat_mode_ccs_requested() const {
   // RFC 9147 Section 5
   //    DTLS implementations do not use the TLS 1.3 "compatibility mode" [...].
   if(is_datagram()) {
      return false;
   }

   // RFC 9846 E.4
   //    This "compatibility mode" is partially negotiated: the client can opt
   //    to provide a session ID or not, [...].
   //
   // I.e., before we received a ClientHello, we cannot know whether the client
   // requested middlebox compatibility mode or not.
   if(m_handshake == nullptr || !m_handshake->state.has_client_hello()) {
      return false;
   }

   // RFC 9846 E.4
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
   const bool client_requested_compatibility_mode = !m_handshake->state.client_hello().session_id().empty();

   return policy().tls_13_middlebox_compatibility_mode() || client_requested_compatibility_mode;
}

void Server_Impl_13::handle_reply_to_client_hello(Server_Hello_13 server_hello) {
   const auto& client_hello = m_handshake->state.client_hello();
   const auto& exts = client_hello.extensions();

   const bool uses_psk = server_hello.extensions().has<PSK>();

   const auto cipher_opt = Ciphersuite::by_id(server_hello.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher_opt.has_value());
   const auto& cipher = cipher_opt.value();
   BOTAN_ASSERT_NOMSG(m_transcript_hash.has_value());
   m_transcript_hash->set_algorithm(cipher.prf_algo());

   std::unique_ptr<Cipher_State> psk_cipher_state;
   if(uses_psk) {
      auto* psk_extension = server_hello.extensions().get<PSK>();

      psk_cipher_state = std::visit(
         overloaded{
            [&, this](Session session) {
               m_handshake->resumed_session = std::move(session);
               return Cipher_State::init_with_psk(Connection_Side::Server,
                                                  m_flavor,
                                                  Cipher_State::PSK_Type::Resumption,
                                                  m_handshake->resumed_session->extract_master_secret(),
                                                  cipher.prf_algo());
            },
            [&, this](ExternalPSK psk) {
               m_handshake->psk_identity = psk.identity();
               const auto psk_type =
                  psk.is_imported() ? Cipher_State::PSK_Type::Imported : Cipher_State::PSK_Type::External;
               return Cipher_State::init_with_psk(
                  Connection_Side::Server, m_flavor, psk_type, psk.extract_master_secret(), cipher.prf_algo());
            },
         },
         psk_extension->take_session_to_resume_or_psk());
      psk_cipher_state->set_secret_logger(secret_logger());

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
                                           psk_cipher_state->psk_binder_mac(m_transcript_hash->truncated()))) {
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
   auto flight = Flight(*m_transcript_hash, callbacks())  //
                    .add(m_handshake->state.sending(std::move(server_hello)));

   // RFC 9846 E.4
   //    The server sends a dummy change_cipher_spec record immediately after
   //    its first handshake message. This may either be after a ServerHello or
   //    a HelloRetryRequest.
   if(compat_mode_ccs_requested() && !m_handshake->state.has_hello_retry_request()) {
      flight.add_dummy_change_cipher_spec();
   }

   // Setup encryption for all the remaining handshake messages. Note that this
   // is not promoted to m_cipher_state yet, because the ServerHello is not yet
   // sent to the peer. The promotion happens only immediately before the
   // sending of the ServerHello, because then the existence of m_cipher_state
   // means that the peer can decrypt. (This is relevant if anything throws
   // before the ServerHello is sent and results in an alert. In that case, if
   // m_cipher_state were set, an encrypted alert would be sent without the peer
   // being able to decrypt it.)
   auto new_cipher_state = [&] {
      // Currently, PSK without DHE is not implemented...
      auto* const my_keyshare = m_handshake->state.server_hello().extensions().get<Key_Share>();
      BOTAN_ASSERT_NONNULL(my_keyshare);

      if(uses_psk) {
         BOTAN_ASSERT_NONNULL(psk_cipher_state);
         psk_cipher_state->advance_with_client_hello(m_transcript_hash->previous());
         psk_cipher_state->advance_with_server_hello(
            cipher, my_keyshare->take_shared_secret(), m_transcript_hash->current());

         return std::move(psk_cipher_state);
      } else {
         return Cipher_State::init_with_server_hello(
            m_side, m_flavor, my_keyshare->take_shared_secret(), cipher, m_transcript_hash->current(), secret_logger());
      }
   }();

   // Decide up front whether we will request client authentication so the
   // EncryptedExtensions can attach client_certificate_type when applicable
   // (RFC 7250 4.2 requires the two messages to agree).
   auto certificate_request =
      uses_psk ? std::nullopt
               : Certificate_Request_13::maybe_create(client_hello, credentials_manager(), callbacks(), policy());

   const bool is_resumption = m_handshake->resumed_session.has_value();
   const bool requesting_client_auth = certificate_request.has_value();

   flight.add(m_handshake->state.sending(
      Encrypted_Extensions(client_hello, policy(), callbacks(), is_resumption, requesting_client_auth, m_flavor)));

   if(!uses_psk) {
      // RFC 8446 4.3.2
      //    A server which is authenticating with a certificate MAY optionally
      //    request a certificate from the client. This message, if sent, MUST
      //    follow EncryptedExtensions.
      if(certificate_request.has_value()) {
         flight.add(m_handshake->state.sending(std::move(certificate_request.value())));
      }

      const auto& enc_exts = m_handshake->state.encrypted_extensions().extensions();

      // RFC 7250 4.2
      //   This client_certificate_type extension in the server hello then
      //   indicates the type of certificates the client is requested to provide
      //   in a subsequent certificate payload.
      //
      // Note: TLS 1.3 carries this extension in the Encrypted Extensions
      //       message instead of the Server Hello.
      if(const auto* client_cert_type = enc_exts.get<Client_Certificate_Type>()) {
         set_selected_certificate_type(client_cert_type->selected_certificate_type());
      }

      // RFC 8446 4.4.2
      //    If the corresponding certificate type extension [...]  was not
      //    negotiated in EncryptedExtensions, or the X.509 certificate type
      //    was negotiated, then each CertificateEntry contains a DER-encoded
      //    X.509 certificate.
      const auto cert_type = [&] {
         if(const auto* server_cert_type = enc_exts.get<Server_Certificate_Type>()) {
            return server_cert_type->selected_certificate_type();
         } else {
            return Certificate_Type::X509;
         }
      }();

      flight
         .add(m_handshake->state.sending(Certificate_13(client_hello, credentials_manager(), callbacks(), cert_type)))
         .add(m_handshake->state.sending(Certificate_Verify_13(m_handshake->state.server_certificate(),
                                                               client_hello.signature_schemes(),
                                                               client_hello.sni_hostname(),
                                                               m_transcript_hash->current(),
                                                               Connection_Side::Server,
                                                               credentials_manager(),
                                                               policy(),
                                                               callbacks(),
                                                               rng())));
   }

   flight.add(m_handshake->state.sending(Finished_13(*new_cipher_state, m_transcript_hash->current())));

   if(client_hello.extensions().has<Record_Size_Limit>() &&
      m_handshake->state.encrypted_extensions().extensions().has<Record_Size_Limit>()) {
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
      const auto* const outgoing_limit = client_hello.extensions().get<Record_Size_Limit>();
      const auto* const incoming_limit =
         m_handshake->state.encrypted_extensions().extensions().get<Record_Size_Limit>();
      set_record_size_limits(outgoing_limit->limit(), incoming_limit->limit());
   }

   // Promote cipher state immediately before sending the flight (see comment
   // at declaration of new_cipher_state).
   auto& cs = setup_cipher_state(std::move(new_cipher_state));
   send_flight(flight.commit());

   cs.advance_with_server_finished(m_transcript_hash->current());

   if(m_handshake->state.has_certificate_request()) {
      // RFC 8446 4.4.2
      //    The client MUST send a Certificate message if and only if the server
      //    has requested client authentication via a CertificateRequest message
      //    [...]. If the server requests client authentication but no
      //    suitable certificate is available, the client MUST send a Certificate
      //    message containing no certificates [...].
      m_handshake->transitions.set_expected_next(Handshake_Type::Certificate);
   } else {
      m_handshake->transitions.set_expected_next(Handshake_Type::Finished);
   }
}

void Server_Impl_13::handle_reply_to_client_hello(Hello_Retry_Request hello_retry_request) {
   BOTAN_ASSERT_NOMSG(m_transcript_hash.has_value());

   auto cipher = Ciphersuite::by_id(hello_retry_request.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we chose that suite

   auto flight = Flight(*m_transcript_hash, callbacks())  //
                    .add(m_handshake->state.sending(std::move(hello_retry_request)));

   // RFC 9846 E.4
   //    The server sends a dummy change_cipher_spec record immediately after
   //    its first handshake message. This may either be after a ServerHello or
   //    a HelloRetryRequest.
   if(compat_mode_ccs_requested()) {
      flight.add_dummy_change_cipher_spec();
   }

   send_flight(flight.commit());

   m_transcript_hash =
      Transcript_Hash_State::recreate_after_hello_retry_request(cipher->prf_algo(), *m_transcript_hash);

   m_handshake->transitions.set_expected_next(Handshake_Type::ClientHello);
}

void Server_Impl_13::handle(const Client_Hello_12_Shim& ch) {
   // The detailed handling of the TLS 1.2 compliant Client Hello is left to
   // the TLS 1.2 server implementation.
   BOTAN_UNUSED(ch);
   BOTAN_ASSERT_NONNULL(m_handshake);

   // After we sent a Hello Retry Request we must not accept a downgrade.
   if(m_handshake->state.has_hello_retry_request()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received a TLS 1.2 Client Hello after Hello Retry Request");
   }

#if !defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
   throw TLS_Exception(Alert::ProtocolVersion, "Received an unsupported Client Hello");
#else

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
#endif
}

void Server_Impl_13::handle(const Client_Hello_13& client_hello) {
   BOTAN_ASSERT_NONNULL(m_handshake);

   const auto& exts = client_hello.extensions();

   const bool is_initial_client_hello = !m_handshake->state.has_hello_retry_request();

   // We received a TLS 1.3 ClientHello. Now, we can be sure that our peer uses
   // TLS 1.3. Note that for DTLS, we don't have to explicitly clear our resend
   // buffer like on the client side, because the server never sends any flights
   // before commiting the protocol version anyway.
   m_channel_io->notify_protocol_version_committed();

   // By definition, SH is the "final" message of this flight.
   m_channel_io->notify_received_complete_flight();

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
      // RFC 9846 4.2.2
      //    The client will also send a ClientHello when the server has
      //    responded to its ClientHello with a HelloRetryRequest. In that case,
      //    the client MUST send the same ClientHello without modification,
      //    except as follows: ...
      const auto& hrr_exts = m_handshake->state.hello_retry_request().extensions();
      const auto offered_groups = exts.get<Key_Share>()->offered_groups();
      const auto* hrr_key_share = hrr_exts.get<Key_Share>();

      // RFC 9846 4.2.2
      //    ... If a "key_share" extension was supplied in the HelloRetryRequest,
      //    replacing the list of shares with a list containing a single
      //    KeyShareEntry from the indicated group.
      if(hrr_key_share != nullptr) {
         const auto selected_group = hrr_key_share->selected_group();
         if(offered_groups.size() != 1 || offered_groups.at(0) != selected_group) {
            throw TLS_Exception(Alert::IllegalParameter, "Client did not comply with the requested key exchange group");
         }
      }

      const auto* ch_cookie = exts.get<Cookie>();
      const auto* hrr_cookie = hrr_exts.get<Cookie>();

      // RFC 9846 4.2.2
      //    ... Including a "cookie" extension if one was provided in the
      //    HelloRetryRequest.
      if(hrr_cookie == nullptr && ch_cookie != nullptr) {
         throw TLS_Exception(Alert::IllegalParameter,
                             "Received a Cookie in a second ClientHello, but we did not send one in HelloRetryRequest");
      }

      // RFC 9846 4.3.2
      //    When sending the new ClientHello, the client MUST copy the contents
      //    of the extension received in the HelloRetryRequest into a "cookie"
      //    extension in the new ClientHello.
      if(hrr_cookie != nullptr) {
         if(ch_cookie == nullptr) {
            throw TLS_Exception(Alert::IllegalParameter,
                                "Received a second ClientHello without a Cookie, but we sent one in HelloRetryRequest");
         }

         if(!CT::is_equal<uint8_t>(hrr_cookie->get_cookie(), ch_cookie->get_cookie()).as_bool()) {
            throw TLS_Exception(Alert::IllegalParameter,
                                "The second ClientHello did not contain the matching cookie from HelloRetryRequest");
         }
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
                                      callbacks(),
                                      m_flavor));
}

void Server_Impl_13::handle(const Certificate_13& certificate_msg) {
   BOTAN_ASSERT_NONNULL(m_handshake);

   // RFC 8446 4.3.2
   //    certificate_request_context:  [...] This field SHALL be zero length
   //    unless used for the post-handshake authentication exchanges [...].
   if(!is_handshake_complete() && !certificate_msg.request_context().empty()) {
      throw TLS_Exception(Alert::DecodeError, "Received a client certificate message with non-empty request context");
   }

   // RFC 8446 4.4.2
   //    Extensions in the Certificate message from the client MUST correspond
   //    to extensions in the CertificateRequest message from the server.
   certificate_msg.validate_extensions(m_handshake->state.certificate_request().extensions().extension_types(),
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
      m_handshake->transitions.set_expected_next(Handshake_Type::Finished);
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

      const bool use_ocsp = m_handshake->state.certificate_request().extensions().has<Certificate_Status_Request>();
      certificate_msg.verify(
         callbacks(), policy(), credentials_manager(), m_handshake->state.client_hello().sni_hostname(), use_ocsp);

      // RFC 8446 4.4.3
      //    Clients MUST send this message whenever authenticating via a
      //    certificate (i.e., when the Certificate message
      //    is non-empty). When sent, this message MUST appear immediately after
      //    the Certificate message [...].
      m_handshake->transitions.set_expected_next(Handshake_Type::CertificateVerify);
   }
}

void Server_Impl_13::handle(const Certificate_Verify_13& certificate_verify_msg) {
   BOTAN_ASSERT_NONNULL(m_handshake);
   BOTAN_ASSERT_NOMSG(m_transcript_hash.has_value());

   // RFC 8446 4.4.3
   //    If sent by a client, the signature algorithm used in the signature
   //    MUST be one of those present in the supported_signature_algorithms
   //    field of the "signature_algorithms" extension in the
   //    CertificateRequest message.
   const auto offered = m_handshake->state.certificate_request().signature_schemes();
   if(!value_exists(offered, certificate_verify_msg.signature_scheme())) {
      throw TLS_Exception(Alert::IllegalParameter,
                          "We did not offer the usage of " + certificate_verify_msg.signature_scheme().to_string() +
                             " as a signature scheme");
   }

   BOTAN_ASSERT_NOMSG(m_handshake->state.has_client_certificate_msg() &&
                      !m_handshake->state.client_certificate().empty());
   const bool sig_valid = certificate_verify_msg.verify(
      *m_handshake->state.client_certificate().public_key(), callbacks(), m_transcript_hash->previous());

   // RFC 8446 4.4.3
   //   If the verification fails, the receiver MUST terminate the handshake
   //   with a "decrypt_error" alert.
   if(!sig_valid) {
      throw TLS_Exception(Alert::DecryptError, "Client certificate verification failed");
   }

   m_handshake->transitions.set_expected_next(Handshake_Type::Finished);
}

void Server_Impl_13::handle(const Finished_13& finished_msg) {
   BOTAN_ASSERT_NONNULL(m_handshake);
   BOTAN_ASSERT_NOMSG(m_transcript_hash.has_value());

   auto* cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);

   // RFC 8446 4.4.4
   //    Recipients of Finished messages MUST verify that the contents are
   //    correct and if incorrect MUST terminate the connection with a
   //    "decrypt_error" alert.
   if(!finished_msg.verify(*cs, m_transcript_hash->previous())) {
      throw TLS_Exception(Alert::DecryptError, "Finished message didn't verify");
   }

   m_handshake->state.confirm_peer_finished_verified();

   // Give the application a chance for a final veto before fully
   // establishing the connection.
   callbacks().tls_session_established(
      Session_Summary(m_handshake->state.server_hello(),
                      Connection_Side::Server,
                      peer_cert_chain(),
                      peer_raw_public_key(),
                      m_handshake->psk_identity,
                      m_handshake->resumed_session.has_value(),
                      Server_Information(m_handshake->state.client_hello().sni_hostname()),
                      callbacks().tls_current_timestamp()));

   cs->advance_with_client_finished(m_transcript_hash->current());

   m_channel_io->notify_received_final_flight();

   // no more handshake messages expected
   m_handshake->transitions.set_expected_next({});

   // Extract post-handshake state before signaling activation.
   {
      const auto extract_certs = [&]() -> std::vector<X509_Certificate> {
         if(m_handshake->state.has_client_certificate_msg() &&
            m_handshake->state.client_certificate().has_certificate_chain()) {
            return m_handshake->state.client_certificate().cert_chain();
         }
         if(m_handshake->resumed_session.has_value()) {
            return m_handshake->resumed_session->peer_certs();
         }
         return {};
      };

      const auto extract_raw_pk = [&]() -> std::shared_ptr<const Public_Key> {
         if(m_handshake->state.has_client_certificate_msg() &&
            m_handshake->state.client_certificate().is_raw_public_key()) {
            return m_handshake->state.client_certificate().public_key();
         }
         if(m_handshake->resumed_session.has_value()) {
            return m_handshake->resumed_session->peer_raw_public_key();
         }
         return nullptr;
      };

      const bool supports_psk_dhe =
         m_handshake->state.client_hello().extensions().has<PSK_Key_Exchange_Modes>() &&
         value_exists(m_handshake->state.client_hello().extensions().get<PSK_Key_Exchange_Modes>()->modes(),
                      PSK_Key_Exchange_Mode::PSK_DHE_KE);

      m_active_state = Active_Connection_State_13(m_handshake->state,
                                                  extract_certs(),
                                                  extract_raw_pk(),
                                                  m_handshake->psk_identity,
                                                  m_handshake->state.client_hello().sni_hostname(),
                                                  supports_psk_dhe);
   }

   m_handshake.reset();
   m_transcript_hash.reset();
   callbacks().tls_session_activated();

   const auto session_tickets_after_handshake = policy().new_session_tickets_upon_handshake_success();
   if(new_session_ticket_supported() && session_tickets_after_handshake > 0) {
      BOTAN_ASSERT_NOMSG(m_channel_io->can_send_post_handshake_messages());
      send_new_session_tickets(session_tickets_after_handshake);
   }
}

}  // namespace Botan::TLS

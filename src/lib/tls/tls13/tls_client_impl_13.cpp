/*
* TLS Client - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/internal/tls_client_impl_13.h>

#include <botan/credentials_manager.h>
#include <botan/hash.h>
#include <botan/tls_client.h>
#include <botan/tls_messages.h>
#include <botan/types.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_cipher_state.h>

#include <iterator>
#include <utility>

namespace Botan::TLS {

Client_Impl_13::Client_Impl_13(const std::shared_ptr<Callbacks>& callbacks,
                               const std::shared_ptr<Session_Manager>& session_manager,
                               const std::shared_ptr<Credentials_Manager>& creds,
                               const std::shared_ptr<const Policy>& policy,
                               const std::shared_ptr<RandomNumberGenerator>& rng,
                               Server_Information info,
                               const std::vector<std::string>& next_protocols) :
      Channel_Impl_13(callbacks, session_manager, creds, rng, policy, false /* is_server */),
      m_info(std::move(info)),
      m_should_send_ccs(false) {
#if defined(BOTAN_HAS_TLS_12)
   if(policy->allow_tls12()) {
      expect_downgrade(m_info, next_protocols);
   }
#endif

   if(auto session = find_session_for_resumption()) {
      if(!session->session.version().is_pre_tls_13()) {
         m_resumed_session = std::move(session);
      } else if(expects_downgrade()) {
         // If we found a session that was created with TLS 1.2, we downgrade
         // the implementation right away, before even issuing a Client Hello.
         request_downgrade_for_resumption(std::move(session.value()));
         return;
      }
   }

   auto msg = send_handshake_message(m_handshake_state.sending(
      Client_Hello_13(*policy,
                      *callbacks,
                      *rng,
                      m_info.hostname(),
                      next_protocols,
                      m_resumed_session,
                      creds->find_preshared_keys(m_info.hostname(), Connection_Side::Client))));

   if(expects_downgrade()) {
      preserve_client_hello(msg);
   }

   // RFC 8446 Appendix D.4
   //    If not offering early data, the client sends a dummy change_cipher_spec
   //    record [...] immediately before its second flight. This may either be before
   //    its second ClientHello or before its encrypted handshake flight.
   //
   // TODO: don't schedule ccs here when early data is used
   if(policy->tls_13_middlebox_compatibility_mode()) {
      m_should_send_ccs = true;
   }

   m_transitions.set_expected_next({Handshake_Type::ServerHello, Handshake_Type::HelloRetryRequest});
}

void Client_Impl_13::process_handshake_msg(Handshake_Message_13 message) {
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

void Client_Impl_13::process_post_handshake_msg(Post_Handshake_Message_13 message) {
   BOTAN_STATE_CHECK(is_handshake_complete());

   std::visit([&](auto msg) { handle(msg); }, m_handshake_state.received(std::move(message)));
}

void Client_Impl_13::process_dummy_change_cipher_spec() {
   // RFC 8446 5.
   //    If an implementation detects a change_cipher_spec record received before
   //    the first ClientHello message or after the peer's Finished message, it MUST be
   //    treated as an unexpected record type [("unexpected_message" alert)].
   if(!m_handshake_state.has_client_hello() || m_handshake_state.has_server_finished()) {
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

bool Client_Impl_13::is_handshake_complete() const {
   return m_handshake_state.handshake_finished();
}

std::optional<Session_with_Handle> Client_Impl_13::find_session_for_resumption() {
   // RFC 8446 4.6.1
   //    Clients MUST only resume if the new SNI value is valid for the
   //    server certificate presented in the original session and SHOULD only
   //    resume if the SNI value matches the one used in the original session.
   //
   // Below we search sessions based on their SNI value. Assuming that a
   // 3rd party session manager does not lie to the implementation, we don't
   // explicitly re-check that the SNI values match.
   //
   // Also, the default implementation did verify that very same SNI information
   // against the server's certificate (via Callbacks::tls_verify_cert_chain())
   // before storing it in the session.
   //
   // We therefore assume that the session returned by the `Session_Manager` is
   // suitable for resumption in this context.
   auto sessions = session_manager().find(m_info, callbacks(), policy());
   if(sessions.empty()) {
      return std::nullopt;
   }

   // TODO: TLS 1.3 allows sending more than one ticket (for resumption) in a
   //       Client Hello. Currently, we do not support that. The Session_Manager
   //       does imply otherwise with its API, though.
   auto& session_to_resume = sessions.front();

   return std::move(session_to_resume);
}

void Client_Impl_13::handle(const Server_Hello_12& server_hello_msg) {
   if(m_handshake_state.has_hello_retry_request()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Version downgrade received after Hello Retry");
   }

   // RFC 8446 Appendix D.1
   //    If the version chosen by the server is not supported by the client
   //    (or is not acceptable), the client MUST abort the handshake with a
   //    "protocol_version" alert.
   if(!expects_downgrade()) {
      throw TLS_Exception(Alert::ProtocolVersion, "Received an unexpected legacy Server Hello");
   }

   // RFC 8446 4.1.3
   //    TLS 1.3 has a downgrade protection mechanism embedded in the server's
   //    random value.  TLS 1.3 servers which negotiate TLS 1.2 or below in
   //    response to a ClientHello MUST set the last 8 bytes of their Random
   //    value specially in their ServerHello.
   //
   //    TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
   //    MUST check that the [downgrade indication is not set]. [...] If a match
   //    is found, the client MUST abort the handshake with an
   //    "illegal_parameter" alert.
   if(server_hello_msg.random_signals_downgrade().has_value()) {
      throw TLS_Exception(Alert::IllegalParameter, "Downgrade attack detected");
   }

   // RFC 8446 4.2.1
   //    A server which negotiates a version of TLS prior to TLS 1.3 [...]
   //    MUST NOT send the "supported_versions" extension.
   //
   // Note that this condition should never happen, as the Server_Hello parsing
   // code decides to create a Server_Hello_12 based on the absense of this extension.
   if(server_hello_msg.extensions().has<Supported_Versions>()) {
      throw TLS_Exception(Alert::IllegalParameter, "Unexpected extension received");
   }

   // RFC 8446 Appendix D.1
   //    If the version chosen by the server is not supported by the client
   //    (or is not acceptable), the client MUST abort the handshake with a
   //    "protocol_version" alert.
   const auto& client_hello_exts = m_handshake_state.client_hello().extensions();
   BOTAN_ASSERT_NOMSG(client_hello_exts.has<Supported_Versions>());
   if(!client_hello_exts.get<Supported_Versions>()->supports(server_hello_msg.selected_version())) {
      throw TLS_Exception(Alert::ProtocolVersion, "Protocol version was not offered");
   }

   if(policy().tls_13_middlebox_compatibility_mode() &&
      m_handshake_state.client_hello().session_id() == server_hello_msg.session_id()) {
      // In compatibility mode, the server will reflect the session ID we sent in the client hello.
      // However, a TLS 1.2 server that wants to downgrade cannot have found the random session ID
      // we sent. Therefore, we have to consider this as an attack.
      // (Thanks BoGo test EchoTLS13CompatibilitySessionID!)
      throw TLS_Exception(Alert::IllegalParameter, "Unexpected session ID during downgrade");
   }

   request_downgrade();

   // After this, no further messages are expected here because this instance will be replaced
   // by a Client_Impl_12.
   m_transitions.set_expected_next({});
}

namespace {
// validate Server_Hello_13 and Hello_Retry_Request
void validate_server_hello_ish(const Client_Hello_13& ch, const Server_Hello_13& sh) {
   // RFC 8446 4.1.3
   //    A client which receives a legacy_session_id_echo field that does not match what
   //    it sent in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
   if(ch.session_id() != sh.session_id()) {
      throw TLS_Exception(Alert::IllegalParameter, "echoed session id did not match");
   }

   // RFC 8446 4.1.3
   //    A client which receives a cipher suite that was not offered MUST abort the handshake
   //    with an "illegal_parameter" alert.
   if(!ch.offered_suite(sh.ciphersuite())) {
      throw TLS_Exception(Alert::IllegalParameter, "Server replied with ciphersuite we didn't send");
   }

   // RFC 8446 4.2.1
   //    If the "supported_versions" extension in the ServerHello contains a
   //    version not offered by the client or contains a version prior to
   //    TLS 1.3, the client MUST abort the handshake with an "illegal_parameter" alert.
   //
   // Note: Server_Hello_13 parsing checks that its selected version is TLS 1.3
   BOTAN_ASSERT_NOMSG(ch.extensions().has<Supported_Versions>());
   if(!ch.extensions().get<Supported_Versions>()->supports(sh.selected_version())) {
      throw TLS_Exception(Alert::IllegalParameter, "Protocol version was not offered");
   }
}
}  // namespace

void Client_Impl_13::handle(const Server_Hello_13& sh) {
   // Note: Basic checks (that do not require contextual information) were already
   //       performed during the construction of the Server_Hello_13 object.

   const auto& ch = m_handshake_state.client_hello();

   validate_server_hello_ish(ch, sh);

   // RFC 8446 4.2
   //    Implementations MUST NOT send extension responses if the remote
   //    endpoint did not send the corresponding extension requests, [...]. Upon
   //    receiving such an extension, an endpoint MUST abort the handshake
   //    with an "unsupported_extension" alert.
   if(sh.extensions().contains_other_than(ch.extensions().extension_types())) {
      throw TLS_Exception(Alert::UnsupportedExtension, "Unsupported extension found in Server Hello");
   }

   if(m_handshake_state.has_hello_retry_request()) {
      const auto& hrr = m_handshake_state.hello_retry_request();

      // RFC 8446 4.1.4
      //    Upon receiving the ServerHello, clients MUST check that the cipher suite
      //    supplied in the ServerHello is the same as that in the HelloRetryRequest
      //    and otherwise abort the handshake with an "illegal_parameter" alert.
      if(hrr.ciphersuite() != sh.ciphersuite()) {
         throw TLS_Exception(Alert::IllegalParameter, "server changed its chosen ciphersuite");
      }

      // RFC 8446 4.1.4
      //    The value of selected_version in the HelloRetryRequest "supported_versions"
      //    extension MUST be retained in the ServerHello, and a client MUST abort the
      //    handshake with an "illegal_parameter" alert if the value changes.
      if(hrr.selected_version() != sh.selected_version()) {
         throw TLS_Exception(Alert::IllegalParameter, "server changed its chosen protocol version");
      }
   }

   auto cipher = Ciphersuite::by_id(sh.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we offered this suite

   // RFC 8446 Appendix B.4
   //    Although TLS 1.3 uses the same cipher suite space as previous versions
   //    of TLS [...] cipher suites for TLS 1.2 and lower cannot be used with
   //    TLS 1.3.
   if(!cipher->usable_in_version(Protocol_Version::TLS_V13)) {
      throw TLS_Exception(Alert::IllegalParameter,
                          "Server replied using a ciphersuite not allowed in version it offered");
   }

   // RFC 8446 4.2.11
   //    Clients MUST verify that [...] a server "key_share" extension is present
   //    if required by the ClientHello "psk_key_exchange_modes" extension.  If
   //    these values are not consistent, the client MUST abort the handshake
   //    with an "illegal_parameter" alert.
   //
   // Currently, we don't support PSK-only mode, hence a key share extension is
   // considered mandatory.
   //
   // TODO: Implement PSK-only mode.
   if(!sh.extensions().has<Key_Share>()) {
      throw TLS_Exception(Alert::IllegalParameter, "Server Hello did not contain a key share extension");
   }

   auto my_keyshare = ch.extensions().get<Key_Share>();
   auto shared_secret = my_keyshare->decapsulate(*sh.extensions().get<Key_Share>(), policy(), callbacks(), rng());

   m_transcript_hash.set_algorithm(cipher.value().prf_algo());

   if(sh.extensions().has<PSK>()) {
      std::tie(m_psk_identity, m_cipher_state) =
         ch.extensions().get<PSK>()->take_selected_psk_info(*sh.extensions().get<PSK>(), cipher.value());

      // If we offered a session for resumption *and* an externally provided PSK
      // and the latter was chosen by the server over the offered resumption, we
      // want to invalidate the now-outdated session in m_resumed_session.
      if(m_psk_identity.has_value() && m_resumed_session.has_value()) {
         m_resumed_session.reset();
      }

      // TODO: When implementing early data, `advance_with_client_hello` must
      //       happen _before_ encrypting any early application data.
      //       Same when we want to support early key export.
      m_cipher_state->advance_with_client_hello(m_transcript_hash.previous(), *this);
      m_cipher_state->advance_with_server_hello(
         cipher.value(), std::move(shared_secret), m_transcript_hash.current(), *this);
   } else {
      m_resumed_session.reset();  // might have been set if we attempted a resumption
      m_cipher_state = Cipher_State::init_with_server_hello(
         m_side, std::move(shared_secret), cipher.value(), m_transcript_hash.current(), *this);
   }

   callbacks().tls_examine_extensions(sh.extensions(), Connection_Side::Server, Handshake_Type::ServerHello);

   m_transitions.set_expected_next(Handshake_Type::EncryptedExtensions);
}

void Client_Impl_13::handle(const Hello_Retry_Request& hrr) {
   // Note: Basic checks (that do not require contextual information) were already
   //       performed during the construction of the Hello_Retry_Request object as
   //       a subclass of Server_Hello_13.

   auto& ch = m_handshake_state.client_hello();

   validate_server_hello_ish(ch, hrr);

   // RFC 8446 4.1.4.
   //    A HelloRetryRequest MUST NOT contain any
   //    extensions that were not first offered by the client in its
   //    ClientHello, with the exception of optionally the "cookie".
   auto allowed_exts = ch.extensions().extension_types();
   allowed_exts.insert(Extension_Code::Cookie);
   if(hrr.extensions().contains_other_than(allowed_exts)) {
      throw TLS_Exception(Alert::UnsupportedExtension, "Unsupported extension found in Hello Retry Request");
   }

   auto cipher = Ciphersuite::by_id(hrr.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we offered this suite

   m_transcript_hash =
      Transcript_Hash_State::recreate_after_hello_retry_request(cipher.value().prf_algo(), m_transcript_hash);

   ch.retry(hrr, m_transcript_hash, callbacks(), rng());

   callbacks().tls_examine_extensions(hrr.extensions(), Connection_Side::Server, Handshake_Type::HelloRetryRequest);

   send_handshake_message(std::reference_wrapper(ch));

   // RFC 8446 4.1.4
   //    If a client receives a second HelloRetryRequest in the same connection [...],
   //    it MUST abort the handshake with an "unexpected_message" alert.
   m_transitions.set_expected_next(Handshake_Type::ServerHello);
}

void Client_Impl_13::handle(const Encrypted_Extensions& encrypted_extensions_msg) {
   const auto& exts = encrypted_extensions_msg.extensions();

   // RFC 8446 4.2
   //    Implementations MUST NOT send extension responses if the remote
   //    endpoint did not send the corresponding extension requests, [...]. Upon
   //    receiving such an extension, an endpoint MUST abort the handshake
   //    with an "unsupported_extension" alert.
   const auto& requested_exts = m_handshake_state.client_hello().extensions().extension_types();
   if(exts.contains_other_than(requested_exts)) {
      throw TLS_Exception(Alert::UnsupportedExtension,
                          "Encrypted Extensions contained an extension that was not offered");
   }

   // Note: As per RFC 6066 3. we can check for an empty SNI extensions to
   // determine if the server used the SNI we sent here.

   if(exts.has<Record_Size_Limit>() && m_handshake_state.client_hello().extensions().has<Record_Size_Limit>()) {
      // RFC 8449 4.
      //     The record size limit only applies to records sent toward the
      //     endpoint that advertises the limit.  An endpoint can send records
      //     that are larger than the limit it advertises as its own limit.
      //
      // Hence, the "outgoing" limit is what the server requested and the
      // "incoming" limit is what we requested in the Client Hello.
      const auto outgoing_limit = exts.get<Record_Size_Limit>();
      const auto incoming_limit = m_handshake_state.client_hello().extensions().get<Record_Size_Limit>();
      set_record_size_limits(outgoing_limit->limit(), incoming_limit->limit());
   }

   if(exts.has<Server_Certificate_Type>() &&
      m_handshake_state.client_hello().extensions().has<Server_Certificate_Type>()) {
      const auto* server_cert_type = exts.get<Server_Certificate_Type>();
      const auto* our_server_cert_types = m_handshake_state.client_hello().extensions().get<Server_Certificate_Type>();
      our_server_cert_types->validate_selection(*server_cert_type);

      // RFC 7250 4.2
      //    With the server_certificate_type extension in the server hello, the
      //    TLS server indicates the certificate type carried in the Certificate
      //    payload.
      //
      // Note: TLS 1.3 carries this extension in the Encrypted Extensions
      //       message instead of the Server Hello.
      set_selected_certificate_type(server_cert_type->selected_certificate_type());
   }

   callbacks().tls_examine_extensions(exts, Connection_Side::Server, Handshake_Type::EncryptedExtensions);

   if(m_handshake_state.server_hello().extensions().has<PSK>()) {
      // RFC 8446 2.2
      //    As the server is authenticating via a PSK, it does not send a
      //    Certificate or a CertificateVerify message.
      m_transitions.set_expected_next(Handshake_Type::Finished);
   } else {
      m_transitions.set_expected_next({Handshake_Type::Certificate, Handshake_Type::CertificateRequest});
   }
}

void Client_Impl_13::handle(const Certificate_Request_13& certificate_request_msg) {
   // RFC 8446 4.3.2
   //    [The 'context' field] SHALL be zero length unless used for the
   //    post-handshake authentication exchanges described in Section 4.6.2.
   if(!is_handshake_complete() && !certificate_request_msg.context().empty()) {
      throw TLS_Exception(Alert::DecodeError, "Certificate_Request context must be empty in the main handshake");
   }

   callbacks().tls_examine_extensions(
      certificate_request_msg.extensions(), Connection_Side::Server, Handshake_Type::CertificateRequest);
   m_transitions.set_expected_next(Handshake_Type::Certificate);
}

void Client_Impl_13::handle(const Certificate_13& certificate_msg) {
   // RFC 8446 4.4.2
   //    certificate_request_context:  [...] In the case of server authentication,
   //    this field SHALL be zero length.
   if(!certificate_msg.request_context().empty()) {
      throw TLS_Exception(Alert::DecodeError, "Received a server certificate message with non-empty request context");
   }

   // RFC 8446 4.4.2
   //    Extensions in the Certificate message from the server MUST correspond
   //    to ones from the ClientHello message.
   certificate_msg.validate_extensions(m_handshake_state.client_hello().extensions().extension_types(), callbacks());
   certificate_msg.verify(callbacks(),
                          policy(),
                          credentials_manager(),
                          m_info.hostname(),
                          m_handshake_state.client_hello().extensions().has<Certificate_Status_Request>());

   m_transitions.set_expected_next(Handshake_Type::CertificateVerify);
}

void Client_Impl_13::handle(const Certificate_Verify_13& certificate_verify_msg) {
   // RFC 8446 4.4.3
   //    If the CertificateVerify message is sent by a server, the signature
   //    algorithm MUST be one offered in the client's "signature_algorithms"
   //    extension unless no valid certificate chain can be produced without
   //    unsupported algorithms.
   //
   // Note: if the server failed to produce a certificate chain without using
   //       an unsupported signature scheme, we opt to abort the handshake.
   const auto offered = m_handshake_state.client_hello().signature_schemes();
   if(!value_exists(offered, certificate_verify_msg.signature_scheme())) {
      throw TLS_Exception(Alert::IllegalParameter,
                          "We did not offer the usage of " + certificate_verify_msg.signature_scheme().to_string() +
                             " as a signature scheme");
   }

   bool sig_valid = certificate_verify_msg.verify(
      *m_handshake_state.server_certificate().public_key(), callbacks(), m_transcript_hash.previous());

   if(!sig_valid) {
      throw TLS_Exception(Alert::DecryptError, "Server certificate verification failed");
   }

   m_transitions.set_expected_next(Handshake_Type::Finished);
}

void Client_Impl_13::send_client_authentication(Channel_Impl_13::AggregatedHandshakeMessages& flight) {
   BOTAN_ASSERT_NOMSG(m_handshake_state.has_certificate_request());
   const auto& cert_request = m_handshake_state.certificate_request();

   const auto cert_type = [&] {
      const auto& exts = m_handshake_state.encrypted_extensions().extensions();
      const auto& chexts = m_handshake_state.client_hello().extensions();
      if(exts.has<Client_Certificate_Type>() && chexts.has<Client_Certificate_Type>()) {
         const auto* client_cert_type = exts.get<Client_Certificate_Type>();
         chexts.get<Client_Certificate_Type>()->validate_selection(*client_cert_type);

         // RFC 7250 4.2
         //   This client_certificate_type extension in the server hello then
         //   indicates the type of certificates the client is requested to
         //   provide in a subsequent certificate payload.
         //
         // Note: TLS 1.3 carries this extension in the Encrypted Extensions
         //       message instead of the Server Hello.
         return client_cert_type->selected_certificate_type();
      } else {
         // RFC 8446 4.4.2
         //    If the corresponding certificate type extension [...] was not
         //    negotiated in EncryptedExtensions, [...] then each
         //    CertificateEntry contains a DER-encoded X.509 certificate.
         return Certificate_Type::X509;
      }
   }();

   // RFC 8446 4.4.2
   //    certificate_request_context:  If this message is in response to a
   //       CertificateRequest, the value of certificate_request_context in
   //       that message.
   flight.add(m_handshake_state.sending(
      Certificate_13(cert_request, m_info.hostname(), credentials_manager(), callbacks(), cert_type)));

   // RFC 8446 4.4.2
   //    If the server requests client authentication but no suitable certificate
   //    is available, the client MUST send a Certificate message containing no
   //    certificates.
   //
   // In that case, no Certificate Verify message will be sent.
   if(!m_handshake_state.client_certificate().empty()) {
      flight.add(m_handshake_state.sending(Certificate_Verify_13(m_handshake_state.client_certificate(),
                                                                 cert_request.signature_schemes(),
                                                                 m_info.hostname(),
                                                                 m_transcript_hash.current(),
                                                                 Connection_Side::Client,
                                                                 credentials_manager(),
                                                                 policy(),
                                                                 callbacks(),
                                                                 rng())));
   }
}

void Client_Impl_13::handle(const Finished_13& finished_msg) {
   // RFC 8446 4.4.4
   //    Recipients of Finished messages MUST verify that the contents are
   //    correct and if incorrect MUST terminate the connection with a
   //    "decrypt_error" alert.
   if(!finished_msg.verify(m_cipher_state.get(), m_transcript_hash.previous())) {
      throw TLS_Exception(Alert::DecryptError, "Finished message didn't verify");
   }

   // Give the application a chance for a final veto before fully
   // establishing the connection.
   callbacks().tls_session_established(Session_Summary(m_handshake_state.server_hello(),
                                                       Connection_Side::Server,
                                                       peer_cert_chain(),
                                                       peer_raw_public_key(),
                                                       external_psk_identity(),
                                                       m_resumed_session.has_value(),
                                                       m_info,
                                                       callbacks().tls_current_timestamp()));

   // Derives the secrets for receiving application data but defers
   // the derivation of sending application data.
   m_cipher_state->advance_with_server_finished(m_transcript_hash.current(), *this);

   auto flight = aggregate_handshake_messages();

   // RFC 8446 4.4.2
   //    The client MUST send a Certificate message if and only if the server
   //    has requested client authentication via a CertificateRequest message.
   if(m_handshake_state.has_certificate_request()) {
      send_client_authentication(flight);
   }

   // send client finished handshake message (still using handshake traffic secrets)
   flight.add(m_handshake_state.sending(Finished_13(m_cipher_state.get(), m_transcript_hash.current())));

   flight.send();

   // derives the sending application traffic secrets
   m_cipher_state->advance_with_client_finished(m_transcript_hash.current());

   // TODO: Create a dummy session object and invoke tls_session_established.
   //       Alternatively, consider changing the expectations described in the
   //       callback's doc string.

   // no more handshake messages expected
   m_transitions.set_expected_next({});

   callbacks().tls_session_activated();
}

void TLS::Client_Impl_13::handle(const New_Session_Ticket_13& new_session_ticket) {
   callbacks().tls_examine_extensions(
      new_session_ticket.extensions(), Connection_Side::Server, Handshake_Type::NewSessionTicket);

   Session session(m_cipher_state->psk(new_session_ticket.nonce()),
                   new_session_ticket.early_data_byte_limit(),
                   new_session_ticket.ticket_age_add(),
                   new_session_ticket.lifetime_hint(),
                   m_handshake_state.server_hello().selected_version(),
                   m_handshake_state.server_hello().ciphersuite(),
                   Connection_Side::Client,
                   peer_cert_chain(),
                   peer_raw_public_key(),
                   m_info,
                   callbacks().tls_current_timestamp());

   if(callbacks().tls_should_persist_resumption_information(session)) {
      session_manager().store(session, new_session_ticket.handle());
   }
}

std::vector<X509_Certificate> Client_Impl_13::peer_cert_chain() const {
   if(m_handshake_state.has_server_certificate_msg() &&
      m_handshake_state.server_certificate().has_certificate_chain()) {
      return m_handshake_state.server_certificate().cert_chain();
   }

   if(m_resumed_session.has_value()) {
      return m_resumed_session->session.peer_certs();
   }

   return {};
}

std::shared_ptr<const Public_Key> Client_Impl_13::peer_raw_public_key() const {
   if(m_handshake_state.has_server_certificate_msg() && m_handshake_state.server_certificate().is_raw_public_key()) {
      return m_handshake_state.server_certificate().public_key();
   }

   if(m_resumed_session.has_value()) {
      return m_resumed_session->session.peer_raw_public_key();
   }

   return nullptr;
}

std::optional<std::string> Client_Impl_13::external_psk_identity() const {
   return m_psk_identity;
}

bool Client_Impl_13::prepend_ccs() {
   return std::exchange(m_should_send_ccs, false);  // test-and-set
}

void Client_Impl_13::maybe_log_secret(std::string_view label, std::span<const uint8_t> secret) const {
   if(policy().allow_ssl_key_log_file()) {
      callbacks().tls_ssl_key_log_data(label, m_handshake_state.client_hello().random(), secret);
   }
}

std::string Client_Impl_13::application_protocol() const {
   if(is_handshake_complete()) {
      const auto& eee = m_handshake_state.encrypted_extensions().extensions();
      if(eee.has<Application_Layer_Protocol_Notification>()) {
         return eee.get<Application_Layer_Protocol_Notification>()->single_protocol();
      }
   }

   return "";
}

}  // namespace Botan::TLS

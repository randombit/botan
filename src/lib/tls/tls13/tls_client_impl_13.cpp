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
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/tls_client.h>
#include <botan/tls_messages.h>
#include <botan/build.h>

#include <iterator>
#include <utility>

namespace Botan::TLS {

Client_Impl_13::Client_Impl_13(Callbacks& callbacks,
                               Session_Manager& session_manager,
                               Credentials_Manager& creds,
                               const Policy& policy,
                               RandomNumberGenerator& rng,
                               const Server_Information& info,
                               const std::vector<std::string>& next_protocols) :
   Channel_Impl_13(callbacks, session_manager, creds, rng, policy, false /* is_server */),
   m_info(info),
   m_should_send_ccs(false)
   {
#if defined(BOTAN_HAS_TLS_12)
   if(policy.allow_tls12())
      { expect_downgrade(info); }
#endif

   auto msg = send_handshake_message(m_handshake_state.sent(Client_Hello_13(
                             policy,
                             callbacks,
                             rng,
                             m_info.hostname(),
                             next_protocols)));

   if(expects_downgrade())
      { preserve_client_hello(msg); }

   // RFC 8446 Appendix D.4
   //    If not offering early data, the client sends a dummy change_cipher_spec
   //    record [...] immediately before its second flight. This may either be before
   //    its second ClientHello or before its encrypted handshake flight.
   //
   // TODO: don't schedule ccs here when early data is used
   if(policy.tls_13_middlebox_compatibility_mode())
      m_should_send_ccs = true;

   m_transitions.set_expected_next({SERVER_HELLO, HELLO_RETRY_REQUEST});
   }

void Client_Impl_13::process_handshake_msg(Handshake_Message_13 message)
   {
   std::visit([&](auto msg)
      {
      // first verify that the message was expected by the state machine...
      m_transitions.confirm_transition_to(msg.get().type());

      // ... then allow the library user to abort on their discretion
      callbacks().tls_inspect_handshake_msg(msg.get());

      // ... finally handle the message
      handle(msg.get());
      }, m_handshake_state.received(std::move(message)));
   }

void Client_Impl_13::process_post_handshake_msg(Post_Handshake_Message_13 message)
   {
   BOTAN_STATE_CHECK(handshake_finished());

   std::visit([&](auto msg)
      {
      handle(msg);
      }, std::move(message));
   }

void Client_Impl_13::process_dummy_change_cipher_spec()
   {
   // RFC 8446 5.
   //    If an implementation detects a change_cipher_spec record received before
   //    the first ClientHello message or after the peer's Finished message, it MUST be
   //    treated as an unexpected record type [("unexpected_message" alert)].
   if(!m_handshake_state.has_client_hello() || m_handshake_state.has_server_finished())
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received an unexpected dummy Change Cipher Spec");
      }

   // RFC 8446 5.
   //    An implementation may receive an unencrypted record of type change_cipher_spec [...]
   //    at any time after the first ClientHello message has been sent or received
   //    and before the peer's Finished message has been received [...]
   //    and MUST simply drop it without further processing.
   //
   // ... no further processing.
   }

bool Client_Impl_13::handshake_finished() const
   {
   return m_handshake_state.handshake_finished();
   }

void Client_Impl_13::handle(const Server_Hello_12& server_hello_msg)
   {
   if(m_handshake_state.has_hello_retry_request())
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Version downgrade received after Hello Retry");
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
   if(server_hello_msg.random_signals_downgrade().has_value())
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Downgrade attack detected");
      }

   // RFC 8446 4.2.1
   //    A server which negotiates a version of TLS prior to TLS 1.3 [...]
   //    MUST NOT send the "supported_versions" extension.
   //
   // Note that this condition should never happen, as the Server_Hello parsing
   // code decides to create a Server_Hello_12 based on the absense of this extension.
   if(server_hello_msg.extensions().has<Supported_Versions>())
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Unexpected extension received");
      }

   // RFC 8446 Appendix D.1
   //    If the version chosen by the server is not supported by the client
   //    (or is not acceptable), the client MUST abort the handshake with a
   //    "protocol_version" alert.
   const auto& client_hello_exts = m_handshake_state.client_hello().extensions();
   BOTAN_ASSERT_NOMSG(client_hello_exts.has<Supported_Versions>());
   if(!client_hello_exts.get<Supported_Versions>()->supports(server_hello_msg.selected_version()))
      {
      throw TLS_Exception(Alert::PROTOCOL_VERSION, "Protocol version was not offered");
      }

   if(policy().tls_13_middlebox_compatibility_mode() &&
      m_handshake_state.client_hello().session_id() == server_hello_msg.session_id())
      {
      // In compatibility mode, the server will reflect the session ID we sent in the client hello.
      // However, a TLS 1.2 server that wants to downgrade cannot have found the random session ID
      // we sent. Therefore, we have to consider this as an attack.
      // (Thanks BoGo test EchoTLS13CompatibilitySessionID!)
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Unexpected session ID during downgrade");
      }

   BOTAN_ASSERT_NOMSG(expects_downgrade());

   // After this, no further messages are expected here because this instance will be replaced
   // by a Client_Impl_12.
   m_transitions.set_expected_next({});
   }

namespace  {
// validate Server_Hello_13 and Hello_Retry_Request
void validate_server_hello_ish(const Client_Hello_13& ch, const Server_Hello_13& sh)
   {
   // RFC 8446 4.1.3
   //    A client which receives a legacy_session_id_echo field that does not match what
   //    it sent in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
   if(ch.session_id() != sh.session_id())
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "echoed session id did not match");
      }

   // RFC 8446 4.1.3
   //    A client which receives a cipher suite that was not offered MUST abort the handshake
   //    with an "illegal_parameter" alert.
   if(!ch.offered_suite(sh.ciphersuite()))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Server replied with ciphersuite we didn't send");
      }

   // RFC 8446 4.2.1
   //    If the "supported_versions" extension in the ServerHello contains a
   //    version not offered by the client or contains a version prior to
   //    TLS 1.3, the client MUST abort the handshake with an "illegal_parameter" alert.
   //
   // Note: Server_Hello_13 parsing checks that its selected version is TLS 1.3
   BOTAN_ASSERT_NOMSG(ch.extensions().has<Supported_Versions>());
   if(!ch.extensions().get<Supported_Versions>()->supports(sh.selected_version()))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Protocol version was not offered");
      }
   }
}

void Client_Impl_13::handle(const Server_Hello_13& sh)
   {
   // Note: Basic checks (that do not require contextual information) were already
   //       performed during the construction of the Server_Hello_13 object.

   const auto& ch = m_handshake_state.client_hello();

   validate_server_hello_ish(ch, sh);

   // RFC 8446 4.2
   //    Implementations MUST NOT send extension responses if the remote
   //    endpoint did not send the corresponding extension requests, [...]. Upon
   //    receiving such an extension, an endpoint MUST abort the handshake
   //    with an "unsupported_extension" alert.
   if(sh.extensions().contains_other_than(ch.extensions().extension_types()))
      {
      throw TLS_Exception(Alert::UNSUPPORTED_EXTENSION, "Unsupported extension found in Server Hello");
      }

   if(m_handshake_state.has_hello_retry_request())
      {
      const auto& hrr = m_handshake_state.hello_retry_request();

      // RFC 8446 4.1.4
      //    Upon receiving the ServerHello, clients MUST check that the cipher suite
      //    supplied in the ServerHello is the same as that in the HelloRetryRequest
      //    and otherwise abort the handshake with an "illegal_parameter" alert.
      if(hrr.ciphersuite() != sh.ciphersuite())
         {
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "server changed its chosen ciphersuite");
         }

      // RFC 8446 4.1.4
      //    The value of selected_version in the HelloRetryRequest "supported_versions"
      //    extension MUST be retained in the ServerHello, and a client MUST abort the
      //    handshake with an "illegal_parameter" alert if the value changes.
      if(hrr.selected_version() != sh.selected_version())
         {
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "server changed its chosen protocol version");
         }
      }

   auto cipher = Ciphersuite::by_id(sh.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we offered this suite

   // RFC 8446 Appendix B.4
   //    Although TLS 1.3 uses the same cipher suite space as previous versions
   //    of TLS [...] cipher suites for TLS 1.2 and lower cannot be used with
   //    TLS 1.3.
   if(!cipher->usable_in_version(Protocol_Version::TLS_V13))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Server replied using a ciphersuite not allowed in version it offered");
      }

   if(!sh.extensions().has<Key_Share>())
      {
      throw Not_Implemented("PSK mode (without key agreement) is NYI");
      }

   // TODO: this is assuming a standard handshake without any PSK mode!
   BOTAN_ASSERT_NOMSG(ch.extensions().has<Key_Share>());
   auto my_keyshare = ch.extensions().get<Key_Share>();
   auto shared_secret = my_keyshare->exchange(*sh.extensions().get<Key_Share>(), policy(), callbacks(), rng());
   my_keyshare->erase();

   m_transcript_hash.set_algorithm(cipher.value().prf_algo());

   m_cipher_state = Cipher_State::init_with_server_hello(m_side,
                    std::move(shared_secret),
                    cipher.value(),
                    m_transcript_hash.current());

   callbacks().tls_examine_extensions(sh.extensions(), SERVER);

   m_transitions.set_expected_next(ENCRYPTED_EXTENSIONS);
   }

void Client_Impl_13::handle(const Hello_Retry_Request& hrr)
   {
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
   allowed_exts.insert(TLSEXT_COOKIE);
   if(hrr.extensions().contains_other_than(allowed_exts))
      {
      throw TLS_Exception(Alert::UNSUPPORTED_EXTENSION, "Unsupported extension found in Hello Retry Request");
      }

   auto cipher = Ciphersuite::by_id(hrr.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we offered this suite

   m_transcript_hash = Transcript_Hash_State::recreate_after_hello_retry_request(cipher.value().prf_algo(),
                       m_transcript_hash);

   ch.retry(hrr, callbacks(), rng());

   callbacks().tls_examine_extensions(hrr.extensions(), SERVER);

   send_handshake_message(ch);

   // RFC 8446 4.1.4
   //    If a client receives a second HelloRetryRequest in the same connection [...],
   //    it MUST abort the handshake with an "unexpected_message" alert.
   m_transitions.set_expected_next(SERVER_HELLO);
   }

void Client_Impl_13::handle(const Encrypted_Extensions& encrypted_extensions_msg)
   {
   // RFC 8446 4.2
   //    Implementations MUST NOT send extension responses if the remote
   //    endpoint did not send the corresponding extension requests, [...]. Upon
   //    receiving such an extension, an endpoint MUST abort the handshake
   //    with an "unsupported_extension" alert.
   const auto& requested_exts = m_handshake_state.client_hello().extensions().extension_types();
   if(encrypted_extensions_msg.extensions().contains_other_than(requested_exts))
      { throw TLS_Exception(Alert::UNSUPPORTED_EXTENSION,
            "Encrypted Extensions contained an extension that was not offered"); }

   // Note: As per RFC 6066 3. we can check for an empty SNI extensions to
   // determine if the server used the SNI we sent here.

   if(encrypted_extensions_msg.extensions().has<Record_Size_Limit>() &&
      m_handshake_state.client_hello().extensions().has<Record_Size_Limit>())
      {
      // RFC 8449 4.
      //     The record size limit only applies to records sent toward the
      //     endpoint that advertises the limit.  An endpoint can send records
      //     that are larger than the limit it advertises as its own limit.
      //
      // Hence, the "outgoing" limit is what the server requested and the
      // "incoming" limit is what we requested in the Client Hello.
      const auto outgoing_limit = encrypted_extensions_msg.extensions().get<Record_Size_Limit>();
      const auto incoming_limit = m_handshake_state.client_hello().extensions().get<Record_Size_Limit>();
      set_record_size_limits(outgoing_limit->limit(), incoming_limit->limit());
      }

   callbacks().tls_examine_extensions(encrypted_extensions_msg.extensions(), SERVER);

   bool psk_mode = false;  // TODO
   if(psk_mode)
      {
      m_transitions.set_expected_next(FINISHED);
      }
   else
      {
      m_transitions.set_expected_next({CERTIFICATE, CERTIFICATE_REQUEST});
      }
   }

void Client_Impl_13::handle(const Certificate_13& certificate_msg)
   {
   certificate_msg.validate_extensions(m_handshake_state.client_hello().extensions().extension_types());
   certificate_msg.verify(callbacks(),
                          policy(),
                          credentials_manager(),
                          m_info.hostname(),
                          m_handshake_state.client_hello().extensions().has<Certificate_Status_Request>());

   m_transitions.set_expected_next(CERTIFICATE_VERIFY);
   }

void Client_Impl_13::handle(const Certificate_Verify_13& certificate_verify_msg)
   {
   // RFC 8446 4.4.3
   //    If the CertificateVerify message is sent by a server, the signature
   //    algorithm MUST be one offered in the client's "signature_algorithms"
   //    extension unless no valid certificate chain can be produced without
   //    unsupported algorithms.
   //
   // Note: if the server failed to produce a certificate chain without using
   //       an unsupported signature scheme, we opt to abort the handshake.
   const auto offered = m_handshake_state.client_hello().signature_schemes();
   if(!value_exists(offered, certificate_verify_msg.signature_scheme()))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "We did not offer the usage of " +
                          certificate_verify_msg.signature_scheme().to_string() +
                          " as a signature scheme");
      }

   bool sig_valid = certificate_verify_msg.verify(
                       m_handshake_state.certificate().cert_chain().front().certificate,
                       callbacks(),
                       m_transcript_hash.previous());

   if(!sig_valid)
      { throw TLS_Exception(Alert::DECRYPT_ERROR, "Server certificate verification failed"); }

   m_transitions.set_expected_next(FINISHED);
   }

void Client_Impl_13::handle(const Finished_13& finished_msg)
   {
   // RFC 8446 4.4.4
   //    Recipients of Finished messages MUST verify that the contents are
   //    correct and if incorrect MUST terminate the connection with a
   //    "decrypt_error" alert.
   if(!finished_msg.verify(m_cipher_state.get(),
                           m_transcript_hash.previous()))
      { throw TLS_Exception(Alert::DECRYPT_ERROR, "Finished message didn't verify"); }

   // send client finished handshake message (still using handshake traffic secrets)
   send_handshake_message(m_handshake_state.sent(Finished_13(m_cipher_state.get(),
                          m_transcript_hash.current())));

   // derives the application traffic secrets and _replaces_ the handshake traffic secrets
   // Note: this MUST happen AFTER the client finished message was sent!
   m_cipher_state->advance_with_server_finished(m_transcript_hash.previous());
   m_cipher_state->advance_with_client_finished(m_transcript_hash.current());

   // TODO: save session and invoke tls_session_established callback

   // no more handshake messages expected
   m_transitions.set_expected_next({});

   callbacks().tls_session_activated();
   }

void TLS::Client_Impl_13::handle(const New_Session_Ticket_13&)
   {
   // TODO: resumption is not yet implemented, hence we ignore session tickets
   //       received from the server.
   }

void TLS::Client_Impl_13::handle(const Key_Update& key_update)
   {
   m_cipher_state->update_read_keys();

   // TODO: introduce some kind of rate limit of key updates, otherwise we
   //       might be forced into an endless loop of key updates.

   // RFC 8446 4.6.3
   //    If the request_update field is set to "update_requested", then the
   //    receiver MUST send a KeyUpdate of its own with request_update set to
   //    "update_not_requested" prior to sending its next Application Data
   //    record.
   if(key_update.expects_reciprocation())
      {
      // RFC 8446 4.6.3
      //    This mechanism allows either side to force an update to the
      //    multiple KeyUpdates while it is silent to respond with a single
      //    update.
      opportunistically_update_traffic_keys();
      }
   }

std::vector<X509_Certificate> Client_Impl_13::peer_cert_chain() const
   {
   throw Not_Implemented("peer cert chain is not implemented");
   return std::vector<X509_Certificate>();
   }

bool Client_Impl_13::prepend_ccs()
   {
   return std::exchange(m_should_send_ccs, false);  // test-and-set
   }

std::string Client_Impl_13::application_protocol() const
   {
   if(m_handshake_state.handshake_finished())
      {
      const auto& eee = m_handshake_state.encrypted_extensions().extensions();
      if(eee.has<Application_Layer_Protocol_Notification>())
         {
         return eee.get<Application_Layer_Protocol_Notification>()->single_protocol();
         }
      }

   return "";
   }


}

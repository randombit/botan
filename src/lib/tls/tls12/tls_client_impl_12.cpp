/*
* TLS Client
* (C) 2004-2011,2012,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_client_impl_12.h>

#include <botan/ocsp.h>
#include <botan/tls_client.h>
#include <botan/tls_messages.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_state.h>

#include <optional>
#include <sstream>
#include <utility>

namespace Botan::TLS {

namespace {

class Client_Handshake_State_12 final : public Handshake_State {
   public:
      Client_Handshake_State_12(std::unique_ptr<Handshake_IO> io, Callbacks& cb) :
            Handshake_State(std::move(io), cb), m_is_reneg(false) {}

      const Public_Key& server_public_key() const {
         BOTAN_ASSERT(m_server_public_key, "Server sent us a certificate");
         return *m_server_public_key;
      }

      const Public_Key* maybe_server_public_key() const { return m_server_public_key.get(); }

      void record_server_public_key(std::unique_ptr<Public_Key> spk) {
         BOTAN_STATE_CHECK(!m_server_public_key);
         m_server_public_key = std::move(spk);
      }

      bool is_a_resumption() const { return m_resumed_session.has_value(); }

      void discard_resumption_state() { m_resumed_session.reset(); }

      void record_resumption_info(std::optional<Session> session_info) {
         BOTAN_STATE_CHECK(!m_resumed_session.has_value());
         m_resumed_session = std::move(session_info);
      }

      bool is_a_renegotiation() const { return m_is_reneg; }

      void mark_as_renegotiation() { m_is_reneg = true; }

      const secure_vector<uint8_t>& resume_master_secret() const {
         BOTAN_STATE_CHECK(is_a_resumption());
         return m_resumed_session->master_secret();
      }

      const std::vector<X509_Certificate>& resume_peer_certs() const {
         BOTAN_STATE_CHECK(is_a_resumption());
         return m_resumed_session->peer_certs();
      }

      bool resumed_session_supports_extended_master_secret() const {
         BOTAN_STATE_CHECK(is_a_resumption());
         return m_resumed_session->supports_extended_master_secret();
      }

   private:
      std::unique_ptr<Public_Key> m_server_public_key;

      // Used during session resumption
      std::optional<Session> m_resumed_session;
      bool m_is_reneg = false;
};

}  // namespace

/*
* TLS 1.2 Client  Constructor
*/
Client_Impl_12::Client_Impl_12(const std::shared_ptr<Callbacks>& callbacks,
                               const std::shared_ptr<Session_Manager>& session_manager,
                               const std::shared_ptr<Credentials_Manager>& creds,
                               const std::shared_ptr<const Policy>& policy,
                               const std::shared_ptr<RandomNumberGenerator>& rng,
                               Server_Information info,
                               bool datagram,
                               const std::vector<std::string>& next_protocols,
                               size_t io_buf_sz) :
      Channel_Impl_12(callbacks, session_manager, rng, policy, false, datagram, io_buf_sz),
      m_creds(creds),
      m_info(std::move(info)) {
   BOTAN_ASSERT_NONNULL(m_creds);
   const auto version = datagram ? Protocol_Version::DTLS_V12 : Protocol_Version::TLS_V12;
   Handshake_State& state = create_handshake_state(version);
   send_client_hello(state, false, version, std::nullopt /* no a-priori session to resume */, next_protocols);
}

Client_Impl_12::Client_Impl_12(const Channel_Impl::Downgrade_Information& downgrade_info) :
      Channel_Impl_12(downgrade_info.callbacks,
                      downgrade_info.session_manager,
                      downgrade_info.rng,
                      downgrade_info.policy,
                      false /* is_server */,
                      false /* datagram -- not supported by Botan in TLS 1.3 */,
                      downgrade_info.io_buffer_size),
      m_creds(downgrade_info.creds),
      m_info(downgrade_info.server_info) {
   Handshake_State& state = create_handshake_state(Protocol_Version::TLS_V12);

   if(!downgrade_info.client_hello_message.empty()) {
      // Downgrade detected after receiving a TLS 1.2 server hello. We need to
      // recreate the state as if this implementation issued the client hello.
      std::vector<uint8_t> client_hello_msg(
         downgrade_info.client_hello_message.begin() + 4 /* handshake header length */,
         downgrade_info.client_hello_message.end());

      state.client_hello(new Client_Hello_12(client_hello_msg));
      state.hash().update(downgrade_info.client_hello_message);

      secure_renegotiation_check(state.client_hello());
      state.set_expected_next(Handshake_Type::ServerHello);
   } else {
      // Downgrade initiated after a TLS 1.2 session was found. No communication
      // has happened yet but the found session should be used for resumption.
      BOTAN_ASSERT_NOMSG(downgrade_info.tls12_session.has_value() &&
                         downgrade_info.tls12_session->session.version().is_pre_tls_13());
      send_client_hello(state,
                        false,
                        downgrade_info.tls12_session->session.version(),
                        downgrade_info.tls12_session,
                        downgrade_info.next_protocols);
   }
}

std::unique_ptr<Handshake_State> Client_Impl_12::new_handshake_state(std::unique_ptr<Handshake_IO> io) {
   return std::make_unique<Client_Handshake_State_12>(std::move(io), callbacks());
}

std::vector<X509_Certificate> Client_Impl_12::get_peer_cert_chain(const Handshake_State& state) const {
   const Client_Handshake_State_12& cstate = dynamic_cast<const Client_Handshake_State_12&>(state);

   if(cstate.is_a_resumption()) {
      return cstate.resume_peer_certs();
   }

   if(state.server_certs()) {
      return state.server_certs()->cert_chain();
   }
   return std::vector<X509_Certificate>();
}

/*
* Send a new client hello to renegotiate
*/
void Client_Impl_12::initiate_handshake(Handshake_State& state, bool force_full_renegotiation) {
   // we don't support TLS < 1.2 anymore and TLS 1.3 should not use this client impl
   const auto version = state.version().is_datagram_protocol() ? Protocol_Version::DTLS_V12 : Protocol_Version::TLS_V12;
   send_client_hello(state, force_full_renegotiation, version);
}

void Client_Impl_12::send_client_hello(Handshake_State& state_base,
                                       bool force_full_renegotiation,
                                       Protocol_Version version,
                                       std::optional<Session_with_Handle> session_and_handle,
                                       const std::vector<std::string>& next_protocols) {
   Client_Handshake_State_12& state = dynamic_cast<Client_Handshake_State_12&>(state_base);

   if(state.version().is_datagram_protocol()) {
      state.set_expected_next(Handshake_Type::HelloVerifyRequest);  // optional
   }
   state.set_expected_next(Handshake_Type::ServerHello);

   if(!force_full_renegotiation) {
      // if no session is provided, we need to try and find one opportunistically
      if(!session_and_handle.has_value() && !m_info.empty()) {
         if(auto sessions = session_manager().find(m_info, callbacks(), policy()); !sessions.empty()) {
            session_and_handle = std::move(sessions.front());
         }
      }

      if(session_and_handle.has_value()) {
         /*
         Ensure that the session protocol cipher and version are acceptable
         If not skip the resume and establish a new session
         */
         auto& session_info = session_and_handle->session;
         const bool exact_version = session_info.version() == version;
         const bool ok_version = (session_info.version().is_datagram_protocol() == version.is_datagram_protocol()) &&
                                 policy().acceptable_protocol_version(session_info.version());

         const bool session_version_ok = policy().only_resume_with_exact_version() ? exact_version : ok_version;

         if(policy().acceptable_ciphersuite(session_info.ciphersuite()) && session_version_ok) {
            state.client_hello(new Client_Hello_12(state.handshake_io(),
                                                   state.hash(),
                                                   policy(),
                                                   callbacks(),
                                                   rng(),
                                                   secure_renegotiation_data_for_client_hello(),
                                                   session_and_handle.value(),
                                                   next_protocols));

            state.record_resumption_info(std::move(session_info));
         }
      }
   }

   if(!state.client_hello()) {
      // not resuming
      Client_Hello_12::Settings client_settings(version, m_info.hostname());
      state.client_hello(new Client_Hello_12(state.handshake_io(),
                                             state.hash(),
                                             policy(),
                                             callbacks(),
                                             rng(),
                                             secure_renegotiation_data_for_client_hello(),
                                             client_settings,
                                             next_protocols));
   }

   secure_renegotiation_check(state.client_hello());
}

namespace {

bool key_usage_matches_ciphersuite(Key_Constraints usage, const Ciphersuite& suite) {
   if(usage == Key_Constraints::None) {
      return true;  // anything goes ...
   }

   if(suite.kex_method() == Kex_Algo::STATIC_RSA) {
      return usage.includes_any(Key_Constraints::KeyEncipherment, Key_Constraints::DataEncipherment);
   } else {
      return usage.includes_any(Key_Constraints::DigitalSignature, Key_Constraints::NonRepudiation);
   }
}

}  // namespace

/*
* Process a handshake message
*/
void Client_Impl_12::process_handshake_msg(const Handshake_State* active_state,
                                           Handshake_State& state_base,
                                           Handshake_Type type,
                                           const std::vector<uint8_t>& contents,
                                           bool epoch0_restart) {
   BOTAN_ASSERT_NOMSG(epoch0_restart == false);  // only happens on server side

   Client_Handshake_State_12& state = dynamic_cast<Client_Handshake_State_12&>(state_base);

   if(type == Handshake_Type::HelloRequest && active_state) {
      Hello_Request hello_request(contents);

      if(state.client_hello()) {
         throw TLS_Exception(Alert::HandshakeFailure, "Cannot renegotiate during a handshake");
      }

      if(policy().allow_server_initiated_renegotiation()) {
         if(secure_renegotiation_supported() || policy().allow_insecure_renegotiation()) {
            state.mark_as_renegotiation();
            initiate_handshake(state, true /* force_full_renegotiation */);
         } else {
            throw TLS_Exception(Alert::HandshakeFailure, "Client policy prohibits insecure renegotiation");
         }
      } else {
         if(policy().abort_connection_on_undesired_renegotiation()) {
            throw TLS_Exception(Alert::NoRenegotiation, "Client policy prohibits renegotiation");
         } else {
            // RFC 5746 section 4.2
            send_warning_alert(Alert::NoRenegotiation);
         }
      }

      return;
   }

   state.confirm_transition_to(type);

   if(type != Handshake_Type::HandshakeCCS && type != Handshake_Type::Finished &&
      type != Handshake_Type::HelloVerifyRequest) {
      state.hash().update(state.handshake_io().format(contents, type));
   }

   if(type == Handshake_Type::HelloVerifyRequest) {
      state.set_expected_next(Handshake_Type::ServerHello);
      state.set_expected_next(Handshake_Type::HelloVerifyRequest);  // might get it again

      Hello_Verify_Request hello_verify_request(contents);
      state.hello_verify_request(hello_verify_request);
   } else if(type == Handshake_Type::ServerHello) {
      state.server_hello(new Server_Hello_12(contents));

      if(!state.server_hello()->legacy_version().valid()) {
         throw TLS_Exception(Alert::ProtocolVersion, "Server replied with an invalid version");
      }

      if(!state.client_hello()->offered_suite(state.server_hello()->ciphersuite())) {
         throw TLS_Exception(Alert::HandshakeFailure, "Server replied with ciphersuite we didn't send");
      }

      const auto suite = Ciphersuite::by_id(state.server_hello()->ciphersuite());
      if(!suite || !suite->usable_in_version(state.server_hello()->legacy_version())) {
         throw TLS_Exception(Alert::HandshakeFailure,
                             "Server replied using a ciphersuite not allowed in version it offered");
      }

      // RFC 7366 3.:
      //   If a server receives an encrypt-then-MAC request extension from a client
      //   and then selects a stream or Authenticated Encryption with Associated
      //   Data (AEAD) ciphersuite, it MUST NOT send an encrypt-then-MAC
      //   response extension back to the client.
      if(suite->aead_ciphersuite() && state.server_hello()->supports_encrypt_then_mac()) {
         throw TLS_Exception(Alert::IllegalParameter,
                             "Server replied using an AEAD ciphersuite and an encrypt-then-MAC response extension");
      }

      if(Ciphersuite::is_scsv(state.server_hello()->ciphersuite())) {
         throw TLS_Exception(Alert::HandshakeFailure, "Server replied with a signaling ciphersuite");
      }

      if(state.server_hello()->compression_method() != 0) {
         throw TLS_Exception(Alert::IllegalParameter, "Server replied with non-null compression method");
      }

      if(state.client_hello()->legacy_version() > state.server_hello()->legacy_version()) {
         // check for downgrade attacks
         //
         // RFC 8446 4.1.3.:
         //   TLS 1.2 clients SHOULD also check that the last 8 bytes are
         //   not equal to the [magic value DOWNGRADE_TLS11] if the ServerHello
         //   indicates TLS 1.1 or below.  If a match is found, the client MUST
         //   abort the handshake with an "illegal_parameter" alert.
         //
         // TLS 1.3 servers will still set the magic string to DOWNGRADE_TLS12. Don't abort in this case.
         if(auto requested = state.server_hello()->random_signals_downgrade();
            requested.has_value() && requested.value() <= Protocol_Version::TLS_V11) {
            throw TLS_Exception(Alert::IllegalParameter, "Downgrade attack detected");
         }
      }

      auto client_extn = state.client_hello()->extension_types();
      auto server_extn = state.server_hello()->extension_types();

      std::vector<Extension_Code> diff;

      std::set_difference(
         server_extn.begin(), server_extn.end(), client_extn.begin(), client_extn.end(), std::back_inserter(diff));

      if(!diff.empty()) {
         // Server sent us back an extension we did not send!

         std::ostringstream msg;
         msg << "Server replied with unsupported extensions:";
         for(auto&& d : diff) {
            msg << " " << static_cast<int>(d);
         }
         throw TLS_Exception(Alert::UnsupportedExtension, msg.str());
      }

      if(uint16_t srtp = state.server_hello()->srtp_profile()) {
         if(!value_exists(state.client_hello()->srtp_profiles(), srtp)) {
            throw TLS_Exception(Alert::HandshakeFailure, "Server replied with DTLS-SRTP alg we did not send");
         }
      }

      callbacks().tls_examine_extensions(
         state.server_hello()->extensions(), Connection_Side::Server, Handshake_Type::ServerHello);

      state.set_version(state.server_hello()->legacy_version());
      m_application_protocol = state.server_hello()->next_protocol();

      secure_renegotiation_check(state.server_hello());

      const bool server_returned_same_session_id =
         !state.server_hello()->session_id().empty() &&
         (state.server_hello()->session_id() == state.client_hello()->session_id());

      if(server_returned_same_session_id) {
         // successful resumption
         BOTAN_ASSERT_NOMSG(state.is_a_resumption());

         /*
         * In this case, we offered the version used in the original
         * session, and the server must resume with the same version.
         */
         if(state.server_hello()->legacy_version() != state.client_hello()->legacy_version()) {
            throw TLS_Exception(Alert::HandshakeFailure, "Server resumed session but with wrong version");
         }

         if(state.server_hello()->supports_extended_master_secret() &&
            !state.resumed_session_supports_extended_master_secret()) {
            throw TLS_Exception(Alert::HandshakeFailure, "Server resumed session but added extended master secret");
         }

         if(!state.server_hello()->supports_extended_master_secret() &&
            state.resumed_session_supports_extended_master_secret()) {
            throw TLS_Exception(Alert::HandshakeFailure, "Server resumed session and removed extended master secret");
         }

         state.compute_session_keys(state.resume_master_secret());
         if(policy().allow_ssl_key_log_file()) {
            // draft-thomson-tls-keylogfile-00 Section 3.2
            //    An implementation of TLS 1.2 (and also earlier versions) use
            //    the label "CLIENT_RANDOM" to identify the "master" secret for
            //    the connection.
            callbacks().tls_ssl_key_log_data(
               "CLIENT_RANDOM", state.client_hello()->random(), state.session_keys().master_secret());
         }

         if(state.server_hello()->supports_session_ticket()) {
            state.set_expected_next(Handshake_Type::NewSessionTicket);
         } else {
            state.set_expected_next(Handshake_Type::HandshakeCCS);
         }
      } else {
         // new session

         if(active_state) {
            // Here we are testing things that should not change during a renegotation,
            // even if the server creates a new session. Howerver they might change
            // in a resumption scenario.

            if(active_state->version() != state.server_hello()->legacy_version()) {
               throw TLS_Exception(Alert::ProtocolVersion, "Server changed version after renegotiation");
            }

            if(state.server_hello()->supports_extended_master_secret() !=
               active_state->server_hello()->supports_extended_master_secret()) {
               throw TLS_Exception(Alert::HandshakeFailure, "Server changed its mind about extended master secret");
            }
         }

         state.discard_resumption_state();

         if(state.client_hello()->legacy_version().is_datagram_protocol() !=
            state.server_hello()->legacy_version().is_datagram_protocol()) {
            throw TLS_Exception(Alert::ProtocolVersion, "Server replied with different protocol type than we offered");
         }

         if(state.version() > state.client_hello()->legacy_version()) {
            throw TLS_Exception(Alert::HandshakeFailure, "Server replied with later version than client offered");
         }

         if(state.version().major_version() == 3 && state.version().minor_version() == 0) {
            throw TLS_Exception(Alert::ProtocolVersion, "Server attempting to negotiate SSLv3 which is not supported");
         }

         if(!policy().acceptable_protocol_version(state.version())) {
            throw TLS_Exception(Alert::ProtocolVersion,
                                "Server version " + state.version().to_string() + " is unacceptable by policy");
         }

         if(state.ciphersuite().signature_used() || state.ciphersuite().kex_method() == Kex_Algo::STATIC_RSA) {
            state.set_expected_next(Handshake_Type::Certificate);
         } else if(state.ciphersuite().kex_method() == Kex_Algo::PSK) {
            /* PSK is anonymous so no certificate/cert req message is
               ever sent. The server may or may not send a server kex,
               depending on if it has an identity hint for us.

               (EC)DHE_PSK always sends a server key exchange for the
               DH exchange portion, and is covered by block below
            */

            state.set_expected_next(Handshake_Type::ServerKeyExchange);
            state.set_expected_next(Handshake_Type::ServerHelloDone);
         } else if(state.ciphersuite().kex_method() != Kex_Algo::STATIC_RSA) {
            state.set_expected_next(Handshake_Type::ServerKeyExchange);
         } else {
            state.set_expected_next(Handshake_Type::CertificateRequest);  // optional
            state.set_expected_next(Handshake_Type::ServerHelloDone);
         }
      }
   } else if(type == Handshake_Type::Certificate) {
      state.server_certs(new Certificate_12(contents, policy()));

      const std::vector<X509_Certificate>& server_certs = state.server_certs()->cert_chain();

      if(server_certs.empty()) {
         throw TLS_Exception(Alert::HandshakeFailure, "Client: No certificates sent by server");
      }

      /*
      If the server supports certificate status messages,
      certificate verification happens after we receive the server hello done,
      in case an OCSP response was also available
      */

      X509_Certificate server_cert = server_certs[0];

      if(active_state && active_state->server_certs()) {
         X509_Certificate current_cert = active_state->server_certs()->cert_chain().at(0);

         if(current_cert != server_cert) {
            throw TLS_Exception(Alert::BadCertificate, "Server certificate changed during renegotiation");
         }
      }

      auto peer_key = server_cert.subject_public_key();

      const std::string expected_key_type =
         state.ciphersuite().signature_used() ? state.ciphersuite().sig_algo() : "RSA";

      if(peer_key->algo_name() != expected_key_type) {
         throw TLS_Exception(Alert::IllegalParameter, "Certificate key type did not match ciphersuite");
      }

      if(!key_usage_matches_ciphersuite(server_cert.constraints(), state.ciphersuite())) {
         throw TLS_Exception(Alert::BadCertificate, "Certificate usage constraints do not allow this ciphersuite");
      }

      state.record_server_public_key(std::move(peer_key));

      if(state.ciphersuite().kex_method() != Kex_Algo::STATIC_RSA) {
         state.set_expected_next(Handshake_Type::ServerKeyExchange);
      } else {
         state.set_expected_next(Handshake_Type::CertificateRequest);  // optional
         state.set_expected_next(Handshake_Type::ServerHelloDone);
      }

      if(state.server_hello()->supports_certificate_status_message()) {
         state.set_expected_next(Handshake_Type::CertificateStatus);  // optional
      } else {
         try {
            auto trusted_CAs = m_creds->trusted_certificate_authorities("tls-client", m_info.hostname());

            callbacks().tls_verify_cert_chain(
               server_certs, {}, trusted_CAs, Usage_Type::TLS_SERVER_AUTH, m_info.hostname(), policy());
         } catch(TLS_Exception&) {
            throw;
         } catch(std::exception& e) {
            throw TLS_Exception(Alert::InternalError, e.what());
         }
      }
   } else if(type == Handshake_Type::CertificateStatus) {
      state.server_cert_status(new Certificate_Status(contents, Connection_Side::Server));

      if(state.ciphersuite().kex_method() != Kex_Algo::STATIC_RSA) {
         state.set_expected_next(Handshake_Type::ServerKeyExchange);
      } else {
         state.set_expected_next(Handshake_Type::CertificateRequest);  // optional
         state.set_expected_next(Handshake_Type::ServerHelloDone);
      }
   } else if(type == Handshake_Type::ServerKeyExchange) {
      if(state.ciphersuite().psk_ciphersuite() == false) {
         state.set_expected_next(Handshake_Type::CertificateRequest);  // optional
      }
      state.set_expected_next(Handshake_Type::ServerHelloDone);

      state.server_kex(new Server_Key_Exchange(
         contents, state.ciphersuite().kex_method(), state.ciphersuite().auth_method(), state.version()));

      if(state.ciphersuite().signature_used()) {
         const Public_Key& server_key = state.server_public_key();

         if(!state.server_kex()->verify(server_key, state, policy())) {
            throw TLS_Exception(Alert::DecryptError, "Bad signature on server key exchange");
         }
      }
   } else if(type == Handshake_Type::CertificateRequest) {
      state.set_expected_next(Handshake_Type::ServerHelloDone);
      state.cert_req(new Certificate_Request_12(contents));
   } else if(type == Handshake_Type::ServerHelloDone) {
      state.server_hello_done(new Server_Hello_Done(contents));

      if(state.handshake_io().have_more_data()) {
         throw TLS_Exception(Alert::UnexpectedMessage, "Have data remaining in buffer after ServerHelloDone");
      }

      if(state.server_certs() != nullptr && state.server_hello()->supports_certificate_status_message()) {
         try {
            auto trusted_CAs = m_creds->trusted_certificate_authorities("tls-client", m_info.hostname());

            std::vector<std::optional<OCSP::Response>> ocsp;
            if(state.server_cert_status() != nullptr) {
               ocsp.emplace_back(callbacks().tls_parse_ocsp_response(state.server_cert_status()->response()));
            }

            callbacks().tls_verify_cert_chain(state.server_certs()->cert_chain(),
                                              ocsp,
                                              trusted_CAs,
                                              Usage_Type::TLS_SERVER_AUTH,
                                              m_info.hostname(),
                                              policy());
         } catch(TLS_Exception&) {
            throw;
         } catch(std::exception& e) {
            throw TLS_Exception(Alert::InternalError, e.what());
         }
      }

      if(state.received_handshake_msg(Handshake_Type::CertificateRequest)) {
         const auto& types = state.cert_req()->acceptable_cert_types();

         std::vector<X509_Certificate> client_certs =
            m_creds->find_cert_chain(types, {}, state.cert_req()->acceptable_CAs(), "tls-client", m_info.hostname());

         state.client_certs(new Certificate_12(state.handshake_io(), state.hash(), client_certs));
      }

      state.client_kex(new Client_Key_Exchange(
         state.handshake_io(), state, policy(), *m_creds, state.maybe_server_public_key(), m_info.hostname(), rng()));

      state.compute_session_keys();
      if(policy().allow_ssl_key_log_file()) {
         // draft-thomson-tls-keylogfile-00 Section 3.2
         //    An implementation of TLS 1.2 (and also earlier versions) use
         //    the label "CLIENT_RANDOM" to identify the "master" secret for
         //    the connection.
         callbacks().tls_ssl_key_log_data(
            "CLIENT_RANDOM", state.client_hello()->random(), state.session_keys().master_secret());
      }

      if(state.received_handshake_msg(Handshake_Type::CertificateRequest) && !state.client_certs()->empty()) {
         auto private_key =
            m_creds->private_key_for(state.client_certs()->cert_chain()[0], "tls-client", m_info.hostname());

         if(!private_key) {
            throw TLS_Exception(Alert::InternalError, "Failed to get private key for signing");
         }

         state.client_verify(
            new Certificate_Verify_12(state.handshake_io(), state, policy(), rng(), private_key.get()));
      }

      state.handshake_io().send(Change_Cipher_Spec());

      change_cipher_spec_writer(Connection_Side::Client);

      state.client_finished(new Finished_12(state.handshake_io(), state, Connection_Side::Client));

      if(state.server_hello()->supports_session_ticket()) {
         state.set_expected_next(Handshake_Type::NewSessionTicket);
      } else {
         state.set_expected_next(Handshake_Type::HandshakeCCS);
      }
   } else if(type == Handshake_Type::NewSessionTicket) {
      state.new_session_ticket(new New_Session_Ticket_12(contents));

      state.set_expected_next(Handshake_Type::HandshakeCCS);
   } else if(type == Handshake_Type::HandshakeCCS) {
      state.set_expected_next(Handshake_Type::Finished);

      change_cipher_spec_reader(Connection_Side::Client);
   } else if(type == Handshake_Type::Finished) {
      if(state.handshake_io().have_more_data()) {
         throw TLS_Exception(Alert::UnexpectedMessage, "Have data remaining in buffer after Finished");
      }

      state.server_finished(new Finished_12(contents));

      if(!state.server_finished()->verify(state, Connection_Side::Server)) {
         throw TLS_Exception(Alert::DecryptError, "Finished message didn't verify");
      }

      state.hash().update(state.handshake_io().format(contents, type));

      if(!state.client_finished()) {
         // session resume case
         state.handshake_io().send(Change_Cipher_Spec());
         change_cipher_spec_writer(Connection_Side::Client);
         state.client_finished(new Finished_12(state.handshake_io(), state, Connection_Side::Client));
      }

      Session session_info(state.session_keys().master_secret(),
                           state.server_hello()->legacy_version(),
                           state.server_hello()->ciphersuite(),
                           Connection_Side::Client,
                           state.server_hello()->supports_extended_master_secret(),
                           state.server_hello()->supports_encrypt_then_mac(),
                           get_peer_cert_chain(state),
                           m_info,
                           state.server_hello()->srtp_profile(),
                           callbacks().tls_current_timestamp(),

                           // Session Tickets (as defined in RFC 5077) contain a lifetime_hint,
                           // sessions identified via a Session_ID do not.
                           ((state.new_session_ticket()) ? state.new_session_ticket()->ticket_lifetime_hint()
                                                         : std::chrono::seconds::max()));

      // RFC 5077 3.4
      //    If the client receives a session ticket from the server, then it
      //    discards any Session ID that was sent in the ServerHello.
      const auto handle = [&]() -> std::optional<Session_Handle> {
         if(const auto& session_ticket = state.session_ticket(); !session_ticket.empty()) {
            return session_ticket;
         } else if(const auto& session_id = state.server_hello()->session_id(); !session_id.empty()) {
            return session_id;
         } else {
            return std::nullopt;
         }
      }();

      // Give the application a chance for a final veto before fully
      // establishing the connection.
      callbacks().tls_session_established([&, this] {
         Session_Summary summary(session_info, state.is_a_resumption(), external_psk_identity());
         summary.set_session_id(state.server_hello()->session_id());
         if(auto nst = state.new_session_ticket()) {
            summary.set_session_ticket(nst->ticket());
         }
         return summary;
      }());

      if(handle.has_value()) {
         const bool should_save = callbacks().tls_should_persist_resumption_information(session_info);

         // RFC 5077 3.3
         //    If the server successfully verifies the client's ticket, then it
         //    MAY renew the ticket by including a NewSessionTicket handshake
         //    message after the ServerHello in the abbreviated handshake. The
         //    client should start using the new ticket as soon as possible
         //    after it verifies the server's Finished message for new
         //    connections.
         if(state.is_a_resumption() && !state.client_hello()->session_ticket().empty() && handle->is_ticket() &&
            should_save) {
            // renew the session ticket by removing the one we used to establish
            // this connection and replace it with the one we just received
            session_manager().remove(state.client_hello()->session_ticket());
            session_manager().store(session_info, handle.value());
         }

         if(!state.is_a_resumption()) {
            if(should_save) {
               session_manager().store(session_info, handle.value());
            } else {
               session_manager().remove(handle.value());
            }
         }
      }

      activate_session();
   } else {
      throw Unexpected_Message("Unknown handshake message received");
   }
}

}  // namespace Botan::TLS

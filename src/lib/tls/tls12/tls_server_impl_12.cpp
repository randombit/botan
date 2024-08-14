/*
* TLS Server
* (C) 2004-2011,2012,2016 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_server_impl_12.h>

#include <botan/ocsp.h>
#include <botan/tls_magic.h>
#include <botan/tls_messages.h>
#include <botan/tls_server.h>
#include <botan/tls_version.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_state.h>

namespace Botan::TLS {

class Server_Handshake_State final : public Handshake_State {
   public:
      Server_Handshake_State(std::unique_ptr<Handshake_IO> io, Callbacks& cb) : Handshake_State(std::move(io), cb) {}

      Private_Key* server_rsa_kex_key() { return m_server_rsa_kex_key.get(); }

      void set_server_rsa_kex_key(std::shared_ptr<Private_Key> key) { m_server_rsa_kex_key = std::move(key); }

      bool allow_session_resumption() const { return m_allow_session_resumption; }

      void set_allow_session_resumption(bool allow_session_resumption) {
         m_allow_session_resumption = allow_session_resumption;
      }

      const std::vector<X509_Certificate>& resume_peer_certs() const { return m_resume_peer_certs; }

      void set_resume_certs(const std::vector<X509_Certificate>& certs) { m_resume_peer_certs = certs; }

      void mark_as_resumption() { m_is_a_resumption = true; }

      bool is_a_resumption() const { return m_is_a_resumption; }

   private:
      // Used by the server only, in case of RSA key exchange.
      std::shared_ptr<Private_Key> m_server_rsa_kex_key;

      /*
      * Used by the server to know if resumption should be allowed on
      * a server-initiated renegotiation
      */
      bool m_allow_session_resumption = true;

      bool m_is_a_resumption = false;

      std::vector<X509_Certificate> m_resume_peer_certs;
};

namespace {

std::optional<Session> check_for_resume(const Session_Handle& handle_to_resume,
                                        Session_Manager& session_manager,
                                        Callbacks& cb,
                                        const Policy& policy,
                                        const Client_Hello_12* client_hello) {
   auto session = session_manager.retrieve(handle_to_resume, cb, policy);
   if(!session.has_value()) {
      return std::nullopt;
   }

   // wrong version
   if(client_hello->legacy_version() != session->version()) {
      return std::nullopt;
   }

   // client didn't send original ciphersuite
   if(!value_exists(client_hello->ciphersuites(), session->ciphersuite_code())) {
      return std::nullopt;
   }

   // client sent a different SNI hostname
   if(!client_hello->sni_hostname().empty() && client_hello->sni_hostname() != session->server_info().hostname()) {
      return std::nullopt;
   }

   // Checking extended_master_secret on resume (RFC 7627 section 5.3)
   if(client_hello->supports_extended_master_secret() != session->supports_extended_master_secret()) {
      if(!session->supports_extended_master_secret()) {
         return std::nullopt;  // force new handshake with extended master secret
      } else {
         /*
         Client previously negotiated session with extended master secret,
         but has now attempted to resume without the extension: abort
         */
         throw TLS_Exception(Alert::HandshakeFailure, "Client resumed extended ms session without sending extension");
      }
   }

   // Checking encrypt_then_mac on resume (RFC 7366 section 3.1)
   if(!client_hello->supports_encrypt_then_mac() && session->supports_encrypt_then_mac()) {
      /*
      Client previously negotiated session with Encrypt-then-MAC,
      but has now attempted to resume without the extension: abort
      */
      throw TLS_Exception(Alert::HandshakeFailure, "Client resumed Encrypt-then-MAC session without sending extension");
   }

   return session;
}

/*
* Choose which ciphersuite to use
*/
uint16_t choose_ciphersuite(const Policy& policy,
                            Protocol_Version version,
                            const std::map<std::string, std::vector<X509_Certificate>>& cert_chains,
                            const Client_Hello_12& client_hello) {
   const bool our_choice = policy.server_uses_own_ciphersuite_preferences();
   const std::vector<uint16_t>& client_suites = client_hello.ciphersuites();
   const std::vector<uint16_t> server_suites = policy.ciphersuite_list(version);

   if(server_suites.empty()) {
      throw TLS_Exception(Alert::HandshakeFailure, "Policy forbids us from negotiating any ciphersuite");
   }

   const bool have_shared_ecc_curve =
      (policy.choose_key_exchange_group(client_hello.supported_ecc_curves(), {}) != Group_Params::NONE);

   const bool client_supports_ffdhe_groups = !client_hello.supported_dh_groups().empty();

   const bool have_shared_dh_group =
      (policy.choose_key_exchange_group(client_hello.supported_dh_groups(), {}) != Group_Params::NONE);

   /*
   Walk down one list in preference order
   */
   std::vector<uint16_t> pref_list = server_suites;
   std::vector<uint16_t> other_list = client_suites;

   if(!our_choice) {
      std::swap(pref_list, other_list);
   }

   for(auto suite_id : pref_list) {
      if(!value_exists(other_list, suite_id)) {
         continue;
      }

      const auto suite = Ciphersuite::by_id(suite_id);

      if(!suite.has_value() || !suite->valid()) {
         continue;
      }

      if(have_shared_ecc_curve == false && suite->ecc_ciphersuite()) {
         continue;
      }

      if(suite->kex_method() == Kex_Algo::DH && client_supports_ffdhe_groups && !have_shared_dh_group) {
         continue;
      }

      // For non-anon ciphersuites
      if(suite->signature_used()) {
         const std::string sig_algo = suite->sig_algo();

         // Do we have any certificates for this sig?
         if(!cert_chains.contains(sig_algo)) {
            continue;
         }

         const std::vector<Signature_Scheme> allowed = policy.allowed_signature_schemes();

         std::vector<Signature_Scheme> client_sig_methods = client_hello.signature_schemes();

         /*
         Contrary to the wording of draft-ietf-tls-md5-sha1-deprecate we do
         not enforce that clients do not offer support SHA-1 or MD5
         signatures; we just ignore it.
         */
         bool we_support_some_hash_by_client = false;

         for(Signature_Scheme scheme : client_sig_methods) {
            if(!scheme.is_available()) {
               continue;
            }

            if(scheme.algorithm_name() == suite->sig_algo() &&
               policy.allowed_signature_hash(scheme.hash_function_name())) {
               we_support_some_hash_by_client = true;
            }
         }

         if(we_support_some_hash_by_client == false) {
            throw TLS_Exception(Alert::HandshakeFailure,
                                "Policy does not accept any hash function supported by client");
         }
      }

      return suite_id;
   }

   // RFC 7919 Section 4.
   //   If the [Supported Groups] extension is present
   //   with FFDHE groups, none of the client’s offered groups are acceptable
   //   by the server, and none of the client’s proposed non-FFDHE cipher
   //   suites are acceptable to the server, the server MUST end the
   //   connection with a fatal TLS alert of type insufficient_security(71).
   if(client_supports_ffdhe_groups && !have_shared_dh_group) {
      throw TLS_Exception(Alert::InsufficientSecurity, "Can't agree on a sufficiently strong ciphersuite with client");
   }

   throw TLS_Exception(Alert::HandshakeFailure, "Can't agree on a ciphersuite with client");
}

std::map<std::string, std::vector<X509_Certificate>> get_server_certs(
   std::string_view hostname, const std::vector<Signature_Scheme>& cert_sig_schemes, Credentials_Manager& creds) {
   const char* cert_types[] = {"RSA", "ECDSA", "DSA", nullptr};

   std::map<std::string, std::vector<X509_Certificate>> cert_chains;

   for(size_t i = 0; cert_types[i]; ++i) {
      const std::vector<X509_Certificate> certs = creds.cert_chain_single_type(
         cert_types[i], to_algorithm_identifiers(cert_sig_schemes), "tls-server", std::string(hostname));

      if(!certs.empty()) {
         cert_chains[cert_types[i]] = certs;
      }
   }

   return cert_chains;
}

}  // namespace

Server_Impl_12::Server_Impl_12(const std::shared_ptr<Callbacks>& callbacks,
                               const std::shared_ptr<Session_Manager>& session_manager,
                               const std::shared_ptr<Credentials_Manager>& creds,
                               const std::shared_ptr<const Policy>& policy,
                               const std::shared_ptr<RandomNumberGenerator>& rng,
                               bool is_datagram,
                               size_t io_buf_sz) :
      Channel_Impl_12(callbacks, session_manager, rng, policy, true, is_datagram, io_buf_sz), m_creds(creds) {
   BOTAN_ASSERT_NONNULL(m_creds);
}

Server_Impl_12::Server_Impl_12(const Channel_Impl::Downgrade_Information& downgrade_info) :
      Channel_Impl_12(downgrade_info.callbacks,
                      downgrade_info.session_manager,
                      downgrade_info.rng,
                      downgrade_info.policy,
                      true /* is_server*/,
                      false /* TLS 1.3 does not support DTLS yet */,
                      downgrade_info.io_buffer_size),
      m_creds(downgrade_info.creds) {}

std::unique_ptr<Handshake_State> Server_Impl_12::new_handshake_state(std::unique_ptr<Handshake_IO> io) {
   auto state = std::make_unique<Server_Handshake_State>(std::move(io), callbacks());
   state->set_expected_next(Handshake_Type::ClientHello);
   return state;
}

std::vector<X509_Certificate> Server_Impl_12::get_peer_cert_chain(const Handshake_State& state_base) const {
   const Server_Handshake_State& state = dynamic_cast<const Server_Handshake_State&>(state_base);
   if(!state.resume_peer_certs().empty()) {
      return state.resume_peer_certs();
   }

   if(state.client_certs()) {
      return state.client_certs()->cert_chain();
   }
   return std::vector<X509_Certificate>();
}

/*
* Send a hello request to the client
*/
void Server_Impl_12::initiate_handshake(Handshake_State& state, bool force_full_renegotiation) {
   dynamic_cast<Server_Handshake_State&>(state).set_allow_session_resumption(!force_full_renegotiation);

   Hello_Request hello_req(state.handshake_io());
}

namespace {

Protocol_Version select_version(const TLS::Policy& policy,
                                Protocol_Version client_offer,
                                Protocol_Version active_version,
                                const std::vector<Protocol_Version>& supported_versions) {
   const bool is_datagram = client_offer.is_datagram_protocol();
   const bool initial_handshake = (active_version.valid() == false);

   if(!supported_versions.empty()) {
      if(is_datagram) {
         if(policy.allow_dtls12() && value_exists(supported_versions, Protocol_Version(Protocol_Version::DTLS_V12))) {
            return Protocol_Version::DTLS_V12;
         }
         throw TLS_Exception(Alert::ProtocolVersion, "No shared DTLS version");
      } else {
         if(policy.allow_tls12() && value_exists(supported_versions, Protocol_Version(Protocol_Version::TLS_V12))) {
            return Protocol_Version::TLS_V12;
         }
         throw TLS_Exception(Alert::ProtocolVersion, "No shared TLS version");
      }
   }

   if(!initial_handshake) {
      /*
      * If this is a renegotiation, and the client has offered a
      * later version than what it initially negotiated, negotiate
      * the old version. This matches OpenSSL's behavior. If the
      * client is offering a version earlier than what it initially
      * negotiated, reject as a probable attack.
      */
      if(active_version > client_offer) {
         throw TLS_Exception(
            Alert::ProtocolVersion,
            "Client negotiated " + active_version.to_string() + " then renegotiated with " + client_offer.to_string());
      } else {
         return active_version;
      }
   }

   if(is_datagram) {
      if(policy.allow_dtls12() && client_offer >= Protocol_Version::DTLS_V12) {
         return Protocol_Version::DTLS_V12;
      }
   } else {
      if(policy.allow_tls12() && client_offer >= Protocol_Version::TLS_V12) {
         return Protocol_Version::TLS_V12;
      }
   }

   throw TLS_Exception(Alert::ProtocolVersion,
                       "Client version " + client_offer.to_string() + " is unacceptable by policy");
}
}  // namespace

/*
* Process a Client Hello Message
*/
void Server_Impl_12::process_client_hello_msg(const Handshake_State* active_state,
                                              Server_Handshake_State& pending_state,
                                              const std::vector<uint8_t>& contents,
                                              bool epoch0_restart) {
   BOTAN_ASSERT_IMPLICATION(epoch0_restart, active_state != nullptr, "Can't restart with a dead connection");

   const bool initial_handshake = epoch0_restart || !active_state;

   if(initial_handshake == false && policy().allow_client_initiated_renegotiation() == false) {
      if(policy().abort_connection_on_undesired_renegotiation()) {
         throw TLS_Exception(Alert::NoRenegotiation, "Server policy prohibits renegotiation");
      } else {
         send_warning_alert(Alert::NoRenegotiation);
      }
      return;
   }

   if(!policy().allow_insecure_renegotiation() && !(initial_handshake || secure_renegotiation_supported())) {
      send_warning_alert(Alert::NoRenegotiation);
      return;
   }

   if(pending_state.handshake_io().have_more_data()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Have data remaining in buffer after ClientHello");
   }

   pending_state.client_hello(new Client_Hello_12(contents));
   const Protocol_Version client_offer = pending_state.client_hello()->legacy_version();
   const bool datagram = client_offer.is_datagram_protocol();

   if(datagram) {
      if(client_offer.major_version() == 0xFF) {
         throw TLS_Exception(Alert::ProtocolVersion, "Client offered DTLS version with major version 0xFF");
      }
   } else {
      if(client_offer.major_version() < 3) {
         throw TLS_Exception(Alert::ProtocolVersion, "Client offered TLS version with major version under 3");
      }
      if(client_offer.major_version() == 3 && client_offer.minor_version() == 0) {
         throw TLS_Exception(Alert::ProtocolVersion, "Client offered SSLv3 which is not supported");
      }
   }

   /*
   * BoGo test suite expects that we will send the hello verify with a record
   * version matching the version that is eventually negotiated. This is wrong
   * but harmless, so go with it. Also doing the version negotiation step first
   * allows to immediately close the connection with an alert if the client has
   * offered a version that we are not going to negotiate anyway, instead of
   * making them first do the cookie exchange and then telling them no.
   *
   * There is no issue with amplification here, since the alert is just 2 bytes.
   */
   const Protocol_Version negotiated_version =
      select_version(policy(),
                     client_offer,
                     active_state ? active_state->version() : Protocol_Version(),
                     pending_state.client_hello()->supported_versions());

   pending_state.set_version(negotiated_version);

   const auto compression_methods = pending_state.client_hello()->compression_methods();
   if(!value_exists(compression_methods, uint8_t(0))) {
      throw TLS_Exception(Alert::IllegalParameter, "Client did not offer NULL compression");
   }

   if(initial_handshake && datagram) {
      SymmetricKey cookie_secret;

      try {
         cookie_secret = m_creds->psk("tls-server", "dtls-cookie-secret", "");
      } catch(...) {}

      if(!cookie_secret.empty()) {
         const std::string client_identity = callbacks().tls_peer_network_identity();
         Hello_Verify_Request verify(pending_state.client_hello()->cookie_input_data(), client_identity, cookie_secret);

         if(pending_state.client_hello()->cookie() != verify.cookie()) {
            if(epoch0_restart) {
               pending_state.handshake_io().send_under_epoch(verify, 0);
            } else {
               pending_state.handshake_io().send(verify);
            }

            pending_state.client_hello(static_cast<Client_Hello_12*>(nullptr));
            pending_state.set_expected_next(Handshake_Type::ClientHello);
            return;
         }
      } else if(epoch0_restart) {
         throw TLS_Exception(Alert::HandshakeFailure, "Reuse of DTLS association requires DTLS cookie secret be set");
      }
   }

   if(epoch0_restart) {
      // If we reached here then we were able to verify the cookie
      reset_active_association_state();
   }

   secure_renegotiation_check(pending_state.client_hello());

   callbacks().tls_examine_extensions(
      pending_state.client_hello()->extensions(), Connection_Side::Client, Handshake_Type::ClientHello);

   const auto session_handle = pending_state.client_hello()->session_handle();

   std::optional<Session> session_info;
   if(pending_state.allow_session_resumption() && session_handle.has_value()) {
      session_info = check_for_resume(
         session_handle.value(), session_manager(), callbacks(), policy(), pending_state.client_hello());
   }

   m_next_protocol = "";
   if(pending_state.client_hello()->supports_alpn()) {
      m_next_protocol = callbacks().tls_server_choose_app_protocol(pending_state.client_hello()->next_protocols());
   }

   if(session_info.has_value()) {
      this->session_resume(pending_state, {session_info.value(), session_handle.value()});
   } else {
      // new session
      this->session_create(pending_state);
   }
}

void Server_Impl_12::process_certificate_msg(Server_Handshake_State& pending_state,
                                             const std::vector<uint8_t>& contents) {
   pending_state.client_certs(new Certificate_12(contents, policy()));

   // CERTIFICATE_REQUIRED would make more sense but BoGo expects handshake failure alert
   if(pending_state.client_certs()->empty() && policy().require_client_certificate_authentication()) {
      throw TLS_Exception(Alert::HandshakeFailure, "Policy requires client send a certificate, but it did not");
   }

   pending_state.set_expected_next(Handshake_Type::ClientKeyExchange);
}

void Server_Impl_12::process_client_key_exchange_msg(Server_Handshake_State& pending_state,
                                                     const std::vector<uint8_t>& contents) {
   if(pending_state.received_handshake_msg(Handshake_Type::Certificate) && !pending_state.client_certs()->empty()) {
      pending_state.set_expected_next(Handshake_Type::CertificateVerify);
   } else {
      pending_state.set_expected_next(Handshake_Type::HandshakeCCS);
   }

   pending_state.client_kex(
      new Client_Key_Exchange(contents, pending_state, pending_state.server_rsa_kex_key(), *m_creds, policy(), rng()));

   pending_state.compute_session_keys();
   if(policy().allow_ssl_key_log_file()) {
      // draft-thomson-tls-keylogfile-00 Section 3.2
      //    An implementation of TLS 1.2 (and also earlier versions) use
      //    the label "CLIENT_RANDOM" to identify the "master" secret for
      //    the connection.
      callbacks().tls_ssl_key_log_data(
         "CLIENT_RANDOM", pending_state.client_hello()->random(), pending_state.session_keys().master_secret());
   }
}

void Server_Impl_12::process_change_cipher_spec_msg(Server_Handshake_State& pending_state) {
   pending_state.set_expected_next(Handshake_Type::Finished);
   change_cipher_spec_reader(Connection_Side::Server);
}

void Server_Impl_12::process_certificate_verify_msg(Server_Handshake_State& pending_state,
                                                    Handshake_Type type,
                                                    const std::vector<uint8_t>& contents) {
   pending_state.client_verify(new Certificate_Verify_12(contents));

   const std::vector<X509_Certificate>& client_certs = pending_state.client_certs()->cert_chain();

   if(client_certs.empty()) {
      throw TLS_Exception(Alert::DecodeError, "No client certificate sent");
   }

   if(!client_certs[0].allowed_usage(Key_Constraints::DigitalSignature)) {
      throw TLS_Exception(Alert::BadCertificate, "Client certificate does not support signing");
   }

   const bool sig_valid = pending_state.client_verify()->verify(client_certs[0], pending_state, policy());

   pending_state.hash().update(pending_state.handshake_io().format(contents, type));

   /*
   * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
   * "A handshake cryptographic operation failed, including being
   * unable to correctly verify a signature, ..."
   */
   if(!sig_valid) {
      throw TLS_Exception(Alert::DecryptError, "Client cert verify failed");
   }

   try {
      const std::string sni_hostname = pending_state.client_hello()->sni_hostname();
      auto trusted_CAs = m_creds->trusted_certificate_authorities("tls-server", sni_hostname);

      callbacks().tls_verify_cert_chain(client_certs,
                                        {},  // ocsp
                                        trusted_CAs,
                                        Usage_Type::TLS_CLIENT_AUTH,
                                        sni_hostname,
                                        policy());
   } catch(std::exception& e) {
      throw TLS_Exception(Alert::BadCertificate, e.what());
   }

   pending_state.set_expected_next(Handshake_Type::HandshakeCCS);
}

void Server_Impl_12::process_finished_msg(Server_Handshake_State& pending_state,
                                          Handshake_Type type,
                                          const std::vector<uint8_t>& contents) {
   pending_state.set_expected_next(Handshake_Type::None);

   if(pending_state.handshake_io().have_more_data()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Have data remaining in buffer after Finished");
   }

   pending_state.client_finished(new Finished_12(contents));

   if(!pending_state.client_finished()->verify(pending_state, Connection_Side::Client)) {
      throw TLS_Exception(Alert::DecryptError, "Finished message didn't verify");
   }

   if(!pending_state.server_finished()) {
      // already sent finished if resuming, so this is a new session

      pending_state.hash().update(pending_state.handshake_io().format(contents, type));

      Session session_info(pending_state.session_keys().master_secret(),
                           pending_state.server_hello()->legacy_version(),
                           pending_state.server_hello()->ciphersuite(),
                           Connection_Side::Server,
                           pending_state.server_hello()->supports_extended_master_secret(),
                           pending_state.server_hello()->supports_encrypt_then_mac(),
                           get_peer_cert_chain(pending_state),
                           Server_Information(pending_state.client_hello()->sni_hostname()),
                           pending_state.server_hello()->srtp_profile(),
                           callbacks().tls_current_timestamp());

      // Give the application a chance for a final veto before fully
      // establishing the connection.
      callbacks().tls_session_established([&, this] {
         Session_Summary summary(session_info, pending_state.is_a_resumption(), external_psk_identity());
         summary.set_session_id(pending_state.server_hello()->session_id());
         return summary;
      }());

      if(callbacks().tls_should_persist_resumption_information(session_info)) {
         auto handle = session_manager().establish(session_info,
                                                   pending_state.server_hello()->session_id(),
                                                   !pending_state.server_hello()->supports_session_ticket());

         if(pending_state.server_hello()->supports_session_ticket() && handle.has_value() && handle->is_ticket()) {
            pending_state.new_session_ticket(new New_Session_Ticket_12(pending_state.handshake_io(),
                                                                       pending_state.hash(),
                                                                       handle->ticket().value(),
                                                                       policy().session_ticket_lifetime()));
         }
      }

      if(!pending_state.new_session_ticket() && pending_state.server_hello()->supports_session_ticket()) {
         pending_state.new_session_ticket(
            new New_Session_Ticket_12(pending_state.handshake_io(), pending_state.hash()));
      }

      pending_state.handshake_io().send(Change_Cipher_Spec());

      change_cipher_spec_writer(Connection_Side::Server);

      pending_state.server_finished(
         new Finished_12(pending_state.handshake_io(), pending_state, Connection_Side::Server));
   }

   activate_session();
}

/*
* Process a handshake message
*/
void Server_Impl_12::process_handshake_msg(const Handshake_State* active_state,
                                           Handshake_State& state_base,
                                           Handshake_Type type,
                                           const std::vector<uint8_t>& contents,
                                           bool epoch0_restart) {
   Server_Handshake_State& state = dynamic_cast<Server_Handshake_State&>(state_base);
   state.confirm_transition_to(type);

   /*
   * The change cipher spec message isn't technically a handshake
   * message so it's not included in the hash. The finished and
   * certificate verify messages are verified based on the current
   * state of the hash *before* this message so we delay adding them
   * to the hash computation until we've processed them below.
   */
   if(type != Handshake_Type::HandshakeCCS && type != Handshake_Type::Finished &&
      type != Handshake_Type::CertificateVerify) {
      state.hash().update(state.handshake_io().format(contents, type));
   }

   switch(type) {
      case Handshake_Type::ClientHello:
         return this->process_client_hello_msg(active_state, state, contents, epoch0_restart);

      case Handshake_Type::Certificate:
         return this->process_certificate_msg(state, contents);

      case Handshake_Type::ClientKeyExchange:
         return this->process_client_key_exchange_msg(state, contents);

      case Handshake_Type::CertificateVerify:
         return this->process_certificate_verify_msg(state, type, contents);

      case Handshake_Type::HandshakeCCS:
         return this->process_change_cipher_spec_msg(state);

      case Handshake_Type::Finished:
         return this->process_finished_msg(state, type, contents);

      default:
         throw Unexpected_Message("Unknown handshake message received");
   }
}

void Server_Impl_12::session_resume(Server_Handshake_State& pending_state, const Session_with_Handle& session) {
   // Only offer a resuming client a new ticket if they didn't send one this time,
   // ie, resumed via server-side resumption. TODO: also send one if expiring soon?

   const bool offer_new_session_ticket = pending_state.client_hello()->supports_session_ticket() &&
                                         pending_state.client_hello()->session_ticket().empty() &&
                                         session_manager().emits_session_tickets();

   pending_state.server_hello(new Server_Hello_12(pending_state.handshake_io(),
                                                  pending_state.hash(),
                                                  policy(),
                                                  callbacks(),
                                                  rng(),
                                                  secure_renegotiation_data_for_server_hello(),
                                                  *pending_state.client_hello(),
                                                  session.session,
                                                  offer_new_session_ticket,
                                                  m_next_protocol));

   secure_renegotiation_check(pending_state.server_hello());

   pending_state.mark_as_resumption();
   pending_state.compute_session_keys(session.session.master_secret());
   if(policy().allow_ssl_key_log_file()) {
      // draft-thomson-tls-keylogfile-00 Section 3.2
      //    An implementation of TLS 1.2 (and also earlier versions) use
      //    the label "CLIENT_RANDOM" to identify the "master" secret for
      //    the connection.
      callbacks().tls_ssl_key_log_data(
         "CLIENT_RANDOM", pending_state.client_hello()->random(), pending_state.session_keys().master_secret());
   }
   pending_state.set_resume_certs(session.session.peer_certs());

   // Give the application a chance for a final veto before fully
   // establishing the connection.
   callbacks().tls_session_established([&, this] {
      Session_Summary summary(session.session, pending_state.is_a_resumption(), external_psk_identity());
      summary.set_session_id(pending_state.server_hello()->session_id());
      if(auto ticket = session.handle.ticket()) {
         summary.set_session_ticket(std::move(ticket.value()));
      }
      return summary;
   }());

   auto new_handle = [&, this]() -> std::optional<Session_Handle> {
      if(!callbacks().tls_should_persist_resumption_information(session.session)) {
         session_manager().remove(session.handle);
         return std::nullopt;
      } else {
         return session_manager().establish(session.session, session.handle.id());
      }
   }();

   if(pending_state.server_hello()->supports_session_ticket()) {
      if(new_handle.has_value() && new_handle->is_ticket()) {
         pending_state.new_session_ticket(new New_Session_Ticket_12(pending_state.handshake_io(),
                                                                    pending_state.hash(),
                                                                    new_handle->ticket().value(),
                                                                    policy().session_ticket_lifetime()));
      } else {
         pending_state.new_session_ticket(
            new New_Session_Ticket_12(pending_state.handshake_io(), pending_state.hash()));
      }
   }

   pending_state.handshake_io().send(Change_Cipher_Spec());

   change_cipher_spec_writer(Connection_Side::Server);

   pending_state.server_finished(new Finished_12(pending_state.handshake_io(), pending_state, Connection_Side::Server));
   pending_state.set_expected_next(Handshake_Type::HandshakeCCS);
}

void Server_Impl_12::session_create(Server_Handshake_State& pending_state) {
   std::map<std::string, std::vector<X509_Certificate>> cert_chains;

   const std::string sni_hostname = pending_state.client_hello()->sni_hostname();

   // RFC 8446 1.3
   //    The "signature_algorithms_cert" extension allows a client to indicate
   //    which signature algorithms it can validate in X.509 certificates.
   //
   // RFC 8446 4.2.3
   //     TLS 1.2 implementations SHOULD also process this extension.
   const auto cert_signature_schemes = pending_state.client_hello()->certificate_signature_schemes();
   cert_chains = get_server_certs(sni_hostname, cert_signature_schemes, *m_creds);

   if(!sni_hostname.empty() && cert_chains.empty()) {
      cert_chains = get_server_certs("", cert_signature_schemes, *m_creds);

      /*
      * Only send the unrecognized_name alert if we couldn't
      * find any certs for the requested name but did find at
      * least one cert to use in general. That avoids sending an
      * unrecognized_name when a server is configured for purely
      * anonymous/PSK operation.
      */
      if(!cert_chains.empty()) {
         send_warning_alert(Alert::UnrecognizedName);
      }
   }

   const uint16_t ciphersuite =
      choose_ciphersuite(policy(), pending_state.version(), cert_chains, *pending_state.client_hello());

   Server_Hello_12::Settings srv_settings(Session_ID(make_hello_random(rng(), callbacks(), policy())),
                                          pending_state.version(),
                                          ciphersuite,
                                          session_manager().emits_session_tickets());

   pending_state.server_hello(new Server_Hello_12(pending_state.handshake_io(),
                                                  pending_state.hash(),
                                                  policy(),
                                                  callbacks(),
                                                  rng(),
                                                  secure_renegotiation_data_for_server_hello(),
                                                  *pending_state.client_hello(),
                                                  srv_settings,
                                                  m_next_protocol));

   secure_renegotiation_check(pending_state.server_hello());

   const Ciphersuite& pending_suite = pending_state.ciphersuite();

   std::shared_ptr<Private_Key> private_key;

   if(pending_suite.signature_used() || pending_suite.kex_method() == Kex_Algo::STATIC_RSA) {
      const std::string algo_used = pending_suite.signature_used() ? pending_suite.sig_algo() : "RSA";

      BOTAN_ASSERT(!cert_chains[algo_used].empty(), "Attempting to send empty certificate chain");

      pending_state.server_certs(
         new Certificate_12(pending_state.handshake_io(), pending_state.hash(), cert_chains[algo_used]));

      if(pending_state.client_hello()->supports_cert_status_message() && pending_state.is_a_resumption() == false) {
         auto* csr = pending_state.client_hello()->extensions().get<Certificate_Status_Request>();
         // csr is non-null if client_hello()->supports_cert_status_message()
         BOTAN_ASSERT_NOMSG(csr != nullptr);
         const auto resp_bytes = callbacks().tls_provide_cert_status(cert_chains[algo_used], *csr);
         if(!resp_bytes.empty()) {
            pending_state.server_cert_status(
               new Certificate_Status(pending_state.handshake_io(), pending_state.hash(), resp_bytes));
         }
      }

      private_key = m_creds->private_key_for(pending_state.server_certs()->cert_chain()[0], "tls-server", sni_hostname);

      if(!private_key) {
         throw Internal_Error("No private key located for associated server cert");
      }
   }

   if(pending_suite.kex_method() == Kex_Algo::STATIC_RSA) {
      pending_state.set_server_rsa_kex_key(private_key);
   } else {
      pending_state.server_kex(new Server_Key_Exchange(
         pending_state.handshake_io(), pending_state, policy(), *m_creds, rng(), private_key.get()));
   }

   auto trusted_CAs = m_creds->trusted_certificate_authorities("tls-server", sni_hostname);

   std::vector<X509_DN> client_auth_CAs;

   for(auto* store : trusted_CAs) {
      auto subjects = store->all_subjects();
      client_auth_CAs.insert(client_auth_CAs.end(), subjects.begin(), subjects.end());
   }

   const bool request_cert = (client_auth_CAs.empty() == false) || policy().request_client_certificate_authentication();

   if(request_cert && pending_state.ciphersuite().signature_used()) {
      pending_state.cert_req(
         new Certificate_Request_12(pending_state.handshake_io(), pending_state.hash(), policy(), client_auth_CAs));

      /*
      SSLv3 allowed clients to skip the Certificate message entirely
      if they wanted. In TLS v1.0 and later clients must send a
      (possibly empty) Certificate message
      */
      pending_state.set_expected_next(Handshake_Type::Certificate);
   } else {
      pending_state.set_expected_next(Handshake_Type::ClientKeyExchange);
   }

   pending_state.server_hello_done(new Server_Hello_Done(pending_state.handshake_io(), pending_state.hash()));
}
}  // namespace Botan::TLS

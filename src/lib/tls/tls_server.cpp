/*
* TLS Server
* (C) 2004-2011,2012,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_server.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace TLS {

namespace {

class Server_Handshake_State : public Handshake_State
   {
   public:
      // using Handshake_State::Handshake_State;

      Server_Handshake_State(Handshake_IO* io, handshake_msg_cb cb) : Handshake_State(io, cb) {}

      // Used by the server only, in case of RSA key exchange. Not owned
      Private_Key* server_rsa_kex_key = nullptr;

      /*
      * Used by the server to know if resumption should be allowed on
      * a server-initiated renegotiation
      */
      bool allow_session_resumption = true;
   };

bool check_for_resume(Session& session_info,
                      Session_Manager& session_manager,
                      Credentials_Manager& credentials,
                      const Client_Hello* client_hello,
                      std::chrono::seconds session_ticket_lifetime)
   {
   const std::vector<byte>& client_session_id = client_hello->session_id();
   const std::vector<byte>& session_ticket = client_hello->session_ticket();

   if(session_ticket.empty())
      {
      if(client_session_id.empty()) // not resuming
         return false;

      // not found
      if(!session_manager.load_from_session_id(client_session_id, session_info))
         return false;
      }
   else
      {
      // If a session ticket was sent, ignore client session ID
      try
         {
         session_info = Session::decrypt(
            session_ticket,
            credentials.psk("tls-server", "session-ticket", ""));

         if(session_ticket_lifetime != std::chrono::seconds(0) &&
            session_info.session_age() > session_ticket_lifetime)
            return false; // ticket has expired
         }
      catch(...)
         {
         return false;
         }
      }

   // wrong version
   if(client_hello->version() != session_info.version())
      return false;

   // client didn't send original ciphersuite
   if(!value_exists(client_hello->ciphersuites(),
                    session_info.ciphersuite_code()))
      return false;

   // client didn't send original compression method
   if(!value_exists(client_hello->compression_methods(),
                    session_info.compression_method()))
      return false;

#if defined(BOTAN_HAS_SRP6)
   // client sent a different SRP identity
   if(client_hello->srp_identifier() != "")
      {
      if(client_hello->srp_identifier() != session_info.srp_identifier())
         return false;
      }
#endif

   // client sent a different SNI hostname
   if(client_hello->sni_hostname() != "")
      {
      if(client_hello->sni_hostname() != session_info.server_info().hostname())
         return false;
      }

   // Checking extended_master_secret on resume (RFC 7627 section 5.3)
   if(client_hello->supports_extended_master_secret() != session_info.supports_extended_master_secret())
      {
      if(!session_info.supports_extended_master_secret())
         {
         return false; // force new handshake with extended master secret
         }
      else
         {
         /*
         Client previously negotiated session with extended master secret,
         but has now attempted to resume without the extension: abort
         */
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client resumed extended ms session without sending extension");
         }
      }

   return true;
   }

/*
* Choose which ciphersuite to use
*/
u16bit choose_ciphersuite(
   const Policy& policy,
   Protocol_Version version,
   Credentials_Manager& creds,
   const std::map<std::string, std::vector<X509_Certificate> >& cert_chains,
   const Client_Hello* client_hello)
   {
   const bool our_choice = policy.server_uses_own_ciphersuite_preferences();
   const bool have_srp = creds.attempt_srp("tls-server", client_hello->sni_hostname());
   const std::vector<u16bit> client_suites = client_hello->ciphersuites();
   const std::vector<u16bit> server_suites = policy.ciphersuite_list(version, have_srp);

   if(server_suites.empty())
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                          "Policy forbids us from negotiating any ciphersuite");

   const bool have_shared_ecc_curve =
      (policy.choose_curve(client_hello->supported_ecc_curves()) != "");

   std::vector<u16bit> pref_list = server_suites;
   std::vector<u16bit> other_list = client_suites;

   if(!our_choice)
      std::swap(pref_list, other_list);

   for(auto suite_id : pref_list)
      {
      if(!value_exists(other_list, suite_id))
         continue;

      Ciphersuite suite = Ciphersuite::by_id(suite_id);

      if(!have_shared_ecc_curve && suite.ecc_ciphersuite())
         continue;

      if(suite.sig_algo() != "" && cert_chains.count(suite.sig_algo()) == 0)
         continue;

#if defined(BOTAN_HAS_SRP6)
      /*
      The client may offer SRP cipher suites in the hello message but
      omit the SRP extension.  If the server would like to select an
      SRP cipher suite in this case, the server SHOULD return a fatal
      "unknown_psk_identity" alert immediately after processing the
      client hello message.
       - RFC 5054 section 2.5.1.2
      */
      if(suite.kex_algo() == "SRP_SHA" && client_hello->srp_identifier() == "")
         throw TLS_Exception(Alert::UNKNOWN_PSK_IDENTITY,
                             "Client wanted SRP but did not send username");
#endif

      return suite_id;
      }

   throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                       "Can't agree on a ciphersuite with client");
   }


/*
* Choose which compression algorithm to use
*/
byte choose_compression(const Policy& policy,
                        const std::vector<byte>& c_comp)
   {
   std::vector<byte> s_comp = policy.compression();

   for(size_t i = 0; i != s_comp.size(); ++i)
      for(size_t j = 0; j != c_comp.size(); ++j)
         if(s_comp[i] == c_comp[j])
            return s_comp[i];

   return NO_COMPRESSION;
   }

std::map<std::string, std::vector<X509_Certificate> >
get_server_certs(const std::string& hostname,
                 Credentials_Manager& creds)
   {
   const char* cert_types[] = { "RSA", "DSA", "ECDSA", nullptr };

   std::map<std::string, std::vector<X509_Certificate> > cert_chains;

   for(size_t i = 0; cert_types[i]; ++i)
      {
      std::vector<X509_Certificate> certs =
         creds.cert_chain_single_type(cert_types[i], "tls-server", hostname);

      if(!certs.empty())
         cert_chains[cert_types[i]] = certs;
      }

   return cert_chains;
   }

}

/*
* TLS Server Constructor
*/
Server::Server(output_fn output,
               data_cb data_cb,
               alert_cb alert_cb,
               handshake_cb handshake_cb,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               next_protocol_fn next_proto,
               bool is_datagram,
               size_t io_buf_sz) :
   Channel(output, data_cb, alert_cb, handshake_cb, Channel::handshake_msg_cb(),
           session_manager, rng, policy, is_datagram, io_buf_sz),
   m_creds(creds),
   m_choose_next_protocol(next_proto)
   {
   }

Server::Server(output_fn output,
               data_cb data_cb,
               alert_cb alert_cb,
               handshake_cb handshake_cb,
               handshake_msg_cb hs_msg_cb,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               next_protocol_fn next_proto,
               bool is_datagram) :
   Channel(output, data_cb, alert_cb, handshake_cb, hs_msg_cb,
           session_manager, rng, policy, is_datagram),
   m_creds(creds),
   m_choose_next_protocol(next_proto)
   {
   }

Handshake_State* Server::new_handshake_state(Handshake_IO* io)
   {
   std::unique_ptr<Handshake_State> state(
      new Server_Handshake_State(io, get_handshake_msg_cb()));

   state->set_expected_next(CLIENT_HELLO);
   return state.release();
   }

std::vector<X509_Certificate>
Server::get_peer_cert_chain(const Handshake_State& state) const
   {
   if(state.client_certs())
      return state.client_certs()->cert_chain();
   return std::vector<X509_Certificate>();
   }

/*
* Send a hello request to the client
*/
void Server::initiate_handshake(Handshake_State& state,
                                bool force_full_renegotiation)
   {
   dynamic_cast<Server_Handshake_State&>(state).allow_session_resumption =
      !force_full_renegotiation;

   Hello_Request hello_req(state.handshake_io());
   }

/*
* Process a handshake message
*/
void Server::process_handshake_msg(const Handshake_State* active_state,
                                   Handshake_State& state_base,
                                   Handshake_Type type,
                                   const std::vector<byte>& contents)
   {
   Server_Handshake_State& state = dynamic_cast<Server_Handshake_State&>(state_base);

   state.confirm_transition_to(type);

   /*
   * The change cipher spec message isn't technically a handshake
   * message so it's not included in the hash. The finished and
   * certificate verify messages are verified based on the current
   * state of the hash *before* this message so we delay adding them
   * to the hash computation until we've processed them below.
   */
   if(type != HANDSHAKE_CCS && type != FINISHED && type != CERTIFICATE_VERIFY)
      {
      state.hash().update(state.handshake_io().format(contents, type));
      }

   if(type == CLIENT_HELLO)
      {
      const bool initial_handshake = !active_state;

      if(!policy().allow_insecure_renegotiation() &&
         !(initial_handshake || secure_renegotiation_supported()))
         {
         send_warning_alert(Alert::NO_RENEGOTIATION);
         return;
         }

      state.client_hello(new Client_Hello(contents));

      const Protocol_Version client_version = state.client_hello()->version();

      Protocol_Version negotiated_version;

      const Protocol_Version latest_supported =
         policy().latest_supported_version(client_version.is_datagram_protocol());

      if((initial_handshake && client_version.known_version()) ||
         (!initial_handshake && client_version == active_state->version()))
         {
         /*
         Common cases: new client hello with some known version, or a
         renegotiation using the same version as previously
         negotiated.
         */

         negotiated_version = client_version;
         }
      else if(!initial_handshake && (client_version != active_state->version()))
         {
         /*
         * If this is a renegotiation, and the client has offered a
         * later version than what it initially negotiated, negotiate
         * the old version. This matches OpenSSL's behavior. If the
         * client is offering a version earlier than what it initially
         * negotiated, reject as a probable attack.
         */
         if(active_state->version() > client_version)
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Client negotiated " +
                                active_state->version().to_string() +
                                " then renegotiated with " +
                                client_version.to_string());
            }
         else
            negotiated_version = active_state->version();
         }
      else
         {
         /*
         New negotiation using a version we don't know. Offer them the
         best we currently know and support
         */
         negotiated_version = latest_supported;
         }

      if(!policy().acceptable_protocol_version(negotiated_version))
         {
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Client version " + negotiated_version.to_string() +
                             " is unacceptable by policy");
         }

      if(state.client_hello()->sent_fallback_scsv())
         {
         if(latest_supported > client_version)
            throw TLS_Exception(Alert::INAPPROPRIATE_FALLBACK,
                                "Client signalled fallback SCSV, possible attack");
         }

      secure_renegotiation_check(state.client_hello());

      state.set_version(negotiated_version);

      Session session_info;
      const bool resuming =
         state.allow_session_resumption &&
         check_for_resume(session_info,
                          session_manager(),
                          m_creds,
                          state.client_hello(),
                          std::chrono::seconds(policy().session_ticket_lifetime()));

      bool have_session_ticket_key = false;

      try
         {
         have_session_ticket_key =
            m_creds.psk("tls-server", "session-ticket", "").length() > 0;
         }
      catch(...) {}

      m_next_protocol = "";
      if(m_choose_next_protocol && state.client_hello()->supports_alpn())
         m_next_protocol = m_choose_next_protocol(state.client_hello()->next_protocols());

      if(resuming)
         {
         // Only offer a resuming client a new ticket if they didn't send one this time,
         // ie, resumed via server-side resumption. TODO: also send one if expiring soon?

         const bool offer_new_session_ticket =
            (state.client_hello()->supports_session_ticket() &&
             state.client_hello()->session_ticket().empty() &&
             have_session_ticket_key);

         state.server_hello(new Server_Hello(
               state.handshake_io(),
               state.hash(),
               policy(),
               rng(),
               secure_renegotiation_data_for_server_hello(),
               *state.client_hello(),
               session_info,
               offer_new_session_ticket,
               m_next_protocol
            ));

         secure_renegotiation_check(state.server_hello());

         state.compute_session_keys(session_info.master_secret());

         if(!save_session(session_info))
            {
            session_manager().remove_entry(session_info.session_id());

            if(state.server_hello()->supports_session_ticket()) // send an empty ticket
               {
               state.new_session_ticket(
                  new New_Session_Ticket(state.handshake_io(),
                                         state.hash())
                  );
               }
            }

         if(state.server_hello()->supports_session_ticket() && !state.new_session_ticket())
            {
            try
               {
               const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");

               state.new_session_ticket(
                  new New_Session_Ticket(state.handshake_io(),
                                         state.hash(),
                                         session_info.encrypt(ticket_key, rng()),
                                         policy().session_ticket_lifetime())
                  );
               }
            catch(...) {}

            if(!state.new_session_ticket())
               {
               state.new_session_ticket(
                  new New_Session_Ticket(state.handshake_io(), state.hash())
                  );
               }
            }

         state.handshake_io().send(Change_Cipher_Spec());

         change_cipher_spec_writer(SERVER);

         state.server_finished(new Finished(state.handshake_io(), state, SERVER));
         state.set_expected_next(HANDSHAKE_CCS);
         }
      else // new session
         {
         std::map<std::string, std::vector<X509_Certificate> > cert_chains;

         const std::string sni_hostname = state.client_hello()->sni_hostname();

         cert_chains = get_server_certs(sni_hostname, m_creds);

         if(sni_hostname != "" && cert_chains.empty())
            {
            cert_chains = get_server_certs("", m_creds);

            /*
            * Only send the unrecognized_name alert if we couldn't
            * find any certs for the requested name but did find at
            * least one cert to use in general. That avoids sending an
            * unrecognized_name when a server is configured for purely
            * anonymous operation.
            */
            if(!cert_chains.empty())
               send_alert(Alert(Alert::UNRECOGNIZED_NAME));
            }

         state.server_hello(new Server_Hello(
               state.handshake_io(),
               state.hash(),
               policy(),
               rng(),
               secure_renegotiation_data_for_server_hello(),
               *state.client_hello(),
               make_hello_random(rng(), policy()), // new session ID
               state.version(),
               choose_ciphersuite(policy(), state.version(), m_creds, cert_chains, state.client_hello()),
               choose_compression(policy(), state.client_hello()->compression_methods()),
               have_session_ticket_key,
               m_next_protocol)
            );

         secure_renegotiation_check(state.server_hello());

         const std::string sig_algo = state.ciphersuite().sig_algo();
         const std::string kex_algo = state.ciphersuite().kex_algo();

         if(sig_algo != "")
            {
            BOTAN_ASSERT(!cert_chains[sig_algo].empty(),
                         "Attempting to send empty certificate chain");

            state.server_certs(new Certificate(state.handshake_io(),
                                               state.hash(),
                                               cert_chains[sig_algo]));
            }

         Private_Key* private_key = nullptr;

         if(kex_algo == "RSA" || sig_algo != "")
            {
            private_key = m_creds.private_key_for(
               state.server_certs()->cert_chain()[0],
               "tls-server",
               sni_hostname);

            if(!private_key)
               throw Internal_Error("No private key located for associated server cert");
            }

         if(kex_algo == "RSA")
            {
            state.server_rsa_kex_key = private_key;
            }
         else
            {
            state.server_kex(new Server_Key_Exchange(state.handshake_io(),
                                                     state, policy(),
                                                     m_creds, rng(), private_key));
            }

         auto trusted_CAs = m_creds.trusted_certificate_authorities("tls-server", sni_hostname);

         std::vector<X509_DN> client_auth_CAs;

         for(auto store : trusted_CAs)
            {
            auto subjects = store->all_subjects();
            client_auth_CAs.insert(client_auth_CAs.end(), subjects.begin(), subjects.end());
            }

         if(!client_auth_CAs.empty() && state.ciphersuite().sig_algo() != "")
            {
            state.cert_req(
               new Certificate_Req(state.handshake_io(), state.hash(),
                                   policy(), client_auth_CAs, state.version()));

            state.set_expected_next(CERTIFICATE);
            }

         /*
         * If the client doesn't have a cert they want to use they are
         * allowed to send either an empty cert message or proceed
         * directly to the client key exchange, so allow either case.
         */
         state.set_expected_next(CLIENT_KEX);

         state.server_hello_done(new Server_Hello_Done(state.handshake_io(), state.hash()));
         }
      }
   else if(type == CERTIFICATE)
      {
      state.client_certs(new Certificate(contents));

      state.set_expected_next(CLIENT_KEX);
      }
   else if(type == CLIENT_KEX)
      {
      if(state.received_handshake_msg(CERTIFICATE) && !state.client_certs()->empty())
         state.set_expected_next(CERTIFICATE_VERIFY);
      else
         state.set_expected_next(HANDSHAKE_CCS);

      state.client_kex(
         new Client_Key_Exchange(contents, state,
                                 state.server_rsa_kex_key,
                                 m_creds, policy(), rng())
         );

      state.compute_session_keys();
      }
   else if(type == CERTIFICATE_VERIFY)
      {
      state.client_verify(new Certificate_Verify(contents, state.version()));

      const std::vector<X509_Certificate>& client_certs =
         state.client_certs()->cert_chain();

      const bool sig_valid =
         state.client_verify()->verify(client_certs[0], state, policy());

      state.hash().update(state.handshake_io().format(contents, type));

      /*
      * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
      * "A handshake cryptographic operation failed, including being
      * unable to correctly verify a signature, ..."
      */
      if(!sig_valid)
         throw TLS_Exception(Alert::DECRYPT_ERROR, "Client cert verify failed");

      try
         {
         m_creds.verify_certificate_chain("tls-server", "", client_certs);
         }
      catch(std::exception& e)
         {
         throw TLS_Exception(Alert::BAD_CERTIFICATE, e.what());
         }

      state.set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      state.set_expected_next(FINISHED);
      change_cipher_spec_reader(SERVER);
      }
   else if(type == FINISHED)
      {
      state.set_expected_next(HANDSHAKE_NONE);

      state.client_finished(new Finished(contents));

      if(!state.client_finished()->verify(state, CLIENT))
         throw TLS_Exception(Alert::DECRYPT_ERROR,
                             "Finished message didn't verify");

      if(!state.server_finished())
         {
         // already sent finished if resuming, so this is a new session

         state.hash().update(state.handshake_io().format(contents, type));

         Session session_info(
            state.server_hello()->session_id(),
            state.session_keys().master_secret(),
            state.server_hello()->version(),
            state.server_hello()->ciphersuite(),
            state.server_hello()->compression_method(),
            SERVER,
            state.server_hello()->supports_extended_master_secret(),
            get_peer_cert_chain(state),
            std::vector<byte>(),
            Server_Information(state.client_hello()->sni_hostname()),
            state.srp_identifier(),
            state.server_hello()->srtp_profile()
            );

         if(save_session(session_info))
            {
            if(state.server_hello()->supports_session_ticket())
               {
               try
                  {
                  const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");

                  state.new_session_ticket(
                     new New_Session_Ticket(state.handshake_io(),
                                            state.hash(),
                                            session_info.encrypt(ticket_key, rng()),
                                            policy().session_ticket_lifetime())
                     );
                  }
               catch(...) {}
               }
            else
               session_manager().save(session_info);
            }

         if(!state.new_session_ticket() &&
            state.server_hello()->supports_session_ticket())
            {
            state.new_session_ticket(
               new New_Session_Ticket(state.handshake_io(), state.hash())
               );
            }

         state.handshake_io().send(Change_Cipher_Spec());

         change_cipher_spec_writer(SERVER);

         state.server_finished(new Finished(state.handshake_io(), state, SERVER));
         }

      activate_session();
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

}

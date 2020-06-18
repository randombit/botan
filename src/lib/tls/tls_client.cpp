/*
* TLS Client
* (C) 2004-2011,2012,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_client.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/stl_util.h>
#include <iterator>
#include <sstream>

namespace Botan {

namespace TLS {

namespace {

class Client_Handshake_State final : public Handshake_State
   {
   public:
      Client_Handshake_State(Handshake_IO* io, Callbacks& cb) :
         Handshake_State(io, cb),
         m_is_reneg(false)
         {}

      const Public_Key& get_server_public_key() const
         {
         BOTAN_ASSERT(server_public_key, "Server sent us a certificate");
         return *server_public_key.get();
         }

      bool is_a_resumption() const { return (resumed_session != nullptr); }

      bool is_a_renegotiation() const { return m_is_reneg; }

      const secure_vector<uint8_t>& resume_master_secret() const
         {
         BOTAN_STATE_CHECK(is_a_resumption());
         return resumed_session->master_secret();
         }

      const std::vector<X509_Certificate>& resume_peer_certs() const
         {
         BOTAN_STATE_CHECK(is_a_resumption());
         return resumed_session->peer_certs();
         }

      std::unique_ptr<Public_Key> server_public_key;
      // Used during session resumption
      std::unique_ptr<Session> resumed_session;
      bool m_is_reneg = false;
   };

}

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
               const std::vector<std::string>& next_protos,
               size_t io_buf_sz) :
   Channel(callbacks, session_manager, rng, policy,
           false, offer_version.is_datagram_protocol(), io_buf_sz),
   m_creds(creds),
   m_info(info)
   {
   init(offer_version, next_protos);
   }

Client::Client(output_fn data_output_fn,
               data_cb proc_cb,
               alert_cb recv_alert_cb,
               handshake_cb hs_cb,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const Server_Information& info,
               const Protocol_Version& offer_version,
               const std::vector<std::string>& next_protos,
               size_t io_buf_sz) :
   Channel(data_output_fn, proc_cb, recv_alert_cb, hs_cb, Channel::handshake_msg_cb(),
           session_manager, rng, policy, false, offer_version.is_datagram_protocol(), io_buf_sz),
   m_creds(creds),
   m_info(info)
   {
   init(offer_version, next_protos);
   }

Client::Client(output_fn data_output_fn,
               data_cb proc_cb,
               alert_cb recv_alert_cb,
               handshake_cb hs_cb,
               handshake_msg_cb hs_msg_cb,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const Server_Information& info,
               const Protocol_Version& offer_version,
               const std::vector<std::string>& next_protos) :
   Channel(data_output_fn, proc_cb, recv_alert_cb, hs_cb, hs_msg_cb,
           session_manager, rng, policy, false, offer_version.is_datagram_protocol()),
   m_creds(creds),
   m_info(info)
   {
   init(offer_version, next_protos);
   }

void Client::init(const Protocol_Version& protocol_version,
                  const std::vector<std::string>& next_protocols)
   {
   const std::string srp_identifier = m_creds.srp_identifier("tls-client", m_info.hostname());

   Handshake_State& state = create_handshake_state(protocol_version);
   send_client_hello(state, false, protocol_version,
                     srp_identifier, next_protocols);
   }

Handshake_State* Client::new_handshake_state(Handshake_IO* io)
   {
   return new Client_Handshake_State(io, callbacks());
   }

std::vector<X509_Certificate>
Client::get_peer_cert_chain(const Handshake_State& state) const
   {
   const Client_Handshake_State& cstate = dynamic_cast<const Client_Handshake_State&>(state);

   if(cstate.is_a_resumption())
      return cstate.resume_peer_certs();

   if(state.server_certs())
      return state.server_certs()->cert_chain();
   return std::vector<X509_Certificate>();
   }

/*
* Send a new client hello to renegotiate
*/
void Client::initiate_handshake(Handshake_State& state,
                                bool force_full_renegotiation)
   {
   send_client_hello(state, force_full_renegotiation,
                     policy().latest_supported_version(state.version().is_datagram_protocol()));
   }

void Client::send_client_hello(Handshake_State& state_base,
                               bool force_full_renegotiation,
                               Protocol_Version version,
                               const std::string& srp_identifier,
                               const std::vector<std::string>& next_protocols)
   {
   Client_Handshake_State& state = dynamic_cast<Client_Handshake_State&>(state_base);

   if(state.version().is_datagram_protocol())
      state.set_expected_next(HELLO_VERIFY_REQUEST); // optional
   state.set_expected_next(SERVER_HELLO);

   if(!force_full_renegotiation && !m_info.empty())
      {
      std::unique_ptr<Session> session_info(new Session);;
      if(session_manager().load_from_server_info(m_info, *session_info))
         {
         /*
         Ensure that the session protocol cipher and version are acceptable
         If not skip the resume and establish a new session
         */
         const bool exact_version = session_info->version() == version;
         const bool ok_version =
            (session_info->version().is_datagram_protocol() == version.is_datagram_protocol()) &&
            policy().acceptable_protocol_version(session_info->version());

         const bool session_version_ok = policy().only_resume_with_exact_version() ? exact_version : ok_version;

         if(policy().acceptable_ciphersuite(session_info->ciphersuite()) && session_version_ok)
            {
            if(srp_identifier == "" || session_info->srp_identifier() == srp_identifier)
               {
               state.client_hello(
                  new Client_Hello(state.handshake_io(),
                                   state.hash(),
                                   policy(),
                                   callbacks(),
                                   rng(),
                                   secure_renegotiation_data_for_client_hello(),
                                   *session_info,
                                   next_protocols));

               state.resumed_session = std::move(session_info);
               }
            }
         }
      }

   if(!state.client_hello()) // not resuming
      {
      Client_Hello::Settings client_settings(version, m_info.hostname(), srp_identifier);
      state.client_hello(new Client_Hello(
         state.handshake_io(),
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

bool key_usage_matches_ciphersuite(Key_Constraints usage,
                                   const Ciphersuite& suite)
   {
   if(usage == NO_CONSTRAINTS)
      return true; // anything goes ...

   if(suite.kex_method() == Kex_Algo::STATIC_RSA)
      {
      return (usage & KEY_ENCIPHERMENT) | (usage & DATA_ENCIPHERMENT);
      }
   else
      {
      return (usage & DIGITAL_SIGNATURE) | (usage & NON_REPUDIATION);
      }
   }

}

/*
* Process a handshake message
*/
void Client::process_handshake_msg(const Handshake_State* active_state,
                                   Handshake_State& state_base,
                                   Handshake_Type type,
                                   const std::vector<uint8_t>& contents,
                                   bool epoch0_restart)
   {
   BOTAN_ASSERT_NOMSG(epoch0_restart == false); // only happens on server side

   Client_Handshake_State& state = dynamic_cast<Client_Handshake_State&>(state_base);

   if(type == HELLO_REQUEST && active_state)
      {
      Hello_Request hello_request(contents);

      if(state.client_hello())
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "Cannot renegotiate during a handshake");
         }

      if(policy().allow_server_initiated_renegotiation())
         {
         if(secure_renegotiation_supported() || policy().allow_insecure_renegotiation())
            {
            state.m_is_reneg = true;
            this->initiate_handshake(state, true);
            }
         else
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "Client policy prohibits insecure renegotiation");
            }
         }
      else
         {
         if(policy().abort_connection_on_undesired_renegotiation())
            {
            throw TLS_Exception(Alert::NO_RENEGOTIATION, "Client policy prohibits renegotiation");
            }
         else
            {
            // RFC 5746 section 4.2
            send_warning_alert(Alert::NO_RENEGOTIATION);
            }
         }

      return;
      }

   state.confirm_transition_to(type);

   if(type != HANDSHAKE_CCS && type != FINISHED && type != HELLO_VERIFY_REQUEST)
      state.hash().update(state.handshake_io().format(contents, type));

   if(type == HELLO_VERIFY_REQUEST)
      {
      state.set_expected_next(SERVER_HELLO);
      state.set_expected_next(HELLO_VERIFY_REQUEST); // might get it again

      Hello_Verify_Request hello_verify_request(contents);
      state.hello_verify_request(hello_verify_request);
      }
   else if(type == SERVER_HELLO)
      {
      state.server_hello(new Server_Hello(contents));

      if(!state.client_hello()->offered_suite(state.server_hello()->ciphersuite()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with ciphersuite we didn't send");
         }

      if(!Ciphersuite::by_id(state.server_hello()->ciphersuite()).usable_in_version(state.server_hello()->version()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied using a ciphersuite not allowed in version it offered");
         }

      if(Ciphersuite::is_scsv(state.server_hello()->ciphersuite()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with a signaling ciphersuite");
         }

      if(state.server_hello()->compression_method() != 0)
         {
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                             "Server replied with non-null compression method");
         }

      if(state.client_hello()->version() > state.server_hello()->version())
         {
         if(state.server_hello()->random_signals_downgrade())
            throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Downgrade attack detected");
         }

      auto client_extn = state.client_hello()->extension_types();
      auto server_extn = state.server_hello()->extension_types();

      std::vector<Handshake_Extension_Type> diff;

      std::set_difference(server_extn.begin(), server_extn.end(),
                          client_extn.begin(), client_extn.end(),
                          std::back_inserter(diff));

      if(!diff.empty())
         {
         // Server sent us back an extension we did not send!

         std::ostringstream msg;
         msg << "Server replied with unsupported extensions:";
         for(auto&& d : diff)
            msg << " " << static_cast<int>(d);
         throw TLS_Exception(Alert::UNSUPPORTED_EXTENSION, msg.str());
         }

      if(uint16_t srtp = state.server_hello()->srtp_profile())
         {
         if(!value_exists(state.client_hello()->srtp_profiles(), srtp))
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server replied with DTLS-SRTP alg we did not send");
         }

      callbacks().tls_examine_extensions(state.server_hello()->extensions(), SERVER);

      state.set_version(state.server_hello()->version());
      m_application_protocol = state.server_hello()->next_protocol();

      secure_renegotiation_check(state.server_hello());

      const bool server_returned_same_session_id =
         !state.server_hello()->session_id().empty() &&
         (state.server_hello()->session_id() == state.client_hello()->session_id());

      if(server_returned_same_session_id)
         {
         // successful resumption

         /*
         * In this case, we offered the version used in the original
         * session, and the server must resume with the same version.
         */
         if(state.server_hello()->version() != state.client_hello()->version())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server resumed session but with wrong version");

         if(state.server_hello()->supports_extended_master_secret() &&
            !state.resumed_session->supports_extended_master_secret())
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server resumed session but added extended master secret");
            }

         if(!state.server_hello()->supports_extended_master_secret() &&
            state.resumed_session->supports_extended_master_secret())
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server resumed session and removed extended master secret");
            }

         state.compute_session_keys(state.resume_master_secret());

         if(state.server_hello()->supports_session_ticket())
            {
            state.set_expected_next(NEW_SESSION_TICKET);
            }
         else
            {
            state.set_expected_next(HANDSHAKE_CCS);
            }
         }
      else
         {
         // new session

         if(active_state)
            {
            // Here we are testing things that should not change during a renegotation,
            // even if the server creates a new session. Howerver they might change
            // in a resumption scenario.

            if(active_state->version() != state.server_hello()->version())
               throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                   "Server changed version after renegotiation");

            if(state.server_hello()->supports_extended_master_secret() !=
               active_state->server_hello()->supports_extended_master_secret())
               {
               throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                   "Server changed its mind about extended master secret");
               }
            }

         state.resumed_session.reset(); // non-null if we were attempting a resumption

         if(state.client_hello()->version().is_datagram_protocol() !=
            state.server_hello()->version().is_datagram_protocol())
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Server replied with different protocol type than we offered");
            }

         if(state.version() > state.client_hello()->version())
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server replied with later version than client offered");
            }

         if(state.version().major_version() == 3 && state.version().minor_version() == 0)
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Server attempting to negotiate SSLv3 which is not supported");
            }

         if(!policy().acceptable_protocol_version(state.version()))
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Server version " + state.version().to_string() +
                                " is unacceptable by policy");
            }

         if(state.ciphersuite().signature_used() || state.ciphersuite().kex_method() == Kex_Algo::STATIC_RSA)
            {
            state.set_expected_next(CERTIFICATE);
            }
         else if(state.ciphersuite().kex_method() == Kex_Algo::PSK)
            {
            /* PSK is anonymous so no certificate/cert req message is
               ever sent. The server may or may not send a server kex,
               depending on if it has an identity hint for us.

               (EC)DHE_PSK always sends a server key exchange for the
               DH exchange portion, and is covered by block below
            */

            state.set_expected_next(SERVER_KEX);
            state.set_expected_next(SERVER_HELLO_DONE);
            }
         else if(state.ciphersuite().kex_method() != Kex_Algo::STATIC_RSA)
            {
            state.set_expected_next(SERVER_KEX);
            }
         else
            {
            state.set_expected_next(CERTIFICATE_REQUEST); // optional
            state.set_expected_next(SERVER_HELLO_DONE);
            }
         }
      }
   else if(type == CERTIFICATE)
      {
      state.server_certs(new Certificate(contents, policy()));

      const std::vector<X509_Certificate>& server_certs =
         state.server_certs()->cert_chain();

      if(server_certs.empty())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client: No certificates sent by server");

      /*
      If the server supports certificate status messages,
      certificate verification happens after we receive the server hello done,
      in case an OCSP response was also available
      */

      X509_Certificate server_cert = server_certs[0];

      if(active_state && active_state->server_certs())
         {
         X509_Certificate current_cert = active_state->server_certs()->cert_chain().at(0);

         if(current_cert != server_cert)
            throw TLS_Exception(Alert::BAD_CERTIFICATE, "Server certificate changed during renegotiation");
         }

      std::unique_ptr<Public_Key> peer_key(server_cert.subject_public_key());

      const std::string expected_key_type =
         state.ciphersuite().signature_used() ? state.ciphersuite().sig_algo() : "RSA";

      if(peer_key->algo_name() != expected_key_type)
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");

      if(!key_usage_matches_ciphersuite(server_cert.constraints(), state.ciphersuite()))
         throw TLS_Exception(Alert::BAD_CERTIFICATE,
                             "Certificate usage constraints do not allow this ciphersuite");

      state.server_public_key.reset(peer_key.release());

      if(state.ciphersuite().kex_method() != Kex_Algo::STATIC_RSA)
         {
         state.set_expected_next(SERVER_KEX);
         }
      else
         {
         state.set_expected_next(CERTIFICATE_REQUEST); // optional
         state.set_expected_next(SERVER_HELLO_DONE);
         }

      if(state.server_hello()->supports_certificate_status_message())
         {
         state.set_expected_next(CERTIFICATE_STATUS); // optional
         }
      else
         {
         try
            {
            auto trusted_CAs = m_creds.trusted_certificate_authorities("tls-client", m_info.hostname());

            callbacks().tls_verify_cert_chain(server_certs,
                                              {},
                                              trusted_CAs,
                                              Usage_Type::TLS_SERVER_AUTH,
                                              m_info.hostname(),
                                              policy());
            }
         catch(TLS_Exception&)
            {
            throw;
            }
         catch(std::exception& e)
            {
            throw TLS_Exception(Alert::INTERNAL_ERROR, e.what());
            }
         }
      }
   else if(type == CERTIFICATE_STATUS)
      {
      state.server_cert_status(new Certificate_Status(contents));

      if(state.ciphersuite().kex_method() != Kex_Algo::STATIC_RSA)
         {
         state.set_expected_next(SERVER_KEX);
         }
      else
         {
         state.set_expected_next(CERTIFICATE_REQUEST); // optional
         state.set_expected_next(SERVER_HELLO_DONE);
         }
      }
   else if(type == SERVER_KEX)
      {
      if(state.ciphersuite().psk_ciphersuite() == false)
         state.set_expected_next(CERTIFICATE_REQUEST); // optional
      state.set_expected_next(SERVER_HELLO_DONE);

      state.server_kex(
         new Server_Key_Exchange(contents,
                                 state.ciphersuite().kex_method(),
                                 state.ciphersuite().auth_method(),
                                 state.version())
         );

      if(state.ciphersuite().signature_used())
         {
         const Public_Key& server_key = state.get_server_public_key();

         if(!state.server_kex()->verify(server_key, state, policy()))
            {
            throw TLS_Exception(Alert::DECRYPT_ERROR,
                                "Bad signature on server key exchange");
            }
         }
      }
   else if(type == CERTIFICATE_REQUEST)
      {
      state.set_expected_next(SERVER_HELLO_DONE);
      state.cert_req(new Certificate_Req(contents, state.version()));
      }
   else if(type == SERVER_HELLO_DONE)
      {
      state.server_hello_done(new Server_Hello_Done(contents));

      if(state.server_certs() != nullptr &&
         state.server_hello()->supports_certificate_status_message())
         {
         try
            {
            auto trusted_CAs = m_creds.trusted_certificate_authorities("tls-client", m_info.hostname());

            std::vector<std::shared_ptr<const OCSP::Response>> ocsp;
            if(state.server_cert_status() != nullptr)
               {
               try {
                   ocsp.push_back(std::make_shared<OCSP::Response>(state.server_cert_status()->response()));
               }
               catch(Decoding_Error&)
                  {
                  // ignore it here because it might be our fault
                  }
               }

            callbacks().tls_verify_cert_chain(state.server_certs()->cert_chain(),
                                              ocsp,
                                              trusted_CAs,
                                              Usage_Type::TLS_SERVER_AUTH,
                                              m_info.hostname(),
                                              policy());
            }
         catch(TLS_Exception&)
            {
            throw;
            }
         catch(std::exception& e)
            {
            throw TLS_Exception(Alert::INTERNAL_ERROR, e.what());
            }
         }

      if(state.received_handshake_msg(CERTIFICATE_REQUEST))
         {
         const auto& types = state.cert_req()->acceptable_cert_types();

         std::vector<X509_Certificate> client_certs =
            m_creds.find_cert_chain(types,
                                    state.cert_req()->acceptable_CAs(),
                                    "tls-client",
                                    m_info.hostname());

         state.client_certs(new Certificate(state.handshake_io(),
                                            state.hash(),
                                            client_certs));
         }

      state.client_kex(
         new Client_Key_Exchange(state.handshake_io(),
                                 state,
                                 policy(),
                                 m_creds,
                                 state.server_public_key.get(),
                                 m_info.hostname(),
                                 rng())
         );

      state.compute_session_keys();

      if(state.received_handshake_msg(CERTIFICATE_REQUEST) &&
         !state.client_certs()->empty())
         {
         Private_Key* private_key =
            m_creds.private_key_for(state.client_certs()->cert_chain()[0],
                                    "tls-client",
                                    m_info.hostname());

         state.client_verify(
            new Certificate_Verify(state.handshake_io(),
                                   state,
                                   policy(),
                                   rng(),
                                   private_key)
            );
         }

      state.handshake_io().send(Change_Cipher_Spec());

      change_cipher_spec_writer(CLIENT);

      state.client_finished(new Finished(state.handshake_io(), state, CLIENT));

      if(state.server_hello()->supports_session_ticket())
         state.set_expected_next(NEW_SESSION_TICKET);
      else
         state.set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == NEW_SESSION_TICKET)
      {
      state.new_session_ticket(new New_Session_Ticket(contents));

      state.set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      state.set_expected_next(FINISHED);

      change_cipher_spec_reader(CLIENT);
      }
   else if(type == FINISHED)
      {
      state.server_finished(new Finished(contents));

      if(!state.server_finished()->verify(state, SERVER))
         throw TLS_Exception(Alert::DECRYPT_ERROR,
                             "Finished message didn't verify");

      state.hash().update(state.handshake_io().format(contents, type));

      if(!state.client_finished()) // session resume case
         {
         state.handshake_io().send(Change_Cipher_Spec());
         change_cipher_spec_writer(CLIENT);
         state.client_finished(new Finished(state.handshake_io(), state, CLIENT));
         }

      std::vector<uint8_t> session_id = state.server_hello()->session_id();

      const std::vector<uint8_t>& session_ticket = state.session_ticket();

      if(session_id.empty() && !session_ticket.empty())
         session_id = make_hello_random(rng(), policy());

      Session session_info(
         session_id,
         state.session_keys().master_secret(),
         state.server_hello()->version(),
         state.server_hello()->ciphersuite(),
         CLIENT,
         state.server_hello()->supports_extended_master_secret(),
         state.server_hello()->supports_encrypt_then_mac(),
         get_peer_cert_chain(state),
         session_ticket,
         m_info,
         "",
         state.server_hello()->srtp_profile()
         );

      const bool should_save = save_session(session_info);

      if(session_id.size() > 0 && state.is_a_resumption() == false)
         {
         if(should_save)
            session_manager().save(session_info);
         else
            session_manager().remove_entry(session_info.session_id());
         }

      activate_session();
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

}

/*
* TLS Client
* (C) 2004-2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_client.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/stl_util.h>
#include <memory>

namespace Botan {

namespace TLS {

namespace {

class Client_Handshake_State : public Handshake_State
   {
   public:
      // using Handshake_State::Handshake_State;

      Client_Handshake_State(Handshake_IO* io,
                             std::function<void (const Handshake_Message&)> msg_callback =
                                std::function<void (const Handshake_Message&)>()) :
         Handshake_State(io, msg_callback) {}

      // Used during session resumption
      secure_vector<byte> resume_master_secret;

      // Used by client using NPN
      std::function<std::string (std::vector<std::string>)> client_npn_cb;
   };

}

/*
* TLS Client Constructor
*/
Client::Client(std::function<void (const byte[], size_t)> output_fn,
               std::function<void (const byte[], size_t, Alert)> proc_fn,
               std::function<bool (const Session&)> handshake_fn,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const std::string& hostname,
               u16bit port,
               std::function<std::string (std::vector<std::string>)> next_protocol) :
   Channel(output_fn, proc_fn, handshake_fn, session_manager, rng),
   m_policy(policy),
   m_creds(creds),
   m_hostname(hostname),
   m_port(port)
   {
   const std::string srp_identifier = m_creds.srp_identifier("tls-client", m_hostname);

   Handshake_State& state = create_handshake_state();
   const Protocol_Version version = m_policy.pref_version();
   initiate_handshake(state, false, version, srp_identifier, next_protocol);
   }

Handshake_State* Client::new_handshake_state()
   {
   using namespace std::placeholders;

   return new Client_Handshake_State(
      new Stream_Handshake_IO(
         [this](byte type, const std::vector<byte>& rec)
            { this->send_record(type, rec); }
         )
      );
   }

/*
* Send a new client hello to renegotiate
*/
void Client::initiate_handshake(Handshake_State& state,
                                bool force_full_renegotiation)
   {
   initiate_handshake(state,
                      force_full_renegotiation,
                      current_protocol_version());
   }

void Client::initiate_handshake(Handshake_State& state,
                                bool force_full_renegotiation,
                                Protocol_Version version,
                                const std::string& srp_identifier,
                                std::function<std::string (std::vector<std::string>)> next_protocol)
   {
   if(state.version().is_datagram_protocol())
      state.set_expected_next(HELLO_VERIFY_REQUEST);
   state.set_expected_next(SERVER_HELLO);

   dynamic_cast<Client_Handshake_State&>(state).client_npn_cb = next_protocol;

   const bool send_npn_request = static_cast<bool>(next_protocol);

   if(!force_full_renegotiation && m_hostname != "")
      {
      Session session_info;
      if(m_session_manager.load_from_host_info(m_hostname, m_port, session_info))
         {
         if(srp_identifier == "" || session_info.srp_identifier() == srp_identifier)
            {
            state.client_hello(new Client_Hello(
               state.handshake_io(),
               state.hash(),
               m_policy,
               m_rng,
               m_secure_renegotiation.for_client_hello(),
               session_info,
               send_npn_request));

            dynamic_cast<Client_Handshake_State&>(state).resume_master_secret =
               session_info.master_secret();
            }
         }
      }

   if(!state.client_hello()) // not resuming
      {
      state.client_hello(new Client_Hello(
         state.handshake_io(),
         state.hash(),
         version,
         m_policy,
         m_rng,
         m_secure_renegotiation.for_client_hello(),
         send_npn_request,
         m_hostname,
         srp_identifier));
      }

   m_secure_renegotiation.update(state.client_hello());

   set_maximum_fragment_size(state.client_hello()->fragment_size());
   }

/*
* Process a handshake message
*/
void Client::process_handshake_msg(const Handshake_State* /*active_state*/,
                                   Handshake_State& state,
                                   Handshake_Type type,
                                   const std::vector<byte>& contents)
   {
   if(type == HELLO_REQUEST)
      {
      Hello_Request hello_request(contents);

      // Ignore request entirely if we are currently negotiating a handshake
      if(state.client_hello())
         return;

      if(!m_policy.allow_server_initiated_renegotiation() ||
         (!m_policy.allow_insecure_renegotiation() && !m_secure_renegotiation.supported()))
         {
         // RFC 5746 section 4.2
         send_alert(Alert(Alert::NO_RENEGOTIATION));
         return;
         }

      this->initiate_handshake(state, false);

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

      state.note_message(hello_verify_request);

      std::unique_ptr<Client_Hello> client_hello_w_cookie(
         new Client_Hello(state.handshake_io(),
                          state.hash(),
                          *state.client_hello(),
                          hello_verify_request));

      state.client_hello(client_hello_w_cookie.release());
      }
   else if(type == SERVER_HELLO)
      {
      state.server_hello(new Server_Hello(contents));

      if(!state.client_hello()->offered_suite(state.server_hello()->ciphersuite()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with ciphersuite we didn't send");
         }

      if(!value_exists(state.client_hello()->compression_methods(),
                       state.server_hello()->compression_method()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with compression method we didn't send");
         }

      if(!state.client_hello()->next_protocol_notification() &&
         state.server_hello()->next_protocol_notification())
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server sent next protocol but we didn't request it");
         }

      if(state.server_hello()->supports_session_ticket())
         {
         if(!state.client_hello()->supports_session_ticket())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server sent session ticket extension but we did not");
         }

      set_protocol_version(state.server_hello()->version());

      m_secure_renegotiation.update(state.server_hello());

      heartbeat_support(state.server_hello()->supports_heartbeats(),
                        state.server_hello()->peer_can_send_heartbeats());

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

         state.compute_session_keys(
            dynamic_cast<Client_Handshake_State&>(state).resume_master_secret
            );

         if(state.server_hello()->supports_session_ticket())
            state.set_expected_next(NEW_SESSION_TICKET);
         else
            state.set_expected_next(HANDSHAKE_CCS);
         }
      else
         {
         // new session

         if(state.version() > state.client_hello()->version())
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server replied with later version than in hello");
            }

         if(!m_policy.acceptable_protocol_version(state.version()))
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Server version is unacceptable by policy");
            }

         if(state.ciphersuite().sig_algo() != "")
            {
            state.set_expected_next(CERTIFICATE);
            }
         else if(state.ciphersuite().kex_algo() == "PSK")
            {
            /* PSK is anonymous so no certificate/cert req message is
               ever sent. The server may or may not send a server kex,
               depending on if it has an identity hint for us.

               (EC)DHE_PSK always sends a server key exchange for the
               DH exchange portion.
            */

            state.set_expected_next(SERVER_KEX);
            state.set_expected_next(SERVER_HELLO_DONE);
            }
         else if(state.ciphersuite().kex_algo() != "RSA")
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
      if(state.ciphersuite().kex_algo() != "RSA")
         {
         state.set_expected_next(SERVER_KEX);
         }
      else
         {
         state.set_expected_next(CERTIFICATE_REQUEST); // optional
         state.set_expected_next(SERVER_HELLO_DONE);
         }

      state.server_certs(new Certificate(contents));

      m_peer_certs = state.server_certs()->cert_chain();
      if(m_peer_certs.empty())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client: No certificates sent by server");

      try
         {
         m_creds.verify_certificate_chain("tls-client", m_hostname, m_peer_certs);
         }
      catch(std::exception& e)
         {
         throw TLS_Exception(Alert::BAD_CERTIFICATE, e.what());
         }

      std::unique_ptr<Public_Key> peer_key(m_peer_certs[0].subject_public_key());

      if(peer_key->algo_name() != state.ciphersuite().sig_algo())
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");
      }
   else if(type == SERVER_KEX)
      {
      state.set_expected_next(CERTIFICATE_REQUEST); // optional
      state.set_expected_next(SERVER_HELLO_DONE);

      state.server_kex(
         new Server_Key_Exchange(contents,
                                 state.ciphersuite().kex_algo(),
                                 state.ciphersuite().sig_algo(),
                                 state.version())
         );

      if(state.ciphersuite().sig_algo() != "")
         {
         if(!state.server_kex()->verify(m_peer_certs[0], state))
            {
            throw TLS_Exception(Alert::DECRYPT_ERROR,
                                "Bad signature on server key exchange");
            }
         }
      }
   else if(type == CERTIFICATE_REQUEST)
      {
      state.set_expected_next(SERVER_HELLO_DONE);
      state.cert_req(
         new Certificate_Req(contents, state.version())
         );
      }
   else if(type == SERVER_HELLO_DONE)
      {
      state.server_hello_done(
         new Server_Hello_Done(contents)
         );

      if(state.received_handshake_msg(CERTIFICATE_REQUEST))
         {
         const std::vector<std::string>& types =
            state.cert_req()->acceptable_cert_types();

         std::vector<X509_Certificate> client_certs =
            m_creds.cert_chain(types,
                               "tls-client",
                               m_hostname);

         state.client_certs(
            new Certificate(state.handshake_io(),
                            state.hash(),
                            client_certs)
            );
         }

      state.client_kex(
         new Client_Key_Exchange(state.handshake_io(),
                                 state,
                                 m_policy,
                                 m_creds,
                                 m_peer_certs,
                                 m_hostname,
                                 m_rng)
         );

      state.compute_session_keys();

      if(state.received_handshake_msg(CERTIFICATE_REQUEST) &&
         !state.client_certs()->empty())
         {
         Private_Key* private_key =
            m_creds.private_key_for(state.client_certs()->cert_chain()[0],
                                    "tls-client",
                                    m_hostname);

         state.client_verify(
            new Certificate_Verify(state.handshake_io(),
                                   state,
                                   m_policy,
                                   m_rng,
                                   private_key)
            );
         }

      state.handshake_io().send(Change_Cipher_Spec());

      change_cipher_spec_writer(CLIENT);

      if(state.server_hello()->next_protocol_notification())
         {
         const std::string protocol =
            dynamic_cast<Client_Handshake_State&>(state).client_npn_cb(
               state.server_hello()->next_protocols());

         state.next_protocol(
            new Next_Protocol(state.handshake_io(), state.hash(), protocol)
            );
         }

      state.client_finished(
         new Finished(state.handshake_io(), state, CLIENT)
         );

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
      state.set_expected_next(HELLO_REQUEST);

      state.server_finished(new Finished(contents));

      if(!state.server_finished()->verify(state, SERVER))
         throw TLS_Exception(Alert::DECRYPT_ERROR,
                             "Finished message didn't verify");

      state.hash().update(state.handshake_io().format(contents, type));

      if(!state.client_finished()) // session resume case
         {
         state.handshake_io().send(Change_Cipher_Spec());

         change_cipher_spec_writer(CLIENT);

         if(state.server_hello()->next_protocol_notification())
            {
            const std::string protocol =
               dynamic_cast<Client_Handshake_State&>(state).client_npn_cb(
                  state.server_hello()->next_protocols());

            state.next_protocol(
               new Next_Protocol(state.handshake_io(), state.hash(), protocol)
               );
            }

         state.client_finished(
            new Finished(state.handshake_io(), state, CLIENT)
            );
         }

      m_secure_renegotiation.update(state.client_finished(),
                                    state.server_finished());

      std::vector<byte> session_id = state.server_hello()->session_id();

      const std::vector<byte>& session_ticket = state.session_ticket();

      if(session_id.empty() && !session_ticket.empty())
         session_id = make_hello_random(m_rng);

      Session session_info(
         session_id,
         state.session_keys().master_secret(),
         state.server_hello()->version(),
         state.server_hello()->ciphersuite(),
         state.server_hello()->compression_method(),
         CLIENT,
         m_secure_renegotiation.supported(),
         state.server_hello()->fragment_size(),
         m_peer_certs,
         session_ticket,
         m_hostname,
         ""
         );

      const bool should_save = m_handshake_fn(session_info);

      if(!session_id.empty())
         {
         if(should_save)
            m_session_manager.save(session_info, m_port);
         else
            m_session_manager.remove_entry(session_info.session_id());
         }

      activate_session();
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

}

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
   m_rng(rng),
   m_creds(creds),
   m_hostname(hostname),
   m_port(port)
   {
   const std::string srp_identifier = m_creds.srp_identifier("tls-client", m_hostname);

   const Protocol_Version version = m_policy.pref_version();
   initiate_handshake(false, version, srp_identifier, next_protocol);
   }

Handshake_State* Client::new_handshake_state()
   {
   return new Handshake_State(new Stream_Handshake_IO(m_writer));
   }

/*
* Send a new client hello to renegotiate
*/
void Client::renegotiate(bool force_full_renegotiation)
   {
   if(m_state && m_state->client_hello)
      return; // currently in active handshake

   m_state.reset();

   const Protocol_Version version = m_reader.get_version();

   initiate_handshake(force_full_renegotiation, version);
   }

void Client::initiate_handshake(bool force_full_renegotiation,
                                Protocol_Version version,
                                const std::string& srp_identifier,
                                std::function<std::string (std::vector<std::string>)> next_protocol)
   {
   m_state.reset(new_handshake_state());

   if(!m_writer.record_version_set())
      m_writer.set_version(m_state->handshake_io().initial_record_version());

   if(m_state->version().is_datagram_protocol())
      m_state->set_expected_next(HELLO_VERIFY_REQUEST);
   m_state->set_expected_next(SERVER_HELLO);

   m_state->client_npn_cb = next_protocol;

   const bool send_npn_request = static_cast<bool>(next_protocol);

   if(!force_full_renegotiation && m_hostname != "")
      {
      Session session_info;
      if(m_session_manager.load_from_host_info(m_hostname, m_port, session_info))
         {
         if(srp_identifier == "" || session_info.srp_identifier() == srp_identifier)
            {
            m_state->client_hello = new Client_Hello(
               m_state->handshake_io(),
               m_state->hash,
               m_policy,
               m_rng,
               m_secure_renegotiation.for_client_hello(),
               session_info,
               send_npn_request);

            m_state->resume_master_secret = session_info.master_secret();
            }
         }
      }

   if(!m_state->client_hello) // not resuming
      {
      m_state->client_hello = new Client_Hello(
         m_state->handshake_io(),
         m_state->hash,
         version,
         m_policy,
         m_rng,
         m_secure_renegotiation.for_client_hello(),
         send_npn_request,
         m_hostname,
         srp_identifier);
      }

   m_secure_renegotiation.update(m_state->client_hello);
   }

void Client::alert_notify(const Alert& alert)
   {
   if(alert.type() == Alert::NO_RENEGOTIATION)
      {
      if(m_handshake_completed && m_state)
         m_state.reset();
      }
   }

/*
* Process a handshake message
*/
void Client::process_handshake_msg(Handshake_Type type,
                                   const std::vector<byte>& contents)
   {
   if(!m_state)
      throw Unexpected_Message("Unexpected handshake message from server");

   if(type == HELLO_REQUEST)
      {
      Hello_Request hello_request(contents);

      // Ignore request entirely if we are currently negotiating a handshake
      if(m_state->client_hello)
         return;

      if(!m_secure_renegotiation.supported() && !m_policy.allow_insecure_renegotiation())
         {
         m_state.reset();

         // RFC 5746 section 4.2
         send_alert(Alert(Alert::NO_RENEGOTIATION));
         return;
         }

      this->renegotiate(false);

      return;
      }

   m_state->confirm_transition_to(type);

   if(type != HANDSHAKE_CCS && type != FINISHED && type != HELLO_VERIFY_REQUEST)
      m_state->hash.update(m_state->handshake_io().format(contents, type));

   if(type == HELLO_VERIFY_REQUEST)
      {
      m_state->set_expected_next(SERVER_HELLO);
      m_state->set_expected_next(HELLO_VERIFY_REQUEST); // might get it again

      Hello_Verify_Request hello_verify_request(contents);

      std::unique_ptr<Client_Hello> client_hello_w_cookie(
         new Client_Hello(m_state->handshake_io(),
                          m_state->hash,
                          *m_state->client_hello,
                          hello_verify_request));

      delete m_state->client_hello;
      m_state->client_hello = client_hello_w_cookie.release();
      }
   else if(type == SERVER_HELLO)
      {
      m_state->server_hello = new Server_Hello(contents);

      if(!m_state->client_hello->offered_suite(m_state->server_hello->ciphersuite()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with ciphersuite we didn't send");
         }

      if(!value_exists(m_state->client_hello->compression_methods(),
                       m_state->server_hello->compression_method()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with compression method we didn't send");
         }

      if(!m_state->client_hello->next_protocol_notification() &&
         m_state->server_hello->next_protocol_notification())
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server sent next protocol but we didn't request it");
         }

      if(m_state->server_hello->supports_session_ticket())
         {
         if(!m_state->client_hello->supports_session_ticket())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server sent session ticket extension but we did not");
         }

      m_state->set_version(m_state->server_hello->version());

      m_writer.set_version(m_state->version());
      m_reader.set_version(m_state->version());

      m_secure_renegotiation.update(m_state->server_hello);

      m_peer_supports_heartbeats = m_state->server_hello->supports_heartbeats();
      m_heartbeat_sending_allowed = m_state->server_hello->peer_can_send_heartbeats();

      m_state->suite = Ciphersuite::by_id(m_state->server_hello->ciphersuite());

      const bool server_returned_same_session_id =
         !m_state->server_hello->session_id().empty() &&
         (m_state->server_hello->session_id() == m_state->client_hello->session_id());

      if(server_returned_same_session_id)
         {
         // successful resumption

         /*
         * In this case, we offered the version used in the original
         * session, and the server must resume with the same version.
         */
         if(m_state->server_hello->version() != m_state->client_hello->version())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server resumed session but with wrong version");

         m_state->keys = Session_Keys(m_state.get(),
                                      m_state->resume_master_secret,
                                      true);

         // The server is not strictly required to send us a new ticket
         if(m_state->server_hello->supports_session_ticket())
            m_state->set_expected_next(NEW_SESSION_TICKET);

         m_state->set_expected_next(HANDSHAKE_CCS);
         }
      else
         {
         // new session

         if(m_state->version() > m_state->client_hello->version())
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server replied with later version than in hello");
            }

         if(!m_policy.acceptable_protocol_version(m_state->version()))
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Server version is unacceptable by policy");
            }

         if(m_state->suite.sig_algo() != "")
            {
            m_state->set_expected_next(CERTIFICATE);
            }
         else if(m_state->suite.kex_algo() == "PSK")
            {
            /* PSK is anonymous so no certificate/cert req message is
               ever sent. The server may or may not send a server kex,
               depending on if it has an identity hint for us.

               (EC)DHE_PSK always sends a server key exchange for the
               DH exchange portion.
            */

            m_state->set_expected_next(SERVER_KEX);
            m_state->set_expected_next(SERVER_HELLO_DONE);
            }
         else if(m_state->suite.kex_algo() != "RSA")
            {
            m_state->set_expected_next(SERVER_KEX);
            }
         else
            {
            m_state->set_expected_next(CERTIFICATE_REQUEST); // optional
            m_state->set_expected_next(SERVER_HELLO_DONE);
            }
         }
      }
   else if(type == CERTIFICATE)
      {
      if(m_state->suite.kex_algo() != "RSA")
         {
         m_state->set_expected_next(SERVER_KEX);
         }
      else
         {
         m_state->set_expected_next(CERTIFICATE_REQUEST); // optional
         m_state->set_expected_next(SERVER_HELLO_DONE);
         }

      m_state->server_certs = new Certificate(contents);

      m_peer_certs = m_state->server_certs->cert_chain();
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

      if(peer_key->algo_name() != m_state->suite.sig_algo())
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");
      }
   else if(type == SERVER_KEX)
      {
      m_state->set_expected_next(CERTIFICATE_REQUEST); // optional
      m_state->set_expected_next(SERVER_HELLO_DONE);

      m_state->server_kex = new Server_Key_Exchange(contents,
                                                    m_state->suite.kex_algo(),
                                                    m_state->suite.sig_algo(),
                                                    m_state->version());

      if(m_state->suite.sig_algo() != "")
         {
         if(!m_state->server_kex->verify(m_peer_certs[0], m_state.get()))
            {
            throw TLS_Exception(Alert::DECRYPT_ERROR,
                                "Bad signature on server key exchange");
            }
         }
      }
   else if(type == CERTIFICATE_REQUEST)
      {
      m_state->set_expected_next(SERVER_HELLO_DONE);
      m_state->cert_req = new Certificate_Req(contents, m_state->version());
      }
   else if(type == SERVER_HELLO_DONE)
      {
      m_state->server_hello_done = new Server_Hello_Done(contents);

      if(m_state->received_handshake_msg(CERTIFICATE_REQUEST))
         {
         const std::vector<std::string>& types =
            m_state->cert_req->acceptable_cert_types();

         std::vector<X509_Certificate> client_certs =
            m_creds.cert_chain(types,
                               "tls-client",
                               m_hostname);

         m_state->client_certs = new Certificate(m_state->handshake_io(),
                                                 m_state->hash,
                                                 client_certs);
         }

      m_state->client_kex =
         new Client_Key_Exchange(m_state->handshake_io(),
                                 m_state.get(),
                                 m_policy,
                                 m_creds,
                                 m_peer_certs,
                                 m_hostname,
                                 m_rng);

      m_state->keys = Session_Keys(m_state.get(),
                                   m_state->client_kex->pre_master_secret(),
                                   false);

      if(m_state->received_handshake_msg(CERTIFICATE_REQUEST) &&
         !m_state->client_certs->empty())
         {
         Private_Key* private_key =
            m_creds.private_key_for(m_state->client_certs->cert_chain()[0],
                                    "tls-client",
                                    m_hostname);

         m_state->client_verify = new Certificate_Verify(m_state->handshake_io(),
                                                         m_state.get(),
                                                         m_policy,
                                                         m_rng,
                                                         private_key);
         }

      m_writer.send(CHANGE_CIPHER_SPEC, 1);

      m_writer.change_cipher_spec(CLIENT,
                                  m_state->suite,
                                  m_state->keys,
                                  m_state->server_hello->compression_method());

      if(m_state->server_hello->next_protocol_notification())
         {
         const std::string protocol =
            m_state->client_npn_cb(m_state->server_hello->next_protocols());

         m_state->next_protocol = new Next_Protocol(m_state->handshake_io(), m_state->hash, protocol);
         }

      m_state->client_finished = new Finished(m_state->handshake_io(),
                                              m_state.get(), CLIENT);

      if(m_state->server_hello->supports_session_ticket())
         m_state->set_expected_next(NEW_SESSION_TICKET);
      else
         m_state->set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == NEW_SESSION_TICKET)
      {
      m_state->new_session_ticket = new New_Session_Ticket(contents);

      m_state->set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      m_state->set_expected_next(FINISHED);

      m_reader.change_cipher_spec(CLIENT,
                                  m_state->suite,
                                  m_state->keys,
                                  m_state->server_hello->compression_method());
      }
   else if(type == FINISHED)
      {
      m_state->set_expected_next(HELLO_REQUEST);

      m_state->server_finished = new Finished(contents);

      if(!m_state->server_finished->verify(m_state.get(), SERVER))
         throw TLS_Exception(Alert::DECRYPT_ERROR,
                             "Finished message didn't verify");

      m_state->hash.update(m_state->handshake_io().format(contents, type));

      if(!m_state->client_finished) // session resume case
         {
         m_writer.send(CHANGE_CIPHER_SPEC, 1);

         m_writer.change_cipher_spec(CLIENT,
                                     m_state->suite,
                                     m_state->keys,
                                     m_state->server_hello->compression_method());

         m_state->client_finished = new Finished(m_state->handshake_io(),
                                                 m_state.get(), CLIENT);
         }

      m_secure_renegotiation.update(m_state->client_finished, m_state->server_finished);

      std::vector<byte> session_id = m_state->server_hello->session_id();

      const std::vector<byte>& session_ticket = m_state->session_ticket();

      if(session_id.empty() && !session_ticket.empty())
         session_id = make_hello_random(m_rng);

      Session session_info(
         session_id,
         m_state->keys.master_secret(),
         m_state->server_hello->version(),
         m_state->server_hello->ciphersuite(),
         m_state->server_hello->compression_method(),
         CLIENT,
         m_secure_renegotiation.supported(),
         m_state->server_hello->fragment_size(),
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

      m_state.reset();
      m_handshake_completed = true;
      m_active_session = session_info.session_id();
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

}

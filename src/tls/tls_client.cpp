/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
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
Client::Client(std::tr1::function<void (const byte[], size_t)> output_fn,
               std::tr1::function<void (const byte[], size_t, Alert)> proc_fn,
               std::tr1::function<bool (const Session&)> handshake_fn,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const std::string& hostname,
               std::tr1::function<std::string (std::vector<std::string>)> next_protocol) :
   Channel(output_fn, proc_fn, handshake_fn),
   policy(policy),
   rng(rng),
   session_manager(session_manager),
   creds(creds)
   {
   writer.set_version(Protocol_Version::SSL_V3);

   state = new Handshake_State(new Stream_Handshake_Reader);
   state->set_expected_next(SERVER_HELLO);

   state->client_npn_cb = next_protocol;

   const std::string srp_identifier = creds.srp_identifier("tls-client", hostname);

   const bool send_npn_request = static_cast<bool>(next_protocol);

   if(hostname != "")
      {
      Session session_info;
      if(session_manager.load_from_host_info(hostname, 0, session_info))
         {
         if(session_info.srp_identifier() == srp_identifier)
            {
            state->client_hello = new Client_Hello(
               writer,
               state->hash,
               policy,
               rng,
               session_info,
               send_npn_request);

            state->resume_master_secret = session_info.master_secret();
            }
         }
      }

   if(!state->client_hello) // not resuming
      {
      state->client_hello = new Client_Hello(
         writer,
         state->hash,
         policy,
         rng,
         secure_renegotiation.for_client_hello(),
         send_npn_request,
         hostname,
         srp_identifier);
      }

   secure_renegotiation.update(state->client_hello);
   }

/*
* Send a new client hello to renegotiate
*/
void Client::renegotiate()
   {
   if(state)
      return; // currently in handshake

   state = new Handshake_State(new Stream_Handshake_Reader);
   state->set_expected_next(SERVER_HELLO);

   state->client_hello = new Client_Hello(writer, state->hash, policy, rng,
                                          secure_renegotiation.for_client_hello());

   secure_renegotiation.update(state->client_hello);
   }

void Client::alert_notify(const Alert& alert)
   {
   if(alert.type() == Alert::NO_RENEGOTIATION)
      {
      if(handshake_completed && state)
         {
         delete state;
         state = 0;
         }
      }
   }

/*
* Process a handshake message
*/
void Client::process_handshake_msg(Handshake_Type type,
                                   const MemoryRegion<byte>& contents)
   {
   if(state == 0)
      throw Unexpected_Message("Unexpected handshake message from server");

   if(type == HELLO_REQUEST)
      {
      Hello_Request hello_request(contents);

      // Ignore request entirely if we are currently negotiating a handshake
      if(state->client_hello)
         return;

      if(!secure_renegotiation.supported() && policy.require_secure_renegotiation())
         {
         delete state;
         state = 0;

         // RFC 5746 section 4.2
         send_alert(Alert(Alert::NO_RENEGOTIATION));
         return;
         }

      state->client_hello = new Client_Hello(writer, state->hash, policy, rng,
                                             secure_renegotiation.for_client_hello());
      secure_renegotiation.update(state->client_hello);

      state->set_expected_next(SERVER_HELLO);

      return;
      }

   state->confirm_transition_to(type);

   if(type != HANDSHAKE_CCS && type != FINISHED)
      state->hash.update(type, contents);

   if(type == SERVER_HELLO)
      {
      state->server_hello = new Server_Hello(contents);

      if(!state->client_hello->offered_suite(state->server_hello->ciphersuite()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with ciphersuite we didn't send");
         }

      if(!value_exists(state->client_hello->compression_methods(),
                       state->server_hello->compression_method()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with compression method we didn't send");
         }

      if(!state->client_hello->next_protocol_notification() &&
         state->server_hello->next_protocol_notification())
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server sent next protocol but we didn't request it");
         }

      if(state->server_hello->supports_session_ticket())
         {
         if(!state->client_hello->supports_session_ticket())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server sent session ticket extension but we did not");
         }

      state->set_version(state->server_hello->version());

      writer.set_version(state->version());
      reader.set_version(state->version());

      secure_renegotiation.update(state->server_hello);

      state->suite = Ciphersuite::by_id(state->server_hello->ciphersuite());

      const bool server_returned_same_session_id =
         !state->server_hello->session_id().empty() &&
         (state->server_hello->session_id() == state->client_hello->session_id());

      if(server_returned_same_session_id)
         {
         // successful resumption

         /*
         * In this case, we offered the version used in the original
         * session, and the server must resume with the same version.
         */
         if(state->server_hello->version() != state->client_hello->version())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server resumed session but with wrong version");

         state->keys = Session_Keys(state,
                                    state->resume_master_secret,
                                    true);

         if(state->server_hello->supports_session_ticket())
            state->set_expected_next(NEW_SESSION_TICKET);
         else
            state->set_expected_next(HANDSHAKE_CCS);
         }
      else
         {
         // new session

         if(state->version() > state->client_hello->version())
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Client: Server replied with bad version");
            }

         if(state->version() < policy.min_version())
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Client: Server is too old for specified policy");
            }

         if(state->suite.sig_algo() != "")
            {
            state->set_expected_next(CERTIFICATE);
            }
         else if(state->suite.kex_algo() == "PSK")
            {
            /* PSK is anonymous so no certificate/cert req message is
               ever sent. The server may or may not send a server kex,
               depending on if it has an identity hint for us.

               DHE_PSK always sends a server key exchange for the DH
               exchange portion.
            */

            state->set_expected_next(SERVER_KEX);
            state->set_expected_next(SERVER_HELLO_DONE);
            }
         else if(state->suite.kex_algo() != "RSA")
            {
            state->set_expected_next(SERVER_KEX);
            }
         else
            {
            state->set_expected_next(CERTIFICATE_REQUEST); // optional
            state->set_expected_next(SERVER_HELLO_DONE);
            }
         }
      }
   else if(type == CERTIFICATE)
      {
      if(state->suite.kex_algo() != "RSA")
         {
         state->set_expected_next(SERVER_KEX);
         }
      else
         {
         state->set_expected_next(CERTIFICATE_REQUEST); // optional
         state->set_expected_next(SERVER_HELLO_DONE);
         }

      state->server_certs = new Certificate(contents);

      peer_certs = state->server_certs->cert_chain();
      if(peer_certs.size() == 0)
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client: No certificates sent by server");

      try
         {
         const std::string hostname = state->client_hello->sni_hostname();
         creds.verify_certificate_chain("tls-client", hostname, peer_certs);
         }
      catch(std::exception& e)
         {
         throw TLS_Exception(Alert::BAD_CERTIFICATE, e.what());
         }

      std::auto_ptr<Public_Key> peer_key(peer_certs[0].subject_public_key());

      if(peer_key->algo_name() != state->suite.sig_algo())
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");
      }
   else if(type == SERVER_KEX)
      {
      state->set_expected_next(CERTIFICATE_REQUEST); // optional
      state->set_expected_next(SERVER_HELLO_DONE);

      state->server_kex = new Server_Key_Exchange(contents,
                                                  state->suite.kex_algo(),
                                                  state->suite.sig_algo(),
                                                  state->version());

      if(state->suite.sig_algo() != "")
         {
         if(!state->server_kex->verify(peer_certs[0], state))
            {
            throw TLS_Exception(Alert::DECRYPT_ERROR,
                                "Bad signature on server key exchange");
            }
         }
      }
   else if(type == CERTIFICATE_REQUEST)
      {
      state->set_expected_next(SERVER_HELLO_DONE);
      state->cert_req = new Certificate_Req(contents, state->version());
      }
   else if(type == SERVER_HELLO_DONE)
      {
      state->server_hello_done = new Server_Hello_Done(contents);

      if(state->received_handshake_msg(CERTIFICATE_REQUEST))
         {
         const std::vector<std::string>& types =
            state->cert_req->acceptable_cert_types();

         std::vector<X509_Certificate> client_certs =
            creds.cert_chain(types,
                             "tls-client",
                             state->client_hello->sni_hostname());

         state->client_certs = new Certificate(writer,
                                               state->hash,
                                               client_certs);
         }

      state->client_kex =
         new Client_Key_Exchange(writer,
                                 state,
                                 creds,
                                 peer_certs,
                                 rng);

      state->keys = Session_Keys(state,
                                 state->client_kex->pre_master_secret(),
                                 false);

      if(state->received_handshake_msg(CERTIFICATE_REQUEST) &&
         !state->client_certs->empty())
         {
         Private_Key* private_key =
            creds.private_key_for(state->client_certs->cert_chain()[0],
                                  "tls-client",
                                  state->client_hello->sni_hostname());

         state->client_verify = new Certificate_Verify(writer,
                                                       state,
                                                       rng,
                                                       private_key);
         }

      writer.send(CHANGE_CIPHER_SPEC, 1);

      writer.activate(CLIENT, state->suite, state->keys,
                      state->server_hello->compression_method());

      if(state->server_hello->next_protocol_notification())
         {
         const std::string protocol =
            state->client_npn_cb(state->server_hello->next_protocols());

         state->next_protocol = new Next_Protocol(writer, state->hash, protocol);
         }

      state->client_finished = new Finished(writer, state, CLIENT);

      if(state->server_hello->supports_session_ticket())
         state->set_expected_next(NEW_SESSION_TICKET);
      else
         state->set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == NEW_SESSION_TICKET)
      {
      state->new_session_ticket = new New_Session_Ticket(contents);

      state->set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      state->set_expected_next(FINISHED);

      reader.activate(CLIENT, state->suite, state->keys,
                      state->server_hello->compression_method());
      }
   else if(type == FINISHED)
      {
      state->set_expected_next(HELLO_REQUEST);

      state->server_finished = new Finished(contents);

      if(!state->server_finished->verify(state, SERVER))
         throw TLS_Exception(Alert::DECRYPT_ERROR,
                             "Finished message didn't verify");

      state->hash.update(type, contents);

      if(!state->client_finished) // session resume case
         {
         writer.send(CHANGE_CIPHER_SPEC, 1);

         writer.activate(CLIENT, state->suite, state->keys,
                         state->server_hello->compression_method());

         state->client_finished = new Finished(writer, state, CLIENT);
         }

      secure_renegotiation.update(state->client_finished, state->server_finished);

      MemoryVector<byte> session_id = state->server_hello->session_id();

      const MemoryRegion<byte>& session_ticket = state->session_ticket();

      if(session_id.empty() && !session_ticket.empty())
         session_id = make_hello_random(rng);

      Session session_info(
         session_id,
         state->keys.master_secret(),
         state->server_hello->version(),
         state->server_hello->ciphersuite(),
         state->server_hello->compression_method(),
         CLIENT,
         secure_renegotiation.supported(),
         state->server_hello->fragment_size(),
         peer_certs,
         session_ticket,
         state->client_hello->sni_hostname(),
         ""
         );

      if(handshake_fn(session_info))
         session_manager.save(session_info);
      else
         session_manager.remove_entry(session_info.session_id());

      delete state;
      state = 0;
      handshake_completed = true;
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

}

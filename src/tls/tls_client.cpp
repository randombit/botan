/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_client.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/stl_util.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/dh.h>

namespace Botan {

/*
* TLS Client Constructor
*/
TLS_Client::TLS_Client(std::tr1::function<void (const byte[], size_t)> output_fn,
                       std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                       std::tr1::function<bool (const TLS_Session&)> handshake_fn,
                       TLS_Session_Manager& session_manager,
                       Credentials_Manager& creds,
                       const TLS_Policy& policy,
                       RandomNumberGenerator& rng,
                       const std::string& hostname) :
   TLS_Channel(output_fn, proc_fn, handshake_fn),
   policy(policy),
   rng(rng),
   session_manager(session_manager),
   creds(creds)
   {
   writer.set_version(SSL_V3);

   state = new Handshake_State;
   state->set_expected_next(SERVER_HELLO);

   const std::string srp_identifier = creds.srp_identifier("tls-client", hostname);

   if(hostname != "")
      {
      TLS_Session session_info;
      if(session_manager.load_from_host_info(hostname, 0, session_info))
         {
         if(session_info.srp_identifier() == srp_identifier)
            {
            state->client_hello = new Client_Hello(
               writer,
               state->hash,
               rng,
               session_info);

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
         hostname,
         srp_identifier);
      }

   secure_renegotiation.update(state->client_hello);
   }

/*
* Send a new client hello to renegotiate
*/
void TLS_Client::renegotiate()
   {
   if(state)
      return; // currently in handshake

   state = new Handshake_State;
   state->set_expected_next(SERVER_HELLO);

   state->client_hello = new Client_Hello(writer, state->hash, policy, rng,
                                          secure_renegotiation.for_client_hello());

   secure_renegotiation.update(state->client_hello);
   }

/*
* Process a handshake message
*/
void TLS_Client::process_handshake_msg(Handshake_Type type,
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
         alert(WARNING, NO_RENEGOTIATION);
         return;
         }

      state->set_expected_next(SERVER_HELLO);
      state->client_hello = new Client_Hello(writer, state->hash, policy, rng,
                                             secure_renegotiation.for_client_hello());

      secure_renegotiation.update(state->client_hello);

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
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "TLS_Client: Server replied with bad ciphersuite");
         }

      if(!value_exists(state->client_hello->compression_methods(),
                       state->server_hello->compression_method()))
         {
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "TLS_Client: Server replied with bad compression method");
         }

      state->version = state->server_hello->version();

      writer.set_version(state->version);
      reader.set_version(state->version);

      secure_renegotiation.update(state->server_hello);

      state->suite = TLS_Cipher_Suite(state->server_hello->ciphersuite());

      if(!state->server_hello->session_id().empty() &&
         (state->server_hello->session_id() == state->client_hello->session_id()))
         {
         // successful resumption

         /*
         * In this case, we offered the original session and the server
         * must resume with it
         */
         if(state->server_hello->version() != state->client_hello->version())
            throw TLS_Exception(HANDSHAKE_FAILURE,
                                "Server resumed session but with wrong version");

         state->keys = SessionKeys(state->suite, state->version,
                                   state->resume_master_secret,
                                   state->client_hello->random(),
                                   state->server_hello->random(),
                                   true);

         state->set_expected_next(HANDSHAKE_CCS);
         }
      else
         {
         // new session

         if(state->version > state->client_hello->version())
            {
            throw TLS_Exception(HANDSHAKE_FAILURE,
                                "TLS_Client: Server replied with bad version");
            }

         if(state->version < policy.min_version())
            {
            throw TLS_Exception(PROTOCOL_VERSION,
                                "TLS_Client: Server is too old for specified policy");
            }

         if(state->suite.sig_type() != TLS_ALGO_SIGNER_ANON)
            {
            state->set_expected_next(CERTIFICATE);
            }
         else if(state->suite.kex_type() != TLS_ALGO_KEYEXCH_NOKEX)
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
      if(state->suite.kex_type() != TLS_ALGO_KEYEXCH_NOKEX)
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
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "TLS_Client: No certificates sent by server");

      if(!policy.check_cert(peer_certs))
         throw TLS_Exception(BAD_CERTIFICATE,
                             "TLS_Client: Server certificate is not valid");

      state->kex_pub = peer_certs[0].subject_public_key();

      bool is_dsa = false, is_rsa = false;

      if(dynamic_cast<DSA_PublicKey*>(state->kex_pub))
         is_dsa = true;
      else if(dynamic_cast<RSA_PublicKey*>(state->kex_pub))
         is_rsa = true;
      else
         throw TLS_Exception(UNSUPPORTED_CERTIFICATE,
                             "Unknown key type received in server kex");

      if((is_dsa && state->suite.sig_type() != TLS_ALGO_SIGNER_DSA) ||
         (is_rsa && state->suite.sig_type() != TLS_ALGO_SIGNER_RSA))
         throw TLS_Exception(ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");
      }
   else if(type == SERVER_KEX)
      {
      state->set_expected_next(CERTIFICATE_REQUEST); // optional
      state->set_expected_next(SERVER_HELLO_DONE);

      state->server_kex = new Server_Key_Exchange(contents);

      if(state->kex_pub)
         delete state->kex_pub;

      state->kex_pub = state->server_kex->key();

      bool is_dh = false, is_rsa = false;

      if(dynamic_cast<DH_PublicKey*>(state->kex_pub))
         is_dh = true;
      else if(dynamic_cast<RSA_PublicKey*>(state->kex_pub))
         is_rsa = true;
      else
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "Unknown key type received in server kex");

      if((is_dh && state->suite.kex_type() != TLS_ALGO_KEYEXCH_DH) ||
         (is_rsa && state->suite.kex_type() != TLS_ALGO_KEYEXCH_RSA))
         throw TLS_Exception(ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");

      if(state->suite.sig_type() != TLS_ALGO_SIGNER_ANON)
         {
         if(!state->server_kex->verify(peer_certs[0],
                                       state->client_hello->random(),
                                       state->server_hello->random()))
            throw TLS_Exception(DECRYPT_ERROR,
                            "Bad signature on server key exchange");
         }
      }
   else if(type == CERTIFICATE_REQUEST)
      {
      state->set_expected_next(SERVER_HELLO_DONE);
      state->cert_req = new Certificate_Req(contents);
      }
   else if(type == SERVER_HELLO_DONE)
      {
      state->set_expected_next(HANDSHAKE_CCS);

      state->server_hello_done = new Server_Hello_Done(contents);

      if(state->received_handshake_msg(CERTIFICATE_REQUEST))
         {
         std::vector<Certificate_Type> types =
            state->cert_req->acceptable_types();

         std::vector<X509_Certificate> client_certs =
            creds.cert_chain("", // use types here
                             "tls-client",
                             state->client_hello->sni_hostname());

         state->client_certs = new Certificate(writer,
                                               state->hash,
                                               client_certs);
         }

      state->client_kex =
         new Client_Key_Exchange(writer, state->hash, rng,
                                 state->kex_pub, state->version,
                                 state->client_hello->version());

      if(state->received_handshake_msg(CERTIFICATE_REQUEST) &&
         !state->client_certs->empty())
         {
         Private_Key* private_key =
            creds.private_key_for(state->client_certs->cert_chain()[0],
                                  "tls-client",
                                  state->client_hello->sni_hostname());

         state->client_verify = new Certificate_Verify(writer, state->hash,
                                                       rng, private_key);
         }

      state->keys = SessionKeys(state->suite, state->version,
                                state->client_kex->pre_master_secret(),
                                state->client_hello->random(),
                                state->server_hello->random());

      writer.send(CHANGE_CIPHER_SPEC, 1);

      writer.activate(state->suite, state->keys, CLIENT);

      state->client_finished = new Finished(writer, state->hash,
                                            state->version, CLIENT,
                                            state->keys.master_secret());
      }
   else if(type == HANDSHAKE_CCS)
      {
      state->set_expected_next(FINISHED);

      reader.activate(state->suite, state->keys, CLIENT);
      }
   else if(type == FINISHED)
      {
      state->set_expected_next(HELLO_REQUEST);

      state->server_finished = new Finished(contents);

      if(!state->server_finished->verify(state->keys.master_secret(),
                                         state->version, state->hash, SERVER))
         throw TLS_Exception(DECRYPT_ERROR,
                             "Finished message didn't verify");

      state->hash.update(type, contents);

      if(!state->client_finished) // session resume case
         {
         writer.send(CHANGE_CIPHER_SPEC, 1);

         writer.activate(state->suite, state->keys, CLIENT);

         state->client_finished = new Finished(writer, state->hash,
                                               state->version, CLIENT,
                                               state->keys.master_secret());
         }

      TLS_Session session_info(
         state->server_hello->session_id(),
         state->keys.master_secret(),
         state->server_hello->version(),
         state->server_hello->ciphersuite(),
         state->server_hello->compression_method(),
         CLIENT,
         secure_renegotiation.supported(),
         state->server_hello->fragment_size(),
         peer_certs,
         state->client_hello->sni_hostname(),
         ""
         );

      if(handshake_fn(session_info))
         session_manager.save(session_info);
      else
         session_manager.remove_entry(session_info.session_id());

      secure_renegotiation.update(state->client_finished, state->server_finished);

      delete state;
      state = 0;
      handshake_completed = true;
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

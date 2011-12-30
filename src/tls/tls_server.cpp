/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_server.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_state.h>
#include <botan/internal/stl_util.h>
#include <botan/rsa.h>
#include <botan/dh.h>

namespace Botan {

namespace {

/*
* Choose what version to respond with
*/
Version_Code choose_version(Version_Code client, Version_Code minimum)
   {
   if(client < minimum)
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Client version is unacceptable by policy");

   if(client == SSL_V3 || client == TLS_V10 || client == TLS_V11)
      return client;
   return TLS_V11;
   }

bool check_for_resume(TLS_Session_Params& session_info,
                      TLS_Session_Manager& session_manager,
                      Client_Hello* client_hello)
   {
   MemoryVector<byte> client_session_id = client_hello->session_id();

   if(client_session_id.empty()) // not resuming
      return false;

   // not found
   if(!session_manager.find(client_session_id, session_info))
      return false;

   // wrong version
   if(client_hello->version() != session_info.version())
      return false;

   // client didn't send original ciphersuite
   if(!value_exists(client_hello->ciphersuites(),
                    session_info.ciphersuite()))
      return false;

   // client didn't send original compression method
   if(!value_exists(client_hello->compression_methods(),
                    session_info.compression_method()))
      return false;

   // client sent a different SRP identity (!!!)
   if(client_hello->srp_identifier() != "")
      {
      if(client_hello->srp_identifier() != session_info.srp_identifier())
         return false;
      }

   // client sent a different SNI hostname (!!!)
   if(client_hello->sni_hostname() != "")
      {
      if(client_hello->sni_hostname() != session_info.sni_hostname())
         return false;
      }

   return true;
   }

}

/*
* TLS Server Constructor
*/
TLS_Server::TLS_Server(std::tr1::function<void (const byte[], size_t)> output_fn,
                       std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                       std::tr1::function<void (const TLS_Session_Params&)> handshake_fn,
                       TLS_Session_Manager& session_manager,
                       const TLS_Policy& policy,
                       RandomNumberGenerator& rng,
                       const X509_Certificate& cert,
                       const Private_Key& cert_key) :
   TLS_Channel(output_fn, proc_fn, handshake_fn),
   policy(policy),
   rng(rng),
   session_manager(session_manager)
   {
   cert_chain.push_back(cert);
   private_key = PKCS8::copy_key(cert_key, rng);
   }

/*
* TLS Server Destructor
*/
TLS_Server::~TLS_Server()
   {
   delete private_key;
   }

/*
* Send a hello request to the client
*/
void TLS_Server::renegotiate()
   {
   if(state)
      return; // currently in handshake

   state = new Handshake_State;
   state->set_expected_next(CLIENT_HELLO);
   Hello_Request hello_req(writer);
   }

/*
* Split up and process handshake messages
*/
void TLS_Server::read_handshake(byte rec_type,
                                const MemoryRegion<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE && !state)
      {
      state = new Handshake_State;
      state->set_expected_next(CLIENT_HELLO);
      }

   TLS_Channel::read_handshake(rec_type, rec_buf);
   }

/*
* Process a handshake message
*/
void TLS_Server::process_handshake_msg(Handshake_Type type,
                                       const MemoryRegion<byte>& contents)
   {
   if(state == 0)
      throw Unexpected_Message("Unexpected handshake message from client");

   state->confirm_transition_to(type);

   /*
   * The change cipher spec message isn't technically a handshake
   * message so it's not included in the hash. The finished and
   * certificate verify messages are verified based on the current
   * state of the hash *before* this message so we delay adding them
   * to the hash computation until we've processed them below.
   */
   if(type != HANDSHAKE_CCS && type != FINISHED && type != CERTIFICATE_VERIFY)
      {
      if(type == CLIENT_HELLO_SSLV2)
         state->hash.update(contents);
      else
         state->hash.update(type, contents);
      }

   if(type == CLIENT_HELLO || type == CLIENT_HELLO_SSLV2)
      {
      state->client_hello = new Client_Hello(contents, type);

      client_requested_hostname = state->client_hello->sni_hostname();

      state->version = choose_version(state->client_hello->version(),
                                      policy.min_version());

      secure_renegotiation.update(state->client_hello);

      writer.set_version(state->version);
      reader.set_version(state->version);

      TLS_Session_Params session_info;
      const bool resuming = check_for_resume(session_info,
                                             session_manager,
                                             state->client_hello);

      if(resuming)
         {
         // resume session
         state->server_hello = new Server_Hello(
            writer,
            state->hash,
            rng,
            secure_renegotiation.supported(),
            secure_renegotiation.for_server_hello(),
            session_info.session_id(),
            session_info.ciphersuite(),
            session_info.compression_method(),
            session_info.fragment_size(),
            Version_Code(session_info.version()));

         if(session_info.fragment_size())
            writer.set_maximum_fragment_size(session_info.fragment_size());

         state->suite = TLS_Cipher_Suite(state->server_hello->ciphersuite());

         state->keys = SessionKeys(state->suite, state->version,
                                   session_info.master_secret(),
                                   state->client_hello->random(),
                                   state->server_hello->random(),
                                   true);

         writer.send(CHANGE_CIPHER_SPEC, 1);

         writer.activate(state->suite, state->keys, SERVER);

         state->server_finished = new Finished(writer, state->hash,
                                               state->version, SERVER,
                                               state->keys.master_secret());

         if(handshake_fn)
            handshake_fn(session_info);

         state->set_expected_next(HANDSHAKE_CCS);
         }
      else // new session
         {
         state->server_hello = new Server_Hello(
            writer,
            state->hash,
            policy,
            rng,
            secure_renegotiation.supported(),
            secure_renegotiation.for_server_hello(),
            cert_chain,
            *(state->client_hello),
            rng.random_vec(32),
            state->version);

         if(state->client_hello->fragment_size())
            writer.set_maximum_fragment_size(state->client_hello->fragment_size());

         state->suite = TLS_Cipher_Suite(state->server_hello->ciphersuite());

         if(state->suite.sig_type() != TLS_ALGO_SIGNER_ANON)
            {
            // FIXME: should choose certs based on sig type
            state->server_certs = new Certificate(writer,
                                                  state->hash,
                                                  cert_chain);
            }

         if(state->suite.kex_type() == TLS_ALGO_KEYEXCH_NOKEX)
            {
            state->kex_priv = PKCS8::copy_key(*private_key, rng);
            }
         else if(state->suite.kex_type() == TLS_ALGO_KEYEXCH_RSA)
            {
            // this seems, er, non-optimal...
            state->kex_priv = new RSA_PrivateKey(rng, policy.rsa_export_keysize());
            }
         else if(state->suite.kex_type() == TLS_ALGO_KEYEXCH_DH)
            {
            state->kex_priv = new DH_PrivateKey(rng, policy.dh_group());
            }
         else
            throw Internal_Error("TLS_Server: Unknown ciphersuite kex type");

         state->server_kex =
            new Server_Key_Exchange(writer, state->hash, rng,
                                    state->kex_priv, private_key,
                                    state->client_hello->random(),
                                    state->server_hello->random());

         if(policy.require_client_auth())
            {
            // FIXME: figure out the allowed CAs/cert types

            state->cert_req = new Certificate_Req(writer, state->hash,
                                                  std::vector<X509_Certificate>());

            state->set_expected_next(CERTIFICATE);
            }

         secure_renegotiation.update(state->server_hello);

         /*
         * If the client doesn't have a cert they want to use they are
         * allowed to send either an empty cert message or proceed
         * directly to the client key exchange, so allow either case.
         */
         state->set_expected_next(CLIENT_KEX);

         state->server_hello_done = new Server_Hello_Done(writer, state->hash);
         }
      }
   else if(type == CERTIFICATE)
      {
      state->client_certs = new Certificate(contents);

      // Is this allowed by the protocol?
      if(state->client_certs->count() > 1)
         throw TLS_Exception(CERTIFICATE_UNKNOWN,
                             "Client sent more than one certificate");

      state->set_expected_next(CLIENT_KEX);
      }
   else if(type == CLIENT_KEX)
      {
      if(state->received_handshake_msg(CERTIFICATE) && !state->client_certs->empty())
         state->set_expected_next(CERTIFICATE_VERIFY);
      else
         state->set_expected_next(HANDSHAKE_CCS);

      state->client_kex = new Client_Key_Exchange(contents, state->suite,
                                                  state->version);

      SecureVector<byte> pre_master =
         state->client_kex->pre_master_secret(rng, state->kex_priv,
                                              state->server_hello->version());

      state->keys = SessionKeys(state->suite, state->version, pre_master,
                                state->client_hello->random(),
                                state->server_hello->random());
      }
   else if(type == CERTIFICATE_VERIFY)
      {
      state->client_verify = new Certificate_Verify(contents);

      const std::vector<X509_Certificate>& client_certs =
         state->client_certs->cert_chain();

      const bool sig_valid =
         state->client_verify->verify(client_certs[0],
                                      state->hash,
                                      state->server_hello->version(),
                                      state->keys.master_secret());

      state->hash.update(type, contents);

      /*
      * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
      * "A handshake cryptographic operation failed, including being
      * unable to correctly verify a signature, ..."
      */
      if(!sig_valid)
         throw TLS_Exception(DECRYPT_ERROR, "Client cert verify failed");

      // FIXME: check cert was issued by a CA we requested, signatures, etc.

      state->set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      state->set_expected_next(FINISHED);

      reader.activate(state->suite, state->keys, SERVER);
      }
   else if(type == FINISHED)
      {
      state->set_expected_next(HANDSHAKE_NONE);

      state->client_finished = new Finished(contents);

      if(!state->client_finished->verify(state->keys.master_secret(),
                                         state->version, state->hash, CLIENT))
         throw TLS_Exception(DECRYPT_ERROR,
                             "Finished message didn't verify");

      // already sent it if resuming
      if(!state->server_finished)
         {
         state->hash.update(type, contents);

         writer.send(CHANGE_CIPHER_SPEC, 1);

         writer.activate(state->suite, state->keys, SERVER);

         state->server_finished = new Finished(writer, state->hash,
                                               state->version, SERVER,
                                               state->keys.master_secret());

         std::vector<X509_Certificate> peer_certs;

         if(state->client_certs && state->client_verify)
            peer_certs = state->client_certs->cert_chain();

         TLS_Session_Params session_info(
            state->server_hello->session_id(),
            state->keys.master_secret(),
            state->server_hello->version(),
            state->server_hello->ciphersuite(),
            state->server_hello->compression_method(),
            SERVER,
            secure_renegotiation.supported(),
            state->server_hello->fragment_size(),
            peer_certs,
            client_requested_hostname,
            ""
            );

         session_manager.save(session_info);

         if(handshake_fn)
            handshake_fn(session_info);
         }

      secure_renegotiation.update(state->client_finished,
                                  state->server_finished);

      delete state;
      state = 0;
      handshake_completed = true;
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

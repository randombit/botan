/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_server.h>
#include <botan/internal/tls_state.h>
#include <botan/rsa.h>
#include <botan/dh.h>

#include <stdio.h>

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

// FIXME: checks are wrong for session reuse (add a flag for that)
/*
* Verify the state transition is allowed
*/
void server_check_state(Handshake_Type new_msg, Handshake_State* state)
   {
   class State_Transition_Error : public Unexpected_Message
      {
      public:
         State_Transition_Error(const std::string& err) :
            Unexpected_Message("State transition error from " + err) {}
      };

   if(new_msg == CLIENT_HELLO || new_msg == CLIENT_HELLO_SSLV2)
      {
      if(state->server_hello)
         throw State_Transition_Error("ClientHello");
      }
   else if(new_msg == CERTIFICATE)
      {
      if(!state->do_client_auth || !state->cert_req ||
         !state->server_hello_done || state->client_kex)
         throw State_Transition_Error("ClientCertificate");
      }
   else if(new_msg == CLIENT_KEX)
      {
      if(!state->server_hello_done || state->client_verify ||
         state->got_client_ccs)
         throw State_Transition_Error("ClientKeyExchange");
      }
   else if(new_msg == CERTIFICATE_VERIFY)
      {
      if(!state->cert_req || !state->client_certs || !state->client_kex ||
         state->got_client_ccs)
         throw State_Transition_Error("CertificateVerify");
      }
   else if(new_msg == HANDSHAKE_CCS)
      {
      if(!state->client_kex || state->client_finished)
         throw State_Transition_Error("ClientChangeCipherSpec");
      }
   else if(new_msg == FINISHED)
      {
      if(!state->got_client_ccs)
         throw State_Transition_Error("ClientFinished");
      }
   else
      throw Unexpected_Message("Unexpected message in handshake");
   }

}

/*
* TLS Server Constructor
*/
TLS_Server::TLS_Server(std::tr1::function<void (const byte[], size_t)> output_fn,
                       std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                       TLS_Session_Manager& session_manager,
                       const TLS_Policy& policy,
                       RandomNumberGenerator& rng,
                       const X509_Certificate& cert,
                       const Private_Key& cert_key) :
   TLS_Channel(output_fn, proc_fn),
   policy(policy),
   rng(rng),
   session_manager(session_manager)
   {
   writer.set_version(TLS_V10);

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
* Split up and process handshake messages
*/
void TLS_Server::read_handshake(byte rec_type,
                                const MemoryRegion<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE && !state)
      state = new Handshake_State;

   TLS_Channel::read_handshake(rec_type, rec_buf);
   }

/*
* Process a handshake message
*/
void TLS_Server::process_handshake_msg(Handshake_Type type,
                                       const MemoryRegion<byte>& contents)
   {
   rng.add_entropy(&contents[0], contents.size());

   if(state == 0)
      throw Unexpected_Message("Unexpected handshake message");

   if(type != HANDSHAKE_CCS && type != FINISHED)
      {
      if(type != CLIENT_HELLO_SSLV2)
         {
         state->hash.update(static_cast<byte>(type));

         const size_t record_length = contents.size();
         for(size_t i = 0; i != 3; i++)
            state->hash.update(get_byte<u32bit>(i+1, record_length));
         }

      state->hash.update(contents);
      }

   if(type == CLIENT_HELLO || type == CLIENT_HELLO_SSLV2)
      {
      server_check_state(type, state);

      state->client_hello = new Client_Hello(contents, type);

      client_requested_hostname = state->client_hello->hostname();

      state->version = choose_version(state->client_hello->version(),
                                      policy.min_version());

      writer.set_version(state->version);
      reader.set_version(state->version);

      TLS_Session_Params params;
      const bool found = session_manager.find(
         state->client_hello->session_id_vector(),
         params);

      if(found && params.connection_side == SERVER)
         {




         }
      else // new session
         {
         MemoryVector<byte> sess_id = rng.random_vec(32);

         state->server_hello = new Server_Hello(rng, writer,
                                                policy, cert_chain,
                                                *(state->client_hello),
                                                sess_id,
                                                state->version, state->hash);

         state->suite = CipherSuite(state->server_hello->ciphersuite());

         if(state->suite.sig_type() != TLS_ALGO_SIGNER_ANON)
            {
            // FIXME: should choose certs based on sig type
            state->server_certs = new Certificate(writer, cert_chain,
                                                  state->hash);
            }

         state->kex_priv = PKCS8::copy_key(*private_key, rng);
         if(state->suite.kex_type() != TLS_ALGO_KEYEXCH_NOKEX)
            {
            if(state->suite.kex_type() == TLS_ALGO_KEYEXCH_RSA)
               {
               state->kex_priv = new RSA_PrivateKey(rng,
                                                    policy.rsa_export_keysize());
               }
            else if(state->suite.kex_type() == TLS_ALGO_KEYEXCH_DH)
               {
               state->kex_priv = new DH_PrivateKey(rng, policy.dh_group());
               }
            else
               throw Internal_Error("TLS_Server: Unknown ciphersuite kex type");

            state->server_kex =
               new Server_Key_Exchange(rng, writer,
                                       state->kex_priv, private_key,
                                       state->client_hello->random(),
                                       state->server_hello->random(),
                                       state->hash);
            }

         if(policy.require_client_auth())
            {
            state->do_client_auth = true;
            throw Internal_Error("Client auth not implemented");
            // FIXME: send client auth request here
            }
         }

      state->server_hello_done = new Server_Hello_Done(writer, state->hash);
      }
   else if(type == CERTIFICATE)
      {
      server_check_state(type, state);
      // FIXME: process this
      }
   else if(type == CLIENT_KEX)
      {
      server_check_state(type, state);

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
      server_check_state(type, state);
      // FIXME: process this
      }
   else if(type == HANDSHAKE_CCS)
      {
      server_check_state(type, state);

      reader.set_keys(state->suite, state->keys, SERVER);
      state->got_client_ccs = true;
      }
   else if(type == FINISHED)
      {
      server_check_state(type, state);

      state->client_finished = new Finished(contents);

      if(!state->client_finished->verify(state->keys.master_secret(),
                                         state->version, state->hash, CLIENT))
         throw TLS_Exception(DECRYPT_ERROR,
                             "Finished message didn't verify");

      state->hash.update(static_cast<byte>(type));

      const size_t record_length = contents.size();
      for(size_t i = 0; i != 3; i++)
         state->hash.update(get_byte<u32bit>(i+1, record_length));

      state->hash.update(contents);

      writer.send(CHANGE_CIPHER_SPEC, 1);
      writer.flush();

      writer.set_keys(state->suite, state->keys, SERVER);

      state->server_finished = new Finished(writer, state->version, SERVER,
                                            state->keys.master_secret(),
                                            state->hash);

      delete state;
      state = 0;
      active = true;
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

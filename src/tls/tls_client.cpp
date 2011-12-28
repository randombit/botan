/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_client.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_state.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/dh.h>

namespace Botan {

/*
* TLS Client Constructor
*/
TLS_Client::TLS_Client(std::tr1::function<void (const byte[], size_t)> output_fn,
                       std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                       TLS_Session_Manager& session_manager,
                       const TLS_Policy& policy,
                       RandomNumberGenerator& rng) :
   TLS_Channel(output_fn, proc_fn),
   policy(policy),
   rng(rng),
   session_manager(session_manager)
   {
   writer.set_version(policy.pref_version());

   state = new Handshake_State;
   state->set_expected_next(SERVER_HELLO);
   state->client_hello = new Client_Hello(rng, writer, policy, state->hash);
   }

void TLS_Client::add_client_cert(const X509_Certificate& cert,
                                 Private_Key* cert_key)
   {
   certs.push_back(std::make_pair(cert, cert_key));
   }

/*
* TLS Client Destructor
*/
TLS_Client::~TLS_Client()
   {
   for(size_t i = 0; i != certs.size(); i++)
      delete certs[i].second;
   }

/*
* Process a handshake message
*/
void TLS_Client::process_handshake_msg(Handshake_Type type,
                                       const MemoryRegion<byte>& contents)
   {
   rng.add_entropy(&contents[0], contents.size());

   if(type == HELLO_REQUEST)
      {
      if(state == 0)
         state = new Handshake_State();
      else
         return; // hello request in middle of handshake?
      }

   if(state == 0)
      throw Unexpected_Message("Unexpected handshake message");

   state->confirm_transition_to(type);

   if(type != HANDSHAKE_CCS && type != HELLO_REQUEST && type != FINISHED)
      {
      state->hash.update(static_cast<byte>(type));
      const size_t record_length = contents.size();
      for(size_t i = 0; i != 3; i++)
         state->hash.update(get_byte<u32bit>(i+1, record_length));
      state->hash.update(contents);
      }

   if(type == HELLO_REQUEST)
      {
      Hello_Request hello_request(contents);
      state->client_hello = new Client_Hello(rng, writer, policy, state->hash);
      }
   else if(type == SERVER_HELLO)
      {
      state->server_hello = new Server_Hello(contents);

      if(!state->client_hello->offered_suite(
            state->server_hello->ciphersuite()
            )
         )
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "TLS_Client: Server replied with bad ciphersuite");

      state->version = state->server_hello->version();

      if(state->version > state->client_hello->version())
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "TLS_Client: Server replied with bad version");

      if(state->version < policy.min_version())
         throw TLS_Exception(PROTOCOL_VERSION,
                             "TLS_Client: Server is too old for specified policy");

      writer.set_version(state->version);
      reader.set_version(state->version);

      state->suite = CipherSuite(state->server_hello->ciphersuite());

      // if resuming, next is HANDSHAKE_CCS

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
         std::vector<X509_Certificate> send_certs;

         std::vector<Certificate_Type> types =
            state->cert_req->acceptable_types();

         // FIXME: Fill in useful certs here, if any
         state->client_certs = new Certificate(writer, send_certs,
                                               state->hash);
         }

      state->client_kex =
         new Client_Key_Exchange(rng, writer, state->hash,
                                 state->kex_pub, state->version,
                                 state->client_hello->version());

      if(state->received_handshake_msg(CERTIFICATE_REQUEST))
         {
         Private_Key* key_matching_cert = 0; // FIXME
         state->client_verify = new Certificate_Verify(rng,
                                                       writer, state->hash,
                                                       key_matching_cert);
         }

      state->keys = SessionKeys(state->suite, state->version,
                                state->client_kex->pre_master_secret(),
                                state->client_hello->random(),
                                state->server_hello->random());

      writer.send(CHANGE_CIPHER_SPEC, 1);
      writer.flush();

      writer.set_keys(state->suite, state->keys, CLIENT);

      state->client_finished = new Finished(writer, state->version, CLIENT,
                                            state->keys.master_secret(),
                                            state->hash);
      }
   else if(type == HANDSHAKE_CCS)
      {
      state->set_expected_next(FINISHED);

      reader.set_keys(state->suite, state->keys, CLIENT);
      }
   else if(type == FINISHED)
      {
      state->set_expected_next(HELLO_REQUEST);

      state->server_finished = new Finished(contents);

      if(!state->server_finished->verify(state->keys.master_secret(),
                                         state->version, state->hash, SERVER))
         throw TLS_Exception(DECRYPT_ERROR,
                             "Finished message didn't verify");

      delete state;
      state = 0;
      active = true;
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

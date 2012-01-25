/*
* TLS Server
* (C) 2004-2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_server.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/assert.h>
#include <memory>

namespace Botan {

namespace TLS {

namespace {

bool check_for_resume(Session& session_info,
                      Session_Manager& session_manager,
                      Client_Hello* client_hello)
   {
   MemoryVector<byte> client_session_id = client_hello->session_id();

   if(client_session_id.empty()) // not resuming
      return false;

   // not found
   if(!session_manager.load_from_session_id(client_session_id, session_info))
      return false;

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
Server::Server(std::tr1::function<void (const byte[], size_t)> output_fn,
               std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
               std::tr1::function<bool (const Session&)> handshake_fn,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const std::vector<std::string>& next_protocols) :
   Channel(output_fn, proc_fn, handshake_fn),
   policy(policy),
   rng(rng),
   session_manager(session_manager),
   creds(creds),
   m_possible_protocols(next_protocols)
   {
   }

/*
* Send a hello request to the client
*/
void Server::renegotiate()
   {
   if(state)
      return; // currently in handshake

   state = new Handshake_State;
   state->set_expected_next(CLIENT_HELLO);
   Hello_Request hello_req(writer);
   }

void Server::alert_notify(bool, Alert_Type type)
   {
   if(type == NO_RENEGOTIATION)
      {
      if(handshake_completed && state)
         {
         delete state;
         state = 0;
         }
      }
   }

/*
* Split up and process handshake messages
*/
void Server::read_handshake(byte rec_type,
                            const MemoryRegion<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE && !state)
      {
      state = new Handshake_State;
      state->set_expected_next(CLIENT_HELLO);
      }

   Channel::read_handshake(rec_type, rec_buf);
   }

/*
* Process a handshake message
*/
void Server::process_handshake_msg(Handshake_Type type,
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

      m_hostname = state->client_hello->sni_hostname();

      Protocol_Version client_version = state->client_hello->version();

      if(client_version < policy.min_version())
         throw TLS_Exception(PROTOCOL_VERSION,
                             "Client version is unacceptable by policy");

      if(client_version <= policy.pref_version())
         state->version = client_version;
      else
         state->version = policy.pref_version();

      secure_renegotiation.update(state->client_hello);

      writer.set_version(state->version);
      reader.set_version(state->version);

      Session session_info;
      const bool resuming = check_for_resume(session_info,
                                             session_manager,
                                             state->client_hello);

      if(resuming)
         {
         // resume session

         state->server_hello = new Server_Hello(
            writer,
            state->hash,
            session_info.session_id(),
            Protocol_Version(session_info.version()),
            session_info.ciphersuite_code(),
            session_info.compression_method(),
            session_info.fragment_size(),
            secure_renegotiation.supported(),
            secure_renegotiation.for_server_hello(),
            state->client_hello->next_protocol_notification(),
            m_possible_protocols,
            rng);

         if(session_info.fragment_size())
            {
            reader.set_maximum_fragment_size(session_info.fragment_size());
            writer.set_maximum_fragment_size(session_info.fragment_size());
            }

         state->suite = Ciphersuite::lookup_ciphersuite(state->server_hello->ciphersuite());

         state->keys = Session_Keys(state, session_info.master_secret(), true);

         writer.send(CHANGE_CIPHER_SPEC, 1);

         writer.activate(state->suite, state->keys, SERVER);

         state->server_finished = new Finished(writer, state, SERVER);

         if(!handshake_fn(session_info))
            session_manager.remove_entry(session_info.session_id());

         state->set_expected_next(HANDSHAKE_CCS);
         }
      else // new session
         {
         std::map<std::string, std::vector<X509_Certificate> > cert_chains;

         cert_chains["RSA"] = creds.cert_chain_single_type("RSA", "tls-server", m_hostname);
         cert_chains["DSA"] = creds.cert_chain_single_type("DSA", "tls-server", m_hostname);
         cert_chains["ECDSA"] = creds.cert_chain_single_type("ECDSA", "tls-server", m_hostname);

         std::vector<std::string> available_cert_types;

         for(std::map<std::string, std::vector<X509_Certificate> >::const_iterator i = cert_chains.begin();
             i != cert_chains.end(); ++i)
            {
            if(!i->second.empty())
               available_cert_types.push_back(i->first);
            }

         state->server_hello = new Server_Hello(
            writer,
            state->hash,
            state->version,
            *(state->client_hello),
            available_cert_types,
            policy,
            secure_renegotiation.supported(),
            secure_renegotiation.for_server_hello(),
            state->client_hello->next_protocol_notification(),
            m_possible_protocols,
            rng);

         if(state->client_hello->fragment_size())
            {
            reader.set_maximum_fragment_size(state->client_hello->fragment_size());
            writer.set_maximum_fragment_size(state->client_hello->fragment_size());
            }

         state->suite = Ciphersuite::lookup_ciphersuite(state->server_hello->ciphersuite());

         const std::string sig_algo = state->suite.sig_algo();
         const std::string kex_algo = state->suite.kex_algo();

         if(sig_algo != "")
            {
            BOTAN_ASSERT(!cert_chains[sig_algo].empty(),
                         "Attempting to send empty certificate chain");

            state->server_certs = new Certificate(writer,
                                                  state->hash,
                                                  cert_chains[sig_algo]);
            }

         std::auto_ptr<Private_Key> private_key(0);

         if(kex_algo == "RSA" || sig_algo != "")
            {
            private_key.reset(
               creds.private_key_for(state->server_certs->cert_chain()[0],
                                     "tls-server",
                                     m_hostname));
            }

         if(kex_algo == "RSA")
            {
            state->server_rsa_kex_key = private_key.release();
            }
         else
            {
            state->server_kex =
               new Server_Key_Exchange(writer, state, policy, rng, private_key.get());
            }

         std::vector<X509_Certificate> client_auth_CAs =
            creds.trusted_certificate_authorities("tls-server", m_hostname);

         if(!client_auth_CAs.empty() && state->suite.sig_algo() != "")
            {
            state->cert_req = new Certificate_Req(writer,
                                                  state->hash,
                                                  policy,
                                                  client_auth_CAs,
                                                  state->version);

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
         state->client_kex->pre_master_secret(rng, state);

      state->keys = Session_Keys(state, pre_master, false);
      }
   else if(type == CERTIFICATE_VERIFY)
      {
      state->client_verify = new Certificate_Verify(contents, state->version);

      const std::vector<X509_Certificate>& client_certs =
         state->client_certs->cert_chain();

      const bool sig_valid =
         state->client_verify->verify(client_certs[0], state);

      state->hash.update(type, contents);

      /*
      * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
      * "A handshake cryptographic operation failed, including being
      * unable to correctly verify a signature, ..."
      */
      if(!sig_valid)
         throw TLS_Exception(DECRYPT_ERROR, "Client cert verify failed");

      try
         {
         creds.verify_certificate_chain(client_certs);
         }
      catch(std::exception& e)
         {
         throw TLS_Exception(BAD_CERTIFICATE, e.what());
         }

      state->set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      if(state->server_hello->next_protocol_notification())
         state->set_expected_next(NEXT_PROTOCOL);
      else
         state->set_expected_next(FINISHED);

      reader.activate(state->suite, state->keys, SERVER);
      }
   else if(type == NEXT_PROTOCOL)
      {
      state->set_expected_next(FINISHED);

      state->next_protocol = new Next_Protocol(contents);

      m_next_protocol = state->next_protocol->protocol();
      }
   else if(type == FINISHED)
      {
      state->set_expected_next(HANDSHAKE_NONE);

      state->client_finished = new Finished(contents);

      if(!state->client_finished->verify(state, CLIENT))
         throw TLS_Exception(DECRYPT_ERROR,
                             "Finished message didn't verify");

      // already sent it if resuming
      if(!state->server_finished)
         {
         state->hash.update(type, contents);

         writer.send(CHANGE_CIPHER_SPEC, 1);

         writer.activate(state->suite, state->keys, SERVER);

         state->server_finished = new Finished(writer, state, SERVER);

         if(state->client_certs && state->client_verify)
            peer_certs = state->client_certs->cert_chain();
         }

      Session session_info(
         state->server_hello->session_id(),
         state->keys.master_secret(),
         state->server_hello->version(),
         state->server_hello->ciphersuite(),
         state->server_hello->compression_method(),
         SERVER,
         secure_renegotiation.supported(),
         state->server_hello->fragment_size(),
         peer_certs,
         m_hostname,
         ""
         );

      if(handshake_fn(session_info))
         session_manager.save(session_info);
      else
         session_manager.remove_entry(session_info.session_id());

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

}

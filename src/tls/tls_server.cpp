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
                      Credentials_Manager& credentials,
                      Client_Hello* client_hello,
                      u32bit session_ticket_lifetime)
   {
   const MemoryVector<byte>& client_session_id = client_hello->session_id();
   const MemoryVector<byte>& session_ticket = client_hello->session_ticket();

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

         if(session_ticket_lifetime &&
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

   // client sent a different SRP identity
   if(client_hello->srp_identifier() != "")
      {
      if(client_hello->srp_identifier() != session_info.srp_identifier())
         return false;
      }

   // client sent a different SNI hostname
   if(client_hello->sni_hostname() != "")
      {
      if(client_hello->sni_hostname() != session_info.sni_hostname())
         return false;
      }

   return true;
   }

/*
* Choose which ciphersuite to use
*/
u16bit choose_ciphersuite(
   const Policy& policy,
   Credentials_Manager& creds,
   const std::map<std::string, std::vector<X509_Certificate> >& cert_chains,
   const Client_Hello* client_hello)
   {
   const bool have_srp = creds.attempt_srp("tls-server",
                                           client_hello->sni_hostname());

   const std::vector<u16bit> client_suites = client_hello->ciphersuites();
   const std::vector<u16bit> server_suites = ciphersuite_list(policy, have_srp);

   if(server_suites.empty())
      throw Internal_Error("Policy forbids us from negotiating any ciphersuite");

   const bool have_shared_ecc_curve =
      (policy.choose_curve(client_hello->supported_ecc_curves()) != "");

   // Ordering by our preferences rather than by clients
   for(size_t i = 0; i != server_suites.size(); ++i)
      {
      const u16bit suite_id = server_suites[i];

      if(!value_exists(client_suites, suite_id))
         continue;

      Ciphersuite suite = Ciphersuite::by_id(suite_id);

      if(!have_shared_ecc_curve && suite.ecc_ciphersuite())
         continue;

      if(cert_chains.count(suite.sig_algo()) == 0)
         continue;

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
   const char* cert_types[] = { "RSA", "DSA", "ECDSA", 0 };

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
Server::Server(std::tr1::function<void (const byte[], size_t)> output_fn,
               std::tr1::function<void (const byte[], size_t, Alert)> proc_fn,
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

   state = new Handshake_State(new Stream_Handshake_Reader);
   state->set_expected_next(CLIENT_HELLO);
   Hello_Request hello_req(writer);
   }

void Server::alert_notify(const Alert& alert)
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
* Split up and process handshake messages
*/
void Server::read_handshake(byte rec_type,
                            const MemoryRegion<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE && !state)
      {
      state = new Handshake_State(new Stream_Handshake_Reader);
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
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Client version is unacceptable by policy");

      if(client_version <= policy.pref_version())
         state->set_version(client_version);
      else
         state->set_version(policy.pref_version());

      secure_renegotiation.update(state->client_hello);

      m_peer_supports_heartbeats = state->client_hello->supports_heartbeats();
      m_heartbeat_sending_allowed = state->client_hello->peer_can_send_heartbeats();

      writer.set_version(state->version());
      reader.set_version(state->version());

      Session session_info;
      const bool resuming = check_for_resume(session_info,
                                             session_manager,
                                             creds,
                                             state->client_hello,
                                             policy.session_ticket_lifetime());

      bool have_session_ticket_key = false;

      try
         {
         have_session_ticket_key =
            creds.psk("tls-server", "session-ticket", "").length() > 0;
         }
      catch(...) {}

      if(resuming)
         {
         // resume session

         state->server_hello = new Server_Hello(
            writer,
            state->hash,
            state->client_hello->session_id(),
            Protocol_Version(session_info.version()),
            session_info.ciphersuite_code(),
            session_info.compression_method(),
            session_info.fragment_size(),
            secure_renegotiation.supported(),
            secure_renegotiation.for_server_hello(),
            (state->client_hello->supports_session_ticket() &&
             state->client_hello->session_ticket().empty() &&
             have_session_ticket_key),
            state->client_hello->next_protocol_notification(),
            m_possible_protocols,
            state->client_hello->supports_heartbeats(),
            rng);

         secure_renegotiation.update(state->server_hello);

         if(session_info.fragment_size())
            {
            reader.set_maximum_fragment_size(session_info.fragment_size());
            writer.set_maximum_fragment_size(session_info.fragment_size());
            }

         state->suite = Ciphersuite::by_id(state->server_hello->ciphersuite());

         state->keys = Session_Keys(state, session_info.master_secret(), true);

         if(!handshake_fn(session_info))
            {
            session_manager.remove_entry(session_info.session_id());

            if(state->server_hello->supports_session_ticket()) // send an empty ticket
               state->new_session_ticket = new New_Session_Ticket(writer, state->hash);
            }

         if(state->server_hello->supports_session_ticket() && !state->new_session_ticket)
            {
            try
               {
               const SymmetricKey ticket_key = creds.psk("tls-server", "session-ticket", "");

               state->new_session_ticket =
                  new New_Session_Ticket(writer, state->hash,
                                         session_info.encrypt(ticket_key, rng),
                                         policy.session_ticket_lifetime());
               }
            catch(...) {}

            if(!state->new_session_ticket)
               state->new_session_ticket = new New_Session_Ticket(writer, state->hash);
            }

         writer.send(CHANGE_CIPHER_SPEC, 1);

         writer.activate(SERVER, state->suite, state->keys,
                         state->server_hello->compression_method());

         state->server_finished = new Finished(writer, state, SERVER);

         state->set_expected_next(HANDSHAKE_CCS);
         }
      else // new session
         {
         std::map<std::string, std::vector<X509_Certificate> > cert_chains;

         cert_chains = get_server_certs(m_hostname, creds);

         if(m_hostname != "" && cert_chains.empty())
            {
            send_alert(Alert(Alert::UNRECOGNIZED_NAME));
            cert_chains = get_server_certs("", creds);
            }

         state->server_hello = new Server_Hello(
            writer,
            state->hash,
            rng.random_vec(32), // new session ID
            state->version(),
            choose_ciphersuite(policy, creds, cert_chains, state->client_hello),
            choose_compression(policy, state->client_hello->compression_methods()),
            state->client_hello->fragment_size(),
            secure_renegotiation.supported(),
            secure_renegotiation.for_server_hello(),
            state->client_hello->supports_session_ticket() && have_session_ticket_key,
            state->client_hello->next_protocol_notification(),
            m_possible_protocols,
            state->client_hello->supports_heartbeats(),
            rng);

         secure_renegotiation.update(state->server_hello);

         if(state->client_hello->fragment_size())
            {
            reader.set_maximum_fragment_size(state->client_hello->fragment_size());
            writer.set_maximum_fragment_size(state->client_hello->fragment_size());
            }

         state->suite = Ciphersuite::by_id(state->server_hello->ciphersuite());

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

         Private_Key* private_key = 0;

         if(kex_algo == "RSA" || sig_algo != "")
            {
            private_key = creds.private_key_for(state->server_certs->cert_chain()[0],
                                                "tls-server",
                                                m_hostname);

            if(!private_key)
               throw Internal_Error("No private key located for associated server cert");
            }

         if(kex_algo == "RSA")
            {
            state->server_rsa_kex_key = private_key;
            }
         else
            {
            state->server_kex =
               new Server_Key_Exchange(writer, state, policy, creds, rng, private_key);
            }

         std::vector<X509_Certificate> client_auth_CAs =
            creds.trusted_certificate_authorities("tls-server", m_hostname);

         if(!client_auth_CAs.empty() && state->suite.sig_algo() != "")
            {
            state->cert_req = new Certificate_Req(writer,
                                                  state->hash,
                                                  policy,
                                                  client_auth_CAs,
                                                  state->version());

            state->set_expected_next(CERTIFICATE);
            }

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

      state->set_expected_next(CLIENT_KEX);
      }
   else if(type == CLIENT_KEX)
      {
      if(state->received_handshake_msg(CERTIFICATE) && !state->client_certs->empty())
         state->set_expected_next(CERTIFICATE_VERIFY);
      else
         state->set_expected_next(HANDSHAKE_CCS);

      state->client_kex = new Client_Key_Exchange(contents, state, creds, policy, rng);

      state->keys = Session_Keys(state, state->client_kex->pre_master_secret(), false);
      }
   else if(type == CERTIFICATE_VERIFY)
      {
      state->client_verify = new Certificate_Verify(contents, state->version());

      peer_certs = state->client_certs->cert_chain();

      const bool sig_valid =
         state->client_verify->verify(peer_certs[0], state);

      state->hash.update(type, contents);

      /*
      * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
      * "A handshake cryptographic operation failed, including being
      * unable to correctly verify a signature, ..."
      */
      if(!sig_valid)
         throw TLS_Exception(Alert::DECRYPT_ERROR, "Client cert verify failed");

      try
         {
         creds.verify_certificate_chain("tls-server", "", peer_certs);
         }
      catch(std::exception& e)
         {
         throw TLS_Exception(Alert::BAD_CERTIFICATE, e.what());
         }

      state->set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      if(state->server_hello->next_protocol_notification())
         state->set_expected_next(NEXT_PROTOCOL);
      else
         state->set_expected_next(FINISHED);

      reader.activate(SERVER, state->suite, state->keys,
                      state->server_hello->compression_method());
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
         throw TLS_Exception(Alert::DECRYPT_ERROR,
                             "Finished message didn't verify");

      if(!state->server_finished)
         {
         // already sent finished if resuming, so this is a new session

         state->hash.update(type, contents);

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
            MemoryVector<byte>(),
            m_hostname,
            state->srp_identifier()
            );

         if(handshake_fn(session_info))
            {
            if(state->server_hello->supports_session_ticket())
               {
               try
                  {
                  const SymmetricKey ticket_key = creds.psk("tls-server", "session-ticket", "");

                  state->new_session_ticket =
                     new New_Session_Ticket(writer, state->hash,
                                            session_info.encrypt(ticket_key, rng),
                                            policy.session_ticket_lifetime());
                  }
               catch(...) {}
               }
            else
               session_manager.save(session_info);
            }

         if(state->server_hello->supports_session_ticket() && !state->new_session_ticket)
            state->new_session_ticket = new New_Session_Ticket(writer, state->hash);

         writer.send(CHANGE_CIPHER_SPEC, 1);

         writer.activate(SERVER, state->suite, state->keys,
                         state->server_hello->compression_method());

         state->server_finished = new Finished(writer, state, SERVER);
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

}

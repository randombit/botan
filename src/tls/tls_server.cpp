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
                      std::chrono::seconds session_ticket_lifetime)
   {
   const std::vector<byte>& client_session_id = client_hello->session_id();
   const std::vector<byte>& session_ticket = client_hello->session_ticket();

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

         if(session_ticket_lifetime != std::chrono::seconds(0) &&
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

      if(suite.sig_algo() != "" && cert_chains.count(suite.sig_algo()) == 0)
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
   const char* cert_types[] = { "RSA", "DSA", "ECDSA", nullptr };

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
Server::Server(std::function<void (const byte[], size_t)> output_fn,
               std::function<void (const byte[], size_t, Alert)> proc_fn,
               std::function<bool (const Session&)> handshake_fn,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const std::vector<std::string>& next_protocols) :
   Channel(output_fn, proc_fn, handshake_fn, session_manager, rng),
   m_policy(policy),
   m_rng(rng),
   m_creds(creds),
   m_possible_protocols(next_protocols)
   {
   }

Handshake_Reader* Server::new_handshake_reader() const
   {
   return new Stream_Handshake_Reader;
   }

/*
* Send a hello request to the client
*/
void Server::renegotiate(bool force_full_renegotiation)
   {
   if(m_state)
      return; // currently in handshake

   m_state = new Handshake_State(this->new_handshake_reader());

   m_state->allow_session_resumption = !force_full_renegotiation;
   m_state->set_expected_next(CLIENT_HELLO);
   Hello_Request hello_req(m_writer);
   }

void Server::alert_notify(const Alert& alert)
   {
   if(alert.type() == Alert::NO_RENEGOTIATION)
      {
      if(m_handshake_completed && m_state)
         {
         delete m_state;
         m_state = nullptr;
         }
      }
   }

/*
* Split up and process handshake messages
*/
void Server::read_handshake(byte rec_type,
                            const std::vector<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE && !m_state)
      {
      m_state = new Handshake_State(this->new_handshake_reader());
      m_state->set_expected_next(CLIENT_HELLO);
      }

   Channel::read_handshake(rec_type, rec_buf);
   }

/*
* Process a handshake message
*/
void Server::process_handshake_msg(Handshake_Type type,
                                   const std::vector<byte>& contents)
   {
   if(!m_state)
      throw Unexpected_Message("Unexpected handshake message from client");

   m_state->confirm_transition_to(type);

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
         m_state->hash.update(contents);
      else
         m_state->hash.update(type, contents);
      }

   if(type == CLIENT_HELLO || type == CLIENT_HELLO_SSLV2)
      {
      m_state->client_hello = new Client_Hello(contents, type);

      if(m_state->client_hello->sni_hostname() != "")
         m_hostname = m_state->client_hello->sni_hostname();

      Protocol_Version client_version = m_state->client_hello->version();

      if(!m_policy.acceptable_protocol_version(m_state->version()))
         {
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Client version is unacceptable by policy");
         }

      if(!client_version.known_version())
         {
         /*
         This isn't a version we know. This implies this is a later
         version than any version defined as of 2012. Offer them
         the latest version we know.
         */
         m_state->set_version(Protocol_Version::TLS_V12);
         }
      else
         {
         Protocol_Version prev_version = m_reader.get_version();

         if(prev_version.valid() && client_version != prev_version)
            {
            /*
            * If this is a renegotation, and the client has offered a
            * later version than what it initially negotiated,
            * negotiate the old version. This matches OpenSSL's
            * behavior. If the client is offering a version earlier
            * than what it initially negotiated, reject as a probable
            * attack.
            */
            if(prev_version > client_version)
               {
               throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                   "Client negotiated " +
                                   prev_version.to_string() +
                                   " then renegotiated with " +
                                   client_version.to_string());
               }

            m_state->set_version(prev_version);
            }
         else
            {
            m_state->set_version(client_version);
            }
         }

      if(!m_policy.allow_insecure_renegotiation() &&
         !(m_secure_renegotiation.initial_handshake() || m_secure_renegotiation.supported()))
         {
         delete m_state;
         m_state = nullptr;
         send_alert(Alert(Alert::NO_RENEGOTIATION));
         return;
         }

      m_secure_renegotiation.update(m_state->client_hello);

      m_peer_supports_heartbeats = m_state->client_hello->supports_heartbeats();
      m_heartbeat_sending_allowed = m_state->client_hello->peer_can_send_heartbeats();

      m_writer.set_version(m_state->version());
      m_reader.set_version(m_state->version());

      Session session_info;
      const bool resuming =
         m_state->allow_session_resumption &&
         check_for_resume(session_info,
                          m_session_manager,
                          m_creds,
                          m_state->client_hello,
                          std::chrono::seconds(m_policy.session_ticket_lifetime()));

      bool have_session_ticket_key = false;

      try
         {
         have_session_ticket_key =
            m_creds.psk("tls-server", "session-ticket", "").length() > 0;
         }
      catch(...) {}

      if(resuming)
         {
         // resume session

         m_state->server_hello = new Server_Hello(
            m_writer,
            m_state->hash,
            m_state->client_hello->session_id(),
            Protocol_Version(session_info.version()),
            session_info.ciphersuite_code(),
            session_info.compression_method(),
            session_info.fragment_size(),
            m_secure_renegotiation.supported(),
            m_secure_renegotiation.for_server_hello(),
            (m_state->client_hello->supports_session_ticket() &&
             m_state->client_hello->session_ticket().empty() &&
             have_session_ticket_key),
            m_state->client_hello->next_protocol_notification(),
            m_possible_protocols,
            m_state->client_hello->supports_heartbeats(),
            m_rng);

         m_secure_renegotiation.update(m_state->server_hello);

         if(session_info.fragment_size())
            {
            m_reader.set_maximum_fragment_size(session_info.fragment_size());
            m_writer.set_maximum_fragment_size(session_info.fragment_size());
            }

         m_state->suite = Ciphersuite::by_id(m_state->server_hello->ciphersuite());

         m_state->keys = Session_Keys(m_state, session_info.master_secret(), true);

         if(!m_handshake_fn(session_info))
            {
            m_session_manager.remove_entry(session_info.session_id());

            if(m_state->server_hello->supports_session_ticket()) // send an empty ticket
               m_state->new_session_ticket = new New_Session_Ticket(m_writer, m_state->hash);
            }

         if(m_state->server_hello->supports_session_ticket() && !m_state->new_session_ticket)
            {
            try
               {
               const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");

               m_state->new_session_ticket =
                  new New_Session_Ticket(m_writer, m_state->hash,
                                         session_info.encrypt(ticket_key, m_rng),
                                         m_policy.session_ticket_lifetime());
               }
            catch(...) {}

            if(!m_state->new_session_ticket)
               m_state->new_session_ticket = new New_Session_Ticket(m_writer, m_state->hash);
            }

         m_writer.send(CHANGE_CIPHER_SPEC, 1);

         m_writer.activate(SERVER, m_state->suite, m_state->keys,
                           m_state->server_hello->compression_method());

         m_state->server_finished = new Finished(m_writer, m_state, SERVER);

         m_state->set_expected_next(HANDSHAKE_CCS);
         }
      else // new session
         {
         std::map<std::string, std::vector<X509_Certificate> > cert_chains;

         cert_chains = get_server_certs(m_hostname, m_creds);

         if(m_hostname != "" && cert_chains.empty())
            {
            cert_chains = get_server_certs("", m_creds);

            /*
            * Only send the unrecognized_name alert if we couldn't
            * find any certs for the requested name but did find at
            * least one cert to use in general. That avoids sending an
            * unrecognized_name when a server is configured for purely
            * anonymous operation.
            */
            if(!cert_chains.empty())
               send_alert(Alert(Alert::UNRECOGNIZED_NAME));
            }

         m_state->server_hello = new Server_Hello(
            m_writer,
            m_state->hash,
            make_hello_random(m_rng), // new session ID
            m_state->version(),
            choose_ciphersuite(m_policy, m_creds, cert_chains, m_state->client_hello),
            choose_compression(m_policy, m_state->client_hello->compression_methods()),
            m_state->client_hello->fragment_size(),
            m_secure_renegotiation.supported(),
            m_secure_renegotiation.for_server_hello(),
            m_state->client_hello->supports_session_ticket() && have_session_ticket_key,
            m_state->client_hello->next_protocol_notification(),
            m_possible_protocols,
            m_state->client_hello->supports_heartbeats(),
            m_rng);

         m_secure_renegotiation.update(m_state->server_hello);

         if(m_state->client_hello->fragment_size())
            {
            m_reader.set_maximum_fragment_size(m_state->client_hello->fragment_size());
            m_writer.set_maximum_fragment_size(m_state->client_hello->fragment_size());
            }

         m_state->suite = Ciphersuite::by_id(m_state->server_hello->ciphersuite());

         const std::string sig_algo = m_state->suite.sig_algo();
         const std::string kex_algo = m_state->suite.kex_algo();

         if(sig_algo != "")
            {
            BOTAN_ASSERT(!cert_chains[sig_algo].empty(),
                         "Attempting to send empty certificate chain");

            m_state->server_certs = new Certificate(m_writer,
                                                  m_state->hash,
                                                  cert_chains[sig_algo]);
            }

         Private_Key* private_key = nullptr;

         if(kex_algo == "RSA" || sig_algo != "")
            {
            private_key = m_creds.private_key_for(
               m_state->server_certs->cert_chain()[0],
               "tls-server",
               m_hostname);

            if(!private_key)
               throw Internal_Error("No private key located for associated server cert");
            }

         if(kex_algo == "RSA")
            {
            m_state->server_rsa_kex_key = private_key;
            }
         else
            {
            m_state->server_kex =
               new Server_Key_Exchange(m_writer, m_state, m_policy, m_creds, m_rng, private_key);
            }

         std::vector<X509_Certificate> client_auth_CAs =
            m_creds.trusted_certificate_authorities("tls-server", m_hostname);

         if(!client_auth_CAs.empty() && m_state->suite.sig_algo() != "")
            {
            m_state->cert_req = new Certificate_Req(m_writer,
                                                  m_state->hash,
                                                  m_policy,
                                                  client_auth_CAs,
                                                  m_state->version());

            m_state->set_expected_next(CERTIFICATE);
            }

         /*
         * If the client doesn't have a cert they want to use they are
         * allowed to send either an empty cert message or proceed
         * directly to the client key exchange, so allow either case.
         */
         m_state->set_expected_next(CLIENT_KEX);

         m_state->server_hello_done = new Server_Hello_Done(m_writer, m_state->hash);
         }
      }
   else if(type == CERTIFICATE)
      {
      m_state->client_certs = new Certificate(contents);

      m_state->set_expected_next(CLIENT_KEX);
      }
   else if(type == CLIENT_KEX)
      {
      if(m_state->received_handshake_msg(CERTIFICATE) && !m_state->client_certs->empty())
         m_state->set_expected_next(CERTIFICATE_VERIFY);
      else
         m_state->set_expected_next(HANDSHAKE_CCS);

      m_state->client_kex = new Client_Key_Exchange(contents, m_state, m_creds, m_policy, m_rng);

      m_state->keys = Session_Keys(m_state, m_state->client_kex->pre_master_secret(), false);
      }
   else if(type == CERTIFICATE_VERIFY)
      {
      m_state->client_verify = new Certificate_Verify(contents, m_state->version());

      m_peer_certs = m_state->client_certs->cert_chain();

      const bool sig_valid =
         m_state->client_verify->verify(m_peer_certs[0], m_state);

      m_state->hash.update(type, contents);

      /*
      * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
      * "A handshake cryptographic operation failed, including being
      * unable to correctly verify a signature, ..."
      */
      if(!sig_valid)
         throw TLS_Exception(Alert::DECRYPT_ERROR, "Client cert verify failed");

      try
         {
         m_creds.verify_certificate_chain("tls-server", "", m_peer_certs);
         }
      catch(std::exception& e)
         {
         throw TLS_Exception(Alert::BAD_CERTIFICATE, e.what());
         }

      m_state->set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      if(m_state->server_hello->next_protocol_notification())
         m_state->set_expected_next(NEXT_PROTOCOL);
      else
         m_state->set_expected_next(FINISHED);

      m_reader.activate(SERVER, m_state->suite, m_state->keys,
                        m_state->server_hello->compression_method());
      }
   else if(type == NEXT_PROTOCOL)
      {
      m_state->set_expected_next(FINISHED);

      m_state->next_protocol = new Next_Protocol(contents);

      m_next_protocol = m_state->next_protocol->protocol();
      }
   else if(type == FINISHED)
      {
      m_state->set_expected_next(HANDSHAKE_NONE);

      m_state->client_finished = new Finished(contents);

      if(!m_state->client_finished->verify(m_state, CLIENT))
         throw TLS_Exception(Alert::DECRYPT_ERROR,
                             "Finished message didn't verify");

      if(!m_state->server_finished)
         {
         // already sent finished if resuming, so this is a new session

         m_state->hash.update(type, contents);

         Session session_info(
            m_state->server_hello->session_id(),
            m_state->keys.master_secret(),
            m_state->server_hello->version(),
            m_state->server_hello->ciphersuite(),
            m_state->server_hello->compression_method(),
            SERVER,
            m_secure_renegotiation.supported(),
            m_state->server_hello->fragment_size(),
            m_peer_certs,
            std::vector<byte>(),
            m_hostname,
            m_state->srp_identifier()
            );

         if(m_handshake_fn(session_info))
            {
            if(m_state->server_hello->supports_session_ticket())
               {
               try
                  {
                  const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");

                  m_state->new_session_ticket =
                     new New_Session_Ticket(m_writer, m_state->hash,
                                            session_info.encrypt(ticket_key, m_rng),
                                            m_policy.session_ticket_lifetime());
                  }
               catch(...) {}
               }
            else
               m_session_manager.save(session_info);
            }

         if(m_state->server_hello->supports_session_ticket() && !m_state->new_session_ticket)
            m_state->new_session_ticket = new New_Session_Ticket(m_writer, m_state->hash);

         m_writer.send(CHANGE_CIPHER_SPEC, 1);

         m_writer.activate(SERVER, m_state->suite, m_state->keys,
                           m_state->server_hello->compression_method());

         m_state->server_finished = new Finished(m_writer, m_state, SERVER);
         }

      m_secure_renegotiation.update(m_state->client_finished,
                                    m_state->server_finished);

      m_active_session = m_state->server_hello->session_id();
      delete m_state;
      m_state = nullptr;
      m_handshake_completed = true;

      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

}

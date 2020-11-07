/*
* TLS Server
* (C) 2004-2011,2012,2016 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_server.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/stl_util.h>
#include <botan/tls_magic.h>

#include <botan/hash.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_record.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

class Server_Handshake_State final : public Handshake_State
   {
   public:
      Server_Handshake_State(Handshake_IO* io, Callbacks& cb)
         : Handshake_State(io, cb) {}

      Private_Key* server_rsa_kex_key() { return m_server_rsa_kex_key; }
      void set_server_rsa_kex_key(Private_Key* key)
         { m_server_rsa_kex_key = key; }

      bool allow_session_resumption() const
         { return m_allow_session_resumption; }
      void set_allow_session_resumption(bool allow_session_resumption)
         { m_allow_session_resumption = allow_session_resumption; }

      const std::vector<X509_Certificate>& resume_peer_certs() const
         { return m_resume_peer_certs; }

      void set_resume_certs(const std::vector<X509_Certificate>& certs)
         { m_resume_peer_certs = certs; }

      void mark_as_resumption() { m_is_a_resumption = true; }

      bool is_a_resumption() const { return m_is_a_resumption; }

   private:
      // Used by the server only, in case of RSA key exchange. Not owned
      Private_Key* m_server_rsa_kex_key = nullptr;

      /*
      * Used by the server to know if resumption should be allowed on
      * a server-initiated renegotiation
      */
      bool m_allow_session_resumption = true;

      bool m_is_a_resumption = false;

      std::vector<X509_Certificate> m_resume_peer_certs;
   };

namespace {

bool check_for_resume(Session& session_info,
                      Session_Manager& session_manager,
                      Credentials_Manager& credentials,
                      const Client_Hello* client_hello,
                      std::chrono::seconds session_ticket_lifetime)
   {
   const std::vector<uint8_t>& client_session_id = client_hello->session_id();
   const std::vector<uint8_t>& session_ticket = client_hello->session_ticket();

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

#if defined(BOTAN_HAS_SRP6)
   // client sent a different SRP identity
   if(client_hello->srp_identifier() != "")
      {
      if(client_hello->srp_identifier() != session_info.srp_identifier())
         return false;
      }
#endif

   // client sent a different SNI hostname
   if(client_hello->sni_hostname() != "")
      {
      if(client_hello->sni_hostname() != session_info.server_info().hostname())
         return false;
      }

   // Checking extended_master_secret on resume (RFC 7627 section 5.3)
   if(client_hello->supports_extended_master_secret() != session_info.supports_extended_master_secret())
      {
      if(!session_info.supports_extended_master_secret())
         {
         return false; // force new handshake with extended master secret
         }
      else
         {
         /*
         Client previously negotiated session with extended master secret,
         but has now attempted to resume without the extension: abort
         */
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client resumed extended ms session without sending extension");
         }
      }

   // Checking encrypt_then_mac on resume (RFC 7366 section 3.1)
   if(!client_hello->supports_encrypt_then_mac() && session_info.supports_encrypt_then_mac())
      {
      /*
      Client previously negotiated session with Encrypt-then-MAC,
      but has now attempted to resume without the extension: abort
      */
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client resumed Encrypt-then-MAC session without sending extension");
      }

   return true;
   }

/*
* Choose which ciphersuite to use
*/
uint16_t choose_ciphersuite(
   const Policy& policy,
   Protocol_Version version,
   Credentials_Manager& creds,
   const std::map<std::string, std::vector<X509_Certificate>>& cert_chains,
   const Client_Hello& client_hello)
   {
   const bool our_choice = policy.server_uses_own_ciphersuite_preferences();
   const bool have_srp = creds.attempt_srp("tls-server", client_hello.sni_hostname());
   const std::vector<uint16_t> client_suites = client_hello.ciphersuites();
   const std::vector<uint16_t> server_suites = policy.ciphersuite_list(version, have_srp);

   if(server_suites.empty())
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                          "Policy forbids us from negotiating any ciphersuite");

   const bool have_shared_ecc_curve =
      (policy.choose_key_exchange_group(client_hello.supported_ecc_curves()) != Group_Params::NONE);

   /*
   Walk down one list in preference order
   */
   std::vector<uint16_t> pref_list = server_suites;
   std::vector<uint16_t> other_list = client_suites;

   if(!our_choice)
      std::swap(pref_list, other_list);

   for(auto suite_id : pref_list)
      {
      if(!value_exists(other_list, suite_id))
         continue;

      const Ciphersuite suite = Ciphersuite::by_id(suite_id);

      if(suite.valid() == false)
         {
         continue;
         }

      if(have_shared_ecc_curve == false && suite.ecc_ciphersuite())
         {
         continue;
         }

      // For non-anon ciphersuites
      if(suite.signature_used())
         {
         const std::string sig_algo = suite.sig_algo();

         // Do we have any certificates for this sig?
         if(cert_chains.count(sig_algo) == 0)
            {
            continue;
            }

         if(version.supports_negotiable_signature_algorithms())
            {
            const std::vector<Signature_Scheme> allowed =
               policy.allowed_signature_schemes();

            std::vector<Signature_Scheme> client_sig_methods =
               client_hello.signature_schemes();

            if(client_sig_methods.empty())
               {
               // If empty, then implicit SHA-1 (TLS v1.2 rules)
               client_sig_methods.push_back(Signature_Scheme::RSA_PKCS1_SHA1);
               client_sig_methods.push_back(Signature_Scheme::ECDSA_SHA1);
               client_sig_methods.push_back(Signature_Scheme::DSA_SHA1);
               }

            bool we_support_some_hash_by_client = false;

            for(Signature_Scheme scheme : client_sig_methods)
               {
               if(signature_scheme_is_known(scheme) == false)
                  continue;

               if(signature_algorithm_of_scheme(scheme) == suite.sig_algo() &&
                  policy.allowed_signature_hash(hash_function_of_scheme(scheme)))
                  {
                  we_support_some_hash_by_client = true;
                  }
               }

            if(we_support_some_hash_by_client == false)
               {
               throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                   "Policy does not accept any hash function supported by client");
               }
            }
         }

#if defined(BOTAN_HAS_SRP6)
      /*
      The client may offer SRP cipher suites in the hello message but
      omit the SRP extension.  If the server would like to select an
      SRP cipher suite in this case, the server SHOULD return a fatal
      "unknown_psk_identity" alert immediately after processing the
      client hello message.
       - RFC 5054 section 2.5.1.2
      */
      if(suite.kex_method() == Kex_Algo::SRP_SHA && client_hello.srp_identifier() == "")
         throw TLS_Exception(Alert::UNKNOWN_PSK_IDENTITY,
                             "Client wanted SRP but did not send username");
#endif

      return suite_id;
      }

   throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                       "Can't agree on a ciphersuite with client");
   }

std::map<std::string, std::vector<X509_Certificate>>
get_server_certs(const std::string& hostname,
                 Credentials_Manager& creds)
   {
   const char* cert_types[] = { "RSA", "ECDSA", "DSA", nullptr };

   std::map<std::string, std::vector<X509_Certificate>> cert_chains;

   for(size_t i = 0; cert_types[i]; ++i)
      {
      const std::vector<X509_Certificate> certs =
         creds.cert_chain_single_type(cert_types[i], "tls-server", hostname);

      if(!certs.empty())
         cert_chains[cert_types[i]] = certs;
      }

   return cert_chains;
   }

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
read_cookie_and_input_bits(const std::vector<uint8_t>& buf)
   {
   BOTAN_ASSERT_NOMSG(buf.size() > 41);

   TLS_Data_Reader reader("ClientHello", buf);

   reader.discard_next(34); // version, random

   const size_t sess_id_len = reader.get_byte();

   if (sess_id_len > 32)
      {
      throw Decoding_Error("Invalid ClientHello: session id is too long");
      }

   reader.discard_next(sess_id_len);

   std::unique_ptr<HashFunction> sha256;
   sha256 = HashFunction::create_or_throw("SHA-256");
   sha256->update(reader.get_data_read_so_far());

   std::vector<uint8_t> cookie = reader.get_range<uint8_t>(1, 0, 255);

   sha256->update(reader.get_remaining());
   std::vector<uint8_t> input_bits(sha256->output_length());
   sha256->final(input_bits.data());

   return std::make_pair(cookie, input_bits);
   }

}

DTLS_Prestate::DTLS_Prestate(bool validity,
                             std::unique_ptr<std::vector<uint8_t>> contents,
                             Protocol_Version record_version,
                             uint16_t in_message_seq,
                             uint64_t in_record_seq,
                             uint16_t out_message_seq) :
   m_validity(validity),
   m_contents(std::move(contents)),
   m_record_version(record_version),
   m_in_message_seq(in_message_seq),
   m_in_record_seq(in_record_seq),
   m_out_message_seq(out_message_seq)
   {
   }

bool DTLS_Prestate::cookie_valid() const
   {
   return m_validity;
   }

void DTLS_Prestate::invalidate()
   {
   m_validity = false;
   }

/*
* TLS Server Constructor
*/
Server::Server(Callbacks& callbacks,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               bool is_datagram,
               size_t io_buf_sz) :
   Channel(callbacks, session_manager, rng, policy,
           true, is_datagram, io_buf_sz),
   m_creds(creds)
   {
   }

Server::Server(Callbacks& callbacks,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               DTLS_Prestate& prestate,
               size_t io_buf_sz) :
   Channel(callbacks, session_manager, rng, policy,
           true, true, io_buf_sz),
   m_creds(creds),
   m_prestate_set(true)
   {
   BOTAN_ASSERT(prestate.cookie_valid(), "Cookie is invalid");
   prestate.invalidate();
   process_prestate(&prestate);
   }

Server::Server(output_fn output,
               data_cb got_data_cb,
               alert_cb recv_alert_cb,
               handshake_cb hs_cb,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               next_protocol_fn next_proto,
               bool is_datagram,
               size_t io_buf_sz) :
   Channel(output, got_data_cb, recv_alert_cb, hs_cb,
           Channel::handshake_msg_cb(), session_manager,
           rng, policy, true, is_datagram, io_buf_sz),
   m_creds(creds),
   m_choose_next_protocol(next_proto)
   {
   }

Server::Server(output_fn output,
               data_cb got_data_cb,
               alert_cb recv_alert_cb,
               handshake_cb hs_cb,
               handshake_msg_cb hs_msg_cb,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               next_protocol_fn next_proto,
               bool is_datagram) :
   Channel(output, got_data_cb, recv_alert_cb, hs_cb, hs_msg_cb,
           session_manager, rng, policy, true, is_datagram),
   m_creds(creds),
   m_choose_next_protocol(next_proto)
   {
   }

Handshake_State* Server::new_handshake_state(Handshake_IO* io)
   {
   std::unique_ptr<Handshake_State> state(new Server_Handshake_State(io, callbacks()));

   state->set_expected_next(CLIENT_HELLO);
   return state.release();
   }

std::vector<X509_Certificate>
Server::get_peer_cert_chain(const Handshake_State& state_base) const
   {
   const Server_Handshake_State& state = dynamic_cast<const Server_Handshake_State&>(state_base);
   if(state.resume_peer_certs().size() > 0)
      return state.resume_peer_certs();

   if(state.client_certs())
      return state.client_certs()->cert_chain();
   return std::vector<X509_Certificate>();
   }

/*
* Send a hello request to the client
*/
void Server::initiate_handshake(Handshake_State& state,
                                bool force_full_renegotiation)
   {
   dynamic_cast<Server_Handshake_State&>(state).
       set_allow_session_resumption(!force_full_renegotiation);

   Hello_Request hello_req(state.handshake_io());
   }

namespace {

Protocol_Version select_version(const Botan::TLS::Policy& policy,
                                Protocol_Version client_offer,
                                Protocol_Version active_version,
                                bool is_fallback,
                                const std::vector<Protocol_Version>& supported_versions)
   {
   const bool is_datagram = client_offer.is_datagram_protocol();
   const bool initial_handshake = (active_version.valid() == false);

   const Protocol_Version latest_supported = policy.latest_supported_version(is_datagram);

   if(is_fallback)
      {
      if(latest_supported > client_offer)
         throw TLS_Exception(Alert::INAPPROPRIATE_FALLBACK,
                              "Client signalled fallback SCSV, possible attack");
      }

   if(supported_versions.size() > 0)
      {
      if(is_datagram)
         {
         if(policy.allow_dtls12() && value_exists(supported_versions, Protocol_Version(Protocol_Version::DTLS_V12)))
            return Protocol_Version::DTLS_V12;
#if defined(BOTAN_HAS_TLS_V10)
         if(policy.allow_dtls10() && value_exists(supported_versions, Protocol_Version(Protocol_Version::DTLS_V10)))
            return Protocol_Version::DTLS_V10;
#endif
         throw TLS_Exception(Alert::PROTOCOL_VERSION, "No shared DTLS version");
         }
      else
         {
         if(policy.allow_tls12() && value_exists(supported_versions, Protocol_Version(Protocol_Version::TLS_V12)))
            return Protocol_Version::TLS_V12;
#if defined(BOTAN_HAS_TLS_V10)
         if(policy.allow_tls11() && value_exists(supported_versions, Protocol_Version(Protocol_Version::TLS_V11)))
            return Protocol_Version::TLS_V11;
         if(policy.allow_tls10() && value_exists(supported_versions, Protocol_Version(Protocol_Version::TLS_V10)))
            return Protocol_Version::TLS_V10;
#endif
         throw TLS_Exception(Alert::PROTOCOL_VERSION, "No shared TLS version");
         }
      }

   const bool client_offer_acceptable =
      client_offer.known_version() && policy.acceptable_protocol_version(client_offer);

   if(!initial_handshake)
      {
      /*
      * If this is a renegotiation, and the client has offered a
      * later version than what it initially negotiated, negotiate
      * the old version. This matches OpenSSL's behavior. If the
      * client is offering a version earlier than what it initially
      * negotiated, reject as a probable attack.
      */
      if(active_version > client_offer)
         {
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                              "Client negotiated " +
                              active_version.to_string() +
                              " then renegotiated with " +
                              client_offer.to_string());
         }
      else
         {
         return active_version;
         }
      }
   else if(client_offer_acceptable)
      {
      return client_offer;
      }
   else if(!client_offer.known_version() || client_offer > latest_supported)
      {
      /*
      The client offered some version newer than the latest we
      support.  Offer them the best we know.
      */
      return latest_supported;
      }
   else
      {
      throw TLS_Exception(Alert::PROTOCOL_VERSION,
                           "Client version " + client_offer.to_string() +
                           " is unacceptable by policy");
      }
   }

}

/*
* Process a CLIENT HELLO Message
*/
void Server::process_client_hello_msg(const Handshake_State* active_state,
                                      Server_Handshake_State& pending_state,
                                      const std::vector<uint8_t>& contents,
                                      bool epoch0_restart)
   {
   BOTAN_ASSERT_IMPLICATION(epoch0_restart, active_state != nullptr, "Can't restart with a dead connection");

   const bool initial_handshake = epoch0_restart || !active_state;

   if(initial_handshake == false && policy().allow_client_initiated_renegotiation() == false)
      {
      if(policy().abort_connection_on_undesired_renegotiation())
         throw TLS_Exception(Alert::NO_RENEGOTIATION, "Server policy prohibits renegotiation");
      else
         send_warning_alert(Alert::NO_RENEGOTIATION);
      return;
      }

   if(!policy().allow_insecure_renegotiation() &&
      !(initial_handshake || secure_renegotiation_supported()))
      {
      send_warning_alert(Alert::NO_RENEGOTIATION);
      return;
      }

   pending_state.client_hello(new Client_Hello(contents));
   const Protocol_Version client_offer = pending_state.client_hello()->version();
   const bool datagram = client_offer.is_datagram_protocol();

   if(datagram)
      {
      if(client_offer.major_version() == 0xFF)
         throw TLS_Exception(Alert::PROTOCOL_VERSION, "Client offered DTLS version with major version 0xFF");
      }
   else
      {
      if(client_offer.major_version() < 3)
         throw TLS_Exception(Alert::PROTOCOL_VERSION, "Client offered TLS version with major version under 3");
      if(client_offer.major_version() == 3 && client_offer.minor_version() == 0)
         throw TLS_Exception(Alert::PROTOCOL_VERSION, "SSLv3 is not supported");
      }

   /*
   * BoGo test suite expects that we will send the hello verify with a record
   * version matching the version that is eventually negotiated. This is wrong
   * but harmless, so go with it. Also doing the version negotiation step first
   * allows to immediately close the connection with an alert if the client has
   * offered a version that we are not going to negotiate anyway, instead of
   * making them first do the cookie exchange and then telling them no.
   *
   * There is no issue with amplification here, since the alert is just 2 bytes.
   */
   const Protocol_Version negotiated_version =
      select_version(policy(), client_offer,
                     active_state ? active_state->version() : Protocol_Version(),
                     pending_state.client_hello()->sent_fallback_scsv(),
                     pending_state.client_hello()->supported_versions());

   pending_state.set_version(negotiated_version);

   const auto compression_methods = pending_state.client_hello()->compression_methods();
   if(!value_exists(compression_methods, uint8_t(0)))
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Client did not offer NULL compression");

   const bool already_verified = m_prestate_set && !epoch0_restart;

   if(initial_handshake && datagram && !already_verified)
      {
      SymmetricKey cookie_secret;

      try
         {
         cookie_secret = m_creds.psk("tls-server", "dtls-cookie-secret", "");
         }
      catch(...) {}

      if(cookie_secret.size() > 0)
         {
         const std::string client_identity = callbacks().tls_peer_network_identity();
         Hello_Verify_Request verify(pending_state.client_hello()->cookie_input_data(), client_identity, cookie_secret);

         if(pending_state.client_hello()->cookie() != verify.cookie())
            {
            if(epoch0_restart)
               pending_state.handshake_io().send_under_epoch(verify, 0);
            else
               pending_state.handshake_io().send(verify);

            pending_state.client_hello(nullptr);
            pending_state.set_expected_next(CLIENT_HELLO);
            return;
            }
         }
      else if(epoch0_restart)
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "Reuse of DTLS association requires DTLS cookie secret be set");
         }
      }

   if(epoch0_restart)
      {
      // If we reached here then we were able to verify the cookie
      reset_active_association_state();
      }

   secure_renegotiation_check(pending_state.client_hello());

   callbacks().tls_examine_extensions(pending_state.client_hello()->extensions(), CLIENT);

   Session session_info;
   const bool resuming =
      pending_state.allow_session_resumption() &&
      check_for_resume(session_info,
                       session_manager(),
                       m_creds,
                       pending_state.client_hello(),
                       std::chrono::seconds(policy().session_ticket_lifetime()));

   bool have_session_ticket_key = false;

   try
      {
      have_session_ticket_key =
         m_creds.psk("tls-server", "session-ticket", "").length() > 0;
      }
   catch(...) {}

   m_next_protocol = "";
   if(pending_state.client_hello()->supports_alpn())
      {
      m_next_protocol = callbacks().tls_server_choose_app_protocol(pending_state.client_hello()->next_protocols());

      // if the callback return was empty, fall back to the (deprecated) std::function
      if(m_next_protocol.empty() && m_choose_next_protocol)
         {
         m_next_protocol = m_choose_next_protocol(pending_state.client_hello()->next_protocols());
         }
      }

   if(resuming)
      {
      this->session_resume(pending_state, have_session_ticket_key, session_info);
      }
   else // new session
      {
      this->session_create(pending_state, have_session_ticket_key);
      }
   }

void Server::process_certificate_msg(Server_Handshake_State& pending_state,
                                     const std::vector<uint8_t>& contents)
   {
   pending_state.client_certs(new Certificate(contents, policy()));

   // CERTIFICATE_REQUIRED would make more sense but BoGo expects handshake failure alert
   if(pending_state.client_certs()->empty() && policy().require_client_certificate_authentication())
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "Policy requires client send a certificate, but it did not");

   pending_state.set_expected_next(CLIENT_KEX);
   }

void Server::process_client_key_exchange_msg(Server_Handshake_State& pending_state,
                                             const std::vector<uint8_t>& contents)
   {
   if(pending_state.received_handshake_msg(CERTIFICATE) && !pending_state.client_certs()->empty())
      pending_state.set_expected_next(CERTIFICATE_VERIFY);
   else
      pending_state.set_expected_next(HANDSHAKE_CCS);

   pending_state.client_kex(new Client_Key_Exchange(contents, pending_state,
                                                    pending_state.server_rsa_kex_key(),
                                                    m_creds, policy(), rng()));

   pending_state.compute_session_keys();
   }

void Server::process_change_cipher_spec_msg(Server_Handshake_State& pending_state)
   {
   pending_state.set_expected_next(FINISHED);
   change_cipher_spec_reader(SERVER);
   }

void Server::process_certificate_verify_msg(Server_Handshake_State& pending_state,
                                            Handshake_Type type,
                                            const std::vector<uint8_t>& contents)
   {
   pending_state.client_verify(new Certificate_Verify(contents, pending_state.version()));

   const std::vector<X509_Certificate>& client_certs =
      pending_state.client_certs()->cert_chain();

   const bool sig_valid =
      pending_state.client_verify()->verify(client_certs[0], pending_state, policy());

   pending_state.hash().update(pending_state.handshake_io().format(contents, type));

   /*
   * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
   * "A handshake cryptographic operation failed, including being
   * unable to correctly verify a signature, ..."
   */
   if(!sig_valid)
      throw TLS_Exception(Alert::DECRYPT_ERROR, "Client cert verify failed");

   try
      {
      const std::string sni_hostname = pending_state.client_hello()->sni_hostname();
      auto trusted_CAs = m_creds.trusted_certificate_authorities("tls-server", sni_hostname);

      callbacks().tls_verify_cert_chain(client_certs,
                                        {}, // ocsp
                                        trusted_CAs,
                                        Usage_Type::TLS_CLIENT_AUTH,
                                        sni_hostname,
                                        policy());
      }
   catch(std::exception& e)
      {
      throw TLS_Exception(Alert::BAD_CERTIFICATE, e.what());
      }

   pending_state.set_expected_next(HANDSHAKE_CCS);
   }

void Server::process_finished_msg(Server_Handshake_State& pending_state,
                                  Handshake_Type type,
                                  const std::vector<uint8_t>& contents)
   {
   pending_state.set_expected_next(HANDSHAKE_NONE);

   pending_state.client_finished(new Finished(contents));

   if(!pending_state.client_finished()->verify(pending_state, CLIENT))
      throw TLS_Exception(Alert::DECRYPT_ERROR,
                          "Finished message didn't verify");

   if(!pending_state.server_finished())
      {
      // already sent finished if resuming, so this is a new session

      pending_state.hash().update(pending_state.handshake_io().format(contents, type));

      Session session_info(
         pending_state.server_hello()->session_id(),
         pending_state.session_keys().master_secret(),
         pending_state.server_hello()->version(),
         pending_state.server_hello()->ciphersuite(),
         SERVER,
         pending_state.server_hello()->supports_extended_master_secret(),
         pending_state.server_hello()->supports_encrypt_then_mac(),
         get_peer_cert_chain(pending_state),
         std::vector<uint8_t>(),
         Server_Information(pending_state.client_hello()->sni_hostname()),
         pending_state.srp_identifier(),
         pending_state.server_hello()->srtp_profile());

      if(save_session(session_info))
         {
         if(pending_state.server_hello()->supports_session_ticket())
            {
            try
               {
               const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");

               pending_state.new_session_ticket(
                  new New_Session_Ticket(pending_state.handshake_io(),
                                         pending_state.hash(),
                                         session_info.encrypt(ticket_key, rng()),
                                         policy().session_ticket_lifetime()));
               }
            catch(...) {}
            }
         else
            session_manager().save(session_info);
         }

      if(!pending_state.new_session_ticket() &&
         pending_state.server_hello()->supports_session_ticket())
         {
         pending_state.new_session_ticket(
            new New_Session_Ticket(pending_state.handshake_io(), pending_state.hash()));
         }

      pending_state.handshake_io().send(Change_Cipher_Spec());

      change_cipher_spec_writer(SERVER);

      pending_state.server_finished(new Finished(pending_state.handshake_io(), pending_state, SERVER));
      }

   activate_session();
   }

/*
* Process a handshake message
*/
void Server::process_handshake_msg(const Handshake_State* active_state,
                                   Handshake_State& state_base,
                                   Handshake_Type type,
                                   const std::vector<uint8_t>& contents,
                                   bool epoch0_restart)
   {
   Server_Handshake_State& state = dynamic_cast<Server_Handshake_State&>(state_base);
   state.confirm_transition_to(type);

   /*
   * The change cipher spec message isn't technically a handshake
   * message so it's not included in the hash. The finished and
   * certificate verify messages are verified based on the current
   * state of the hash *before* this message so we delay adding them
   * to the hash computation until we've processed them below.
   */
   if(type != HANDSHAKE_CCS && type != FINISHED && type != CERTIFICATE_VERIFY)
      {
      state.hash().update(state.handshake_io().format(contents, type));
      }

   switch(type)
      {
      case CLIENT_HELLO:
         return this->process_client_hello_msg(active_state, state, contents, epoch0_restart);

      case CERTIFICATE:
         return this->process_certificate_msg(state, contents);

      case CLIENT_KEX:
         return this->process_client_key_exchange_msg(state, contents);

      case CERTIFICATE_VERIFY:
         return this->process_certificate_verify_msg(state, type, contents);

      case HANDSHAKE_CCS:
         return this->process_change_cipher_spec_msg(state);

      case FINISHED:
         return this->process_finished_msg(state, type, contents);

      default:
         throw Unexpected_Message("Unknown handshake message received");
      }
   }

void Server::session_resume(Server_Handshake_State& pending_state,
                            bool have_session_ticket_key,
                            Session& session_info)
   {
   // Only offer a resuming client a new ticket if they didn't send one this time,
   // ie, resumed via server-side resumption. TODO: also send one if expiring soon?

   const bool offer_new_session_ticket =
      (pending_state.client_hello()->supports_session_ticket() &&
       pending_state.client_hello()->session_ticket().empty() &&
       have_session_ticket_key);

   pending_state.server_hello(new Server_Hello(
                                 pending_state.handshake_io(),
                                 pending_state.hash(),
                                 policy(),
                                 callbacks(),
                                 rng(),
                                 secure_renegotiation_data_for_server_hello(),
                                 *pending_state.client_hello(),
                                 session_info,
                                 offer_new_session_ticket,
                                 m_next_protocol));

   secure_renegotiation_check(pending_state.server_hello());

   pending_state.mark_as_resumption();
   pending_state.compute_session_keys(session_info.master_secret());
   pending_state.set_resume_certs(session_info.peer_certs());

   if(!save_session(session_info))
      {
      session_manager().remove_entry(session_info.session_id());

      if(pending_state.server_hello()->supports_session_ticket()) // send an empty ticket
         {
         pending_state.new_session_ticket(
            new New_Session_Ticket(pending_state.handshake_io(),
                                   pending_state.hash()));
         }
      }

   if(pending_state.server_hello()->supports_session_ticket() && !pending_state.new_session_ticket())
      {
      try
         {
         const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");

         pending_state.new_session_ticket(
            new New_Session_Ticket(pending_state.handshake_io(),
                                   pending_state.hash(),
                                   session_info.encrypt(ticket_key, rng()),
                                   policy().session_ticket_lifetime()));
         }
      catch(...) {}

      if(!pending_state.new_session_ticket())
         {
         pending_state.new_session_ticket(
            new New_Session_Ticket(pending_state.handshake_io(), pending_state.hash()));
         }
      }

   pending_state.handshake_io().send(Change_Cipher_Spec());

   change_cipher_spec_writer(SERVER);

   pending_state.server_finished(new Finished(pending_state.handshake_io(), pending_state, SERVER));
   pending_state.set_expected_next(HANDSHAKE_CCS);
   }

void Server::session_create(Server_Handshake_State& pending_state,
                            bool have_session_ticket_key)
   {
   std::map<std::string, std::vector<X509_Certificate>> cert_chains;

   const std::string sni_hostname = pending_state.client_hello()->sni_hostname();

   cert_chains = get_server_certs(sni_hostname, m_creds);

   if(sni_hostname != "" && cert_chains.empty())
      {
      cert_chains = get_server_certs("", m_creds);

      /*
      * Only send the unrecognized_name alert if we couldn't
      * find any certs for the requested name but did find at
      * least one cert to use in general. That avoids sending an
      * unrecognized_name when a server is configured for purely
      * anonymous/PSK operation.
      */
      if(!cert_chains.empty())
         send_warning_alert(Alert::UNRECOGNIZED_NAME);
      }

   const uint16_t ciphersuite = choose_ciphersuite(policy(), pending_state.version(),
                                                   m_creds, cert_chains,
                                                   *pending_state.client_hello());

   Server_Hello::Settings srv_settings(
      make_hello_random(rng(), policy()), // new session ID
      pending_state.version(),
      ciphersuite,
      have_session_ticket_key);

   pending_state.server_hello(new Server_Hello(
                                 pending_state.handshake_io(),
                                 pending_state.hash(),
                                 policy(),
                                 callbacks(),
                                 rng(),
                                 secure_renegotiation_data_for_server_hello(),
                                 *pending_state.client_hello(),
                                 srv_settings,
                                 m_next_protocol));

   secure_renegotiation_check(pending_state.server_hello());

   const Ciphersuite& pending_suite = pending_state.ciphersuite();

   Private_Key* private_key = nullptr;

   if(pending_suite.signature_used() || pending_suite.kex_method() == Kex_Algo::STATIC_RSA)
      {
      const std::string algo_used =
         pending_suite.signature_used() ? pending_suite.sig_algo() : "RSA";

      BOTAN_ASSERT(!cert_chains[algo_used].empty(),
                     "Attempting to send empty certificate chain");

      pending_state.server_certs(new Certificate(pending_state.handshake_io(),
                                                 pending_state.hash(),
                                                 cert_chains[algo_used]));

      if(pending_state.client_hello()->supports_cert_status_message() && pending_state.is_a_resumption() == false)
         {
         auto csr = pending_state.client_hello()->extensions().get<Certificate_Status_Request>();
         // csr is non-null if client_hello()->supports_cert_status_message()
         BOTAN_ASSERT_NOMSG(csr != nullptr);
         const auto resp_bytes = callbacks().tls_provide_cert_status(cert_chains[algo_used], *csr);
         if(resp_bytes.size() > 0)
            {
            pending_state.server_cert_status(new Certificate_Status(
                                                pending_state.handshake_io(),
                                                pending_state.hash(),
                                                resp_bytes
                                                ));
            }
         }

      private_key = m_creds.private_key_for(
         pending_state.server_certs()->cert_chain()[0],
         "tls-server",
         sni_hostname);

      if(!private_key)
         throw Internal_Error("No private key located for associated server cert");
      }

   if(pending_suite.kex_method() == Kex_Algo::STATIC_RSA)
      {
      pending_state.set_server_rsa_kex_key(private_key);
      }
   else
      {
      pending_state.server_kex(new Server_Key_Exchange(pending_state.handshake_io(),
                                                       pending_state, policy(),
                                                       m_creds, rng(), private_key));
      }

   auto trusted_CAs = m_creds.trusted_certificate_authorities("tls-server", sni_hostname);

   std::vector<X509_DN> client_auth_CAs;

   for(auto store : trusted_CAs)
      {
      auto subjects = store->all_subjects();
      client_auth_CAs.insert(client_auth_CAs.end(), subjects.begin(), subjects.end());
      }

   const bool request_cert =
      (client_auth_CAs.empty() == false) ||
      policy().request_client_certificate_authentication();

   if(request_cert && pending_state.ciphersuite().signature_used())
      {
      pending_state.cert_req(
         new Certificate_Req(pending_state.handshake_io(),
                             pending_state.hash(),
                             policy(),
                             client_auth_CAs,
                             pending_state.version()));

      /*
      SSLv3 allowed clients to skip the Certificate message entirely
      if they wanted. In TLS v1.0 and later clients must send a
      (possibly empty) Certificate message
      */
      pending_state.set_expected_next(CERTIFICATE);
      }
   else
      {
      pending_state.set_expected_next(CLIENT_KEX);
      }

   pending_state.server_hello_done(new Server_Hello_Done(pending_state.handshake_io(), pending_state.hash()));
   }

DTLS_Prestate Server::pre_verify_cookie(Credentials_Manager& creds,
                                        const Policy& policy,
                                        const std::string& client_identity,
                                        const uint8_t input[],
                                        size_t buf_size,
                                        output_fn emit_data_fn)
   {
   secure_vector<uint8_t> readbuf;
   secure_vector<uint8_t> record_buf;
   size_t consumed = 0;

   const Record_Header record =
      read_record(true, readbuf, input,
                  buf_size, consumed,
                  record_buf, nullptr,
                  [](uint16_t) -> std::shared_ptr<Connection_Cipher_State> {return nullptr;},
                  true);

   if (record.type() != HANDSHAKE)
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                          "Not a handshake record");
      }

   // the same check as in Channel::received_data
   if (record.version().major_version() != 0xFE)
      {
      throw TLS_Exception(Alert::PROTOCOL_VERSION,
                          "Unexpected record version");
      }

   if (record.epoch() != 0)
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                          "Initial client hello is not epoch 0");
      }

   // 12 bytes message header plus 41 bytes contents
   if (record_buf.size() < 53)
      {
      throw TLS_Exception(Alert::DECODE_ERROR,
                          "Message is too short");
      }

   const Handshake_Type msg_type =
      static_cast<Handshake_Type>(record_buf[0]);

   if (msg_type != CLIENT_HELLO)
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                        "Not a client hello");
      }

   const size_t length = 4 + make_uint32(0, record_buf[1], record_buf[2], record_buf[3]);

   if (length <= 4 || record_buf.size() != length + 8)
      {
      throw TLS_Exception(Alert::DECODE_ERROR,
                          "Bad length in client hello");
      }

   const uint16_t msg_seq = make_uint16(record_buf[4], record_buf[5]);
   const size_t fragment_offset = make_uint32(0, record_buf[6], record_buf[7], record_buf[8]);
   const size_t fragment_len = make_uint32(0, record_buf[9], record_buf[10], record_buf[11]);

   if (fragment_offset != 0 || fragment_len != length - 4)
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                          "Fragmented first client hello");
      }

   SymmetricKey cookie_secret;
   try
      {
      cookie_secret = creds.psk("tls-server", "dtls-cookie-secret", "");
      }
   catch (...)
      {
      throw TLS_Exception(Alert::INTERNAL_ERROR,
                          "No available DTLS cookie");
      }

   std::unique_ptr<std::vector<uint8_t>> msg_contents(
      new std::vector<uint8_t>(record_buf.begin() + 12,
                               record_buf.begin() + length + 8));

   std::vector<uint8_t> cookie, input_bits;
   std::tie(cookie, input_bits) = read_cookie_and_input_bits(*msg_contents);

   Hello_Verify_Request verify(input_bits, client_identity, cookie_secret);

   if (cookie == verify.cookie())
      {
      // We should be expecting seq+1 when done with client hello.
      return DTLS_Prestate(/*validity=*/true,
                           /*contents=*/std::move(msg_contents),
                           /*record_version=*/record.version(),
                           /*in_message_seq=*/msg_seq + 1,
                           /*in_record_seq=*/record.sequence() + 1,
                           /*out_message_seq=*/msg_seq);
      }
   else
      {
      Datagram_Handshake_IO::unconnected_send_message(
         msg_seq, 0, verify.type(), verify.serialize(),
         static_cast<uint16_t>(policy.dtls_default_mtu()),
         [&](uint16_t, uint8_t record_type,
             const std::vector<uint8_t>& message) {
            Botan::secure_vector<uint8_t> temp_writebuf;
            write_unencrypted_record(
               temp_writebuf,
               record_type,
               Protocol_Version::DTLS_V10,
               msg_seq,
               message.data(),
               message.size());
            emit_data_fn(
               temp_writebuf.data(),
               temp_writebuf.size());
         });
      }
   return DTLS_Prestate();
   }
}

}

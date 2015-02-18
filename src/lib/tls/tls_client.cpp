/*
* TLS Client
* (C) 2004-2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_client.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/stl_util.h>
#include <iterator>
#include <sstream>

namespace Botan {

namespace TLS {

namespace {

class Client_Handshake_State : public Handshake_State
   {
   public:
      // using Handshake_State::Handshake_State;

      Client_Handshake_State(Handshake_IO* io, hs_msg_cb cb = hs_msg_cb()) :
         Handshake_State(io, cb) {}

      const Public_Key& get_server_public_Key() const
         {
         BOTAN_ASSERT(server_public_key, "Server sent us a certificate");
         return *server_public_key.get();
         }

      // Used during session resumption
      secure_vector<byte> resume_master_secret;

      std::unique_ptr<Public_Key> server_public_key;

      // Used by client using NPN
      Client::next_protocol_fn client_npn_cb;
   };

}

/*
* TLS Client Constructor
*/
Client::Client(output_fn output_fn,
               data_cb proc_cb,
               alert_cb alert_cb,
               handshake_cb handshake_cb,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const Server_Information& info,
               const Protocol_Version offer_version,
               next_protocol_fn npn,
               size_t io_buf_sz) :
   Channel(output_fn, proc_cb, alert_cb, handshake_cb, session_manager, rng,
           offer_version.is_datagram_protocol(), io_buf_sz),
   m_policy(policy),
   m_creds(creds),
   m_info(info)
   {
   const std::string srp_identifier = m_creds.srp_identifier("tls-client", m_info.hostname());

   Handshake_State& state = create_handshake_state(offer_version);
   send_client_hello(state, false, offer_version, srp_identifier, npn);
   }

Handshake_State* Client::new_handshake_state(Handshake_IO* io)
   {
   return new Client_Handshake_State(io); // , m_hs_msg_cb);
   }

std::vector<X509_Certificate>
Client::get_peer_cert_chain(const Handshake_State& state) const
   {
   if(state.server_certs())
      return state.server_certs()->cert_chain();
   return std::vector<X509_Certificate>();
   }

/*
* Send a new client hello to renegotiate
*/
void Client::initiate_handshake(Handshake_State& state,
                                bool force_full_renegotiation)
   {
   send_client_hello(state,
                     force_full_renegotiation,
                     state.version());
   }

void Client::send_client_hello(Handshake_State& state_base,
                               bool force_full_renegotiation,
                               Protocol_Version version,
                               const std::string& srp_identifier,
                               next_protocol_fn next_protocol)
   {
   Client_Handshake_State& state = dynamic_cast<Client_Handshake_State&>(state_base);

   if(state.version().is_datagram_protocol())
      state.set_expected_next(HELLO_VERIFY_REQUEST); // optional
   state.set_expected_next(SERVER_HELLO);

   state.client_npn_cb = next_protocol;

   const bool send_npn_request = static_cast<bool>(next_protocol);

   if(!force_full_renegotiation && !m_info.empty())
      {
      Session session_info;
      if(session_manager().load_from_server_info(m_info, session_info))
         {
         if(srp_identifier == "" || session_info.srp_identifier() == srp_identifier)
            {
            state.client_hello(new Client_Hello(
               state.handshake_io(),
               state.hash(),
               m_policy,
               rng(),
               secure_renegotiation_data_for_client_hello(),
               session_info,
               send_npn_request));

            state.resume_master_secret = session_info.master_secret();
            }
         }
      }

   if(!state.client_hello()) // not resuming
      {
      state.client_hello(new Client_Hello(
         state.handshake_io(),
         state.hash(),
         version,
         m_policy,
         rng(),
         secure_renegotiation_data_for_client_hello(),
         send_npn_request,
         m_info.hostname(),
         srp_identifier));
      }

   secure_renegotiation_check(state.client_hello());
   }

/*
* Process a handshake message
*/
void Client::process_handshake_msg(const Handshake_State* active_state,
                                   Handshake_State& state_base,
                                   Handshake_Type type,
                                   const std::vector<byte>& contents)
   {
   Client_Handshake_State& state = dynamic_cast<Client_Handshake_State&>(state_base);

   if(type == HELLO_REQUEST && active_state)
      {
      Hello_Request hello_request(contents);

      // Ignore request entirely if we are currently negotiating a handshake
      if(state.client_hello())
         return;

      if(m_policy.allow_server_initiated_renegotiation())
         {
         if(!secure_renegotiation_supported() && m_policy.allow_insecure_renegotiation() == false)
            send_warning_alert(Alert::NO_RENEGOTIATION);
         else
            this->initiate_handshake(state, false);
         }
      else
         {
         // RFC 5746 section 4.2
         send_warning_alert(Alert::NO_RENEGOTIATION);
         }

      return;
      }

   state.confirm_transition_to(type);

   if(type != HANDSHAKE_CCS && type != FINISHED && type != HELLO_VERIFY_REQUEST)
      state.hash().update(state.handshake_io().format(contents, type));

   if(type == HELLO_VERIFY_REQUEST)
      {
      state.set_expected_next(SERVER_HELLO);
      state.set_expected_next(HELLO_VERIFY_REQUEST); // might get it again

      Hello_Verify_Request hello_verify_request(contents);

      state.hello_verify_request(hello_verify_request);
      }
   else if(type == SERVER_HELLO)
      {
      state.server_hello(new Server_Hello(contents));

      if(!state.client_hello()->offered_suite(state.server_hello()->ciphersuite()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with ciphersuite we didn't send");
         }

      if(Ciphersuite::is_scsv(state.server_hello()->ciphersuite()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with a signaling ciphersuite");
         }

      if(!value_exists(state.client_hello()->compression_methods(),
                       state.server_hello()->compression_method()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server replied with compression method we didn't send");
         }

      auto client_extn = state.client_hello()->extension_types();
      auto server_extn = state.server_hello()->extension_types();

      std::vector<Handshake_Extension_Type> diff;

      std::set_difference(server_extn.begin(), server_extn.end(),
                          client_extn.begin(), server_extn.end(),
                          std::back_inserter(diff));

      if(!diff.empty())
         {
         // Server sent us back an extension we did not send!

         std::ostringstream msg;
         msg << "Server replied with " << diff.size() << " unsupported extensions:";
         for(auto&& d : diff)
            msg << " " << static_cast<int>(d);
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE, msg.str());
         }

      if(u16bit srtp = state.server_hello()->srtp_profile())
         {
         if(!value_exists(state.client_hello()->srtp_profiles(), srtp))
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server replied with DTLS-SRTP alg we did not send");
         }

      state.set_version(state.server_hello()->version());

      secure_renegotiation_check(state.server_hello());

      const bool server_returned_same_session_id =
         !state.server_hello()->session_id().empty() &&
         (state.server_hello()->session_id() == state.client_hello()->session_id());

      if(server_returned_same_session_id)
         {
         // successful resumption

         /*
         * In this case, we offered the version used in the original
         * session, and the server must resume with the same version.
         */
         if(state.server_hello()->version() != state.client_hello()->version())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server resumed session but with wrong version");

         state.compute_session_keys(state.resume_master_secret);

         if(state.server_hello()->supports_session_ticket())
            state.set_expected_next(NEW_SESSION_TICKET);
         else
            state.set_expected_next(HANDSHAKE_CCS);
         }
      else
         {
         // new session

         if(state.client_hello()->version().is_datagram_protocol() !=
            state.server_hello()->version().is_datagram_protocol())
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Server replied with different protocol type than we offered");
            }

         if(state.version() > state.client_hello()->version())
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server replied with later version than in hello");
            }

         if(!m_policy.acceptable_protocol_version(state.version()))
            {
            throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                "Server version " + state.version().to_string() +
                                " is unacceptable by policy");
            }

         if(state.ciphersuite().sig_algo() != "")
            {
            state.set_expected_next(CERTIFICATE);
            }
         else if(state.ciphersuite().kex_algo() == "PSK")
            {
            /* PSK is anonymous so no certificate/cert req message is
               ever sent. The server may or may not send a server kex,
               depending on if it has an identity hint for us.

               (EC)DHE_PSK always sends a server key exchange for the
               DH exchange portion.
            */

            state.set_expected_next(SERVER_KEX);
            state.set_expected_next(SERVER_HELLO_DONE);
            }
         else if(state.ciphersuite().kex_algo() != "RSA")
            {
            state.set_expected_next(SERVER_KEX);
            }
         else
            {
            state.set_expected_next(CERTIFICATE_REQUEST); // optional
            state.set_expected_next(SERVER_HELLO_DONE);
            }
         }
      }
   else if(type == CERTIFICATE)
      {
      if(state.ciphersuite().kex_algo() != "RSA")
         {
         state.set_expected_next(SERVER_KEX);
         }
      else
         {
         state.set_expected_next(CERTIFICATE_REQUEST); // optional
         state.set_expected_next(SERVER_HELLO_DONE);
         }

      state.server_certs(new Certificate(contents));

      const std::vector<X509_Certificate>& server_certs =
         state.server_certs()->cert_chain();

      if(server_certs.empty())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client: No certificates sent by server");

      try
         {
         m_creds.verify_certificate_chain("tls-client", m_info.hostname(), server_certs);
         }
      catch(std::exception& e)
         {
         throw TLS_Exception(Alert::BAD_CERTIFICATE, e.what());
         }

      std::unique_ptr<Public_Key> peer_key(server_certs[0].subject_public_key());

      if(peer_key->algo_name() != state.ciphersuite().sig_algo())
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");

      state.server_public_key.reset(peer_key.release());
      }
   else if(type == SERVER_KEX)
      {
      state.set_expected_next(CERTIFICATE_REQUEST); // optional
      state.set_expected_next(SERVER_HELLO_DONE);

      state.server_kex(
         new Server_Key_Exchange(contents,
                                 state.ciphersuite().kex_algo(),
                                 state.ciphersuite().sig_algo(),
                                 state.version())
         );

      if(state.ciphersuite().sig_algo() != "")
         {
         const Public_Key& server_key = state.get_server_public_Key();

         if(!state.server_kex()->verify(server_key, state))
            {
            throw TLS_Exception(Alert::DECRYPT_ERROR,
                                "Bad signature on server key exchange");
            }
         }
      }
   else if(type == CERTIFICATE_REQUEST)
      {
      state.set_expected_next(SERVER_HELLO_DONE);
      state.cert_req(
         new Certificate_Req(contents, state.version())
         );
      }
   else if(type == SERVER_HELLO_DONE)
      {
      state.server_hello_done(
         new Server_Hello_Done(contents)
         );

      if(state.received_handshake_msg(CERTIFICATE_REQUEST))
         {
         const std::vector<std::string>& types =
            state.cert_req()->acceptable_cert_types();

         std::vector<X509_Certificate> client_certs =
            m_creds.cert_chain(types,
                               "tls-client",
                               m_info.hostname());

         state.client_certs(
            new Certificate(state.handshake_io(),
                            state.hash(),
                            client_certs)
            );
         }

      state.client_kex(
         new Client_Key_Exchange(state.handshake_io(),
                                 state,
                                 m_policy,
                                 m_creds,
                                 state.server_public_key.get(),
                                 m_info.hostname(),
                                 rng())
         );

      state.compute_session_keys();

      if(state.received_handshake_msg(CERTIFICATE_REQUEST) &&
         !state.client_certs()->empty())
         {
         Private_Key* private_key =
            m_creds.private_key_for(state.client_certs()->cert_chain()[0],
                                    "tls-client",
                                    m_info.hostname());

         state.client_verify(
            new Certificate_Verify(state.handshake_io(),
                                   state,
                                   m_policy,
                                   rng(),
                                   private_key)
            );
         }

      state.handshake_io().send(Change_Cipher_Spec());

      change_cipher_spec_writer(CLIENT);

      if(state.server_hello()->next_protocol_notification())
         {
         const std::string protocol = state.client_npn_cb(
            state.server_hello()->next_protocols());

         state.next_protocol(
            new Next_Protocol(state.handshake_io(), state.hash(), protocol)
            );
         }

      state.client_finished(
         new Finished(state.handshake_io(), state, CLIENT)
         );

      if(state.server_hello()->supports_session_ticket())
         state.set_expected_next(NEW_SESSION_TICKET);
      else
         state.set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == NEW_SESSION_TICKET)
      {
      state.new_session_ticket(new New_Session_Ticket(contents));

      state.set_expected_next(HANDSHAKE_CCS);
      }
   else if(type == HANDSHAKE_CCS)
      {
      state.set_expected_next(FINISHED);

      change_cipher_spec_reader(CLIENT);
      }
   else if(type == FINISHED)
      {
      state.server_finished(new Finished(contents));

      if(!state.server_finished()->verify(state, SERVER))
         throw TLS_Exception(Alert::DECRYPT_ERROR,
                             "Finished message didn't verify");

      state.hash().update(state.handshake_io().format(contents, type));

      if(!state.client_finished()) // session resume case
         {
         state.handshake_io().send(Change_Cipher_Spec());

         change_cipher_spec_writer(CLIENT);

         if(state.server_hello()->next_protocol_notification())
            {
            const std::string protocol = state.client_npn_cb(
                  state.server_hello()->next_protocols());

            state.next_protocol(
               new Next_Protocol(state.handshake_io(), state.hash(), protocol)
               );
            }

         state.client_finished(
            new Finished(state.handshake_io(), state, CLIENT)
            );
         }

      std::vector<byte> session_id = state.server_hello()->session_id();

      const std::vector<byte>& session_ticket = state.session_ticket();

      if(session_id.empty() && !session_ticket.empty())
         session_id = make_hello_random(rng(), m_policy);

      Session session_info(
         session_id,
         state.session_keys().master_secret(),
         state.server_hello()->version(),
         state.server_hello()->ciphersuite(),
         state.server_hello()->compression_method(),
         CLIENT,
         state.server_hello()->fragment_size(),
         get_peer_cert_chain(state),
         session_ticket,
         m_info,
         "",
         state.server_hello()->srtp_profile()
         );

      const bool should_save = save_session(session_info);

      if(!session_id.empty())
         {
         if(should_save)
            session_manager().save(session_info);
         else
            session_manager().remove_entry(session_info.session_id());
         }

      activate_session();
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

}

}

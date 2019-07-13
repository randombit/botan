/*
* TLS Handshaking
* (C) 2004-2006,2011,2012,2015,2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/tls_messages.h>
#include <botan/kdf.h>
#include <sstream>

namespace Botan {

namespace TLS {

std::string Handshake_Message::type_string() const
   {
   return handshake_type_to_string(type());
   }

const char* handshake_type_to_string(Handshake_Type type)
   {
   switch(type)
      {
      case HELLO_VERIFY_REQUEST:
         return "hello_verify_request";

      case HELLO_REQUEST:
         return "hello_request";

      case CLIENT_HELLO:
         return "client_hello";

      case SERVER_HELLO:
         return "server_hello";

      case CERTIFICATE:
         return "certificate";

      case CERTIFICATE_URL:
         return "certificate_url";

      case CERTIFICATE_STATUS:
         return "certificate_status";

      case SERVER_KEX:
         return "server_key_exchange";

      case CERTIFICATE_REQUEST:
         return "certificate_request";

      case SERVER_HELLO_DONE:
         return "server_hello_done";

      case CERTIFICATE_VERIFY:
         return "certificate_verify";

      case CLIENT_KEX:
         return "client_key_exchange";

      case NEW_SESSION_TICKET:
         return "new_session_ticket";

      case HANDSHAKE_CCS:
         return "change_cipher_spec";

      case FINISHED:
         return "finished";

      case HANDSHAKE_NONE:
         return "invalid";
      }

   throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                       "Unknown TLS handshake message type " + std::to_string(type));
   }

namespace {

uint32_t bitmask_for_handshake_type(Handshake_Type type)
   {
   switch(type)
      {
      case HELLO_VERIFY_REQUEST:
         return (1 << 0);

      case HELLO_REQUEST:
         return (1 << 1);

      case CLIENT_HELLO:
         return (1 << 2);

      case SERVER_HELLO:
         return (1 << 3);

      case CERTIFICATE:
         return (1 << 4);

      case CERTIFICATE_URL:
         return (1 << 5);

      case CERTIFICATE_STATUS:
         return (1 << 6);

      case SERVER_KEX:
         return (1 << 7);

      case CERTIFICATE_REQUEST:
         return (1 << 8);

      case SERVER_HELLO_DONE:
         return (1 << 9);

      case CERTIFICATE_VERIFY:
         return (1 << 10);

      case CLIENT_KEX:
         return (1 << 11);

      case NEW_SESSION_TICKET:
         return (1 << 12);

      case HANDSHAKE_CCS:
         return (1 << 13);

      case FINISHED:
         return (1 << 14);

      // allow explicitly disabling new handshakes
      case HANDSHAKE_NONE:
         return 0;
      }

   throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                       "Unknown TLS handshake message type " + std::to_string(type));
   }

std::string handshake_mask_to_string(uint32_t mask, char combiner)
   {
   const Handshake_Type types[] = {
      HELLO_VERIFY_REQUEST,
      HELLO_REQUEST,
      CLIENT_HELLO,
      SERVER_HELLO,
      CERTIFICATE,
      CERTIFICATE_URL,
      CERTIFICATE_STATUS,
      SERVER_KEX,
      CERTIFICATE_REQUEST,
      SERVER_HELLO_DONE,
      CERTIFICATE_VERIFY,
      CLIENT_KEX,
      NEW_SESSION_TICKET,
      HANDSHAKE_CCS,
      FINISHED
   };

   std::ostringstream o;
   bool empty = true;

   for(auto&& t : types)
      {
      if(mask & bitmask_for_handshake_type(t))
         {
         if(!empty)
            o << combiner;
         o << handshake_type_to_string(t);
         empty = false;
         }
      }

   return o.str();
   }

}

/*
* Initialize the SSL/TLS Handshake State
*/
Handshake_State::Handshake_State(Handshake_IO* io, Callbacks& cb) :
   m_callbacks(cb),
   m_handshake_io(io),
   m_version(m_handshake_io->initial_record_version())
   {
   }

void Handshake_State::note_message(const Handshake_Message& msg)
   {
   m_callbacks.tls_inspect_handshake_msg(msg);
   }

void Handshake_State::hello_verify_request(const Hello_Verify_Request& hello_verify)
   {
   note_message(hello_verify);

   m_client_hello->update_hello_cookie(hello_verify);
   hash().reset();
   hash().update(handshake_io().send(*m_client_hello));
   note_message(*m_client_hello);
   }

void Handshake_State::client_hello(Client_Hello* client_hello)
   {
   if(client_hello == nullptr)
      {
      m_client_hello.reset();
      hash().reset();
      }
   else
      {
      m_client_hello.reset(client_hello);
      note_message(*m_client_hello);
      }
   }

void Handshake_State::server_hello(Server_Hello* server_hello)
   {
   m_server_hello.reset(server_hello);
   m_ciphersuite = Ciphersuite::by_id(m_server_hello->ciphersuite());
   note_message(*m_server_hello);
   }

void Handshake_State::server_certs(Certificate* server_certs)
   {
   m_server_certs.reset(server_certs);
   note_message(*m_server_certs);
   }

void Handshake_State::server_cert_status(Certificate_Status* server_cert_status)
   {
   m_server_cert_status.reset(server_cert_status);
   note_message(*m_server_cert_status);
   }

void Handshake_State::server_kex(Server_Key_Exchange* server_kex)
   {
   m_server_kex.reset(server_kex);
   note_message(*m_server_kex);
   }

void Handshake_State::cert_req(Certificate_Req* cert_req)
   {
   m_cert_req.reset(cert_req);
   note_message(*m_cert_req);
   }

void Handshake_State::server_hello_done(Server_Hello_Done* server_hello_done)
   {
   m_server_hello_done.reset(server_hello_done);
   note_message(*m_server_hello_done);
   }

void Handshake_State::client_certs(Certificate* client_certs)
   {
   m_client_certs.reset(client_certs);
   note_message(*m_client_certs);
   }

void Handshake_State::client_kex(Client_Key_Exchange* client_kex)
   {
   m_client_kex.reset(client_kex);
   note_message(*m_client_kex);
   }

void Handshake_State::client_verify(Certificate_Verify* client_verify)
   {
   m_client_verify.reset(client_verify);
   note_message(*m_client_verify);
   }

void Handshake_State::new_session_ticket(New_Session_Ticket* new_session_ticket)
   {
   m_new_session_ticket.reset(new_session_ticket);
   note_message(*m_new_session_ticket);
   }

void Handshake_State::server_finished(Finished* server_finished)
   {
   m_server_finished.reset(server_finished);
   note_message(*m_server_finished);
   }

void Handshake_State::client_finished(Finished* client_finished)
   {
   m_client_finished.reset(client_finished);
   note_message(*m_client_finished);
   }

void Handshake_State::set_version(const Protocol_Version& version)
   {
   m_version = version;
   }

void Handshake_State::compute_session_keys()
   {
   m_session_keys = Session_Keys(this, client_kex()->pre_master_secret(), false);
   }

void Handshake_State::compute_session_keys(const secure_vector<uint8_t>& resume_master_secret)
   {
   m_session_keys = Session_Keys(this, resume_master_secret, true);
   }

void Handshake_State::confirm_transition_to(Handshake_Type handshake_msg)
   {
   const uint32_t mask = bitmask_for_handshake_type(handshake_msg);

   m_hand_received_mask |= mask;

   const bool ok = (m_hand_expecting_mask & mask) != 0; // overlap?

   if(!ok)
      {
      const uint32_t seen_so_far = m_hand_received_mask & ~mask;

      std::ostringstream msg;

      msg << "Unexpected state transition in handshake got a " << handshake_type_to_string(handshake_msg);

      if(m_hand_expecting_mask == 0)
         msg << " not expecting messages";
      else
         msg << " expected " << handshake_mask_to_string(m_hand_expecting_mask, '|');

      if(seen_so_far != 0)
         msg << " seen " << handshake_mask_to_string(seen_so_far, '+');

      throw Unexpected_Message(msg.str());
      }

   /* We don't know what to expect next, so force a call to
      set_expected_next; if it doesn't happen, the next transition
      check will always fail which is what we want.
   */
   m_hand_expecting_mask = 0;
   }

void Handshake_State::set_expected_next(Handshake_Type handshake_msg)
   {
   m_hand_expecting_mask |= bitmask_for_handshake_type(handshake_msg);
   }

bool Handshake_State::received_handshake_msg(Handshake_Type handshake_msg) const
   {
   const uint32_t mask = bitmask_for_handshake_type(handshake_msg);

   return (m_hand_received_mask & mask) != 0;
   }

std::pair<Handshake_Type, std::vector<uint8_t>>
Handshake_State::get_next_handshake_msg()
   {
   const bool expecting_ccs =
      (bitmask_for_handshake_type(HANDSHAKE_CCS) & m_hand_expecting_mask) != 0;

   return m_handshake_io->get_next_record(expecting_ccs);
   }

std::string Handshake_State::srp_identifier() const
   {
#if defined(BOTAN_HAS_SRP6)
   // Authenticated via the successful key exchange
   if(ciphersuite().valid() && ciphersuite().kex_method() == Kex_Algo::SRP_SHA)
      return client_hello()->srp_identifier();
#endif

   return "";
   }


std::vector<uint8_t> Handshake_State::session_ticket() const
   {
   if(new_session_ticket() && !new_session_ticket()->ticket().empty())
      return new_session_ticket()->ticket();

   return client_hello()->session_ticket();
   }

KDF* Handshake_State::protocol_specific_prf() const
   {
   if(version().supports_ciphersuite_specific_prf())
      {
      const std::string prf_algo = ciphersuite().prf_algo();

      if(prf_algo == "MD5" || prf_algo == "SHA-1")
         return get_kdf("TLS-12-PRF(SHA-256)");

      return get_kdf("TLS-12-PRF(" + prf_algo + ")");
      }

   // Old PRF used in TLS v1.0, v1.1 and DTLS v1.0
   return get_kdf("TLS-PRF");
   }

std::pair<std::string, Signature_Format>
Handshake_State::choose_sig_format(const Private_Key& key,
                                   Signature_Scheme& chosen_scheme,
                                   bool for_client_auth,
                                   const Policy& policy) const
   {
   const std::string sig_algo = key.algo_name();

   if(this->version().supports_negotiable_signature_algorithms())
      {
      const std::vector<Signature_Scheme> allowed = policy.allowed_signature_schemes();

      std::vector<Signature_Scheme> requested =
         (for_client_auth) ? cert_req()->signature_schemes() : client_hello()->signature_schemes();

      if(requested.empty())
         {
         // Implicit SHA-1
         requested.push_back(Signature_Scheme::RSA_PKCS1_SHA1);
         requested.push_back(Signature_Scheme::ECDSA_SHA1);
         requested.push_back(Signature_Scheme::DSA_SHA1);
         }

      for(Signature_Scheme scheme : allowed)
         {
         if(signature_scheme_is_known(scheme) == false)
            {
            continue;
            }

         if(signature_algorithm_of_scheme(scheme) == sig_algo)
            {
            if(std::find(requested.begin(), requested.end(), scheme) != requested.end())
               {
               chosen_scheme = scheme;
               break;
               }
            }
         }

      const std::string hash = hash_function_of_scheme(chosen_scheme);

      if(!policy.allowed_signature_hash(hash))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Policy refuses to accept signing with any hash supported by peer");
         }

      if(sig_algo == "RSA")
         {
         return std::make_pair(padding_string_for_scheme(chosen_scheme), IEEE_1363);
         }
      else if(sig_algo == "DSA" || sig_algo == "ECDSA")
         {
         return std::make_pair(padding_string_for_scheme(chosen_scheme), DER_SEQUENCE);
         }
      }
   else
      {
      if(sig_algo == "RSA")
         {
         const std::string padding = "PKCS1v15(Parallel(MD5,SHA-160))";
         return std::make_pair(padding, IEEE_1363);
         }
      else if(sig_algo == "DSA" || sig_algo == "ECDSA")
         {
         const std::string padding = "EMSA1(SHA-1)";
         return std::make_pair(padding, DER_SEQUENCE);
         }
      }

   throw Invalid_Argument(sig_algo + " is invalid/unknown for TLS signatures");
   }

namespace {

bool supported_algos_include(
   const std::vector<Signature_Scheme>& schemes,
   const std::string& key_type,
   const std::string& hash_type)
   {
   for(Signature_Scheme scheme : schemes)
      {
      if(signature_scheme_is_known(scheme) &&
         hash_function_of_scheme(scheme) == hash_type &&
         signature_algorithm_of_scheme(scheme) == key_type)
         {
         return true;
         }
      }

   return false;
   }

}

std::pair<std::string, Signature_Format>
Handshake_State::parse_sig_format(const Public_Key& key,
                                  Signature_Scheme scheme,
                                  bool for_client_auth,
                                  const Policy& policy) const
   {
   const std::string key_type = key.algo_name();

   if(!policy.allowed_signature_method(key_type))
      {
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                          "Rejecting " + key_type + " signature");
      }

   if(this->version().supports_negotiable_signature_algorithms() == false)
      {
      if(scheme != Signature_Scheme::NONE)
         throw Decoding_Error("Counterparty sent hash/sig IDs with old version");

      /*
      There is no check on the acceptability of a v1.0/v1.1 hash type,
      since it's implicit with use of the protocol
      */

      if(key_type == "RSA")
         {
         const std::string padding = "PKCS1v15(Parallel(MD5,SHA-160))";
         return std::make_pair(padding, IEEE_1363);
         }
      else if(key_type == "DSA" || key_type == "ECDSA")
         {
         const std::string padding = "EMSA1(SHA-1)";
         return std::make_pair(padding, DER_SEQUENCE);
         }
      else
         throw Invalid_Argument(key_type + " is invalid/unknown for TLS signatures");
      }

   if(scheme == Signature_Scheme::NONE)
      throw Decoding_Error("Counterparty did not send hash/sig IDS");

   if(key_type != signature_algorithm_of_scheme(scheme))
      throw Decoding_Error("Counterparty sent inconsistent key and sig types");

   if(for_client_auth && !cert_req())
      {
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                          "No certificate verify set");
      }

   /*
   Confirm the signature type we just received against the
   supported_algos list that we sent; it better be there.
   */

   const std::vector<Signature_Scheme> supported_algos =
      for_client_auth ? cert_req()->signature_schemes() :
      client_hello()->signature_schemes();

   if(!signature_scheme_is_known(scheme))
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                          "Peer sent unknown signature scheme");

   const std::string hash_algo = hash_function_of_scheme(scheme);

   if(!supported_algos_include(supported_algos, key_type, hash_algo))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "TLS signature extension did not allow for " +
                          key_type + "/" + hash_algo + " signature");
      }

   if(key_type == "RSA")
      {
      return std::make_pair(padding_string_for_scheme(scheme), IEEE_1363);
      }
   else if(key_type == "DSA" || key_type == "ECDSA")
      {
      return std::make_pair(padding_string_for_scheme(scheme), DER_SEQUENCE);
      }

   throw Invalid_Argument(key_type + " is invalid/unknown for TLS signatures");
   }

}

}

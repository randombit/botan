/*
* TLS Handshaking
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/assert.h>
#include <botan/lookup.h>

namespace Botan {

namespace TLS {

namespace {

u32bit bitmask_for_handshake_type(Handshake_Type type)
   {
   switch(type)
      {
      case HELLO_VERIFY_REQUEST:
         return (1 << 0);

      case HELLO_REQUEST:
         return (1 << 1);

      /*
      * Same code point for both client hello styles
      */
      case CLIENT_HELLO:
      case CLIENT_HELLO_SSLV2:
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

      case NEXT_PROTOCOL:
         return (1 << 12);

      case NEW_SESSION_TICKET:
         return (1 << 13);

      case HANDSHAKE_CCS:
         return (1 << 14);

      case FINISHED:
         return (1 << 15);

      // allow explicitly disabling new handshakes
      case HANDSHAKE_NONE:
         return 0;
      }

   throw Internal_Error("Unknown handshake type " + std::to_string(type));
   }

}

/*
* Initialize the SSL/TLS Handshake State
*/
Handshake_State::Handshake_State(Handshake_Reader* reader)
   {
   client_hello = nullptr;
   server_hello = nullptr;
   server_certs = nullptr;
   server_kex = nullptr;
   cert_req = nullptr;
   server_hello_done = nullptr;
   next_protocol = nullptr;
   new_session_ticket = nullptr;

   client_certs = nullptr;
   client_kex = nullptr;
   client_verify = nullptr;
   client_finished = nullptr;
   server_finished = nullptr;

   m_handshake_reader = reader;

   server_rsa_kex_key = nullptr;

   m_version = Protocol_Version::SSL_V3;

   hand_expecting_mask = 0;
   hand_received_mask = 0;

   allow_session_resumption = true;
   }

void Handshake_State::set_version(const Protocol_Version& version)
   {
   m_version = version;
   }

void Handshake_State::confirm_transition_to(Handshake_Type handshake_msg)
   {
   const u32bit mask = bitmask_for_handshake_type(handshake_msg);

   hand_received_mask |= mask;

   const bool ok = (hand_expecting_mask & mask); // overlap?

   if(!ok)
      throw Unexpected_Message("Unexpected state transition in handshake, got " +
                               std::to_string(handshake_msg) +
                               " expected " + std::to_string(hand_expecting_mask) +
                               " received " + std::to_string(hand_received_mask));

   /* We don't know what to expect next, so force a call to
      set_expected_next; if it doesn't happen, the next transition
      check will always fail which is what we want.
   */
   hand_expecting_mask = 0;
   }

void Handshake_State::set_expected_next(Handshake_Type handshake_msg)
   {
   hand_expecting_mask |= bitmask_for_handshake_type(handshake_msg);
   }

bool Handshake_State::received_handshake_msg(Handshake_Type handshake_msg) const
   {
   const u32bit mask = bitmask_for_handshake_type(handshake_msg);

   return (hand_received_mask & mask);
   }

std::string Handshake_State::srp_identifier() const
   {
   if(suite.valid() && suite.kex_algo() == "SRP_SHA")
      return client_hello->srp_identifier();

   return "";
   }

const std::vector<byte>& Handshake_State::session_ticket() const
   {
   if(new_session_ticket && !new_session_ticket->ticket().empty())
      return new_session_ticket->ticket();

   return client_hello->session_ticket();
   }

KDF* Handshake_State::protocol_specific_prf()
   {
   if(version() == Protocol_Version::SSL_V3)
      {
      return get_kdf("SSL3-PRF");
      }
   else if(version() == Protocol_Version::TLS_V10 || version() == Protocol_Version::TLS_V11)
      {
      return get_kdf("TLS-PRF");
      }
   else if(version() == Protocol_Version::TLS_V12)
      {
      if(suite.mac_algo() == "MD5" ||
         suite.mac_algo() == "SHA-1" ||
         suite.mac_algo() == "SHA-256")
         {
         return get_kdf("TLS-12-PRF(SHA-256)");
         }

      return get_kdf("TLS-12-PRF(" + suite.mac_algo() + ")");
      }

   throw Internal_Error("Unknown version code " + version().to_string());
   }

namespace {

std::string choose_hash(const std::string& sig_algo,
                        Protocol_Version negotiated_version,
                        const Policy& policy,
                        bool for_client_auth,
                        Client_Hello* client_hello,
                        Certificate_Req* cert_req)
   {
   if(negotiated_version < Protocol_Version::TLS_V12)
      {
      if(for_client_auth && negotiated_version == Protocol_Version::SSL_V3)
         return "Raw";

      if(sig_algo == "RSA")
         return "TLS.Digest.0";

      if(sig_algo == "DSA")
         return "SHA-1";

      if(sig_algo == "ECDSA")
         return "SHA-1";

      throw Internal_Error("Unknown TLS signature algo " + sig_algo);
      }

   const auto supported_algos = for_client_auth ?
      cert_req->supported_algos() :
      client_hello->supported_algos();

   if(!supported_algos.empty())
      {
      const auto hashes = policy.allowed_signature_hashes();

      /*
      * Choose our most preferred hash that the counterparty supports
      * in pairing with the signature algorithm we want to use.
      */
      for(auto hash : hashes)
         {
         for(auto algo : supported_algos)
            {
            if(algo.first == hash && algo.second == sig_algo)
               return hash;
            }
         }
      }

   // TLS v1.2 default hash if the counterparty sent nothing
   return "SHA-1";
   }

}

std::pair<std::string, Signature_Format>
Handshake_State::choose_sig_format(const Private_Key* key,
                                   std::string& hash_algo_out,
                                   std::string& sig_algo_out,
                                   bool for_client_auth,
                                   const Policy& policy)
   {
   const std::string sig_algo = key->algo_name();

   const std::string hash_algo =
      choose_hash(sig_algo,
                  this->version(),
                  policy,
                  for_client_auth,
                  client_hello,
                  cert_req);

   if(this->version() >= Protocol_Version::TLS_V12)
      {
      hash_algo_out = hash_algo;
      sig_algo_out = sig_algo;
      }

   if(sig_algo == "RSA")
      {
      const std::string padding = "EMSA3(" + hash_algo + ")";

      return std::make_pair(padding, IEEE_1363);
      }
   else if(sig_algo == "DSA" || sig_algo == "ECDSA")
      {
      const std::string padding = "EMSA1(" + hash_algo + ")";

      return std::make_pair(padding, DER_SEQUENCE);
      }

   throw Invalid_Argument(sig_algo + " is invalid/unknown for TLS signatures");
   }

std::pair<std::string, Signature_Format>
Handshake_State::understand_sig_format(const Public_Key* key,
                                       std::string hash_algo,
                                       std::string sig_algo,
                                       bool for_client_auth)
   {
   const std::string algo_name = key->algo_name();

   /*
   FIXME: This should check what was sent against the client hello
   preferences, or the certificate request, to ensure it was allowed
   by those restrictions.

   Or not?
   */

   if(this->version() < Protocol_Version::TLS_V12)
      {
      if(hash_algo != "" || sig_algo != "")
         throw Decoding_Error("Counterparty sent hash/sig IDs with old version");
      }
   else
      {
      if(hash_algo == "")
         throw Decoding_Error("Counterparty did not send hash/sig IDS");

      if(sig_algo != algo_name)
         throw Decoding_Error("Counterparty sent inconsistent key and sig types");
      }

   if(algo_name == "RSA")
      {
      if(for_client_auth && this->version() == Protocol_Version::SSL_V3)
         {
         hash_algo = "Raw";
         }
      else if(this->version() < Protocol_Version::TLS_V12)
         {
         hash_algo = "TLS.Digest.0";
         }

      const std::string padding = "EMSA3(" + hash_algo + ")";
      return std::make_pair(padding, IEEE_1363);
      }
   else if(algo_name == "DSA" || algo_name == "ECDSA")
      {
      if(algo_name == "DSA" && for_client_auth && this->version() == Protocol_Version::SSL_V3)
         {
         hash_algo = "Raw";
         }
      else if(this->version() < Protocol_Version::TLS_V12)
         {
         hash_algo = "SHA-1";
         }

      const std::string padding = "EMSA1(" + hash_algo + ")";

      return std::make_pair(padding, DER_SEQUENCE);
      }

   throw Invalid_Argument(algo_name + " is invalid/unknown for TLS signatures");
   }

/*
* Destroy the SSL/TLS Handshake State
*/
Handshake_State::~Handshake_State()
   {
   delete client_hello;
   delete server_hello;
   delete server_certs;
   delete server_kex;
   delete cert_req;
   delete server_hello_done;
   delete next_protocol;
   delete new_session_ticket;

   delete client_certs;
   delete client_kex;
   delete client_verify;
   delete client_finished;
   delete server_finished;

   delete m_handshake_reader;
   }

}

}

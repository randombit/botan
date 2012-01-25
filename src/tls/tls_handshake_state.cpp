/*
* TLS Handshaking
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/assert.h>

namespace Botan {

namespace TLS {

namespace {

u32bit bitmask_for_handshake_type(Handshake_Type type)
   {
   switch(type)
      {
      case HELLO_REQUEST:
         return (1 << 0);

      /*
      * Same code point for both client hello styles
      */
      case CLIENT_HELLO:
      case CLIENT_HELLO_SSLV2:
         return (1 << 1);

      case SERVER_HELLO:
         return (1 << 2);

      case CERTIFICATE:
         return (1 << 3);

      case SERVER_KEX:
         return (1 << 4);

      case CERTIFICATE_REQUEST:
         return (1 << 5);

      case SERVER_HELLO_DONE:
         return (1 << 6);

      case CERTIFICATE_VERIFY:
         return (1 << 7);

      case CLIENT_KEX:
         return (1 << 8);

      case NEXT_PROTOCOL:
         return (1 << 9);

      case HANDSHAKE_CCS:
         return (1 << 10);

      case FINISHED:
         return (1 << 11);

      // allow explicitly disabling new handshakes
      case HANDSHAKE_NONE:
         return 0;

      default:
         throw Internal_Error("Unknown handshake type " + to_string(type));
      }

   return 0;
   }

}

/*
* Initialize the SSL/TLS Handshake State
*/
Handshake_State::Handshake_State()
   {
   client_hello = 0;
   server_hello = 0;
   server_certs = 0;
   server_kex = 0;
   cert_req = 0;
   server_hello_done = 0;
   next_protocol = 0;

   client_certs = 0;
   client_kex = 0;
   client_verify = 0;
   client_finished = 0;
   server_finished = 0;

   server_rsa_kex_key = 0;

   version = Protocol_Version::SSL_V3;

   hand_expecting_mask = 0;
   hand_received_mask = 0;
   }

void Handshake_State::confirm_transition_to(Handshake_Type handshake_msg)
   {
   const u32bit mask = bitmask_for_handshake_type(handshake_msg);

   hand_received_mask |= mask;

   const bool ok = (hand_expecting_mask & mask); // overlap?

   if(!ok)
      throw Unexpected_Message("Unexpected state transition in handshake, got " +
                               to_string(handshake_msg) + " mask is " +
                               to_string(hand_expecting_mask));

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

std::pair<std::string, Signature_Format>
Handshake_State::choose_sig_format(const Private_Key* key,
                                   std::string& hash_algo_out,
                                   std::string& sig_algo_out,
                                   bool for_client_auth)
   {
   const std::string sig_algo = key->algo_name();

   const std::vector<std::pair<std::string, std::string> > supported_algos =
      (for_client_auth) ? cert_req->supported_algos() : client_hello->supported_algos();

   std::string hash_algo;

   for(size_t i = 0; i != supported_algos.size(); ++i)
      {
      if(supported_algos[i].second == sig_algo)
         {
         hash_algo = supported_algos[i].first;
         break;
         }
      }

   if(for_client_auth && this->version == Protocol_Version::SSL_V3)
      hash_algo = "Raw";

   if(hash_algo == "" && this->version == Protocol_Version::TLS_V12)
      hash_algo = "SHA-1"; // TLS 1.2 but no compatible hashes set (?)

   BOTAN_ASSERT(hash_algo != "", "Couldn't figure out hash to use");

   if(this->version >= Protocol_Version::TLS_V12)
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

   if(this->version < Protocol_Version::TLS_V12)
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
      if(for_client_auth && this->version == Protocol_Version::SSL_V3)
         {
         hash_algo = "Raw";
         }
      else if(this->version < Protocol_Version::TLS_V12)
         {
         hash_algo = "TLS.Digest.0";
         }

      const std::string padding = "EMSA3(" + hash_algo + ")";
      return std::make_pair(padding, IEEE_1363);
      }
   else if(algo_name == "DSA" || algo_name == "ECDSA")
      {
      if(algo_name == "DSA" && for_client_auth && this->version == Protocol_Version::SSL_V3)
         {
         hash_algo = "Raw";
         }
      else if(this->version < Protocol_Version::TLS_V12)
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

   delete client_certs;
   delete client_kex;
   delete client_verify;
   delete client_finished;
   delete server_finished;

   delete server_rsa_kex_key;
   }

}

}

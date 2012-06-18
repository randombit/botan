/*
* TLS Handshake State
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_STATE_H__
#define BOTAN_TLS_HANDSHAKE_STATE_H__

#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>

#include <functional>
#include <utility>

namespace Botan {

class KDF;

namespace TLS {

class Policy;

/**
* SSL/TLS Handshake State
*/
class Handshake_State
   {
   public:
      Handshake_State(Handshake_Reader* reader);
      ~Handshake_State();

      bool received_handshake_msg(Handshake_Type handshake_msg) const;

      void confirm_transition_to(Handshake_Type handshake_msg);
      void set_expected_next(Handshake_Type handshake_msg);

      const std::vector<byte>& session_ticket() const;

      std::pair<std::string, Signature_Format>
         understand_sig_format(const Public_Key* key,
                               std::string hash_algo,
                               std::string sig_algo,
                               bool for_client_auth);

      std::pair<std::string, Signature_Format>
         choose_sig_format(const Private_Key* key,
                           std::string& hash_algo,
                           std::string& sig_algo,
                           bool for_client_auth,
                           const Policy& policy);

      std::string srp_identifier() const;

      KDF* protocol_specific_prf();

      Protocol_Version version() const { return m_version; }

      void set_version(const Protocol_Version& version);

      class Client_Hello* client_hello;
      class Server_Hello* server_hello;
      class Certificate* server_certs;
      class Server_Key_Exchange* server_kex;
      class Certificate_Req* cert_req;
      class Server_Hello_Done* server_hello_done;

      class Certificate* client_certs;
      class Client_Key_Exchange* client_kex;
      class Certificate_Verify* client_verify;

      class Next_Protocol* next_protocol;
      class New_Session_Ticket* new_session_ticket;

      class Finished* client_finished;
      class Finished* server_finished;

      // Used by the server only, in case of RSA key exchange
      Private_Key* server_rsa_kex_key;

      Ciphersuite suite;
      Session_Keys keys;
      Handshake_Hash hash;

      /*
      * Only used by clients for session resumption
      */
      secure_vector<byte> resume_master_secret;

      /*
      *
      */
      bool allow_session_resumption;

      /**
      * Used by client using NPN
      */
      std::function<std::string (std::vector<std::string>)> client_npn_cb;

      Handshake_Reader* handshake_reader() { return m_handshake_reader; }
   private:
      Handshake_Reader* m_handshake_reader;
      u32bit hand_expecting_mask, hand_received_mask;
      Protocol_Version m_version;
   };

}

}

#endif

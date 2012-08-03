/*
* TLS Handshake State
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_STATE_H__
#define BOTAN_TLS_HANDSHAKE_STATE_H__

#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
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
      Handshake_State(Handshake_IO* io);

      ~Handshake_State();

      Handshake_State(const Handshake_State&) = delete;
      Handshake_State& operator=(const Handshake_State&) = delete;

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

      class Client_Hello* client_hello = nullptr;
      class Server_Hello* server_hello = nullptr;
      class Certificate* server_certs = nullptr;
      class Server_Key_Exchange* server_kex = nullptr;
      class Certificate_Req* cert_req = nullptr;
      class Server_Hello_Done* server_hello_done = nullptr;

      class Certificate* client_certs = nullptr;
      class Client_Key_Exchange* client_kex = nullptr;
      class Certificate_Verify* client_verify = nullptr;

      class Next_Protocol* next_protocol = nullptr;
      class New_Session_Ticket* new_session_ticket = nullptr;

      class Finished* client_finished = nullptr;
      class Finished* server_finished = nullptr;

      // Used by the server only, in case of RSA key exchange
      Private_Key* server_rsa_kex_key = nullptr;

      Ciphersuite suite;
      Session_Keys keys;
      Handshake_Hash hash;

      /*
      * Only used by clients for session resumption
      */
      secure_vector<byte> resume_master_secret;

      /*
      * Used by the server to know if resumption should be allowed on
      * a server-initiated renegotiation
      */
      bool allow_session_resumption = true;

      /**
      * Used by client using NPN
      */
      std::function<std::string (std::vector<std::string>)> client_npn_cb;

      Handshake_IO& handshake_io() { return *m_handshake_io; }
   private:
      Handshake_IO* m_handshake_io = nullptr;

      u32bit m_hand_expecting_mask = 0;
      u32bit m_hand_received_mask = 0;
      Protocol_Version m_version;
   };

}

}

#endif

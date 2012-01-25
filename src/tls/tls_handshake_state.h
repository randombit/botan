/*
* TLS Handshake State
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_STATE_H__
#define BOTAN_TLS_HANDSHAKE_STATE_H__

#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_session_key.h>
#include <botan/secqueue.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>

#include <utility>

#if defined(BOTAN_USE_STD_TR1)

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
    #include <functional>
#else
    #include <tr1/functional>
#endif

#elif defined(BOTAN_USE_BOOST_TR1)
  #include <boost/tr1/functional.hpp>
#else
  #error "No TR1 library defined for use"
#endif

namespace Botan {

namespace TLS {

/**
* SSL/TLS Handshake State
*/
class Handshake_State
   {
   public:
      Handshake_State();
      ~Handshake_State();

      bool received_handshake_msg(Handshake_Type handshake_msg) const;

      void confirm_transition_to(Handshake_Type handshake_msg);
      void set_expected_next(Handshake_Type handshake_msg);

      std::pair<std::string, Signature_Format>
         understand_sig_format(const Public_Key* key,
                               std::string hash_algo,
                               std::string sig_algo,
                               bool for_client_auth);

      std::pair<std::string, Signature_Format>
         choose_sig_format(const Private_Key* key,
                           std::string& hash_algo,
                           std::string& sig_algo,
                           bool for_client_auth);

      Protocol_Version version;

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

      class Finished* client_finished;
      class Finished* server_finished;

      // Used by the server only, in case of RSA key exchange
      Private_Key* server_rsa_kex_key;

      Ciphersuite suite;
      Session_Keys keys;
      Handshake_Hash hash;

      SecureQueue queue;

      /*
      * Only used by clients for session resumption
      */
      SecureVector<byte> resume_master_secret;

      /**
      * Used by client using NPN
      */
      std::tr1::function<std::string (std::vector<std::string>)> client_npn_cb;

   private:
      u32bit hand_expecting_mask, hand_received_mask;
   };

}

}

#endif

/*
* TLS Handshake State
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_STATE_H__
#define BOTAN_TLS_HANDSHAKE_STATE_H__

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_session_key.h>
#include <botan/secqueue.h>

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

      Version_Code version;

      Client_Hello* client_hello;
      Server_Hello* server_hello;
      Certificate* server_certs;
      Server_Key_Exchange* server_kex;
      Certificate_Req* cert_req;
      Server_Hello_Done* server_hello_done;

      Certificate* client_certs;
      Client_Key_Exchange* client_kex;
      Certificate_Verify* client_verify;

      Next_Protocol* next_protocol;

      Finished* client_finished;
      Finished* server_finished;

      Public_Key* kex_pub;
      Private_Key* kex_priv;

      TLS_Cipher_Suite suite;
      SessionKeys keys;
      TLS_Handshake_Hash hash;

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

#endif

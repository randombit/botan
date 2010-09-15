/*
* TLS Handshake State
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_H__
#define BOTAN_TLS_HANDSHAKE_H__

#include <botan/internal/tls_messages.h>
#include <botan/secqueue.h>

namespace Botan {

/**
* SSL/TLS Handshake State
*/
class Handshake_State
   {
   public:
      Client_Hello* client_hello;
      Server_Hello* server_hello;
      Certificate* server_certs;
      Server_Key_Exchange* server_kex;
      Certificate_Req* cert_req;
      Server_Hello_Done* server_hello_done;

      Certificate* client_certs;
      Client_Key_Exchange* client_kex;
      Certificate_Verify* client_verify;
      Finished* client_finished;
      Finished* server_finished;

      Public_Key* kex_pub;
      Private_Key* kex_priv;

      CipherSuite suite;
      SessionKeys keys;
      HandshakeHash hash;

      SecureQueue queue;

      Version_Code version;
      bool got_client_ccs, got_server_ccs, do_client_auth;

      Handshake_State();
      ~Handshake_State();
   };

}

#endif

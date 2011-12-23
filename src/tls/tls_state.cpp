/*
* TLS Handshaking
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_state.h>

namespace Botan {

/**
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

   client_certs = 0;
   client_kex = 0;
   client_verify = 0;
   client_finished = 0;
   server_finished = 0;

   kex_pub = 0;
   kex_priv = 0;

   do_client_auth = got_client_ccs = got_server_ccs = false;
   version = SSL_V3;
   }

/**
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

   delete client_certs;
   delete client_kex;
   delete client_verify;
   delete client_finished;
   delete server_finished;

   delete kex_pub;
   delete kex_priv;
   }

}

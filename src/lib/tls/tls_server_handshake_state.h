/*
* TLS Server
* (C) 2004-2011,2012,2016 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_HANDSHAKE_STATE_H__
#define BOTAN_TLS_SERVER_HANDSHAKE_STATE_H__

#include <botan/internal/tls_handshake_state.h>
namespace Botan {

namespace TLS {

class Server_Handshake_State : public Handshake_State
   {
   public:
      Server_Handshake_State(Handshake_IO* io, handshake_msg_cb cb)
         : Handshake_State(io, cb) {}

      Private_Key* server_rsa_kex_key() { return m_server_rsa_kex_key; }
      void set_server_rsa_kex_key(Private_Key* key)
         { m_server_rsa_kex_key = key; }

      bool allow_session_resumption() const
         { return m_allow_session_resumption; }
      void set_allow_session_resumption(bool allow_session_resumption)
         { m_allow_session_resumption = allow_session_resumption; }


   private:
      // Used by the server only, in case of RSA key exchange. Not owned
      Private_Key* m_server_rsa_kex_key = nullptr;

      /*
      * Used by the server to know if resumption should be allowed on
      * a server-initiated renegotiation
      */
      bool m_allow_session_resumption = true;
   };

}

}
#endif //BOTAN_TLS_SERVER_HANDSHAKE_STATE_H__

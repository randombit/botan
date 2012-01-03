/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_SERVER_H__
#define BOTAN_TLS_SERVER_H__

#include <botan/tls_channel.h>
#include <botan/tls_session_manager.h>
#include <botan/credentials_manager.h>
#include <vector>

namespace Botan {

/**
* TLS Server
*/
class BOTAN_DLL TLS_Server : public TLS_Channel
   {
   public:
      /**
      * TLS_Server initialization
      */
      TLS_Server(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                 std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                 std::tr1::function<void (const TLS_Session&)> handshake_complete,
                 TLS_Session_Manager& session_manager,
                 Credentials_Manager& creds,
                 const TLS_Policy& policy,
                 RandomNumberGenerator& rng);

      void renegotiate();

      /**
      * Return the server name indicator, if set by the client
      */
      std::string server_name_indicator() const
         { return client_requested_hostname; }
   private:
      void read_handshake(byte, const MemoryRegion<byte>&);

      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      const TLS_Policy& policy;
      RandomNumberGenerator& rng;
      TLS_Session_Manager& session_manager;
      Credentials_Manager& creds;

      std::string client_requested_hostname;
   };

}

#endif

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

namespace TLS {

/**
* TLS Server
*/
class BOTAN_DLL Server : public Channel
   {
   public:
      /**
      * Server initialization
      */
      Server(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                 std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                 std::tr1::function<bool (const Session&)> handshake_complete,
                 Session_Manager& session_manager,
                 Credentials_Manager& creds,
                 const Policy& policy,
                 RandomNumberGenerator& rng,
                 const std::vector<std::string>& protocols =
                    std::vector<std::string>());

      void renegotiate();

      /**
      * Return the server name indicator, if sent by the client
      */
      std::string server_name_indicator() const
         { return m_hostname; }

      /**
      * Return the protocol negotiated with NPN extension
      */
      std::string next_protocol() const
         { return m_next_protocol; }

   private:
      void read_handshake(byte, const MemoryRegion<byte>&);

      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      void alert_notify(bool is_fatal, Alert_Type type);

      const Policy& policy;
      RandomNumberGenerator& rng;
      Session_Manager& session_manager;
      Credentials_Manager& creds;

      std::vector<std::string> m_possible_protocols;
      std::string m_hostname;
      std::string m_next_protocol;
   };

}

}

#endif

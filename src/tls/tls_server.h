/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_SERVER_H__
#define BOTAN_TLS_SERVER_H__

#include <botan/tls_channel.h>
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
      Server(std::function<void (const byte[], size_t)> socket_output_fn,
             std::function<void (const byte[], size_t, Alert)> proc_fn,
             std::function<bool (const Session&)> handshake_complete,
             Session_Manager& session_manager,
             Credentials_Manager& creds,
             const Policy& policy,
             RandomNumberGenerator& rng,
             const std::vector<std::string>& protocols =
                std::vector<std::string>());

      void renegotiate(bool force_full_renegotiation = false) override;

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
      void process_handshake_msg(Handshake_Type, const std::vector<byte>&) override;

      void alert_notify(const Alert& alert) override;

      class Handshake_State* new_handshake_state() override;

      const Policy& m_policy;
      RandomNumberGenerator& m_rng;
      Credentials_Manager& m_creds;

      std::vector<std::string> m_possible_protocols;
      std::string m_hostname;
      std::string m_next_protocol;
   };

}

}

#endif

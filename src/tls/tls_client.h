/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CLIENT_H__
#define BOTAN_TLS_CLIENT_H__

#include <botan/tls_channel.h>
#include <botan/tls_session_manager.h>
#include <botan/credentials_manager.h>
#include <vector>

namespace Botan {

namespace TLS {

/**
* SSL/TLS Client
*/
class BOTAN_DLL Client : public Channel
   {
   public:
      /**
      * Set up a new TLS client session
      * @param socket_output_fn is called with data for the outbound socket
      * @param proc_fn is called when new data (application or alerts) is received
      * @param handshake_complete is called when a handshake is completed
      * @param session_manager manages session state
      * @param creds manages application/user credentials
      * @param policy specifies other connection policy information
      * @param rng a random number generator
      * @param servername the server's DNS name, if known
      * @param next_protocol allows the client to specify what the next
      *        protocol will be. For more information read
      *        http://technotes.googlecode.com/git/nextprotoneg.html.
      *
      *        If the function is not empty, NPN will be negotiated
      *        and if the server supports NPN the function will be
      *        called with the list of protocols the server advertised;
      *        the client should return the protocol it would like to use.
      */
      Client(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                 std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                 std::tr1::function<bool (const Session&)> handshake_complete,
                 Session_Manager& session_manager,
                 Credentials_Manager& creds,
                 const Policy& policy,
                 RandomNumberGenerator& rng,
                 const std::string& servername = "",
                 std::tr1::function<std::string (std::vector<std::string>)> next_protocol =
                    std::tr1::function<std::string (std::vector<std::string>)>());

      void renegotiate();
   private:
      void process_handshake_msg(Handshake_Type type,
                                 const MemoryRegion<byte>& contents);

      void alert_notify(bool is_fatal, Alert_Type type);

      const Policy& policy;
      RandomNumberGenerator& rng;
      Session_Manager& session_manager;
      Credentials_Manager& creds;
   };

}

}

#endif

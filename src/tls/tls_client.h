/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CLIENT_H__
#define BOTAN_TLS_CLIENT_H__

#include <botan/tls_channel.h>
#include <botan/tls_session_state.h>
#include <vector>

namespace Botan {

/**
* SSL/TLS Client
*/
class BOTAN_DLL TLS_Client : public TLS_Channel
   {
   public:
      /**
      * Set up a new TLS client session
      * @param socket_output_fn is called with data for the outbound socket
      * @param proc_fn is called when new data (application or alerts) is received
      * @param handshake_complete is called when a handshake is completed
      * @param session_manager manages session resumption
      * @param policy specifies other connection policy information
      * @param rng a random number generator
      * @param servername the server's DNS name, if known
      * @param srp_username an identifier to use for SRP key exchange
      */
      TLS_Client(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                 std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                 std::tr1::function<void (const TLS_Session_Params&)> handshake_complete,
                 TLS_Session_Manager& session_manager,
                 const TLS_Policy& policy,
                 RandomNumberGenerator& rng,
                 const std::string& servername = "",
                 const std::string& srp_username = "");

      void add_client_cert(const X509_Certificate& cert,
                           Private_Key* cert_key);

      void renegotiate();

      ~TLS_Client();
   private:
      void process_handshake_msg(Handshake_Type type,
                                 const MemoryRegion<byte>& contents);

      const TLS_Policy& policy;
      RandomNumberGenerator& rng;
      TLS_Session_Manager& session_manager;

      std::vector<std::pair<X509_Certificate, Private_Key*> > certs;
   };

}

#endif

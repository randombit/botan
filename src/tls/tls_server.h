/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_SERVER_H__
#define BOTAN_TLS_SERVER_H__

#include <botan/tls_channel.h>
#include <botan/tls_session_state.h>
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
      *
      * FIXME: support cert chains (!)
      * FIXME: support anonymous servers
      */
      TLS_Server(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                 std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                 std::tr1::function<void (const TLS_Session_Params&)> handshake_complete,
                 TLS_Session_Manager& session_manager,
                 const TLS_Policy& policy,
                 RandomNumberGenerator& rng,
                 const X509_Certificate& cert,
                 const Private_Key& cert_key);

      ~TLS_Server();

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

      std::vector<X509_Certificate> cert_chain;
      Private_Key* private_key;

      std::string client_requested_hostname;
   };

}

#endif

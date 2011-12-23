/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CLIENT_H__
#define BOTAN_TLS_CLIENT_H__

#include <botan/tls_channel.h>
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
      */
      TLS_Client(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                 std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                 const TLS_Policy& policy,
                 RandomNumberGenerator& rng);

      void add_client_cert(const X509_Certificate& cert,
                           Private_Key* cert_key);

      ~TLS_Client();
   private:
      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      const TLS_Policy& policy;
      RandomNumberGenerator& rng;

      std::vector<std::pair<X509_Certificate, Private_Key*> > certs;
   };

}

#endif

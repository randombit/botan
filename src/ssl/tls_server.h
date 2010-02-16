/**
* TLS Server 
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_SERVER_H__
#define BOTAN_TLS_SERVER_H__

#include <botan/tls_connection.h>
#include <botan/tls_state.h>
#include <vector>

namespace Botan {

/**
* TLS Server
*/

// FIXME: much of this can probably be moved up to TLS_Connection
class BOTAN_DLL TLS_Server
   {
   public:
      u32bit read(byte[], u32bit);
      void write(const byte[], u32bit);

      std::vector<X509_Certificate> peer_cert_chain() const;

      void close();
      bool is_closed() const;

      // FIXME: support cert chains (!)
      // FIXME: support anonymous servers
      TLS_Server(RandomNumberGenerator& rng,
                 Socket&,
                 const X509_Certificate&, const PKCS8_PrivateKey&,
                 const TLS_Policy* = 0);

      ~TLS_Server();
   private:
      void close(Alert_Level, Alert_Type);

      void do_handshake();
      void state_machine();
      void read_handshake(byte, const MemoryRegion<byte>&);

      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      RandomNumberGenerator& rng;

      Record_Writer writer;
      Record_Reader reader;
      const TLS_Policy* policy;

      // FIXME: rename to match TLS_Client
      std::vector<X509_Certificate> cert_chain, peer_certs;
      PKCS8_PrivateKey* private_key;

      Handshake_State* state;
      SecureVector<byte> session_id;
      SecureQueue read_buf;
      std::string peer_id;
      bool active;
   };

}

#endif

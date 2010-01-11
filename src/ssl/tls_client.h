/**
* TLS Client Header File
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_CLIENT_H__
#define BOTAN_CLIENT_H__

#include <botan/tls_connection.h>
#include <botan/tls_state.h>
#include <vector>
#include <string>

namespace Botan {

/**
* TLS Client
*/

// FIXME: much of this can probably be moved up to TLS_Connection
class BOTAN_DLL TLS_Client : public TLS_Connection
   {
   public:
      u32bit read(byte[], u32bit);
      void write(const byte[], u32bit);

      std::vector<X509_Certificate> peer_cert_chain() const;

      void close();
      bool is_closed() const;

      TLS_Client(RandomNumberGenerator& rng,
                 Socket&, const Policy* = 0);

      // FIXME: support multiple cert/key pairs
      TLS_Client(RandomNumberGenerator& rng,
                 Socket&, const X509_Certificate&, const PKCS8_PrivateKey&,
                 const Policy* = 0);

      ~TLS_Client();
   private:
      void close(Alert_Level, Alert_Type);

      void initialize();
      void do_handshake();

      void state_machine();
      void read_handshake(byte, const MemoryRegion<byte>&);
      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      RandomNumberGenerator& rng;

      Record_Writer writer;
      Record_Reader reader;
      const Policy* policy;

      std::vector<X509_Certificate> certs, peer_certs;
      std::vector<PKCS8_PrivateKey*> keys;

      Handshake_State* state;
      SecureVector<byte> session_id;
      SecureQueue read_buf;
      std::string peer_id;
      bool active;
   };

}

#endif

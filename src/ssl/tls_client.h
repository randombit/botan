/*
* TLS Client
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CLIENT_H__
#define BOTAN_TLS_CLIENT_H__

#include <botan/tls_connection.h>
#include <botan/tls_policy.h>
#include <botan/tls_record.h>
#include <botan/socket.h>
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
      u32bit read(byte buf[], u32bit buf_len);
      void write(const byte buf[], u32bit buf_len);

      std::vector<X509_Certificate> peer_cert_chain() const;

      void close();
      bool is_closed() const;

      TLS_Client(const TLS_Policy& policy,
                 RandomNumberGenerator& rng,
                 Socket& peer);

      // FIXME: support multiple/arbitrary # of cert/key pairs
      TLS_Client(const TLS_Policy& policy,
                 RandomNumberGenerator& rng,
                 Socket& peer,
                 const X509_Certificate& cert,
                 const Private_Key& cert_key);

      ~TLS_Client();
   private:
      void close(Alert_Level, Alert_Type);

      void initialize();
      void do_handshake();

      void state_machine();
      void read_handshake(byte, const MemoryRegion<byte>&);
      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      const TLS_Policy& policy;
      RandomNumberGenerator& rng;
      Socket& peer;

      Record_Writer writer;
      Record_Reader reader;

      std::vector<X509_Certificate> certs, peer_certs;
      std::vector<Private_Key*> keys;

      class Handshake_State* state;
      SecureVector<byte> session_id;
      SecureQueue read_buf;
      bool active;
   };

}

#endif

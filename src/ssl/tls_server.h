/*
* TLS Server
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_SERVER_H__
#define BOTAN_TLS_SERVER_H__

#include <botan/tls_connection.h>
#include <botan/tls_record.h>
#include <botan/tls_policy.h>
#include <botan/socket.h>
#include <vector>

namespace Botan {

/**
* TLS Server
*/

class BOTAN_DLL TLS_Server : public TLS_Connection
   {
   public:
      u32bit read(byte buf[], u32bit buf_len);
      void write(const byte buf[], u32bit buf_len);

      std::vector<X509_Certificate> peer_cert_chain() const;

      std::string requested_hostname() const
         { return client_requested_hostname; }

      void close();
      bool is_closed() const;

      // FIXME: support cert chains (!)
      // FIXME: support anonymous servers
      TLS_Server(RandomNumberGenerator& rng,
                 Socket& peer,
                 const X509_Certificate& cert,
                 const Private_Key& cert_key,
                 const TLS_Policy* policy = 0);

      ~TLS_Server();
   private:
      void close(Alert_Level, Alert_Type);

      void do_handshake();
      void state_machine();
      void read_handshake(byte, const MemoryRegion<byte>&);

      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      RandomNumberGenerator& rng;

      Socket& peer;

      Record_Writer writer;
      Record_Reader reader;
      const TLS_Policy* policy;

      // FIXME: rename to match TLS_Client
      std::vector<X509_Certificate> cert_chain, peer_certs;
      Private_Key* private_key;

      class Handshake_State* state;
      SecureVector<byte> session_id;
      SecureQueue read_buf;
      std::string peer_id;
      std::string client_requested_hostname;
      bool active;
   };

}

#endif

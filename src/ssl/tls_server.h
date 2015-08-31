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
#include <vector>

namespace Botan {

/**
* TLS Server
*/
class BOTAN_DLL TLS_Server : public TLS_Connection
   {
   public:
      size_t read(byte buf[], size_t buf_len);
      void write(const byte buf[], size_t buf_len);

      std::vector<X509_Certificate> peer_cert_chain() const;

      std::string requested_hostname() const
         { return client_requested_hostname; }

      void close();
      bool is_closed() const;

      /*
      * FIXME: support cert chains (!)
      * FIXME: support anonymous servers
      */
      TLS_Server(std::tr1::function<size_t (unsigned char[], size_t)> input_fn,
                 std::tr1::function<void (const unsigned char[], size_t)> output_fn,
                 const TLS_Policy& policy,
                 RandomNumberGenerator& rng,
                 const X509_Certificate& cert,
                 const Private_Key& cert_key);

      ~TLS_Server();
   private:
      void close(Alert_Level, Alert_Type);

      void do_handshake();
      void state_machine();
      void read_handshake(byte, const MemoryRegion<byte>&);

      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      std::tr1::function<size_t (unsigned char[], size_t)> input_fn;

      const TLS_Policy& policy;
      RandomNumberGenerator& rng;

      Record_Writer writer;
      Record_Reader reader;

      // FIXME: rename to match TLS_Client
      std::vector<X509_Certificate> cert_chain, peer_certs;
      Private_Key* private_key;

      class Handshake_State* state;
      SecureVector<byte> session_id;
      SecureQueue read_buf;
      std::string client_requested_hostname;
      bool active;
   };

}

#endif

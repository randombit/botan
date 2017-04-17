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
#include <vector>
#include <string>

namespace Botan {

/**
* SSL/TLS Client
*/
class BOTAN_DLL TLS_Client : public TLS_Connection
   {
   public:
      size_t read(byte buf[], size_t buf_len);
      void write(const byte buf[], size_t buf_len);

      void close();
      bool is_closed() const;

      std::vector<X509_Certificate> peer_cert_chain() const;

      void add_client_cert(const X509_Certificate& cert,
                           Private_Key* cert_key);

      TLS_Client(std::tr1::function<size_t (unsigned char[], size_t)> input_fn,
                 std::tr1::function<void (const unsigned char[], size_t)> output_fn,
                 const TLS_Policy& policy,
                 RandomNumberGenerator& rng);

      ~TLS_Client();
   private:
      void close(Alert_Level, Alert_Type);

      size_t get_pending_socket_input(byte output[], size_t length);

      void initialize();
      void do_handshake();

      void state_machine();
      void read_handshake(byte, const MemoryRegion<byte>&);
      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      std::tr1::function<size_t (unsigned char[], size_t)> input_fn;

      const TLS_Policy& policy;
      RandomNumberGenerator& rng;

      Record_Writer writer;
      Record_Reader reader;

      std::vector<X509_Certificate> peer_certs;
      std::vector<std::pair<X509_Certificate, Private_Key*> > certs;

      class Handshake_State* state;
      SecureVector<byte> session_id;
      SecureQueue read_buf;
      bool active;
   };

}

#endif

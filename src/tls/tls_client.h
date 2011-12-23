/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CLIENT_H__
#define BOTAN_TLS_CLIENT_H__

#include <botan/tls_policy.h>
#include <botan/tls_record.h>
#include <vector>
#include <string>

namespace Botan {

/**
* SSL/TLS Client
*/
class BOTAN_DLL TLS_Client
   {
   public:
      /**
      * Set up a new TLS client session
      */
      TLS_Client(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                 std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn,
                 const TLS_Policy& policy,
                 RandomNumberGenerator& rng);

      /**
      * Inject TLS traffic received from counterparty

      * @return a hint as the how many more bytes we need to process the
                current record (this may be 0 if on a record boundary)
      */
      size_t received_data(const byte buf[], size_t buf_size);

      /**
      * Inject plaintext intended for counterparty
      */
      void queue_for_sending(const byte buf[], size_t buf_size);

      void close();

      bool handshake_complete() const { return active; }

      std::vector<X509_Certificate> peer_cert_chain() const { return peer_certs; }

      void add_client_cert(const X509_Certificate& cert,
                           Private_Key* cert_key);

      ~TLS_Client();
   private:
      void close(Alert_Level, Alert_Type);

      size_t get_pending_socket_input(byte output[], size_t length);

      void initialize();
      void do_handshake();

      void state_machine();
      void read_handshake(byte, const MemoryRegion<byte>&);
      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      const TLS_Policy& policy;
      RandomNumberGenerator& rng;

      std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn;

      Record_Writer writer;
      Record_Reader reader;

      SecureQueue pre_handshake_write_queue;

      std::vector<X509_Certificate> peer_certs;
      std::vector<std::pair<X509_Certificate, Private_Key*> > certs;

      class Handshake_State* state;
      //SecureVector<byte> session_id;
      bool active;
   };

}

#endif

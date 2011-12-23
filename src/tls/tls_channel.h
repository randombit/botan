/*
* TLS Channel
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CHANNEL_H__
#define BOTAN_TLS_CHANNEL_H__

#include <botan/tls_policy.h>
#include <botan/tls_record.h>
#include <botan/x509cert.h>
#include <vector>

namespace Botan {

/**
* Generic interface for TLS endpoint
*/
class BOTAN_DLL TLS_Channel
   {
   public:
      /**
      * Inject TLS traffic received from counterparty

      * @return a hint as the how many more bytes we need to process the
                current record (this may be 0 if on a record boundary)
      */
      virtual size_t received_data(const byte buf[], size_t buf_size);

      /**
      * Inject plaintext intended for counterparty
      */
      virtual void queue_for_sending(const byte buf[], size_t buf_size);

      /**
      * Send a close notification alert
      */
      void close() { alert(WARNING, CLOSE_NOTIFY); }

      /**
      * Send a TLS alert message. If the alert is fatal, the
      * internal state (keys, etc) will be reset
      */
      void alert(Alert_Level level, Alert_Type type);

      /**
      * Is the connection active?
      */
      bool is_active() const { return active; }

      /**
      * Return the certificates of the peer
      */
      std::vector<X509_Certificate> peer_cert_chain() const { return peer_certs; }

      TLS_Channel(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                  std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn);

      virtual ~TLS_Channel();
   protected:
      virtual void read_handshake(byte rec_type,
                                  const MemoryRegion<byte>& rec_buf);

      virtual void process_handshake_msg(Handshake_Type type,
                                         const MemoryRegion<byte>& contents) = 0;

      std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn;

      Record_Writer writer;
      Record_Reader reader;

      SecureQueue pre_handshake_write_queue;

      std::vector<X509_Certificate> peer_certs;

      class Handshake_State* state;

      bool active;
   };

}

#endif

/**
* TLS Client
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CLIENT_H__
#define BOTAN_TLS_CLIENT_H__

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
      u32bit read(byte buf[], u32bit buf_len);
      void write(const byte buf[], u32bit buf_len);

      std::vector<X509_Certificate> peer_cert_chain() const;

      void close();
      bool is_closed() const;

      TLS_Client(RandomNumberGenerator& rng,
                 Socket& peer,
                 const TLS_Policy* policy = 0);

#if 0
      void add_cert(const X509_Certificate& cert,
                    const Private_Key& cert_key);
#endif

      // FIXME: support multiple cert/key pairs
      TLS_Client(RandomNumberGenerator& rng,
                 Socket& peer,
                 const X509_Certificate& cert,
                 const Private_Key& cert_key,
                 const TLS_Policy* policy = 0);

      ~TLS_Client();
   private:
      void close(Alert_Level, Alert_Type);

      void initialize();
      void do_handshake();

      void state_machine();
      void read_handshake(byte, const MemoryRegion<byte>&);
      void process_handshake_msg(Handshake_Type, const MemoryRegion<byte>&);

      RandomNumberGenerator& rng;

      Socket& peer;

      Record_Writer writer;
      Record_Reader reader;
      const TLS_Policy* policy;

      std::vector<X509_Certificate> certs, peer_certs;
      std::vector<Private_Key*> keys;

      Handshake_State* state;
      SecureVector<byte> session_id;
      SecureQueue read_buf;
      std::string peer_id;
      bool active;
   };

}

#endif

/*
* TLS Blocking API
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_BLOCKING_CHANNELS_H__
#define BOTAN_TLS_BLOCKING_CHANNELS_H__

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <deque>

namespace Botan {

//template<typename T> using secure_deque = std::vector<T, secure_allocator<T>>;

namespace TLS {

/**
* Blocking TLS Client
* Can be used directly, or subclass to get handshake and alert notifications
*/
class BOTAN_DLL Blocking_Client
   {
   public:
      /*
      * These functions are expected to block until completing entirely, or
      * fail by throwing an exception.
      */
      typedef std::function<size_t (byte[], size_t)> read_fn;
      typedef std::function<void (const byte[], size_t)> write_fn;

      Blocking_Client(read_fn reader,
                      write_fn writer,
                      Session_Manager& session_manager,
                      Credentials_Manager& creds,
                      const Policy& policy,
                      RandomNumberGenerator& rng,
                      const Server_Information& server_info = Server_Information(),
                      const Protocol_Version& offer_version = Protocol_Version::latest_tls_version(),
                      const std::vector<std::string>& next_protos = {});

      /**
      * Completes full handshake then returns
      */
      void do_handshake();

      /**
      * Number of bytes pending read in the plaintext buffer (bytes
      * readable without blocking)
      */
      size_t pending() const { return m_plaintext.size(); }

      /**
      * Blocking read, will return at least 1 byte or 0 on connection close
      */
      size_t read(byte buf[], size_t buf_len);

      void write(const byte buf[], size_t buf_len) { m_channel.send(buf, buf_len); }

      const TLS::Channel& underlying_channel() const { return m_channel; }
      TLS::Channel& underlying_channel() { return m_channel; }

      void close() { m_channel.close(); }

      bool is_closed() const { return m_channel.is_closed(); }

      std::vector<X509_Certificate> peer_cert_chain() const
         { return m_channel.peer_cert_chain(); }

      virtual ~Blocking_Client() {}

   protected:
      /**
      * Application can override to get the handshake complete notification
      */
      virtual bool handshake_complete(const Session&) { return true; }

      /**
      * Application can override to get notification of alerts
      */
      virtual void alert_notification(const Alert&) {}

   private:

      bool handshake_cb(const Session&);

      void data_cb(const byte data[], size_t data_len);

      void alert_cb(const Alert& alert, const byte data[], size_t data_len);

      read_fn m_read;
      TLS::Client m_channel;
      secure_vector<byte> m_plaintext;
   };

}

}

#endif

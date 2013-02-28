/*
* TLS Blocking API
* (C) 2013 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_BLOCKING_CHANNELS_H__
#define BOTAN_TLS_BLOCKING_CHANNELS_H__

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <deque>

namespace Botan {

template<typename T> using secure_deque = std::vector<T, secure_allocator<T>>;

namespace TLS {

/**
* Blocking TLS Client
*/
class BOTAN_DLL Blocking_Client
   {
   public:

      Blocking_Client(std::function<size_t (byte[], size_t)> read_fn,
                      std::function<void (const byte[], size_t)> write_fn,
                      Session_Manager& session_manager,
                      Credentials_Manager& creds,
                      const Policy& policy,
                      RandomNumberGenerator& rng,
                      const Server_Information& server_info = Server_Information(),
                      const Protocol_Version offer_version = Protocol_Version::latest_tls_version(),
                      std::function<std::string (std::vector<std::string>)> next_protocol =
                        std::function<std::string (std::vector<std::string>)>());

      // Constructor like the 1.10 Client API
      Blocking_Client(std::function<size_t (byte[], size_t)> read_fn,
                      std::function<void (const byte[], size_t)> write_fn,
                      const Policy& policy,
                      RandomNumberGenerator& rng);

      size_t currently_readable() const { return m_plaintext.size(); }

      size_t read(byte buf[], size_t buf_len); // blocking read

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
      * Can override to get the handshake complete notification
      */
      virtual bool handshake_complete(const Session&) { return true; }

      /**
      * Can override to get notification of alerts
      */
      virtual void alert_notification(const Alert&) {}
   private:

      bool handshake_complete_cb(const Session&);

      void process_data(const byte data[], size_t data_len,
                        const Alert& alert);

      std::function<size_t (byte[], size_t)> m_read_fn;
      TLS::Client m_channel;
      secure_deque<byte> m_plaintext;
   };

}

}

#endif

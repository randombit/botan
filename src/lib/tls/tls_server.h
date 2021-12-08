/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_H_
#define BOTAN_TLS_SERVER_H_

#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <botan/credentials_manager.h>
#include <vector>

namespace Botan {

namespace TLS {

class Handshake_IO;
class Server_Impl;

/**
* TLS Server
*/
class BOTAN_PUBLIC_API(2,0) Server final : public Channel
   {
   public:
      /**
      * Server initialization
      *
      * @param callbacks contains a set of callback function references
      *        required by the TLS client.
      *
      * @param session_manager manages session state
      *
      * @param creds manages application/user credentials
      *
      * @param policy specifies other connection policy information
      *
      * @param rng a random number generator
      *
      * @param is_datagram set to true if this server should expect DTLS
      *        connections. Otherwise TLS connections are expected.
      *
      * @param reserved_io_buffer_size This many bytes of memory will
      *        be preallocated for the read and write buffers. Smaller
      *        values just mean reallocations and copies are more likely.
      */
      Server(Callbacks& callbacks,
             Session_Manager& session_manager,
             Credentials_Manager& creds,
             const Policy& policy,
             RandomNumberGenerator& rng,
             bool is_datagram = false,
             size_t reserved_io_buffer_size = TLS::Channel::IO_BUF_DEFAULT_SIZE
         );

      ~Server();

      /**
      * Return the protocol notification set by the client (using the
      * ALPN extension) for this connection, if any. This value is not
      * tied to the session and a later renegotiation of the same
      * session can choose a new protocol.
      */
      std::string next_protocol() const;

      /**
      * Return the protocol notification set by the client (using the
      * ALPN extension) for this connection, if any. This value is not
      * tied to the session and a later renegotiation of the same
      * session can choose a new protocol.
      */
      std::string application_protocol() const override;

      size_t received_data(const uint8_t buf[], size_t buf_size) override;

      using Channel::received_data;

      bool is_active() const override;

      bool is_closed() const override;

      std::vector<X509_Certificate> peer_cert_chain() const override;

      SymmetricKey key_material_export(const std::string& label,
                                       const std::string& context,
                                       size_t length) const override;

      void renegotiate(bool force_full_renegotiation = false) override;

      bool secure_renegotiation_supported() const override;

      void send(const uint8_t buf[], size_t buf_size) override;

      using Channel::send;

      void send_alert(const Alert& alert) override;

      void send_warning_alert(Alert::Type type) override;

      void send_fatal_alert(Alert::Type type) override;

      void close() override;

      bool timeout_check() override;

   private:
      std::unique_ptr<Server_Impl> m_impl;
   };
}

}

#endif

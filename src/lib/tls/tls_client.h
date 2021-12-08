/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_H_
#define BOTAN_TLS_CLIENT_H_

#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <botan/credentials_manager.h>
#include <vector>
#include <memory>

namespace Botan {

namespace TLS {

class Client_Impl;
class Handshake_IO;

/**
* SSL/TLS Client
*/
class BOTAN_PUBLIC_API(2,0) Client final : public Channel
   {
   public:

      /**
      * Set up a new TLS client session
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
      * @param server_info is identifying information about the TLS server
      *
      * @param offer_version specifies which version we will offer
      *        to the TLS server.
      *
      * @param next_protocols specifies protocols to advertise with ALPN
      *
      * @param reserved_io_buffer_size This many bytes of memory will
      *        be preallocated for the read and write buffers. Smaller
      *        values just mean reallocations and copies are more likely.
      */
     Client(Callbacks& callbacks,
            Session_Manager& session_manager,
            Credentials_Manager& creds,
            const Policy& policy,
            RandomNumberGenerator& rng,
            const Server_Information& server_info = Server_Information(),
            const Protocol_Version& offer_version = Protocol_Version::latest_tls_version(),
            const std::vector<std::string>& next_protocols = {},
            size_t reserved_io_buffer_size = TLS::Client::IO_BUF_DEFAULT_SIZE
         );

      ~Client();

      /**
      * @return network protocol as advertised by the TLS server, if server sent the ALPN extension
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
      std::unique_ptr<Client_Impl> m_impl;
   };
}
}

#endif

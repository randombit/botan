/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_H_
#define BOTAN_TLS_CLIENT_H_

#include <botan/credentials_manager.h>
#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <memory>
#include <vector>

namespace Botan::TLS {

class Channel_Impl;
class Handshake_IO;

/**
* SSL/TLS Client
*/
class BOTAN_PUBLIC_API(2, 0) Client final : public Channel {
   public:
      /**
      * Initialize a new TLS client. The constructor will immediately initiate a
      * new session.
      *
      * The @p callbacks parameter specifies the various application callbacks
      * which pertain to this particular client connection.
      *
      * The @p session_manager is an interface for storing TLS sessions, which
      * allows for session resumption upon reconnecting to a server. In the
      * absence of a need for persistent sessions, use
      * TLS::Session_Manager_In_Memory which caches connections for the lifetime
      * of a single process.
      *
      * The @p credentials_manager is an interface that will be called to
      * retrieve any certificates, private keys, or pre-shared keys.
      *
      * Use the optional @p server_info to specify the DNS name of the server
      * you are attempting to connect to, if you know it. This helps the server
      * select what certificate to use and helps the client validate the
      * connection.
      *
      * Use the optional @p offer_version to control the version of TLS you wish
      * the client to offer. Normally, you'll want to offer the most recent
      * version of (D)TLS that is available, however some broken servers are
      * intolerant of certain versions being offered, and for classes of
      * applications that have to deal with such servers (typically web
      * browsers) it may be necessary to implement a version backdown strategy
      * if the initial attempt fails.
      *
      * @warning Implementing such a backdown strategy allows an attacker to
      *          downgrade your connection to the weakest protocol that both you
      *          and the server support.
      *
      * Setting @p offer_version is also used to offer DTLS instead of TLS; use
      * TLS::Protocol_Version::latest_dtls_version().
      *
      * Optionally, the client will advertise @p next_protocols to the server
      * using the ALPN extension.
      *
      * The optional @p reserved_io_buffer_size specifies how many bytes to
      * pre-allocate in the I/O buffers. Use this if you want to control how
      * much memory the channel uses initially (the buffers will be resized as
      * needed to process inputs). Otherwise some reasonable default is used.
      * The TLS 1.3 implementation ignores this.
      */
      Client(const std::shared_ptr<Callbacks>& callbacks,
             const std::shared_ptr<Session_Manager>& session_manager,
             const std::shared_ptr<Credentials_Manager>& creds,
             const std::shared_ptr<const Policy>& policy,
             const std::shared_ptr<RandomNumberGenerator>& rng,
             Server_Information server_info = Server_Information(),
             Protocol_Version offer_version = Protocol_Version::latest_tls_version(),
             const std::vector<std::string>& next_protocols = {},
             size_t reserved_io_buffer_size = TLS::Client::IO_BUF_DEFAULT_SIZE);

      ~Client() override;

      /**
      * @return network protocol as advertised by the TLS server, if server sent the ALPN extension
      */
      std::string application_protocol() const override;

      size_t from_peer(std::span<const uint8_t> data) override;

      bool is_handshake_complete() const override;

      bool is_active() const override;

      bool is_closed() const override;

      bool is_closed_for_reading() const override;
      bool is_closed_for_writing() const override;

      std::vector<X509_Certificate> peer_cert_chain() const override;
      std::shared_ptr<const Public_Key> peer_raw_public_key() const override;
      std::optional<std::string> external_psk_identity() const override;

      SymmetricKey key_material_export(std::string_view label, std::string_view context, size_t length) const override;

      void renegotiate(bool force_full_renegotiation = false) override;

      void update_traffic_keys(bool request_peer_update = false) override;

      bool secure_renegotiation_supported() const override;

      void to_peer(std::span<const uint8_t> data) override;

      void send_alert(const Alert& alert) override;

      void send_warning_alert(Alert::Type type) override;

      void send_fatal_alert(Alert::Type type) override;

      void close() override;

      bool timeout_check() override;

   private:
      size_t downgrade();

   private:
      std::unique_ptr<Channel_Impl> m_impl;
};
}  // namespace Botan::TLS

#endif

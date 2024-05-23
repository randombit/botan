/*
* TLS Server - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_IMPL_13_H_
#define BOTAN_TLS_SERVER_IMPL_13_H_

#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_handshake_state_13.h>
#include <botan/internal/tls_handshake_transitions.h>

namespace Botan::TLS {

/**
* SSL/TLS Server 1.3 implementation
*/
class Server_Impl_13 : public Channel_Impl_13 {
   public:
      explicit Server_Impl_13(const std::shared_ptr<Callbacks>& callbacks,
                              const std::shared_ptr<Session_Manager>& session_manager,
                              const std::shared_ptr<Credentials_Manager>& credentials_manager,
                              const std::shared_ptr<const Policy>& policy,
                              const std::shared_ptr<RandomNumberGenerator>& rng);

      std::string application_protocol() const override;
      std::vector<X509_Certificate> peer_cert_chain() const override;
      std::shared_ptr<const Public_Key> peer_raw_public_key() const override;
      std::optional<std::string> external_psk_identity() const override;

      bool new_session_ticket_supported() const override;
      size_t send_new_session_tickets(size_t tickets) override;

      bool is_handshake_complete() const override;

   private:
      void process_handshake_msg(Handshake_Message_13 msg) override;
      void process_post_handshake_msg(Post_Handshake_Message_13 msg) override;
      void process_dummy_change_cipher_spec() override;

      using Channel_Impl_13::handle;
      void handle(const Client_Hello_12& client_hello_msg);
      void handle(const Client_Hello_13& client_hello_msg);
      void handle(const Certificate_13& certificate_msg);
      void handle(const Certificate_Verify_13& certificate_verify_msg);
      void handle(const Finished_13& finished_msg);

      void handle_reply_to_client_hello(Server_Hello_13 server_hello);
      void handle_reply_to_client_hello(Hello_Retry_Request hello_retry_request);

      void maybe_handle_compatibility_mode();
      void maybe_log_secret(std::string_view label, std::span<const uint8_t> secret) const override;

      void downgrade();

   private:
      Server_Handshake_State_13 m_handshake_state;
      Handshake_Transitions m_transitions;

      std::optional<Session> m_resumed_session;
      std::optional<std::string> m_psk_identity;
};

}  // namespace Botan::TLS

#endif

/*
* TLS 1.3 Client Authentication Resumption Tests
* (C) 2026 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13) && defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/auto_rng.h>
   #include <botan/credentials_manager.h>
   #include <botan/rsa.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_client.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_server.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/x509self.h>

   #include <algorithm>
   #include <memory>
   #include <span>
   #include <utility>
   #include <vector>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS_13) && defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_X509_CERTIFICATES)

class Pipe_Callbacks final : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> data) override {
         m_outbound.insert(m_outbound.end(), data.begin(), data.end());
      }

      void tls_record_received(uint64_t, std::span<const uint8_t>) override {}

      void tls_alert(Botan::TLS::Alert) override {}

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         m_was_resumption = session.was_resumption();
         m_peer_certificates = session.peer_certs().size();
      }

      bool tls_should_persist_resumption_information(const Botan::TLS::Session&) override { return true; }

      void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>&,
                                 const std::vector<std::optional<Botan::OCSP::Response>>&,
                                 const std::vector<Botan::Certificate_Store*>&,
                                 Botan::Usage_Type,
                                 std::string_view,
                                 const Botan::TLS::Policy&) override {}

      std::vector<uint8_t> take_outbound() { return std::exchange(m_outbound, {}); }

      bool was_resumption() const { return m_was_resumption; }

      size_t peer_certificates() const { return m_peer_certificates; }

   private:
      std::vector<uint8_t> m_outbound;
      bool m_was_resumption = false;
      size_t m_peer_certificates = 0;
};

class Server_Credentials final : public Botan::Credentials_Manager {
   public:
      Server_Credentials(const std::shared_ptr<Botan::Private_Key>& key, Botan::X509_Certificate cert) :
            m_key(key), m_cert(std::move(cert)) {}

      std::vector<Botan::X509_Certificate> find_cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::AlgorithmIdentifier>&,
         const std::vector<Botan::X509_DN>&,
         const std::string& type,
         const std::string&) override {
         if(type == "tls-server" &&
            std::find(cert_key_types.begin(), cert_key_types.end(), m_key->algo_name()) != cert_key_types.end()) {
            return {m_cert};
         }
         return {};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string&,
                                                          const std::string&) override {
         return cert == m_cert ? m_key : nullptr;
      }

   private:
      std::shared_ptr<Botan::Private_Key> m_key;
      Botan::X509_Certificate m_cert;
};

class TLS13_Policy : public Botan::TLS::Policy {
   public:
      bool allow_tls12() const override { return false; }

      bool allow_dtls12() const override { return false; }

      size_t new_session_tickets_upon_handshake_success() const override { return 1; }
};

class Require_Client_Certificate_Policy final : public TLS13_Policy {
   public:
      bool require_client_certificate_authentication() const override { return true; }
};

void pump(Botan::TLS::Channel& client,
          Pipe_Callbacks& client_callbacks,
          Botan::TLS::Channel& server,
          Pipe_Callbacks& server_callbacks) {
   for(size_t rounds = 0; rounds != 100; ++rounds) {
      bool moved = false;
      if(auto data = client_callbacks.take_outbound(); !data.empty()) {
         (void)server.received_data(data);
         moved = true;
      }
      if(auto data = server_callbacks.take_outbound(); !data.empty()) {
         (void)client.received_data(data);
         moved = true;
      }
      if(!moved) {
         return;
      }
   }
   throw Test_Error("TLS pump did not quiesce");
}

struct Connection_Result final {
      bool server_active;
      bool server_saw_resumption;
      size_t server_peer_certificates;
};

Connection_Result connect(const std::shared_ptr<Botan::TLS::Session_Manager>& client_sessions,
                          const std::shared_ptr<Botan::TLS::Session_Manager>& server_sessions,
                          const std::shared_ptr<Botan::Credentials_Manager>& credentials,
                          const std::shared_ptr<const Botan::TLS::Policy>& server_policy,
                          const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
   auto client_callbacks = std::make_shared<Pipe_Callbacks>();
   auto server_callbacks = std::make_shared<Pipe_Callbacks>();

   Botan::TLS::Server server(server_callbacks, server_sessions, credentials, server_policy, rng);
   Botan::TLS::Client client(client_callbacks,
                             client_sessions,
                             credentials,
                             std::make_shared<TLS13_Policy>(),
                             rng,
                             Botan::TLS::Server_Information("service.example"),
                             Botan::TLS::Protocol_Version::TLS_V13);
   try {
      pump(client, *client_callbacks, server, *server_callbacks);
   } catch(const std::exception&) {
      // The unauthenticated client cannot complete a handshake when the
      // current server policy requires a client certificate.
   }

   return {server.is_active(), server_callbacks->was_resumption(), server_callbacks->peer_certificates()};
}

class TLS13_Client_Auth_Resumption_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("TLS 1.3 resumption honors current client authentication policy");

         auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
         auto key = std::make_shared<Botan::RSA_PrivateKey>(*rng, 2048);
         Botan::X509_Cert_Options options("service.example");
         auto certificate = Botan::X509::create_self_signed_cert(options, *key, "SHA-256", *rng);
         auto credentials = std::make_shared<Server_Credentials>(key, std::move(certificate));
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16);

         auto fresh_client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16);
         const auto fresh_mtls = connect(fresh_client_sessions,
                                         server_sessions,
                                         credentials,
                                         std::make_shared<Require_Client_Certificate_Policy>(),
                                         rng);
         result.test_is_false("fresh unauthenticated connection is rejected", fresh_mtls.server_active);

         auto returning_client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16);
         const auto initial =
            connect(returning_client_sessions, server_sessions, credentials, std::make_shared<TLS13_Policy>(), rng);
         result.test_is_true("initial unauthenticated connection succeeds", initial.server_active);

         const auto resumed = connect(returning_client_sessions,
                                      server_sessions,
                                      credentials,
                                      std::make_shared<Require_Client_Certificate_Policy>(),
                                      rng);
         result.test_is_false("unauthenticated session cannot resume after client auth becomes mandatory",
                              resumed.server_active);
         result.test_is_false("rejected session is not reported as resumed", resumed.server_saw_resumption);
         result.test_sz_eq("rejected session has no client certificates", resumed.server_peer_certificates, 0);

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls13_client_auth_resumption", TLS13_Client_Auth_Resumption_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests

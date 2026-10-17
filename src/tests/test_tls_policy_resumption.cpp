/*
* (C) 2026 Filipe Casal
*     2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_X509_CERTIFICATES) && \
   ((defined(BOTAN_HAS_TLS_12) && defined(BOTAN_HAS_ECDH)) || defined(BOTAN_HAS_TLS_13))
   #include <botan/auto_rng.h>
   #include <botan/credentials_manager.h>
   #include <botan/rsa.h>
   #include <botan/tls_alert.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_client.h>
   #include <botan/tls_exceptn.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_server.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/x509self.h>

   #include <algorithm>
   #include <memory>
   #include <optional>
   #include <span>
   #include <utility>
   #include <vector>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_X509_CERTIFICATES) && \
   ((defined(BOTAN_HAS_TLS_12) && defined(BOTAN_HAS_ECDH)) || defined(BOTAN_HAS_TLS_13))

class Pipe_Callbacks final : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> data) override {
         m_outbound.insert(m_outbound.end(), data.begin(), data.end());
      }

      void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> /*data*/) override {}

      void tls_alert(Botan::TLS::Alert /*alert*/) override {}

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         m_was_resumption = session.was_resumption();
         m_peer_certificates = session.peer_certs().size();
         m_kex = session.ciphersuite().kex_method();
         m_cipher = session.ciphersuite().cipher_algo();
      }

      bool tls_should_persist_resumption_information(const Botan::TLS::Session& /*session*/) override { return true; }

      void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& /*cert_chain*/,
                                 const std::vector<std::optional<Botan::OCSP::Response>>& /*ocsp_responses*/,
                                 const std::vector<Botan::Certificate_Store*>& /*trusted_roots*/,
                                 Botan::Usage_Type /*usage*/,
                                 std::string_view /*hostname*/,
                                 const Botan::TLS::Policy& /*policy*/) override {}

      void tls_verify_raw_public_key(const Botan::Public_Key& /*raw_public_key*/,
                                     Botan::Usage_Type /*usage*/,
                                     std::string_view /*hostname*/,
                                     const Botan::TLS::Policy& /*policy*/) override {}

      std::vector<uint8_t> take_outbound() { return std::exchange(m_outbound, {}); }

      bool was_resumption() const { return m_was_resumption; }

      size_t peer_certificates() const { return m_peer_certificates; }

      std::optional<Botan::TLS::Kex_Algo> kex() const { return m_kex; }

      const std::string& cipher() const { return m_cipher; }

   private:
      std::vector<uint8_t> m_outbound;
      bool m_was_resumption = false;
      size_t m_peer_certificates = 0;
      std::optional<Botan::TLS::Kex_Algo> m_kex;
      std::string m_cipher;
};

class Server_Credentials final : public Botan::Credentials_Manager {
   public:
      Server_Credentials(const std::shared_ptr<Botan::Private_Key>& key, Botan::X509_Certificate cert) :
            m_key(key), m_cert(std::move(cert)) {}

      std::vector<Botan::X509_Certificate> find_cert_chain(const std::vector<std::string>& cert_key_types,
                                                           const std::vector<Botan::AlgorithmIdentifier>& /*schemes*/,
                                                           const std::vector<Botan::X509_DN>& /*acceptable_CAs*/,
                                                           const std::string& type,
                                                           const std::string& /*context*/) override {
         if(type == "tls-server" &&
            std::find(cert_key_types.begin(), cert_key_types.end(), m_key->algo_name()) != cert_key_types.end()) {
            return {m_cert};
         }
         return {};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string& /*type*/,
                                                          const std::string& /*context*/) override {
         return cert == m_cert ? m_key : nullptr;
      }

   private:
      std::shared_ptr<Botan::Private_Key> m_key;
      Botan::X509_Certificate m_cert;
};

template <typename Base>
class Require_Client_Certificate_Policy final : public Base {
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
      bool server_active = false;
      bool server_saw_resumption = false;
      size_t server_peer_certificates = 0;
      std::optional<Botan::TLS::Kex_Algo> kex;
      std::string cipher;
      std::optional<Botan::TLS::AlertType> alert;
};

Connection_Result connect(Botan::TLS::Protocol_Version version,
                          const std::shared_ptr<Botan::TLS::Session_Manager>& client_sessions,
                          const std::shared_ptr<Botan::TLS::Session_Manager>& server_sessions,
                          const std::shared_ptr<Botan::Credentials_Manager>& client_credentials,
                          const std::shared_ptr<Botan::Credentials_Manager>& server_credentials,
                          const std::shared_ptr<const Botan::TLS::Policy>& client_policy,
                          const std::shared_ptr<const Botan::TLS::Policy>& server_policy,
                          const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
   auto client_callbacks = std::make_shared<Pipe_Callbacks>();
   auto server_callbacks = std::make_shared<Pipe_Callbacks>();

   Botan::TLS::Server server(server_callbacks, server_sessions, server_credentials, server_policy, rng);
   Botan::TLS::Client client(client_callbacks,
                             client_sessions,
                             client_credentials,
                             client_policy,
                             rng,
                             Botan::TLS::Server_Information("service.example"),
                             version);

   std::optional<Botan::TLS::AlertType> alert;
   try {
      pump(client, *client_callbacks, server, *server_callbacks);
   } catch(const Botan::TLS::TLS_Exception& e) {
      // The handshake fails when the current server policy demands client
      // authentication that the peer (or its stored session) cannot satisfy.
      alert = e.type();
   }

   return {server.is_active(),
           server_callbacks->was_resumption(),
           server_callbacks->peer_certificates(),
           server_callbacks->kex(),
           server_callbacks->cipher(),
           alert};
}

   #if defined(BOTAN_HAS_TLS_12) && defined(BOTAN_HAS_ECDH)

class Client_Cert_Credentials final : public Botan::Credentials_Manager {
   public:
      Client_Cert_Credentials(std::shared_ptr<Botan::Private_Key> key, Botan::X509_Certificate cert) :
            m_key(std::move(key)), m_cert(std::move(cert)) {}

      std::vector<Botan::X509_Certificate> find_cert_chain(const std::vector<std::string>& cert_key_types,
                                                           const std::vector<Botan::AlgorithmIdentifier>& /*schemes*/,
                                                           const std::vector<Botan::X509_DN>& /*acceptable_CAs*/,
                                                           const std::string& type,
                                                           const std::string& /*context*/) override {
         if(type == "tls-client" &&
            std::find(cert_key_types.begin(), cert_key_types.end(), m_key->algo_name()) != cert_key_types.end()) {
            return {m_cert};
         }
         return {};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string& /*type*/,
                                                          const std::string& /*context*/) override {
         return cert == m_cert ? m_key : nullptr;
      }

   private:
      std::shared_ptr<Botan::Private_Key> m_key;
      Botan::X509_Certificate m_cert;
};

class TLS12_Policy : public Botan::TLS::Policy {
   public:
      bool allow_tls13() const override { return false; }
};

class AES128_Only_Policy final : public TLS12_Policy {
   public:
      std::vector<std::string> allowed_ciphers() const override { return {"AES-128/GCM"}; }
};

class AES256_Only_Policy final : public TLS12_Policy {
   public:
      std::vector<std::string> allowed_ciphers() const override { return {"AES-256/GCM"}; }
};

class Static_RSA_Kex_Policy final : public TLS12_Policy {
   public:
      std::vector<std::string> allowed_key_exchange_methods() const override { return {"RSA"}; }

      std::vector<std::string> allowed_signature_methods() const override { return {"RSA", "IMPLICIT"}; }
};

class RSA_Or_ECDHE_Kex_Policy final : public TLS12_Policy {
   public:
      std::vector<std::string> allowed_key_exchange_methods() const override { return {"RSA", "ECDH"}; }

      std::vector<std::string> allowed_signature_methods() const override { return {"RSA", "IMPLICIT"}; }
};

class TLS12_Policy_Resumption_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("TLS 1.2 resumption honors current policy");

         const auto version = Botan::TLS::Protocol_Version::TLS_V12;

         auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
         auto server_key = std::make_shared<Botan::RSA_PrivateKey>(*rng, 2048);
         Botan::X509_Cert_Options server_opts("service.example");
         auto server_cert = Botan::X509::create_self_signed_cert(server_opts, *server_key, "SHA-256", *rng);
         auto credentials = std::make_shared<Server_Credentials>(server_key, server_cert);

         auto base_policy = std::make_shared<TLS12_Policy>();

         auto make_sessions = [&]() { return std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16); };

         // Control: resumption works while the policy is unchanged
         {
            auto client_sessions = make_sessions();
            auto server_sessions = make_sessions();
            const auto initial = connect(
               version, client_sessions, server_sessions, credentials, credentials, base_policy, base_policy, rng);
            result.test_is_true("initial connection succeeds", initial.server_active);
            result.test_is_false("initial connection is not a resumption", initial.server_saw_resumption);

            const auto resumed = connect(
               version, client_sessions, server_sessions, credentials, credentials, base_policy, base_policy, rng);
            result.test_is_true("second connection succeeds", resumed.server_active);
            result.test_is_true("second connection is a resumption", resumed.server_saw_resumption);
         }

         // An unauthenticated session must not resume after client certificate
         // authentication became mandatory; the resulting full handshake fails
         // for a client that cannot authenticate.
         {
            auto client_sessions = make_sessions();
            auto server_sessions = make_sessions();
            const auto initial = connect(
               version, client_sessions, server_sessions, credentials, credentials, base_policy, base_policy, rng);
            result.test_is_true("unauthenticated connection succeeds", initial.server_active);

            const auto rejected = connect(version,
                                          client_sessions,
                                          server_sessions,
                                          credentials,
                                          credentials,
                                          base_policy,
                                          std::make_shared<Require_Client_Certificate_Policy<TLS12_Policy>>(),
                                          rng);
            result.test_is_false("certless client cannot connect after client auth becomes mandatory",
                                 rejected.server_active);
            result.test_is_false("rejected connection is not reported as resumed", rejected.server_saw_resumption);
            result.test_is_true("rejection happens in a full handshake requesting a certificate",
                                rejected.alert == Botan::TLS::AlertType::HandshakeFailure);
         }

         // A client that can authenticate is upgraded to a full handshake with
         // a certificate exchange instead of resuming unauthenticated.
         {
            auto client_key = std::make_shared<Botan::RSA_PrivateKey>(*rng, 2048);
            Botan::X509_Cert_Options client_opts("client.example");
            auto client_cert = Botan::X509::create_self_signed_cert(client_opts, *client_key, "SHA-256", *rng);
            auto client_credentials = std::make_shared<Client_Cert_Credentials>(client_key, client_cert);

            auto client_sessions = make_sessions();
            auto server_sessions = make_sessions();
            const auto initial = connect(version,
                                         client_sessions,
                                         server_sessions,
                                         client_credentials,
                                         credentials,
                                         base_policy,
                                         base_policy,
                                         rng);
            result.test_is_true("connection before mTLS mandate succeeds", initial.server_active);
            result.test_sz_eq("no client certificate was exchanged initially", initial.server_peer_certificates, 0);

            const auto upgraded = connect(version,
                                          client_sessions,
                                          server_sessions,
                                          client_credentials,
                                          credentials,
                                          base_policy,
                                          std::make_shared<Require_Client_Certificate_Policy<TLS12_Policy>>(),
                                          rng);
            result.test_is_true("cert-capable client connects after client auth becomes mandatory",
                                upgraded.server_active);
            result.test_is_false("upgraded connection is not a resumption", upgraded.server_saw_resumption);
            result.test_sz_eq("upgraded connection authenticated the client", upgraded.server_peer_certificates, 1);
         }

         // A session must not resume with a ciphersuite the current server
         // policy no longer allows; a full handshake negotiates a fresh suite.
         {
            auto client_sessions = make_sessions();
            auto server_sessions = make_sessions();
            const auto initial = connect(version,
                                         client_sessions,
                                         server_sessions,
                                         credentials,
                                         credentials,
                                         base_policy,
                                         std::make_shared<AES128_Only_Policy>(),
                                         rng);
            result.test_is_true("connection with old cipher policy succeeds", initial.server_active);
            result.test_str_eq("session was established with AES-128/GCM", initial.cipher, "AES-128/GCM");

            const auto renegotiated = connect(version,
                                              client_sessions,
                                              server_sessions,
                                              credentials,
                                              credentials,
                                              base_policy,
                                              std::make_shared<AES256_Only_Policy>(),
                                              rng);
            result.test_is_true("connection after cipher policy change succeeds", renegotiated.server_active);
            result.test_is_false("banned ciphersuite session did not resume", renegotiated.server_saw_resumption);
            result.test_str_eq(
               "connection renegotiated the currently allowed cipher", renegotiated.cipher, "AES-256/GCM");
         }

         // The client must not offer resumption of a session whose ciphersuite
         // its own current policy no longer allows (e.g. after dropping a key
         // exchange method); the server would happily resume it.
         {
            auto static_rsa_policy = std::make_shared<Static_RSA_Kex_Policy>();
            auto client_sessions = make_sessions();
            auto server_sessions = make_sessions();
            const auto initial = connect(version,
                                         client_sessions,
                                         server_sessions,
                                         credentials,
                                         credentials,
                                         static_rsa_policy,
                                         std::make_shared<RSA_Or_ECDHE_Kex_Policy>(),
                                         rng);
            result.test_is_true("connection with static RSA key exchange succeeds", initial.server_active);
            result.test_is_true("session was established with static RSA key exchange",
                                initial.kex == Botan::TLS::Kex_Algo::STATIC_RSA);

            const auto renegotiated = connect(version,
                                              client_sessions,
                                              server_sessions,
                                              credentials,
                                              credentials,
                                              base_policy,
                                              std::make_shared<RSA_Or_ECDHE_Kex_Policy>(),
                                              rng);
            result.test_is_true("connection after client kex policy change succeeds", renegotiated.server_active);
            result.test_is_false("client did not resume the static RSA session", renegotiated.server_saw_resumption);
            result.test_is_true("connection renegotiated an allowed key exchange",
                                renegotiated.kex == Botan::TLS::Kex_Algo::ECDH);
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls12_policy_resumption", TLS12_Policy_Resumption_Tests);

   #endif

   #if defined(BOTAN_HAS_TLS_13)

class Client_RPK_Credentials final : public Botan::Credentials_Manager {
   public:
      explicit Client_RPK_Credentials(std::shared_ptr<Botan::Private_Key> key) : m_key(std::move(key)) {}

      std::shared_ptr<Botan::Public_Key> find_raw_public_key(const std::vector<std::string>& key_types,
                                                             const std::string& type,
                                                             const std::string& /*context*/) override {
         if(type == "tls-client" &&
            std::find(key_types.begin(), key_types.end(), m_key->algo_name()) != key_types.end()) {
            return m_key->public_key();
         }
         return nullptr;
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::Public_Key& /*raw_public_key*/,
                                                          const std::string& /*type*/,
                                                          const std::string& /*context*/) override {
         return m_key;
      }

   private:
      std::shared_ptr<Botan::Private_Key> m_key;
};

class TLS13_Policy : public Botan::TLS::Policy {
   public:
      bool allow_tls12() const override { return false; }

      bool allow_dtls12() const override { return false; }

      size_t new_session_tickets_upon_handshake_success() const override { return 1; }
};

class RPK_Client_Policy final : public TLS13_Policy {
   public:
      std::vector<Botan::TLS::Certificate_Type> accepted_client_certificate_types() const override {
         return {Botan::TLS::Certificate_Type::RawPublicKey, Botan::TLS::Certificate_Type::X509};
      }
};

class Require_RPK_Client_Certificate_Policy final : public TLS13_Policy {
   public:
      bool require_client_certificate_authentication() const override { return true; }

      std::vector<Botan::TLS::Certificate_Type> accepted_client_certificate_types() const override {
         return {Botan::TLS::Certificate_Type::RawPublicKey};
      }
};

class TLS13_Client_Auth_Resumption_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("TLS 1.3 resumption honors current client authentication policy");

         const auto version = Botan::TLS::Protocol_Version::TLS_V13;

         auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
         auto key = std::make_shared<Botan::RSA_PrivateKey>(*rng, 2048);
         Botan::X509_Cert_Options options("service.example");
         auto certificate = Botan::X509::create_self_signed_cert(options, *key, "SHA-256", *rng);
         auto credentials = std::make_shared<Server_Credentials>(key, std::move(certificate));
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16);
         auto unauth_policy = std::make_shared<TLS13_Policy>();

         auto fresh_client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16);
         const auto fresh_mtls = connect(version,
                                         fresh_client_sessions,
                                         server_sessions,
                                         credentials,
                                         credentials,
                                         unauth_policy,
                                         std::make_shared<Require_Client_Certificate_Policy<TLS13_Policy>>(),
                                         rng);
         result.test_is_false("fresh unauthenticated connection is rejected", fresh_mtls.server_active);

         auto returning_client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16);
         const auto initial = connect(version,
                                      returning_client_sessions,
                                      server_sessions,
                                      credentials,
                                      credentials,
                                      unauth_policy,
                                      unauth_policy,
                                      rng);
         result.test_is_true("initial unauthenticated connection succeeds", initial.server_active);

         const auto resumed = connect(version,
                                      returning_client_sessions,
                                      server_sessions,
                                      credentials,
                                      credentials,
                                      unauth_policy,
                                      std::make_shared<Require_Client_Certificate_Policy<TLS13_Policy>>(),
                                      rng);
         result.test_is_false("unauthenticated session cannot resume after client auth becomes mandatory",
                              resumed.server_active);
         result.test_is_false("rejected session is not reported as resumed", resumed.server_saw_resumption);
         result.test_sz_eq("rejected session has no client certificates", resumed.server_peer_certificates, 0);
         result.test_is_true("missing credential is rejected with access_denied",
                             resumed.alert == Botan::TLS::AlertType::AccessDenied);

         // A session authenticated with a raw public key resumes only while
         // the live policy accepts that client credential type.
         auto rpk_key = std::make_shared<Botan::RSA_PrivateKey>(*rng, 2048);
         auto rpk_credentials = std::make_shared<Client_RPK_Credentials>(rpk_key);
         auto rpk_client_policy = std::make_shared<RPK_Client_Policy>();
         auto rpk_server_policy = std::make_shared<Require_RPK_Client_Certificate_Policy>();

         auto rpk_client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16);
         const auto rpk_initial = connect(version,
                                          rpk_client_sessions,
                                          server_sessions,
                                          rpk_credentials,
                                          credentials,
                                          rpk_client_policy,
                                          rpk_server_policy,
                                          rng);
         result.test_is_true("client connects with raw public key authentication", rpk_initial.server_active);

         const auto rpk_resumed = connect(version,
                                          rpk_client_sessions,
                                          server_sessions,
                                          rpk_credentials,
                                          credentials,
                                          rpk_client_policy,
                                          rpk_server_policy,
                                          rng);
         result.test_is_true("raw public key session resumes while the credential type is accepted",
                             rpk_resumed.server_active);
         result.test_is_true("raw public key resumption is reported as resumed", rpk_resumed.server_saw_resumption);

         auto rpk_x509_client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 16);
         const auto rpk_mint = connect(version,
                                       rpk_x509_client_sessions,
                                       server_sessions,
                                       rpk_credentials,
                                       credentials,
                                       rpk_client_policy,
                                       rpk_server_policy,
                                       rng);
         result.test_is_true("second raw public key client connects", rpk_mint.server_active);

         const auto rpk_mismatch = connect(version,
                                           rpk_x509_client_sessions,
                                           server_sessions,
                                           rpk_credentials,
                                           credentials,
                                           rpk_client_policy,
                                           std::make_shared<Require_Client_Certificate_Policy<TLS13_Policy>>(),
                                           rng);
         result.test_is_false("raw public key session cannot resume once only X.509 clients are accepted",
                              rpk_mismatch.server_active);
         result.test_is_true("credential type mismatch is rejected with access_denied",
                             rpk_mismatch.alert == Botan::TLS::AlertType::AccessDenied);

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls13_client_auth_resumption", TLS13_Client_Auth_Resumption_Tests);

   #endif

#endif

}  // namespace

}  // namespace Botan_Tests

/*
* (C) 2026 Moritz Schmitt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_FFI)
   #include <botan/ffi.h>
#endif

#if defined(BOTAN_HAS_FFI_TLS)
   #include <botan/auto_rng.h>
   #include <botan/certstor.h>
   #include <botan/ec_group.h>
   #include <botan/ecdsa.h>
   #include <botan/ffi_tls.h>
   #include <botan/pk_keys.h>
   #include <botan/pkcs8.h>
   #include <botan/rsa.h>
   #include <botan/secmem.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/tls_session_manager_noop.h>
   #include <botan/x509_ca.h>
   #include <botan/x509cert.h>
   #include <botan/x509self.h>
   #include <botan/internal/ffi_tls_impl.h>
   #include <chrono>
   #include <cstring>
   #include <memory>
   #include <string>
   #include <utility>
   #include <vector>
#endif

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
   #include <botan/certstor_system.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_FFI_TLS)

// NOLINTBEGIN(*-macro-usage)

   #define TEST_FFI_STR_HELPER(x) #x

   #define TEST_FFI_STR(x) TEST_FFI_STR_HELPER(x)

   #define TEST_FFI_SOURCE_LOCATION(func, file, line) (func " invoked at " file ":" TEST_FFI_STR(line))

   #define TEST_FFI_OK(func, args) result.test_rc_ok(TEST_FFI_SOURCE_LOCATION(#func, __FILE__, __LINE__), func args)

   #define TEST_FFI_RC(rc, func, args) \
      result.test_rc(TEST_FFI_SOURCE_LOCATION(#func, __FILE__, __LINE__), func args, rc)

   #define REQUIRE_FFI_OK(func, args)                           \
      if(!TEST_FFI_OK(func, args)) {                            \
         result.test_note("Exiting test early due to failure"); \
         return result;                                         \
      }

// NOLINTEND(*-macro-usage)

/*
* Loopback tests: a client and a server channel connected through in-memory
* queues, with certificates generated at runtime and loaded through the FFI.
*/

struct Endpoint final {
      botan_tls_channel_t chan = nullptr;

      std::vector<uint8_t> out;       // ciphertext to deliver to the peer
      std::vector<uint8_t> received;  // plaintext received
      std::vector<std::pair<uint16_t, int>> alerts;
      size_t handshake_completes = 0;
      size_t emit_calls = 0;

      // return codes the callbacks produce
      int emit_rc = 0;
      int record_rc = 0;
      int alert_rc = 0;
      int handshake_rc = 0;

      // misuse from inside callbacks
      bool reenter_from_record = false;
      int reenter_rc = 0;
      bool send_from_emit = false;
      int send_from_emit_rc = 0;
      std::string send_from_handshake;
      int send_from_handshake_rc = 0;

      int last_rc = 0;  // last return code of botan_tls_channel_received_data
};

int ep_emit(void* ctx, const uint8_t data[], size_t len) {
   auto* ep = static_cast<Endpoint*>(ctx);
   ep->emit_calls++;
   if(ep->send_from_emit) {
      ep->send_from_emit_rc = botan_tls_channel_send(ep->chan, data, len);
   }
   if(ep->emit_rc != 0) {
      return ep->emit_rc;
   }
   ep->out.insert(ep->out.end(), data, data + len);
   return 0;
}

int ep_record(void* ctx, uint64_t /*seq_no*/, const uint8_t data[], size_t len) {
   auto* ep = static_cast<Endpoint*>(ctx);
   ep->received.insert(ep->received.end(), data, data + len);
   if(ep->reenter_from_record) {
      ep->reenter_rc = botan_tls_channel_received_data(ep->chan, data, len, nullptr);
   }
   return ep->record_rc;
}

int ep_alert(void* ctx, uint16_t alert_code, int is_fatal) {
   auto* ep = static_cast<Endpoint*>(ctx);
   ep->alerts.emplace_back(alert_code, is_fatal);
   return ep->alert_rc;
}

int ep_handshake(void* ctx) {
   auto* ep = static_cast<Endpoint*>(ctx);
   ep->handshake_completes++;
   if(!ep->send_from_handshake.empty()) {
      const auto& msg = ep->send_from_handshake;
      ep->send_from_handshake_rc =
         botan_tls_channel_send(ep->chan, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
   }
   return ep->handshake_rc;
}

// Deliver everything each side emitted to the other until both queues are empty
void pump(Endpoint& a, Endpoint& b) {
   for(size_t round = 0; round != 64 && (!a.out.empty() || !b.out.empty()); ++round) {
      if(!a.out.empty()) {
         const std::vector<uint8_t> bytes = std::move(a.out);
         a.out.clear();
         b.last_rc = botan_tls_channel_received_data(b.chan, bytes.data(), bytes.size(), nullptr);
      }
      if(!b.out.empty()) {
         const std::vector<uint8_t> bytes = std::move(b.out);
         b.out.clear();
         a.last_rc = botan_tls_channel_received_data(a.chan, bytes.data(), bytes.size(), nullptr);
      }
   }
}

// Certificates generated once per test run: an ECDSA CA with a server and a
// client certificate, a CRL, and an RSA server certificate for a second chain
struct Fixture final {
      std::vector<uint8_t> ca_der;
      std::vector<uint8_t> server_der;
      std::vector<uint8_t> server_key_der;
      std::vector<uint8_t> rsa_server_der;
      std::vector<uint8_t> rsa_server_key_der;
      std::vector<uint8_t> client_der;
      std::vector<uint8_t> client_key_der;
      std::vector<uint8_t> crl_der;
      // subject public key bits, to recognize a certificate through the FFI
      std::vector<uint8_t> server_key_bits;
      std::vector<uint8_t> rsa_server_key_bits;
      std::vector<uint8_t> client_key_bits;
};

const Fixture& fixture() {
   static const Fixture fx = [] {
      Botan::AutoSeeded_RNG rng;
      const auto group = Botan::EC_Group::from_name("secp256r1");

      Botan::X509_Cert_Options ca_opts("FFI TLS Test CA/VT");
      ca_opts.CA_key(1);
      const Botan::ECDSA_PrivateKey ca_key(rng, group);
      const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts, ca_key, "SHA-256", rng);
      const Botan::X509_CA ca(ca_cert, ca_key, "SHA-256", rng);

      typedef std::chrono::duration<int, std::ratio<31556926>> years;
      const auto now = std::chrono::system_clock::now();
      const Botan::X509_Time start(now);
      const Botan::X509_Time end(now + years(1));

      Botan::X509_Cert_Options server_opts("server.example.com/VT");
      server_opts.dns = "server.example.com";
      const Botan::ECDSA_PrivateKey server_key(rng, group);
      const auto server_cert =
         ca.sign_request(Botan::X509::create_cert_req(server_opts, server_key, "SHA-256", rng), rng, start, end);

      Botan::X509_Cert_Options rsa_opts("rsa.example.com/VT");
      rsa_opts.dns = "rsa.example.com";
      const Botan::RSA_PrivateKey rsa_key(rng, 2048);
      const auto rsa_cert =
         ca.sign_request(Botan::X509::create_cert_req(rsa_opts, rsa_key, "SHA-256", rng), rng, start, end);

      const Botan::X509_Cert_Options client_opts("client/VT");
      const Botan::ECDSA_PrivateKey client_key(rng, group);
      const auto client_cert =
         ca.sign_request(Botan::X509::create_cert_req(client_opts, client_key, "SHA-256", rng), rng, start, end);

      Fixture f;
      f.ca_der = ca_cert.BER_encode();
      f.server_der = server_cert.BER_encode();
      f.server_key_der = Botan::unlock(Botan::PKCS8::BER_encode(server_key));
      f.rsa_server_der = rsa_cert.BER_encode();
      f.rsa_server_key_der = Botan::unlock(Botan::PKCS8::BER_encode(rsa_key));
      f.client_der = client_cert.BER_encode();
      f.client_key_der = Botan::unlock(Botan::PKCS8::BER_encode(client_key));
      f.crl_der = ca.new_crl(rng).BER_encode();
      f.server_key_bits = server_cert.subject_public_key_bits();
      f.rsa_server_key_bits = rsa_cert.subject_public_key_bits();
      f.client_key_bits = client_cert.subject_public_key_bits();
      return f;
   }();
   return fx;
}

// Handles for one test: created through the FFI, destroyed together
class Handles final {
   public:
      Handles() = default;

      ~Handles() {
         for(auto& ch : channels) {
            botan_tls_channel_destroy(ch);
         }
         for(auto& cb : callbacks) {
            botan_tls_callbacks_destroy(cb);
         }
         for(auto& c : creds) {
            botan_tls_credentials_destroy(c);
         }
         for(auto& p : policies) {
            botan_tls_policy_destroy(p);
         }
         for(auto& m : managers) {
            botan_tls_session_manager_destroy(m);
         }
         for(auto& c : certs) {
            botan_x509_cert_destroy(c);
         }
         for(auto& c : crls) {
            botan_x509_crl_destroy(c);
         }
         for(auto& k : keys) {
            botan_privkey_destroy(k);
         }
      }

      Handles(const Handles&) = delete;
      Handles(Handles&&) = delete;
      Handles& operator=(const Handles&) = delete;
      Handles& operator=(Handles&&) = delete;

      botan_x509_cert_t cert(const std::vector<uint8_t>& der) {
         botan_x509_cert_t c = nullptr;
         botan_x509_cert_load(&c, der.data(), der.size());
         certs.push_back(c);
         return c;
      }

      botan_x509_crl_t crl(const std::vector<uint8_t>& der) {
         botan_x509_crl_t c = nullptr;
         botan_x509_crl_load(&c, der.data(), der.size());
         crls.push_back(c);
         return c;
      }

      botan_privkey_t key(const std::vector<uint8_t>& der) {
         botan_privkey_t k = nullptr;
         botan_privkey_load(&k, nullptr, der.data(), der.size(), nullptr);
         keys.push_back(k);
         return k;
      }

      botan_tls_policy_t policy(const char* name) {
         botan_tls_policy_t p = nullptr;
         botan_tls_policy_init(&p, name);
         policies.push_back(p);
         return p;
      }

      botan_tls_policy_t text_policy(const char* text) {
         botan_tls_policy_t p = nullptr;
         botan_tls_policy_init_from_text(&p, text);
         policies.push_back(p);
         return p;
      }

      botan_tls_session_manager_t memory_manager() {
         botan_tls_session_manager_t m = nullptr;
         botan_tls_session_manager_init_memory(&m, nullptr, 0);
         managers.push_back(m);
         return m;
      }

      botan_tls_credentials_t empty_creds() {
         botan_tls_credentials_t c = nullptr;
         botan_tls_credentials_init(&c);
         creds.push_back(c);
         return c;
      }

      botan_tls_credentials_t trust_ca(bool with_crl = true) {
         botan_tls_credentials_t c = nullptr;
         botan_tls_credentials_init(&c);
         creds.push_back(c);
         botan_tls_credentials_add_trusted_cert(c, cert(fixture().ca_der));
         if(with_crl) {
            botan_tls_credentials_add_crl(c, crl(fixture().crl_der));
         }
         return c;
      }

      void add_chain(botan_tls_credentials_t c,
                     const std::vector<uint8_t>& leaf_der,
                     const std::vector<uint8_t>& key_der) {
         const botan_x509_cert_t chain[2] = {cert(leaf_der), cert(fixture().ca_der)};
         botan_tls_credentials_add_cert_chain(c, chain, 2, key(key_der));
      }

      botan_tls_credentials_t server_creds(bool with_rsa_chain = false, bool trust_clients = false) {
         botan_tls_credentials_t c = nullptr;
         botan_tls_credentials_init(&c);
         creds.push_back(c);
         add_chain(c, fixture().server_der, fixture().server_key_der);
         if(with_rsa_chain) {
            add_chain(c, fixture().rsa_server_der, fixture().rsa_server_key_der);
         }
         if(trust_clients) {
            botan_tls_credentials_add_trusted_cert(c, cert(fixture().ca_der));
            botan_tls_credentials_add_crl(c, crl(fixture().crl_der));
         }
         return c;
      }

      botan_tls_callbacks_t callbacks_with(botan_tls_handshake_complete_fn hs) {
         botan_tls_callbacks_t cb = nullptr;
         botan_tls_callbacks_init(&cb, ep_emit, ep_record, ep_alert);
         callbacks.push_back(cb);
         if(hs != nullptr) {
            botan_tls_callbacks_set_handshake_complete(cb, hs);
         }
         return cb;
      }

      int client(Endpoint& ep,
                 botan_tls_callbacks_t cb,
                 botan_tls_policy_t pol,
                 botan_tls_credentials_t cred,
                 botan_tls_session_manager_t sessions,
                 const char* server_name,
                 uint16_t offer_version,
                 const std::vector<const char*>& alpn = {}) {
         const int rc = botan_tls_channel_init_client(&ep.chan,
                                                      cb,
                                                      &ep,
                                                      pol,
                                                      cred,
                                                      sessions,
                                                      nullptr,
                                                      server_name,
                                                      443,
                                                      offer_version,
                                                      alpn.empty() ? nullptr : alpn.data(),
                                                      alpn.size(),
                                                      0);
         if(ep.chan != nullptr) {
            channels.push_back(ep.chan);
         }
         return rc;
      }

      int server(Endpoint& ep,
                 botan_tls_callbacks_t cb,
                 botan_tls_policy_t pol,
                 botan_tls_credentials_t cred,
                 botan_tls_session_manager_t sessions,
                 const std::vector<const char*>& alpn = {}) {
         const int rc = botan_tls_channel_init_server(
            &ep.chan, cb, &ep, pol, cred, sessions, nullptr, alpn.empty() ? nullptr : alpn.data(), alpn.size(), 0);
         if(ep.chan != nullptr) {
            channels.push_back(ep.chan);
         }
         return rc;
      }

      // Destroy the policy, credentials and callbacks handles now; the
      // channels created from them must keep working
      void release_shared_objects() {
         for(auto& cb : callbacks) {
            botan_tls_callbacks_destroy(cb);
         }
         for(auto& c : creds) {
            botan_tls_credentials_destroy(c);
         }
         for(auto& p : policies) {
            botan_tls_policy_destroy(p);
         }
         callbacks.clear();
         creds.clear();
         policies.clear();
      }

   private:
      std::vector<botan_tls_channel_t> channels;
      std::vector<botan_tls_callbacks_t> callbacks;
      std::vector<botan_tls_credentials_t> creds;
      std::vector<botan_tls_policy_t> policies;
      std::vector<botan_tls_session_manager_t> managers;
      std::vector<botan_x509_cert_t> certs;
      std::vector<botan_x509_crl_t> crls;
      std::vector<botan_privkey_t> keys;
};

std::vector<uint16_t> offered_versions() {
   std::vector<uint16_t> versions = {0};
   #if defined(BOTAN_HAS_TLS_12)
   versions.push_back(BOTAN_TLS_VERSION_TLS_12);
   #endif
   #if defined(BOTAN_HAS_TLS_13)
   versions.push_back(BOTAN_TLS_VERSION_TLS_13);
   #endif
   return versions;
}

const char* version_name(uint16_t offered) {
   if(offered == BOTAN_TLS_VERSION_TLS_13) {
      return "TLS 1.3";
   }
   if(offered == BOTAN_TLS_VERSION_TLS_12) {
      return "TLS 1.2";
   }
   return "default";
}

class FFI_TLS_Loopback_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(test_init_errors());
         for(const uint16_t version : offered_versions()) {
            results.push_back(test_basic_handshake(version));
         }
         return results;
      }

   private:
      static Test::Result test_init_errors() {
         Test::Result result("FFI TLS channel creation errors");
         Handles h;
         Endpoint client;
         Endpoint server;

         auto* cb = h.callbacks_with(nullptr);

         auto* policy = h.policy("default");
         auto* creds = h.trust_ca();
         auto* server_creds = h.server_creds();

         TEST_FFI_RC(
            BOTAN_FFI_ERROR_NULL_POINTER,
            botan_tls_channel_init_client,
            (nullptr, cb, &client, policy, creds, nullptr, nullptr, "server.example.com", 443, 0, nullptr, 0, 0));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER,
                     botan_tls_channel_init_client,
                     (&client.chan,
                      nullptr,
                      &client,
                      policy,
                      creds,
                      nullptr,
                      nullptr,
                      "server.example.com",
                      443,
                      0,
                      nullptr,
                      0,
                      0));
         TEST_FFI_RC(
            BOTAN_FFI_ERROR_NULL_POINTER,
            botan_tls_channel_init_client,
            (&client.chan, cb, &client, nullptr, creds, nullptr, nullptr, "server.example.com", 443, 0, nullptr, 0, 0));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER,
                     botan_tls_channel_init_client,
                     (&client.chan,
                      cb,
                      &client,
                      policy,
                      nullptr,
                      nullptr,
                      nullptr,
                      "server.example.com",
                      443,
                      0,
                      nullptr,
                      0,
                      0));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER,
                     botan_tls_channel_init_client,
                     (&client.chan, cb, &client, policy, creds, nullptr, nullptr, nullptr, 443, 0, nullptr, 0, 0));
         TEST_FFI_RC(
            BOTAN_FFI_ERROR_NULL_POINTER,
            botan_tls_channel_init_client,
            (&client.chan, cb, &client, policy, creds, nullptr, nullptr, "server.example.com", 443, 0, nullptr, 1, 0));
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER,
                     botan_tls_channel_init_client,
                     (&client.chan, cb, &client, policy, creds, nullptr, nullptr, "", 443, 0, nullptr, 0, 0));
         TEST_FFI_RC(
            BOTAN_FFI_ERROR_BAD_FLAG,
            botan_tls_channel_init_client,
            (&client.chan, cb, &client, policy, creds, nullptr, nullptr, "server.example.com", 443, 0, nullptr, 0, 1));
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER,
                     botan_tls_channel_init_client,
                     (&client.chan,
                      cb,
                      &client,
                      policy,
                      creds,
                      nullptr,
                      nullptr,
                      "server.example.com",
                      443,
                      0x0301,
                      nullptr,
                      0,
                      0));
         result.test_is_true("Channel handle stays NULL on error", client.chan == nullptr);
         result.test_sz_eq("Nothing was emitted", client.emit_calls, 0);

         const char* alpn_with_null[1] = {nullptr};
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER,
                     botan_tls_channel_init_client,
                     (&client.chan,
                      cb,
                      &client,
                      policy,
                      creds,
                      nullptr,
                      nullptr,
                      "server.example.com",
                      443,
                      0,
                      alpn_with_null,
                      1,
                      0));

   #if defined(BOTAN_HAS_TLS_13)
         auto* no_tls13 = h.text_policy("allow_tls13 = false\n");
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER,
                     botan_tls_channel_init_client,
                     (&client.chan,
                      cb,
                      &client,
                      no_tls13,
                      creds,
                      nullptr,
                      nullptr,
                      "server.example.com",
                      443,
                      BOTAN_TLS_VERSION_TLS_13,
                      nullptr,
                      0,
                      0));
   #else
         TEST_FFI_RC(BOTAN_FFI_ERROR_NOT_IMPLEMENTED,
                     botan_tls_channel_init_client,
                     (&client.chan,
                      cb,
                      &client,
                      policy,
                      creds,
                      nullptr,
                      nullptr,
                      "server.example.com",
                      443,
                      BOTAN_TLS_VERSION_TLS_13,
                      nullptr,
                      0,
                      0));
   #endif
   #if !defined(BOTAN_HAS_TLS_12)
         TEST_FFI_RC(BOTAN_FFI_ERROR_NOT_IMPLEMENTED,
                     botan_tls_channel_init_client,
                     (&client.chan,
                      cb,
                      &client,
                      policy,
                      creds,
                      nullptr,
                      nullptr,
                      "server.example.com",
                      443,
                      BOTAN_TLS_VERSION_TLS_12,
                      nullptr,
                      0,
                      0));
   #endif

         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER,
                     botan_tls_channel_init_server,
                     (nullptr, cb, &server, policy, server_creds, nullptr, nullptr, nullptr, 0, 0));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER,
                     botan_tls_channel_init_server,
                     (&server.chan, cb, &server, policy, server_creds, nullptr, nullptr, nullptr, 2, 0));
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_FLAG,
                     botan_tls_channel_init_server,
                     (&server.chan, cb, &server, policy, server_creds, nullptr, nullptr, nullptr, 0, 7));
         auto* nothing = h.text_policy("allow_tls12 = false\nallow_tls13 = false\n");
         TEST_FFI_RC(BOTAN_FFI_ERROR_INVALID_OBJECT_STATE,
                     botan_tls_channel_init_server,
                     (&server.chan, cb, &server, nothing, server_creds, nullptr, nullptr, nullptr, 0, 0));
         result.test_is_true("Server handle stays NULL on error", server.chan == nullptr);

         TEST_FFI_OK(botan_tls_channel_destroy, (nullptr));

         // A client whose transport fails at once: no channel is created
         Endpoint broken;
         broken.emit_rc = -1;
         result.test_i32_eq("emit failure during init",
                            h.client(broken, cb, policy, creds, nullptr, "server.example.com", 0),
                            BOTAN_FFI_ERROR_TLS_ERROR);
         result.test_is_true("No channel after emit failure", broken.chan == nullptr);

         return result;
      }

      static Test::Result test_basic_handshake(uint16_t version) {
         Test::Result result(std::string("FFI TLS loopback handshake ") + version_name(version));
         Handles h;
         Endpoint client;
         Endpoint server;

         auto* cb = h.callbacks_with(ep_handshake);
         auto* policy = h.policy("default");
         auto* client_creds = h.trust_ca();
         auto* server_creds = h.server_creds();

         server.send_from_handshake = "hello from the server";

         if(!result.test_rc_ok("init_server", h.server(server, cb, policy, server_creds, nullptr))) {
            return result;
         }
         result.test_sz_eq("Server emits nothing at creation", server.emit_calls, 0);
         result.test_i32_eq("Server not active before handshake", botan_tls_channel_is_active(server.chan), 0);
         result.test_i32_eq("Server not closed before handshake", botan_tls_channel_is_closed(server.chan), 0);
         const uint8_t hello[] = {'h', 'i'};
         TEST_FFI_RC(BOTAN_FFI_ERROR_INVALID_OBJECT_STATE, botan_tls_channel_send, (server.chan, hello, sizeof(hello)));

         if(!result.test_rc_ok("init_client",
                               h.client(client, cb, policy, client_creds, nullptr, "server.example.com", version))) {
            return result;
         }
         result.test_is_true("ClientHello emitted during init", !client.out.empty());
         result.test_sz_eq("One emit for the ClientHello", client.emit_calls, 1);

         // The shared handles may go away now; the channels keep what they need
         h.release_shared_objects();

         pump(client, server);

         result.test_i32_eq("Client handshake complete", botan_tls_channel_is_handshake_complete(client.chan), 1);
         result.test_i32_eq("Server handshake complete", botan_tls_channel_is_handshake_complete(server.chan), 1);
         result.test_i32_eq("Client active", botan_tls_channel_is_active(client.chan), 1);
         result.test_i32_eq("Server active", botan_tls_channel_is_active(server.chan), 1);
         result.test_sz_eq("Client handshake callback once", client.handshake_completes, 1);
         result.test_sz_eq("Server handshake callback once", server.handshake_completes, 1);
         result.test_i32_eq("send from handshake_complete succeeded", server.send_from_handshake_rc, 0);
         result.test_str_eq("Client received the server's greeting",
                            std::string(client.received.begin(), client.received.end()),
                            "hello from the server");
         result.test_is_true("No alerts so far", client.alerts.empty() && server.alerts.empty());

         // Application data in both directions, including a multi-record message
         client.received.clear();
         const std::string small = "ping";
         TEST_FFI_OK(botan_tls_channel_send,
                     (client.chan, reinterpret_cast<const uint8_t*>(small.data()), small.size()));
         pump(client, server);
         result.test_str_eq("Server received", std::string(server.received.begin(), server.received.end()), "ping");

         std::vector<uint8_t> big(100 * 1024);
         for(size_t i = 0; i != big.size(); ++i) {
            big[i] = static_cast<uint8_t>(i * 7 + 3);
         }
         TEST_FFI_OK(botan_tls_channel_send, (server.chan, big.data(), big.size()));
         pump(client, server);
         result.test_is_true("Client received the large message", client.received == big);
         TEST_FFI_OK(botan_tls_channel_send, (client.chan, nullptr, 0));

         // Orderly shutdown started by the client
         TEST_FFI_OK(botan_tls_channel_close, (client.chan));
         result.test_i32_eq("Client closed for writing", botan_tls_channel_is_closed_for_writing(client.chan), 1);
         pump(client, server);
         result.test_sz_eq("Server got one alert", server.alerts.size(), 1);
         if(!server.alerts.empty()) {
            result.test_u16_eq("Server got close_notify", server.alerts[0].first, BOTAN_TLS_ALERT_CLOSE_NOTIFY);
            result.test_i32_eq("as a warning", server.alerts[0].second, 0);
         }
         result.test_i32_eq("Server closed for reading", botan_tls_channel_is_closed_for_reading(server.chan), 1);
         result.test_sz_eq("Client got the server's close_notify", client.alerts.size(), 1);
         result.test_i32_eq("Client closed", botan_tls_channel_is_closed(client.chan), 1);
         result.test_i32_eq("Server closed", botan_tls_channel_is_closed(server.chan), 1);
         result.test_i32_eq(
            "Handshake state survives the close", botan_tls_channel_is_handshake_complete(client.chan), 1);
         TEST_FFI_OK(botan_tls_channel_close, (client.chan));
         TEST_FFI_RC(BOTAN_FFI_ERROR_INVALID_OBJECT_STATE, botan_tls_channel_send, (client.chan, hello, sizeof(hello)));

         return result;
      }
};

BOTAN_REGISTER_TEST("ffi", "ffi_tls_loopback", FFI_TLS_Loopback_Test);

#endif

}  // namespace

}  // namespace Botan_Tests

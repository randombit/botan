/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/data_src.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager_noop.h>

#include <memory>

namespace {

const char* const fixed_ecdsa_key =
   "-----BEGIN PRIVATE KEY-----"
   "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfUjnfxgvrIyrqa5N"
   "47X1W50cVStDPbASwRcY6zqehjyhRANCAAQTNF0poMBM4tuCY50NrDJU8za/SK45"
   "erOdFpGK7KRWtBE9zNj6J0f1UB+K8GdekFD2me+iL63v+uBqo/PHRPT9"
   "-----END PRIVATE KEY-----";

const char* const fixed_ecdsa_cert =
   "-----BEGIN CERTIFICATE-----"
   "MIIB3zCCAYWgAwIBAgIRAPFi6dun9OY7YLuZHqKzdEMwCgYIKoZIzj0EAwIwOTEa"
   "MBgGA1UEAwwRSXQncyBGdXp6aW5nIFRpbWUxCzAJBgNVBAYTAlZUMQ4wDAYDVQQK"
   "EwVCb3RhbjAeFw0yNTAxMjAxMzI0MjdaFw0zODAxMTgxMzI0MjdaMDkxGjAYBgNV"
   "BAMMEUl0J3MgRnV6emluZyBUaW1lMQswCQYDVQQGEwJWVDEOMAwGA1UEChMFQm90"
   "YW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQTNF0poMBM4tuCY50NrDJU8za/"
   "SK45erOdFpGK7KRWtBE9zNj6J0f1UB+K8GdekFD2me+iL63v+uBqo/PHRPT9o24w"
   "bDAhBgNVHQ4EGgQYevp/SCkZVWPKNAUSez17HTOyneXEWwpEMBQGA1UdEQQNMAuC"
   "CWxvY2FsaG9zdDAMBgNVHRMBAf8EAjAAMCMGA1UdIwQcMBqAGHr6f0gpGVVjyjQF"
   "Ens9ex0zsp3lxFsKRDAKBggqhkjOPQQDAgNIADBFAiEApqVCYhySxK/8GLq8wlPh"
   "MeBg8CwKO83s1h/GYQZD4CUCID5Mzh5mwrkkAuSENjLXAD4dtiu91Zsoye5J0uuU"
   "60v7"
   "-----END CERTIFICATE-----";

class Fuzzer_TLS_Server_Creds : public Botan::Credentials_Manager {
   public:
      Fuzzer_TLS_Server_Creds() {
         Botan::DataSource_Memory cert_in(fixed_ecdsa_cert);
         m_ecdsa_cert = std::make_unique<Botan::X509_Certificate>(cert_in);

         Botan::DataSource_Memory key_in(fixed_ecdsa_key);
         m_ecdsa_key.reset(Botan::PKCS8::load_key(key_in).release());
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& algos,
         const std::vector<Botan::AlgorithmIdentifier>& /*signature_schemes*/,
         const std::string& /*type*/,
         const std::string& /*hostname*/) override {
         std::vector<Botan::X509_Certificate> v;

         for(const auto& algo : algos) {
            if(algo == "ECDSA") {
               v.push_back(*m_ecdsa_cert);
               break;
            }
         }

         return v;
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& /*cert*/,
                                                          const std::string& type,
                                                          const std::string& /*context*/) override {
         if(type == "ECDSA") {
            return m_ecdsa_key;
         }
         return nullptr;
      }

      Botan::secure_vector<uint8_t> session_ticket_key() override {
         return Botan::hex_decode_locked("AABBCCDDEEFF00112233445566778899");
      }

      Botan::secure_vector<uint8_t> dtls_cookie_secret() override {
         return Botan::hex_decode_locked("AABBCCDDEEFF00112233445566778899");
      }

      std::string psk_identity_hint(const std::string&, const std::string&) override { return "psk_hint"; }

      std::string psk_identity(const std::string&, const std::string&, const std::string&) override { return "psk_id"; }

      std::vector<Botan::TLS::ExternalPSK> find_preshared_keys(
         std::string_view host,
         Botan::TLS::Connection_Side whoami,
         const std::vector<std::string>& identities = {},
         const std::optional<std::string>& prf = std::nullopt) override {
         if(!identities.empty() && std::find(identities.begin(), identities.end(), "psk_id") == identities.end()) {
            return Botan::Credentials_Manager::find_preshared_keys(host, whoami, identities, prf);
         }

         std::vector<Botan::TLS::ExternalPSK> psks;
         psks.emplace_back("psk_id", "SHA-256", Botan::hex_decode_locked("AABBCCDDEEFF00112233445566778899"));
         return psks;
      }

   private:
      std::unique_ptr<Botan::X509_Certificate> m_ecdsa_cert;
      std::shared_ptr<Botan::Private_Key> m_ecdsa_key;
};

class Fuzzer_TLS_Policy : public Botan::TLS::Policy {
   public:
      std::vector<uint16_t> ciphersuite_list(Botan::TLS::Protocol_Version) const override {
         std::vector<uint16_t> ciphersuites;

         for(auto&& suite : Botan::TLS::Ciphersuite::all_known_ciphersuites()) {
            if(suite.valid()) {
               ciphersuites.push_back(suite.ciphersuite_code());
            }
         }

         return ciphersuites;
      }
};

class Fuzzer_TLS_Server_Callbacks : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t>) override {
         // discard
      }

      void tls_record_received(uint64_t, std::span<const uint8_t>) override {
         // ignore peer data
      }

      void tls_alert(Botan::TLS::Alert) override {
         // ignore alert
      }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override {
         if(client_protos.size() > 1) {
            return client_protos[0];
         } else {
            return "fuzzy";
         }
      }

      void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                 const std::vector<std::optional<Botan::OCSP::Response>>& ocsp_responses,
                                 const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                 Botan::Usage_Type usage,
                                 std::string_view hostname,
                                 const Botan::TLS::Policy& policy) override {
         try {
            // try to validate to exercise those code paths
            Botan::TLS::Callbacks::tls_verify_cert_chain(
               cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
         } catch(...) {
            // ignore validation result
         }
      }
};

}  // namespace

void fuzz(std::span<const uint8_t> in) {
   if(in.size() <= 1) {
      return;
   }

   auto session_manager = std::make_shared<Botan::TLS::Session_Manager_Noop>();
   auto policy = std::make_shared<Fuzzer_TLS_Policy>();
   Botan::TLS::Server_Information info("server.name", 443);
   auto creds = std::make_shared<Fuzzer_TLS_Server_Creds>();
   auto callbacks = std::make_shared<Fuzzer_TLS_Server_Callbacks>();

   const bool is_datagram = in[0] & 1;

   Botan::TLS::Server server(callbacks, session_manager, creds, policy, fuzzer_rng_as_shared(), is_datagram);

   try {
      server.received_data(in.subspan(1, in.size() - 1));
   } catch(std::exception& e) {}
}

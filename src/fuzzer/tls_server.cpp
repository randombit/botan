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

const char* const fixed_rsa_key =
   "-----BEGIN PRIVATE KEY-----\n"
   "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCe6qqpMQVJ7zCJ\n"
   "oSnpxia0yO6M7Ie3FGqPcd0DzueC+kWPvuHQ+PpP5vfO6qqRaDVII37PFX5NUZQm\n"
   "GK/rAm7spjIHTCMgqSZ8pN13LU8m1gDwIdu9al16LXN9zZjB67uLlFn2trtLi234\n"
   "i0cnyeF8IC0cz7tgCOzMSVEBcqJjkdgGrZ3WUgOXecVm2lXVrYlEiaSxFp4VOE9k\n"
   "RFeVrELCjmNtc4hRd1yJsF+vObCtvyqGYQE1Qcb0MVSQDBHMkiUVmO6zuW7td5ef\n"
   "O/1OyntQJGyVa+SnWbkSLCybta2J7MreHENrF5GA0K1KL140SNRHeWifRMuNQua7\n"
   "qmKXMBTFAgMBAAECggEAIk3fxyQI0zvpy1vZ01ft1QqmzA7nAPNMSWi33/GS8iga\n"
   "SfxXfKeySPs/tQ/dAARxs//NiOBH4mLgyxR7LQzaawU5OXALCSraXv+ruuUx990s\n"
   "WKnGaG4EfbJAAwEVn47Gbkv425P4fEc91vAhzQn8PbIoatbAyOtESpjs/pYDTeC/\n"
   "mnJId8gqO90cqyRECEMjk9sQ8iEjWPlik4ayGlUVbeeMu6/pJ9F8IZEgkLZiNDAB\n"
   "4anmOFaT7EmqUjI4IlcaqfbbXyDXlvWUYukidEss+CNvPuqbQHBDnpFVvBxdDR2N\n"
   "Uj2D5Xd5blcIe2/+1IVRnznjoQ5zvutzb7ThBmMehQKBgQDOITKG0ht2kXLxjVoR\n"
   "r/pVpx+f3hs3H7wE0+vrLHoQgkVjpMWXQ47YuZTT9rCOOYNI2cMoH2D27t1j78/B\n"
   "9kGYABUVpvQQ+6amqJDI1eYI6e68TPueEDjeALfSCdmPNiI3lZZrCIK9XLpkoy8K\n"
   "tGYBRRJ+JJxjj1zPXj9SGshPgwKBgQDFXUtoxY3mCStH3+0b1qxGG9r1L5goHEmd\n"
   "Am8WBYDheNpL0VqPNzouhuM/ZWMGyyAs/py6aLATe+qhR1uX5vn7LVZwjCSONZ4j\n"
   "7ieEEUh1BHetPI1oI5PxgokRYfVuckotqVseanI/536Er3Yf2FXNQ1/ceVp9WykX\n"
   "3mYTKMhQFwKBgQDKakcXpZNaZ5IcKdZcsBZ/rdGcR5sqEnursf9lvRNQytwg8Vkn\n"
   "JSxNHlBLpV/TCh8lltHRwJ6TXhUBYij+KzhWbx5FWOErHDOWTMmArqtp7W6GcoJT\n"
   "wVJWjxXzp8CApYQMWVSQXpckJL7UvHohZO0WKiHyxTjde5aD++TqV2qEyQKBgBbD\n"
   "jvoTpy08K4DLxCZs2Uvw1I1pIuylbpwsdrGciuP2s38BM6fHH+/T4Qwj3osfDKQD\n"
   "7gHWJ1Dn/wUBHQBlRLoC3bB3iZPZfVb5lhc2gxv0GvWhQVIcoGi/vJ2DpfJKPmIL\n"
   "4ZWdg3X5dm9JaZ98rVDSj5D3ckd5J0E4hp95GbmbAoGBAJJHM4O9lx60tIjw9Sf/\n"
   "QmKWyUk0NLnt8DcgRMW7fVxtzPNDy9DBKGIkDdWZ2s+ForICA3C9WSxBC1EOEHGG\n"
   "xkg2xKt66CeutGroP6M191mHQrRClt1VbEYzQFX21BCk5kig9i/BURyoTHtFiV+t\n"
   "kbf4VLg8Vk9u/R3RU1HsYWhe\n"
   "-----END PRIVATE KEY-----\n";

const char* const fixed_rsa_cert =
   "-----BEGIN CERTIFICATE-----\n"
   "MIIDUDCCAjgCCQD7pIb1ZsoafjANBgkqhkiG9w0BAQsFADBqMQswCQYDVQQGEwJW\n"
   "VDEQMA4GA1UECAwHVmVybW9udDEWMBQGA1UEBwwNVGhlIEludGVybmV0czEUMBIG\n"
   "A1UECgwLTWFuZ29zIFIgVXMxGzAZBgNVBAMMEnNlcnZlci5leGFtcGxlLmNvbTAe\n"
   "Fw0xNjAxMDYxNzQ3MjNaFw0yNjAxMDMxNzQ3MjNaMGoxCzAJBgNVBAYTAlZUMRAw\n"
   "DgYDVQQIDAdWZXJtb250MRYwFAYDVQQHDA1UaGUgSW50ZXJuZXRzMRQwEgYDVQQK\n"
   "DAtNYW5nb3MgUiBVczEbMBkGA1UEAwwSc2VydmVyLmV4YW1wbGUuY29tMIIBIjAN\n"
   "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnuqqqTEFSe8wiaEp6cYmtMjujOyH\n"
   "txRqj3HdA87ngvpFj77h0Pj6T+b3zuqqkWg1SCN+zxV+TVGUJhiv6wJu7KYyB0wj\n"
   "IKkmfKTddy1PJtYA8CHbvWpdei1zfc2Yweu7i5RZ9ra7S4tt+ItHJ8nhfCAtHM+7\n"
   "YAjszElRAXKiY5HYBq2d1lIDl3nFZtpV1a2JRImksRaeFThPZERXlaxCwo5jbXOI\n"
   "UXdcibBfrzmwrb8qhmEBNUHG9DFUkAwRzJIlFZjus7lu7XeXnzv9Tsp7UCRslWvk\n"
   "p1m5Eiwsm7WtiezK3hxDaxeRgNCtSi9eNEjUR3lon0TLjULmu6pilzAUxQIDAQAB\n"
   "MA0GCSqGSIb3DQEBCwUAA4IBAQA1eZGc/4V7z/E/6eG0hVkzoAZeuTcSP7WqBSx+\n"
   "OP2yh0163UYjoa6nehmkKYQQ9PbYPZGzIcl+dBFyYzy6jcp0NdtzpWnTFrjl4rMq\n"
   "akcQ1D0LTYjJXVP9G/vF/SvatOFeVTnQmLlLt/a8ZtRUINqejeZZPzH8ifzFW6tu\n"
   "mlhTVIEKyPHpxClh5Y3ubw/mZYygekFTqMkTx3FwJxKU8J6rYGZxanWAODUIvCUo\n"
   "Fxer1qC5Love3uWl3vXPLEZWZdORnExSRByzz2immBP2vX4zYZoeZRhTQ9ae1TIV\n"
   "Dk02a/1AOJZdZReDbgXhlqaUx5pk/rzo4mDzvu5HSCeXmClz\n"
   "-----END CERTIFICATE-----\n";

class Fuzzer_TLS_Server_Creds : public Botan::Credentials_Manager {
   public:
      Fuzzer_TLS_Server_Creds() {
         Botan::DataSource_Memory cert_in(fixed_rsa_cert);
         m_rsa_cert = std::make_unique<Botan::X509_Certificate>(cert_in);

         Botan::DataSource_Memory key_in(fixed_rsa_key);
         m_rsa_key.reset(Botan::PKCS8::load_key(key_in).release());
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& algos,
         const std::vector<Botan::AlgorithmIdentifier>& /*signature_schemes*/,
         const std::string& /*type*/,
         const std::string& /*hostname*/) override {
         std::vector<Botan::X509_Certificate> v;

         for(const auto& algo : algos) {
            if(algo == "RSA") {
               v.push_back(*m_rsa_cert);
               break;
            }
         }

         return v;
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& /*cert*/,
                                                          const std::string& type,
                                                          const std::string& /*context*/) override {
         if(type == "RSA") {
            return m_rsa_key;
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
      std::unique_ptr<Botan::X509_Certificate> m_rsa_cert;
      std::shared_ptr<Botan::Private_Key> m_rsa_key;
};

class Fuzzer_TLS_Policy : public Botan::TLS::Policy {
   public:
      // TODO: Enable this once the TLS 1.3 server implementation is ready.
      //       Maybe even build individual fuzz targets for different versions.
      bool allow_tls13() const override { return false; }

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

void fuzz(const uint8_t in[], size_t len) {
   if(len <= 1) {
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
      server.received_data(in + 1, len - 1);
   } catch(std::exception& e) {}
}

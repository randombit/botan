/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include <botan/tls_server.h>
#include <botan/system_rng.h>

const char* fixed_rsa_key =
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

const char* fixed_rsa_cert =
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

class Fuzzer_TLS_Server_Creds : public Credentials_Manager
   {
   public:
      Fuzzer_TLS_Server_Creds()
         {
         DataSource_Memory cert_in(fixed_rsa_cert);
         DataSource_Memory key_in(fixed_rsa_key);

         m_rsa_cert.reset(new Botan::X509_Certificate(cert_in));
         //m_rsa_key.reset(Botan::PKCS8::load_key(key_in, Botan::system_rng()));
         }

      void verify_certificate_chain(const std::string& type,
                                    const std::string& purported_hostname,
                                    const std::vector<X509_Certificate>& cert_chain) override
         {
         try
            {
            Credentials_Manager::verify_certificate_chain(type,
                                                          purported_hostname,
                                                          cert_chain);
            }
         catch(std::exception& e) {}
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& algos,
         const std::string& type,
         const std::string& hostname) override
         {
         std::vector<Botan::X509_Certificate> v;

         for(auto algo : algos)
            {
            if(algo == "RSA")
               {
               v.push_back(*m_rsa_cert);
               break;
               }
            }

         return v;
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
                                          const std::string& /*type*/,
                                          const std::string& /*context*/) override
         {
         return m_rsa_key.get();
         }

      std::string psk_identity_hint(const std::string&, const std::string&) override { return "psk_hint"; }
      std::string psk_identity(const std::string&, const std::string&, const std::string&) override { return "psk_id"; }
      SymmetricKey psk(const std::string&, const std::string&, const std::string&) override
         {
         return SymmetricKey("AABBCCDDEEFF00112233445566778899");
         }
   private:
      std::unique_ptr<Botan::X509_Certificate> m_rsa_cert;
      std::unique_ptr<Botan::Private_Key> m_rsa_key;
   };

void fuzz(const uint8_t in[], size_t len)
   {
   if(len == 0)
      return;

   auto dev_null = [](const byte[], size_t) {};

   auto ignore_alerts = [](TLS::Alert, const byte[], size_t) {};
   auto ignore_hs = [](const TLS::Session&) { return true; };

   Botan::System_RNG rng;
   TLS::Session_Manager_Noop session_manager;
   TLS::Policy policy;
   TLS::Server_Information info("server.name", 443);
   Fuzzer_TLS_Server_Creds creds;

   auto next_proto_fn = [](const std::vector<std::string>& protos) -> std::string {
      if(protos.size() > 1)
         return protos[0];
      else
         return "fuzzed";
   };

   const bool is_datagram = (len % 2 == 0);

   TLS::Server server(dev_null,
                      dev_null,
                      ignore_alerts,
                      ignore_hs,
                      session_manager,
                      creds,
                      policy,
                      rng,
                      next_proto_fn,
                      is_datagram);

   try
      {
      while(len > 0)
         {
         const size_t write_len = in[0];
         const size_t left = len - 1;

         const size_t consumed = std::min(left, write_len);

         server.received_data(in + 1, consumed);

         in += consumed + 1;
         len -= consumed + 1;
         }
      }
   catch(std::exception& e)
      {
      }
   }

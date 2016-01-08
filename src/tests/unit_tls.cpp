/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <vector>
#include <memory>
#include <thread>

#if defined(BOTAN_HAS_TLS)

#include <botan/tls_server.h>
#include <botan/tls_client.h>
#include <botan/tls_handshake_msg.h>
#include <botan/pkcs10.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/x509_ca.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#endif


namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)
class Credentials_Manager_Test : public Botan::Credentials_Manager
   {
   public:
      Credentials_Manager_Test(const Botan::X509_Certificate& server_cert,
                               const Botan::X509_Certificate& ca_cert,
                               Botan::Private_Key* server_key) :
         m_server_cert(server_cert),
         m_ca_cert(ca_cert),
         m_key(server_key)
         {
         std::unique_ptr<Botan::Certificate_Store> store(new Botan::Certificate_Store_In_Memory(m_ca_cert));
         m_stores.push_back(std::move(store));
         }

      std::vector<Botan::Certificate_Store*>
      trusted_certificate_authorities(const std::string&,
                                      const std::string&) override
         {
         std::vector<Botan::Certificate_Store*> v;
         for(auto&& store : m_stores)
            v.push_back(store.get());
         return v;
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string&) override
         {
         std::vector<Botan::X509_Certificate> chain;

         if(type == "tls-server")
            {
            bool have_match = false;
            for(size_t i = 0; i != cert_key_types.size(); ++i)
               if(cert_key_types[i] == m_key->algo_name())
                  have_match = true;

            if(have_match)
               {
               chain.push_back(m_server_cert);
               chain.push_back(m_ca_cert);
               }
            }

         return chain;
         }

      void verify_certificate_chain(
         const std::string& type,
         const std::string& purported_hostname,
         const std::vector<Botan::X509_Certificate>& cert_chain) override
         {
         Credentials_Manager::verify_certificate_chain(type,
                                                       purported_hostname,
                                                       cert_chain);
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate&,
                                          const std::string&,
                                          const std::string&) override
         {
         return m_key.get();
         }

      Botan::SymmetricKey psk(const std::string& type,
                              const std::string& context,
                              const std::string&) override
         {
         if(type == "tls-server" && context == "session-ticket")
            return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");

         if(context == "server.example.com" && type == "tls-client")
            return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");

         if(context == "server.example.com" && type == "tls-server")
            return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");

         throw Test_Error("No PSK set for " + type + "/" + context);
         }

   public:
      Botan::X509_Certificate m_server_cert, m_ca_cert;
      std::unique_ptr<Botan::Private_Key> m_key;
      std::vector<std::unique_ptr<Botan::Certificate_Store>> m_stores;
   };

Botan::Credentials_Manager* create_creds()
   {
   std::unique_ptr<Botan::Private_Key> ca_key(new Botan::RSA_PrivateKey(Test::rng(), 1024));

   Botan::X509_Cert_Options ca_opts;
   ca_opts.common_name = "Test CA";
   ca_opts.country = "US";
   ca_opts.CA_key(1);

   Botan::X509_Certificate ca_cert =
      Botan::X509::create_self_signed_cert(ca_opts,
                                           *ca_key,
                                           "SHA-256",
                                           Test::rng());

   Botan::Private_Key* server_key = new Botan::RSA_PrivateKey(Test::rng(), 1024);

   Botan::X509_Cert_Options server_opts;
   server_opts.common_name = "server.example.com";
   server_opts.country = "US";

   Botan::PKCS10_Request req = Botan::X509::create_cert_req(server_opts,
                                                            *server_key,
                                                            "SHA-256",
                                                            Test::rng());

   Botan::X509_CA ca(ca_cert, *ca_key, "SHA-256");

   auto now = std::chrono::system_clock::now();
   Botan::X509_Time start_time(now);
   typedef std::chrono::duration<int, std::ratio<31556926>> years;
   Botan::X509_Time end_time(now + years(1));

   Botan::X509_Certificate server_cert = ca.sign_request(req,
                                                         Test::rng(),
                                                         start_time,
                                                         end_time);

   return new Credentials_Manager_Test(server_cert, ca_cert, server_key);
   }

std::function<void (const byte[], size_t)> queue_inserter(std::vector<byte>& q)
   {
   return [&](const byte buf[], size_t sz) { q.insert(q.end(), buf, buf + sz); };
   }

void print_alert(Botan::TLS::Alert, const byte[], size_t)
   {
   }

Test::Result test_tls_handshake(Botan::TLS::Protocol_Version offer_version,
                                Botan::Credentials_Manager& creds,
                                Botan::TLS::Policy& policy)
   {
   Botan::RandomNumberGenerator& rng = Test::rng();

   Botan::TLS::Session_Manager_In_Memory server_sessions(rng);
   Botan::TLS::Session_Manager_In_Memory client_sessions(rng);

   Test::Result result(offer_version.to_string());

   result.start_timer();

   for(size_t r = 1; r <= 4; ++r)
      {
      bool handshake_done = false;

      result.test_note("Test round " + std::to_string(r));

      auto handshake_complete = [&](const Botan::TLS::Session& session) -> bool {
         handshake_done = true;

         result.test_note("Session established " + session.version().to_string() + " " +
                          session.ciphersuite().to_string() + " " +
                          Botan::hex_encode(session.session_id()));

         if(session.version() != offer_version)
            {
            result.test_failure("Offered " + offer_version.to_string() +
                                " got " + session.version().to_string());
            }

         if(r <= 2)
            return true;
         return false;
      };

      auto next_protocol_chooser = [&](std::vector<std::string> protos) {
         if(r <= 2)
            {
            result.test_eq("protocol count", protos.size(), 2);
            result.test_eq("protocol[0]", protos[0], "test/1");
            result.test_eq("protocol[1]", protos[1], "test/2");
            }
         return "test/3";
      };

      const std::vector<std::string> protocols_offered = { "test/1", "test/2" };

      try
         {
         std::vector<byte> c2s_traffic, s2c_traffic, client_recv, server_recv, client_sent, server_sent;

         Botan::TLS::Server server(queue_inserter(s2c_traffic),
                                   queue_inserter(server_recv),
                                   print_alert,
                                   handshake_complete,
                                   server_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   next_protocol_chooser,
                                   false);

         Botan::TLS::Client client(queue_inserter(c2s_traffic),
                                   queue_inserter(client_recv),
                                   print_alert,
                                   handshake_complete,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("server.example.com"),
                                   offer_version,
                                   protocols_offered);

         size_t rounds = 0;

         while(true)
            {
            ++rounds;

            if(rounds > 25)
               {
               if(r <= 2)
                  result.test_failure("Still here after many rounds, deadlock?");
               break;
               }

            if(handshake_done && (client.is_closed() || server.is_closed()))
               break;

            if(client.is_active() && client_sent.empty())
               {
               // Choose a len between 1 and 511
               const size_t c_len = 1 + rng.next_byte() + rng.next_byte();
               client_sent = unlock(rng.random_vec(c_len));

               // TODO send in several records
               client.send(client_sent);
               }

            if(server.is_active() && server_sent.empty())
               {
               result.test_eq("server protocol", server.next_protocol(), "test/3");

               const size_t s_len = 1 + rng.next_byte() + rng.next_byte();
               server_sent = unlock(rng.random_vec(s_len));
               server.send(server_sent);
               }

            const bool corrupt_client_data = (r == 3);
            const bool corrupt_server_data = (r == 4);

            if(c2s_traffic.size() > 0)
               {
               /*
               * Use this as a temp value to hold the queues as otherwise they
               * might end up appending more in response to messages during the
               * handshake.
               */
               std::vector<byte> input;
               std::swap(c2s_traffic, input);

               if(corrupt_server_data)
                  {
                  input = Test::mutate_vec(input, true);
                  size_t needed = server.received_data(input.data(), input.size());

                  size_t total_consumed = needed;

                  while(needed > 0 &&
                        result.test_lt("Never requesting more than max protocol len", needed, 18*1024) &&
                        result.test_lt("Total requested is readonable", total_consumed, 128*1024))
                     {
                     input.resize(needed);
                     Test::rng().randomize(input.data(), input.size());
                     needed = server.received_data(input.data(), input.size());
                     total_consumed += needed;
                     }
                  }
               else
                  {
                  size_t needed = server.received_data(input.data(), input.size());
                  result.test_eq("full packet received", needed, 0);
                  }

               continue;
               }

            if(s2c_traffic.size() > 0)
               {
               std::vector<byte> input;
               std::swap(s2c_traffic, input);

               if(corrupt_client_data)
                  {
                  input = Test::mutate_vec(input, true);
                  size_t needed = client.received_data(input.data(), input.size());

                  size_t total_consumed = 0;

                  while(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                     {
                     input.resize(needed);
                     Test::rng().randomize(input.data(), input.size());
                     needed = client.received_data(input.data(), input.size());
                     total_consumed += needed;
                     }
                  }
               else
                  {
                  size_t needed = client.received_data(input.data(), input.size());
                  result.test_eq("full packet received", needed, 0);
                  }

               continue;
               }

            if(client_recv.size())
               {
               result.test_eq("client recv", client_recv, server_sent);
               }

            if(server_recv.size())
               {
               result.test_eq("server recv", server_recv, client_sent);
               }

            if(r > 2)
               {
               if(client_recv.size() && server_recv.size())
                  {
                  result.test_failure("Negotiated in the face of data corruption " + std::to_string(r));
                  }
               }

            if(client.is_closed() && server.is_closed())
               break;

            if(server_recv.size() && client_recv.size())
               {
               Botan::SymmetricKey client_key = client.key_material_export("label", "context", 32);
               Botan::SymmetricKey server_key = server.key_material_export("label", "context", 32);

               result.test_eq("TLS key material export", client_key.bits_of(), server_key.bits_of());

               if(r % 2 == 0)
                  client.close();
               else
                  server.close();
               }
            }
         }
      catch(std::exception& e)
         {
         if(r > 2)
            {
            result.test_note("Corruption caused exception");
            }
         else
            {
            result.test_failure("TLS client", e.what());
            }
         }
      }

   result.end_timer();

   return result;
   }

Test::Result test_dtls_handshake(Botan::TLS::Protocol_Version offer_version,
                                 Botan::Credentials_Manager& creds,
                                 Botan::TLS::Policy& policy)
   {
   BOTAN_ASSERT(offer_version.is_datagram_protocol(), "Test is for datagram version");

   Botan::RandomNumberGenerator& rng = Test::rng();

   Botan::TLS::Session_Manager_In_Memory server_sessions(rng);
   Botan::TLS::Session_Manager_In_Memory client_sessions(rng);

   Test::Result result(offer_version.to_string());

   result.start_timer();

   for(size_t r = 1; r <= 2; ++r)
      {
      bool handshake_done = false;

      auto handshake_complete = [&](const Botan::TLS::Session& session) -> bool {
         handshake_done = true;

         if(session.version() != offer_version)
            {
            result.test_failure("Offered " + offer_version.to_string() +
                                " got " + session.version().to_string());
            }

         return true;
      };

      auto next_protocol_chooser = [&](std::vector<std::string> protos) {
         if(r <= 2)
            {
            result.test_eq("protocol count", protos.size(), 2);
            result.test_eq("protocol[0]", protos[0], "test/1");
            result.test_eq("protocol[1]", protos[1], "test/2");
            }
         return "test/3";
      };

      const std::vector<std::string> protocols_offered = { "test/1", "test/2" };

      try
         {
         std::vector<byte> c2s_traffic, s2c_traffic, client_recv, server_recv, client_sent, server_sent;

         Botan::TLS::Server server(queue_inserter(s2c_traffic),
                                   queue_inserter(server_recv),
                                   print_alert,
                                   handshake_complete,
                                   server_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   next_protocol_chooser,
                                   true);

         Botan::TLS::Client client(queue_inserter(c2s_traffic),
                                   queue_inserter(client_recv),
                                   print_alert,
                                   handshake_complete,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("server.example.com"),
                                   offer_version,
                                   protocols_offered);

         size_t rounds = 0;

         while(true)
            {
            // TODO: client and server should be in different threads
            std::this_thread::sleep_for(std::chrono::milliseconds(rng.next_byte() % 2));
            ++rounds;

            if(rounds > 100)
               {
               result.test_failure("Still here after many rounds");
               break;
               }

            if(handshake_done && (client.is_closed() || server.is_closed()))
               break;

            if(client.is_active() && client_sent.empty())
               {
               // Choose a len between 1 and 511 and send random chunks:
               const size_t c_len = 1 + rng.next_byte() + rng.next_byte();
               client_sent = unlock(rng.random_vec(c_len));

               // TODO send multiple parts
               client.send(client_sent);
               }

            if(server.is_active() && server_sent.empty())
               {
               result.test_eq("server ALPN", server.next_protocol(), "test/3");

               const size_t s_len = 1 + rng.next_byte() + rng.next_byte();
               server_sent = unlock(rng.random_vec(s_len));
               server.send(server_sent);
               }

            const bool corrupt_client_data = (r == 3 && rng.next_byte() % 3 <= 1 && rounds < 10);
            const bool corrupt_server_data = (r == 4 && rng.next_byte() % 3 <= 1 && rounds < 10);

            if(c2s_traffic.size() > 0)
               {
               /*
               * Use this as a temp value to hold the queues as otherwise they
               * might end up appending more in response to messages during the
               * handshake.
               */
               std::vector<byte> input;
               std::swap(c2s_traffic, input);

               if(corrupt_server_data)
                  {
                  try
                     {
                     input = Test::mutate_vec(input, true);
                     size_t needed = server.received_data(input.data(), input.size());

                     if(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                        {
                        input.resize(needed);
                        Test::rng().randomize(input.data(), input.size());
                        client.received_data(input.data(), input.size());
                        }
                     }
                  catch(std::exception&)
                     {
                     result.test_note("corruption caused server exception");
                     }
                  }
               else
                  {
                  try
                     {
                     size_t needed = server.received_data(input.data(), input.size());
                     result.test_eq("full packet received", needed, 0);
                     }
                  catch(std::exception& e)
                     {
                     result.test_failure("server error", e.what());
                     }
                  }

               continue;
               }

            if(s2c_traffic.size() > 0)
               {
               std::vector<byte> input;
               std::swap(s2c_traffic, input);

               if(corrupt_client_data)
                  {
                  try
                     {
                     input = Test::mutate_vec(input, true);
                     size_t needed = client.received_data(input.data(), input.size());

                     if(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                        {
                        input.resize(needed);
                        Test::rng().randomize(input.data(), input.size());
                        client.received_data(input.data(), input.size());
                        }
                     }
                  catch(std::exception&)
                     {
                     result.test_note("corruption caused client exception");
                     }
                  }
               else
                  {
                  try
                     {
                     size_t needed = client.received_data(input.data(), input.size());
                     result.test_eq("full packet received", needed, 0);
                     }
                  catch(std::exception& e)
                     {
                     result.test_failure("client error", e.what());
                     }
                  }

               continue;
               }

            // If we corrupted a DTLS application message, resend it:
            if(client.is_active() && corrupt_client_data && server_recv.empty())
               client.send(client_sent);
            if(server.is_active() && corrupt_server_data && client_recv.empty())
               server.send(server_sent);

            if(client_recv.size())
               {
               result.test_eq("client recv", client_recv, server_sent);
               }

            if(server_recv.size())
               {
               result.test_eq("server recv", server_recv, client_sent);
               }

            if(client.is_closed() && server.is_closed())
               break;

            if(server_recv.size() && client_recv.size())
               {
               Botan::SymmetricKey client_key = client.key_material_export("label", "context", 32);
               Botan::SymmetricKey server_key = server.key_material_export("label", "context", 32);

               result.test_eq("key material export", client_key.bits_of(), server_key.bits_of());

               if(r % 2 == 0)
                  client.close();
               else
                  server.close();
               }
            }
         }
      catch(std::exception& e)
         {
         if(r > 2)
            {
            result.test_note("Corruption caused failure");
            }
         else
            {
            result.test_failure("DTLS handshake", e.what());
            }
         }
      }

   result.end_timer();
   return result;
   }

class Test_Policy : public Botan::TLS::Text_Policy
   {
   public:
      Test_Policy() : Text_Policy("") {}
      bool acceptable_protocol_version(Botan::TLS::Protocol_Version) const override { return true; }
      bool send_fallback_scsv(Botan::TLS::Protocol_Version) const override { return false; }

      size_t dtls_initial_timeout() const override { return 1; }
      size_t dtls_maximum_timeout() const override { return 8; }
   };


class TLS_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::unique_ptr<Botan::Credentials_Manager> basic_creds(create_creds());
         std::vector<Test::Result> results;

         Test_Policy policy;
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V10, *basic_creds, policy));

         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V11, *basic_creds, policy));
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V10, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));

         policy.set("key_exchange_methods", "RSA");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V10, *basic_creds, policy));
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V11, *basic_creds, policy));
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V10, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));

         policy.set("key_exchange_methods", "DH");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V10, *basic_creds, policy));
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V11, *basic_creds, policy));

         policy.set("key_exchange_methods", "ECDH");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V10, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));

         policy.set("ciphers", "AES-128");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V10, *basic_creds, policy));
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V11, *basic_creds, policy));
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V10, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));

#if defined(BOTAN_HAS_AEAD_OCB)
         policy.set("ciphers", "AES-128/OCB(12)");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));
#endif

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
         policy.set("ciphers", "ChaCha20Poly1305");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));
#endif

         policy.set("ciphers", "AES-128/GCM");
         policy.set("key_exchange_methods", "PSK");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));

         // For whatever reason no (EC)DHE_PSK GCM ciphersuites are defined
         policy.set("ciphers", "AES-128");
         policy.set("key_exchange_methods", "ECDHE_PSK");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));

         policy.set("key_exchange_methods", "DHE_PSK");
         results.push_back(test_tls_handshake(Botan::TLS::Protocol_Version::TLS_V12, *basic_creds, policy));
         results.push_back(test_dtls_handshake(Botan::TLS::Protocol_Version::DTLS_V12, *basic_creds, policy));

         return results;
         }

   };

BOTAN_REGISTER_TEST("tls", TLS_Unit_Tests);

#endif

}

}

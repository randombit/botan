/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

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

#include <iostream>
#include <vector>
#include <memory>
#include <thread>

using namespace Botan;

namespace {

class Credentials_Manager_Test : public Botan::Credentials_Manager
   {
   public:
      Credentials_Manager_Test(const X509_Certificate& server_cert,
                               const X509_Certificate& ca_cert,
                               Private_Key* server_key) :
         m_server_cert(server_cert),
         m_ca_cert(ca_cert),
         m_key(server_key)
         {
         std::unique_ptr<Certificate_Store> store(new Certificate_Store_In_Memory(m_ca_cert));
         m_stores.push_back(std::move(store));
         }

      std::vector<Certificate_Store*>
      trusted_certificate_authorities(const std::string&,
                                      const std::string&) override
         {
         std::vector<Certificate_Store*> v;
         for(auto&& store : m_stores)
            v.push_back(store.get());
         return v;
         }

      std::vector<X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string&) override
         {
         std::vector<X509_Certificate> chain;

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
         try
            {
            Credentials_Manager::verify_certificate_chain(type,
                                                          purported_hostname,
                                                          cert_chain);
            }
         catch(std::exception& e)
            {
            std::cout << "Certificate verification failed - " << e.what() << " - but will ignore" << std::endl;
            }
         }

      Private_Key* private_key_for(const X509_Certificate&,
                                   const std::string&,
                                   const std::string&) override
         {
         return m_key.get();
         }

      SymmetricKey psk(const std::string& type,
                       const std::string& context,
                       const std::string&) override
         {
         if(type == "tls-server" && context == "session-ticket")
            return SymmetricKey("AABBCCDDEEFF012345678012345678");
         throw Exception("No PSK set for " + context);
         }

   public:
      X509_Certificate m_server_cert, m_ca_cert;
      std::unique_ptr<Private_Key> m_key;
      std::vector<std::unique_ptr<Certificate_Store>> m_stores;
   };

Credentials_Manager* create_creds()
   {
   AutoSeeded_RNG rng;
   std::unique_ptr<Private_Key> ca_key(new RSA_PrivateKey(rng, 1024));

   X509_Cert_Options ca_opts;
   ca_opts.common_name = "Test CA";
   ca_opts.country = "US";
   ca_opts.CA_key(1);

   X509_Certificate ca_cert =
      X509::create_self_signed_cert(ca_opts,
                                    *ca_key,
                                    "SHA-256",
                                    rng);

   Private_Key* server_key = new RSA_PrivateKey(rng, 1024);

   X509_Cert_Options server_opts;
   server_opts.common_name = "server.example.com";
   server_opts.country = "US";

   PKCS10_Request req = X509::create_cert_req(server_opts,
                                              *server_key,
                                              "SHA-256",
                                              rng);

   X509_CA ca(ca_cert, *ca_key, "SHA-256");

   auto now = std::chrono::system_clock::now();
   X509_Time start_time(now);
   typedef std::chrono::duration<int, std::ratio<31556926>> years;
   X509_Time end_time(now + years(1));

   X509_Certificate server_cert = ca.sign_request(req,
                                                  rng,
                                                  start_time,
                                                  end_time);

   return new Credentials_Manager_Test(server_cert, ca_cert, server_key);
   }

std::function<void (const byte[], size_t)> queue_inserter(std::vector<byte>& q)
   {
   return [&](const byte buf[], size_t sz) { q.insert(q.end(), buf, buf + sz); };
   }

void print_alert(TLS::Alert alert, const byte[], size_t)
   {
   //std::cout << "Alert " << alert.type_string() << std::endl;
   };

void mutate(std::vector<byte>& v, RandomNumberGenerator& rng)
   {
   if(v.empty())
      return;

   size_t voff = rng.get_random<size_t>() % v.size();
   v[voff] ^= rng.next_nonzero_byte();
 }

size_t test_tls_handshake(RandomNumberGenerator& rng,
                          TLS::Protocol_Version offer_version,
                          Credentials_Manager& creds,
                          TLS::Policy& policy)
   {
   TLS::Session_Manager_In_Memory server_sessions(rng);
   TLS::Session_Manager_In_Memory client_sessions(rng);

   for(size_t r = 1; r <= 4; ++r)
      {
      //std::cout << offer_version.to_string() << " r " << r << "\n";

      bool handshake_done = false;

      auto handshake_complete = [&](const TLS::Session& session) -> bool {
         handshake_done = true;

         /*
         std::cout << "Session established " << session.version().to_string() << " "
                   << session.ciphersuite().to_string() << " " << hex_encode(session.session_id()) << "\n";
         */

         if(session.version() != offer_version)
            std::cout << "Offered " << offer_version.to_string()
                      << " got " << session.version().to_string() << std::endl;
         return true;
         };

      auto next_protocol_chooser = [&](std::vector<std::string> protos) {
         if(protos.size() != 2)
            std::cout << "Bad protocol size" << std::endl;
         if(protos[0] != "test/1" || protos[1] != "test/2")
            std::cout << "Bad protocol values" << std::endl;
         return "test/3";
      };

      const std::vector<std::string> protocols_offered = { "test/1", "test/2" };

      try
         {
         std::vector<byte> c2s_traffic, s2c_traffic, client_recv, server_recv, client_sent, server_sent;

         TLS::Server server(queue_inserter(s2c_traffic),
                            queue_inserter(server_recv),
                            print_alert,
                            handshake_complete,
                            server_sessions,
                            creds,
                            policy,
                            rng,
                            next_protocol_chooser,
                            false);

         TLS::Client client(queue_inserter(c2s_traffic),
                            queue_inserter(client_recv),
                            print_alert,
                            handshake_complete,
                            client_sessions,
                            creds,
                            policy,
                            rng,
                            TLS::Server_Information("server.example.com"),
                            offer_version,
                            protocols_offered);

         size_t rounds = 0;

         while(true)
            {
            ++rounds;

            if(rounds > 25)
               {
               std::cout << "Still here, something went wrong\n";
               return 1;
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
               if(server.next_protocol() != "test/3")
                  std::cout << "Wrong protocol " << server.next_protocol() << std::endl;

               const size_t s_len = 1 + rng.next_byte() + rng.next_byte();
               server_sent = unlock(rng.random_vec(s_len));
               server.send(server_sent);
               }

            const bool corrupt_client_data = (r == 3 && c2s_traffic.size() && rng.next_byte() % 3 == 0 && rounds > 1);
            const bool corrupt_server_data = (r == 4 && s2c_traffic.size() && rng.next_byte() % 3 == 0 && rounds > 1);

            try
               {
               /*
               * Use this as a temp value to hold the queues as otherwise they
               * might end up appending more in response to messages during the
               * handshake.
               */
               //std::cout << "server recv " << c2s_traffic.size() << " bytes\n";
               std::vector<byte> input;
               std::swap(c2s_traffic, input);

               if(corrupt_server_data)
                  {
                  //std::cout << "Corrupting server data\n";
                  mutate(input, rng);
                  }
               server.received_data(input.data(), input.size());
               }
            catch(std::exception& e)
               {
               std::cout << "Server error - " << e.what() << std::endl;
               continue;
               }

            try
               {
               //std::cout << "client recv " << s2c_traffic.size() << " bytes\n";
               std::vector<byte> input;
               std::swap(s2c_traffic, input);
               if(corrupt_client_data)
                  {
                  //std::cout << "Corrupting client data\n";
                  mutate(input, rng);
                  }

               client.received_data(input.data(), input.size());
               }
            catch(std::exception& e)
               {
               std::cout << "Client error - " << e.what() << std::endl;
               continue;
               }

            if(client_recv.size())
               {
               if(client_recv != server_sent)
                  {
                  std::cout << "Error in client recv" << std::endl;
                  return 1;
                  }
               }

            if(server_recv.size())
               {
               if(server_recv != client_sent)
                  {
                  std::cout << "Error in server recv" << std::endl;
                  return 1;
                  }
               }

            if(client.is_closed() && server.is_closed())
               break;

            if(server_recv.size() && client_recv.size())
               {
               SymmetricKey client_key = client.key_material_export("label", "context", 32);
               SymmetricKey server_key = server.key_material_export("label", "context", 32);

               if(client_key != server_key)
                  {
                  std::cout << "TLS key material export mismatch: "
                            << client_key.as_string() << " != "
                            << server_key.as_string() << "\n";
                  return 1;
                  }

               if(r % 2 == 0)
                  client.close();
               else
                  server.close();
               }
            }
         }
      catch(std::exception& e)
         {
         std::cout << e.what() << "\n";
         return 1;
         }
      }

   return 0;
   }

size_t test_dtls_handshake(RandomNumberGenerator& rng,
                            TLS::Protocol_Version offer_version,
                            Credentials_Manager& creds,
                            TLS::Policy& policy)
   {
   BOTAN_ASSERT(offer_version.is_datagram_protocol(), "Test is for datagram version");

   TLS::Session_Manager_In_Memory server_sessions(rng);
   TLS::Session_Manager_In_Memory client_sessions(rng);

   for(size_t r = 1; r <= 2; ++r)
      {
      //std::cout << offer_version.to_string() << " round " << r << "\n";

      bool handshake_done = false;

      auto handshake_complete = [&](const TLS::Session& session) -> bool {
         handshake_done = true;

         /*
         std::cout << "Session established " << session.version().to_string() << " "
                   << session.ciphersuite().to_string() << " " << hex_encode(session.session_id()) << "\n";
         */

         if(session.version() != offer_version)
            std::cout << "Offered " << offer_version.to_string()
                      << " got " << session.version().to_string() << std::endl;
         return true;
         };

      auto next_protocol_chooser = [&](std::vector<std::string> protos) {
         if(protos.size() != 2)
            std::cout << "Bad protocol size" << std::endl;
         if(protos[0] != "test/1" || protos[1] != "test/2")
            std::cout << "Bad protocol values" << std::endl;
         return "test/3";
      };

      const std::vector<std::string> protocols_offered = { "test/1", "test/2" };

      try
         {
         std::vector<byte> c2s_traffic, s2c_traffic, client_recv, server_recv, client_sent, server_sent;

         TLS::Server server(queue_inserter(s2c_traffic),
                            queue_inserter(server_recv),
                            print_alert,
                            handshake_complete,
                            server_sessions,
                            creds,
                            policy,
                            rng,
                            next_protocol_chooser,
                            true);

         TLS::Client client(queue_inserter(c2s_traffic),
                            queue_inserter(client_recv),
                            print_alert,
                            handshake_complete,
                            client_sessions,
                            creds,
                            policy,
                            rng,
                            TLS::Server_Information("server.example.com"),
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
               std::cout << "Still here, something went wrong\n";
               return 1;
               }

            if(handshake_done && (client.is_closed() || server.is_closed()))
               break;

            if(client.is_active() && client_sent.empty())
               {
               // Choose a len between 1 and 511 and send random chunks:
               const size_t c_len = 1 + rng.next_byte() + rng.next_byte();
               client_sent = unlock(rng.random_vec(c_len));

               // TODO send multiple parts
               //std::cout << "Sending " << client_sent.size() << " bytes to server\n";
               client.send(client_sent);
               }

            if(server.is_active() && server_sent.empty())
               {
               if(server.next_protocol() != "test/3")
                  std::cout << "Wrong protocol " << server.next_protocol() << std::endl;

               const size_t s_len = 1 + rng.next_byte() + rng.next_byte();
               server_sent = unlock(rng.random_vec(s_len));
               //std::cout << "Sending " << server_sent.size() << " bytes to client\n";
               server.send(server_sent);
               }

            const bool corrupt_client_data = (r == 3 && c2s_traffic.size() && rng.next_byte() % 3 == 0 && rounds < 10);
            const bool corrupt_server_data = (r == 4 && s2c_traffic.size() && rng.next_byte() % 3 == 0 && rounds < 10);

            try
               {
               /*
               * Use this as a temp value to hold the queues as otherwise they
               * might end up appending more in response to messages during the
               * handshake.
               */
               //std::cout << "server got " << c2s_traffic.size() << " bytes\n";
               std::vector<byte> input;
               std::swap(c2s_traffic, input);

               if(corrupt_client_data)
                  {
                  //std::cout << "Corrupting client data\n";
                  mutate(input, rng);
                  }

               server.received_data(input.data(), input.size());
               }
            catch(std::exception& e)
               {
               std::cout << "Server error - " << e.what() << std::endl;
               continue;
               }

            try
               {
               //std::cout << "client got " << s2c_traffic.size() << " bytes\n";
               std::vector<byte> input;
               std::swap(s2c_traffic, input);

               if(corrupt_server_data)
                  {
                  //std::cout << "Corrupting server data\n";
                  mutate(input, rng);
                  }
               client.received_data(input.data(), input.size());
               }
            catch(std::exception& e)
               {
               std::cout << "Client error - " << e.what() << std::endl;
               continue;
               }

            // If we corrupted a DTLS application message, resend it:
            if(client.is_active() && corrupt_client_data && server_recv.empty())
               client.send(client_sent);
            if(server.is_active() && corrupt_server_data && client_recv.empty())
               server.send(server_sent);

            if(client_recv.size())
               {
               if(client_recv != server_sent)
                  {
                  std::cout << "Error in client recv" << std::endl;
                  return 1;
                  }
               }

            if(server_recv.size())
               {
               if(server_recv != client_sent)
                  {
                  std::cout << "Error in server recv" << std::endl;
                  return 1;
                  }
               }

            if(client.is_closed() && server.is_closed())
               break;

            if(server_recv.size() && client_recv.size())
               {
               SymmetricKey client_key = client.key_material_export("label", "context", 32);
               SymmetricKey server_key = server.key_material_export("label", "context", 32);

               if(client_key != server_key)
                  {
                  std::cout << "TLS key material export mismatch: "
                            << client_key.as_string() << " != "
                            << server_key.as_string() << "\n";
                  return 1;
                  }

               if(r % 2 == 0)
                  client.close();
               else
                  server.close();
               }
            }
         }
      catch(std::exception& e)
         {
         std::cout << e.what() << "\n";
         return 1;
         }
      }

   return 0;
   }

class Test_Policy : public TLS::Text_Policy
   {
   public:
      Test_Policy() : Text_Policy("") {}
      bool acceptable_protocol_version(TLS::Protocol_Version) const override { return true; }
      bool send_fallback_scsv(TLS::Protocol_Version) const override { return false; }

      size_t dtls_initial_timeout() const override { return 1; }
      size_t dtls_maximum_timeout() const override { return 8; }
   };

}

size_t test_tls()
   {
   size_t errors = 0;

   auto& rng = test_rng();
   std::unique_ptr<Credentials_Manager> basic_creds(create_creds());

   Test_Policy policy;
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V10, *basic_creds, policy);
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V11, *basic_creds, policy);
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V12, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V10, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V12, *basic_creds, policy);

   policy.set("key_exchange_methods", "RSA");
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V10, *basic_creds, policy);
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V11, *basic_creds, policy);
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V12, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V10, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V12, *basic_creds, policy);

   policy.set("key_exchange_methods", "DH");
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V10, *basic_creds, policy);
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V11, *basic_creds, policy);
   policy.set("key_exchange_methods", "ECDH");
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V12, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V10, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V12, *basic_creds, policy);

   policy.set("ciphers", "AES-128");
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V10, *basic_creds, policy);
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V11, *basic_creds, policy);
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V12, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V10, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V12, *basic_creds, policy);

   policy.set("ciphers", "ChaCha20Poly1305");
   errors += test_tls_handshake(rng, TLS::Protocol_Version::TLS_V12, *basic_creds, policy);
   errors += test_dtls_handshake(rng, TLS::Protocol_Version::DTLS_V12, *basic_creds, policy);

   test_report("TLS", 22, errors);

   return errors;
   }

#else
size_t test_tls() { return 0; }
#endif

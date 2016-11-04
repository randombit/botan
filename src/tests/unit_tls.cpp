/*
* (C) 2014,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <vector>
#include <memory>
#include <thread>

#if defined(BOTAN_HAS_TLS)

#include <botan/tls_client.h>
#include <botan/tls_server.h>

#include <botan/ec_group.h>
#include <botan/hex.h>
#include <botan/pkcs10.h>
#include <botan/rsa.h>
#include <botan/ecdsa.h>
#include <botan/tls_handshake_msg.h>
#include <botan/x509_ca.h>
#include <botan/x509self.h>

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
  #include <botan/tls_session_manager_sqlite.h>
#endif

#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)
class Credentials_Manager_Test : public Botan::Credentials_Manager
   {
   public:
      Credentials_Manager_Test(const Botan::X509_Certificate& rsa_cert,
                               const Botan::X509_Certificate& rsa_ca,
                               const Botan::X509_Certificate& ecdsa_cert,
                               const Botan::X509_Certificate& ecdsa_ca,
                               Botan::Private_Key* rsa_key,
                               Botan::Private_Key* ecdsa_key) :
         m_rsa_cert(rsa_cert),
         m_rsa_ca(rsa_ca),
         m_ecdsa_cert(ecdsa_cert),
         m_ecdsa_ca(ecdsa_ca),
         m_rsa_key(rsa_key),
         m_ecdsa_key(ecdsa_key)
         {
         std::unique_ptr<Botan::Certificate_Store_In_Memory> store(new Botan::Certificate_Store_In_Memory);
         store->add_certificate(m_rsa_ca);
         store->add_certificate(m_ecdsa_ca);
         m_stores.push_back(std::move(store));
         m_provides_client_certs = false;
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

         if(type == "tls-server" || (type == "tls-client" && m_provides_client_certs))
            {
            for(auto&& key_type : cert_key_types)
               {
               if(key_type == "RSA")
                  {
                  chain.push_back(m_rsa_cert);
                  chain.push_back(m_rsa_ca);
                  break;
                  }
               else if(key_type == "ECDSA")
                  {
                  chain.push_back(m_ecdsa_cert);
                  chain.push_back(m_ecdsa_ca);
                  break;
                  }
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

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& crt,
                                          const std::string&,
                                          const std::string&) override
         {
         if(crt == m_rsa_cert)
            return m_rsa_key.get();
         if(crt == m_ecdsa_cert)
            return m_ecdsa_key.get();
         return nullptr;
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
      Botan::X509_Certificate m_rsa_cert, m_rsa_ca, m_ecdsa_cert, m_ecdsa_ca;
      std::unique_ptr<Botan::Private_Key> m_rsa_key, m_ecdsa_key;
      std::vector<std::unique_ptr<Botan::Certificate_Store>> m_stores;
      bool m_provides_client_certs;
   };

Botan::Credentials_Manager*
create_creds(Botan::RandomNumberGenerator& rng,
             bool with_client_certs = false)
   {
   const Botan::EC_Group ecdsa_params("secp256r1");
   const size_t rsa_params = 1024;

   std::unique_ptr<Botan::Private_Key> rsa_ca_key(new Botan::RSA_PrivateKey(rng, rsa_params));
   std::unique_ptr<Botan::Private_Key> rsa_srv_key(new Botan::RSA_PrivateKey(rng, rsa_params));

   std::unique_ptr<Botan::Private_Key> ecdsa_ca_key(new Botan::ECDSA_PrivateKey(rng, ecdsa_params));
   std::unique_ptr<Botan::Private_Key> ecdsa_srv_key(new Botan::ECDSA_PrivateKey(rng, ecdsa_params));

   Botan::X509_Cert_Options ca_opts("Test CA/VT");
   ca_opts.CA_key(1);

   const Botan::X509_Certificate rsa_ca_cert =
      Botan::X509::create_self_signed_cert(ca_opts, *rsa_ca_key, "SHA-256", rng);
   const Botan::X509_Certificate ecdsa_ca_cert =
      Botan::X509::create_self_signed_cert(ca_opts, *ecdsa_ca_key, "SHA-256", rng);

   const Botan::X509_Cert_Options server_opts("server.example.com");

   const Botan::PKCS10_Request rsa_req =
      Botan::X509::create_cert_req(server_opts, *rsa_srv_key, "SHA-256", rng);
   const Botan::PKCS10_Request ecdsa_req =
      Botan::X509::create_cert_req(server_opts, *ecdsa_srv_key, "SHA-256", rng);

   Botan::X509_CA rsa_ca(rsa_ca_cert, *rsa_ca_key, "SHA-256", rng);
   Botan::X509_CA ecdsa_ca(ecdsa_ca_cert, *ecdsa_ca_key, "SHA-256", rng);

   typedef std::chrono::duration<int, std::ratio<31556926>> years;
   auto now = std::chrono::system_clock::now();

   const Botan::X509_Time start_time(now);
   const Botan::X509_Time end_time(now + years(1));

   const Botan::X509_Certificate rsa_srv_cert =
      rsa_ca.sign_request(rsa_req, rng, start_time, end_time);
   const Botan::X509_Certificate ecdsa_srv_cert =
      ecdsa_ca.sign_request(ecdsa_req, rng, start_time, end_time);

   Credentials_Manager_Test* cmt = new Credentials_Manager_Test(
      rsa_srv_cert, rsa_ca_cert,
      ecdsa_srv_cert, ecdsa_ca_cert,
      rsa_srv_key.release(), ecdsa_srv_key.release());

   cmt->m_provides_client_certs = with_client_certs;
   return cmt;
   }

std::function<void (const byte[], size_t)> queue_inserter(std::vector<byte>& q)
   {
   return [&](const byte buf[], size_t sz) { q.insert(q.end(), buf, buf + sz); };
   }

void print_alert(Botan::TLS::Alert)
   {
   }

void alert_cb_with_data(Botan::TLS::Alert, const byte[], size_t)
   {
   }

Test::Result test_tls_handshake(Botan::TLS::Protocol_Version offer_version,
                                Botan::Credentials_Manager& creds,
                                const Botan::TLS::Policy& client_policy,
                                const Botan::TLS::Policy& server_policy,
                                Botan::RandomNumberGenerator& rng,
                                Botan::TLS::Session_Manager& client_sessions,
                                Botan::TLS::Session_Manager& server_sessions)
   {
   Test::Result result(offer_version.to_string());

   result.start_timer();

   for(size_t r = 1; r <= 4; ++r)
      {
      bool handshake_done = false;

      result.test_note("Test round " + std::to_string(r));

      auto handshake_complete = [&](const Botan::TLS::Session& session) -> bool {
         handshake_done = true;

         const std::string session_report =
            "Session established " + session.version().to_string() + " " +
            session.ciphersuite().to_string() + " " +
            Botan::hex_encode(session.session_id());

         result.test_note(session_report);

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

         std::unique_ptr<Botan::TLS::Callbacks> server_cb(new Botan::TLS::Compat_Callbacks(
                 queue_inserter(s2c_traffic),
                 queue_inserter(server_recv),
                 std::function<void (Botan::TLS::Alert, const byte[], size_t)>(alert_cb_with_data),
                 handshake_complete,
                 nullptr,
                 next_protocol_chooser));

         // TLS::Server object constructed by new constructor using virtual callback interface.
         std::unique_ptr<Botan::TLS::Server> server(
            new Botan::TLS::Server(*server_cb,
                                   server_sessions,
                                   creds,
                                   server_policy,
                                   rng,
                                   false));

         std::unique_ptr<Botan::TLS::Callbacks> client_cb(new Botan::TLS::Compat_Callbacks(
                 queue_inserter(c2s_traffic),
                 queue_inserter(client_recv),
                 std::function<void (Botan::TLS::Alert, const byte[], size_t)>(alert_cb_with_data),
                 handshake_complete));

         // TLS::Client object constructed by new constructor using virtual callback interface.
         std::unique_ptr<Botan::TLS::Client> client(
            new Botan::TLS::Client(*client_cb,
                                   client_sessions,
                                   creds,
                                   client_policy,
                                   rng,
                                   Botan::TLS::Server_Information("server.example.com"),
                                   offer_version,
                                   protocols_offered));

         size_t rounds = 0;

         // Test TLS using both new and legacy constructors.
         for(size_t ctor_sel = 0; ctor_sel < 2; ctor_sel++)
            {
            if(ctor_sel == 1)
               {
               c2s_traffic.clear();
               s2c_traffic.clear();
               server_recv.clear();
               client_recv.clear();
               client_sent.clear();
               server_sent.clear();

               // TLS::Server object constructed by legacy constructor.
               server.reset( 
                  new Botan::TLS::Server(queue_inserter(s2c_traffic),
                                         queue_inserter(server_recv),
                                         alert_cb_with_data, 
                                         handshake_complete,
                                         server_sessions,
                                         creds,
                                         server_policy,
                                         rng,
                                         next_protocol_chooser,
                                         false));

               // TLS::Client object constructed by legacy constructor.
               client.reset( 
                  new Botan::TLS::Client(queue_inserter(c2s_traffic),
                                         queue_inserter(client_recv),
                                         alert_cb_with_data,
                                         handshake_complete,
                                         client_sessions,
                                         creds,
                                         server_policy,
                                         rng,
                                         Botan::TLS::Server_Information("server.example.com"),
                                         offer_version,
                                         protocols_offered));
               }

            while(true)
               {
               ++rounds;

               if(rounds > 25)
                  {
                  if(r <= 2)
                     {
                     result.test_failure("Still here after many rounds, deadlock?");
                     }
                  break;
                  }

               if(handshake_done && (client->is_closed() || server->is_closed()))
                  break;

               if(client->is_active() && client_sent.empty())
                  {
                  // Choose random application data to send
                  const size_t c_len = 1 + ((static_cast<size_t>(rng.next_byte()) << 4) ^ rng.next_byte());
                  client_sent = unlock(rng.random_vec(c_len));

                  size_t sent_so_far = 0;
                  while(sent_so_far != client_sent.size())
                     {
                     const size_t left = client_sent.size() - sent_so_far;
                     const size_t rnd12 = (rng.next_byte() << 4) ^ rng.next_byte();
                     const size_t sending = std::min(left, rnd12);

                     client->send(&client_sent[sent_so_far], sending);
                     sent_so_far += sending;
                     }
                  client->send_warning_alert(Botan::TLS::Alert::NO_RENEGOTIATION);
                  }

               if(server->is_active() && server_sent.empty())
                  {
                  result.test_eq("server->protocol", server->next_protocol(), "test/3");

                  const size_t s_len = 1 + ((static_cast<size_t>(rng.next_byte()) << 4) ^ rng.next_byte());
                  server_sent = unlock(rng.random_vec(s_len));

                  size_t sent_so_far = 0;
                  while(sent_so_far != server_sent.size())
                     {
                     const size_t left = server_sent.size() - sent_so_far;
                     const size_t rnd12 = (rng.next_byte() << 4) ^ rng.next_byte();
                     const size_t sending = std::min(left, rnd12);

                     server->send(&server_sent[sent_so_far], sending);
                     sent_so_far += sending;
                     }

                  server->send_warning_alert(Botan::TLS::Alert::NO_RENEGOTIATION);
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
                     size_t needed = server->received_data(input.data(), input.size());

                     size_t total_consumed = needed;

                     while(needed > 0 &&
                           result.test_lt("Never requesting more than max protocol len", needed, 18*1024) &&
                           result.test_lt("Total requested is readonable", total_consumed, 128*1024))
                        {
                        input.resize(needed);
                        rng.randomize(input.data(), input.size());
                        needed = server->received_data(input.data(), input.size());
                        total_consumed += needed;
                        }
                     }
                  else
                     {
                     size_t needed = server->received_data(input.data(), input.size());
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
                     size_t needed = client->received_data(input.data(), input.size());

                     size_t total_consumed = 0;

                     while(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                        {
                        input.resize(needed);
                        rng.randomize(input.data(), input.size());
                        needed = client->received_data(input.data(), input.size());
                        total_consumed += needed;
                        }
                     }
                  else
                     {
                     size_t needed = client->received_data(input.data(), input.size());
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
                  result.test_eq("server->recv", server_recv, client_sent);
                  }

               if(r > 2)
                  {
                  if(client_recv.size() && server_recv.size())
                     {
                     result.test_failure("Negotiated in the face of data corruption " + std::to_string(r));
                     }
                  }

               if(client->is_closed() && server->is_closed())
                  break;

               if(server_recv.size() && client_recv.size())
                  {
                  Botan::SymmetricKey client_key = client->key_material_export("label", "context", 32);
                  Botan::SymmetricKey server_key = server->key_material_export("label", "context", 32);

                  result.test_eq("TLS key material export", client_key.bits_of(), server_key.bits_of());

                  if(r % 2 == 0)
                     client->close();
                  else
                     server->close();
                  }
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

Test::Result test_tls_handshake(Botan::TLS::Protocol_Version offer_version,
                                Botan::Credentials_Manager& creds,
                                const Botan::TLS::Policy& policy,
                                Botan::RandomNumberGenerator& rng,
                                Botan::TLS::Session_Manager& client_sessions,
                                Botan::TLS::Session_Manager& server_sessions)
   {
   return test_tls_handshake(offer_version, creds, policy, policy, rng,
                             client_sessions, server_sessions);
   }

Test::Result test_dtls_handshake(Botan::TLS::Protocol_Version offer_version,
                                 Botan::Credentials_Manager& creds,
                                 const Botan::TLS::Policy& client_policy,
                                 const Botan::TLS::Policy& server_policy,
                                 Botan::RandomNumberGenerator& rng,
                                 Botan::TLS::Session_Manager& client_sessions,
                                 Botan::TLS::Session_Manager& server_sessions)
   {
   BOTAN_ASSERT(offer_version.is_datagram_protocol(), "Test is for datagram version");

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

         std::unique_ptr<Botan::TLS::Callbacks> server_cb(new Botan::TLS::Compat_Callbacks(
                 queue_inserter(s2c_traffic),
                 queue_inserter(server_recv),
                 std::function<void (Botan::TLS::Alert)>(print_alert),
                 handshake_complete,
                 nullptr,
                 next_protocol_chooser));

         std::unique_ptr<Botan::TLS::Callbacks> client_cb(new Botan::TLS::Compat_Callbacks(
                 queue_inserter(c2s_traffic),
                 queue_inserter(client_recv),
                 std::function<void (Botan::TLS::Alert)>(print_alert),
                 handshake_complete));

         // TLS::Server object constructed by new constructor using virtual callback interface.
         std::unique_ptr<Botan::TLS::Server> server(
            new Botan::TLS::Server(*server_cb,
                                   server_sessions,
                                   creds,
                                   server_policy,
                                   rng,
                                   true));

         // TLS::Client object constructed by new constructor using virtual callback interface.
         std::unique_ptr<Botan::TLS::Client> client(
            new Botan::TLS::Client(*client_cb,
                                   client_sessions,
                                   creds,
                                   client_policy,
                                   rng,
                                   Botan::TLS::Server_Information("server.example.com"),
                                   offer_version,
                                   protocols_offered));

         size_t rounds = 0;

         // Test DTLS using both new and legacy constructors.
         for(size_t ctor_sel = 0; ctor_sel < 2; ctor_sel++)
            {
            if(ctor_sel == 1)
               {
               c2s_traffic.clear();
               s2c_traffic.clear();
               server_recv.clear();
               client_recv.clear();
               client_sent.clear();
               server_sent.clear();
               // TLS::Server object constructed by legacy constructor.
               server.reset(
                  new Botan::TLS::Server(queue_inserter(s2c_traffic),
                                         queue_inserter(server_recv),
                                         alert_cb_with_data, 
                                         handshake_complete,
                                         server_sessions,
                                         creds,
                                         server_policy,
                                         rng,
                                         next_protocol_chooser,
                                         true));

               // TLS::Client object constructed by legacy constructor.
               client.reset(
                  new Botan::TLS::Client(queue_inserter(c2s_traffic),
                                         queue_inserter(client_recv),
                                         alert_cb_with_data, 
                                         handshake_complete,
                                         client_sessions,
                                         creds,
                                         client_policy,
                                         rng,
                                         Botan::TLS::Server_Information("server.example.com"),
                                         offer_version,
                                         protocols_offered));
               }

            while(true)
               {
               // TODO: client and server should be in different threads
               std::this_thread::sleep_for(std::chrono::microseconds(rng.next_byte() % 128));
               ++rounds;

               if(rounds > 100)
                  {
                  result.test_failure("Still here after many rounds");
                  break;
                  }

               if(handshake_done && (client->is_closed() || server->is_closed()))
                  break;

               if(client->is_active() && client_sent.empty())
                  {
                  // Choose a len between 1 and 511, todo use random chunks
                  const size_t c_len = 1 + rng.next_byte() + rng.next_byte();
                  client_sent = unlock(rng.random_vec(c_len));
                  client->send(client_sent);
                  }

               if(server->is_active() && server_sent.empty())
                  {
                  result.test_eq("server ALPN", server->next_protocol(), "test/3");

                  const size_t s_len = 1 + rng.next_byte() + rng.next_byte();
                  server_sent = unlock(rng.random_vec(s_len));
                  server->send(server_sent);
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
                        size_t needed = server->received_data(input.data(), input.size());

                        if(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                           {
                           input.resize(needed);
                           rng.randomize(input.data(), input.size());
                           client->received_data(input.data(), input.size());
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
                        size_t needed = server->received_data(input.data(), input.size());
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
                        size_t needed = client->received_data(input.data(), input.size());

                        if(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                           {
                           input.resize(needed);
                           rng.randomize(input.data(), input.size());
                           client->received_data(input.data(), input.size());
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
                        size_t needed = client->received_data(input.data(), input.size());
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
               if(client->is_active() && corrupt_client_data && server_recv.empty())
                  client->send(client_sent);
               if(server->is_active() && corrupt_server_data && client_recv.empty())
                  server->send(server_sent);

               if(client_recv.size())
                  {
                  result.test_eq("client recv", client_recv, server_sent);
                  }

               if(server_recv.size())
                  {
                  result.test_eq("server recv", server_recv, client_sent);
                  }

               if(client->is_closed() && server->is_closed())
                  break;

               if(server_recv.size() && client_recv.size())
                  {
                  Botan::SymmetricKey client_key = client->key_material_export("label", "context", 32);
                  Botan::SymmetricKey server_key = server->key_material_export("label", "context", 32);

                  result.test_eq("key material export", client_key.bits_of(), server_key.bits_of());

                  if(r % 2 == 0)
                     client->close();
                  else
                     server->close();
                  }
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

Test::Result test_dtls_handshake(Botan::TLS::Protocol_Version offer_version,
                                 Botan::Credentials_Manager& creds,
                                 const Botan::TLS::Policy& policy,
                                 Botan::RandomNumberGenerator& rng,
                                 Botan::TLS::Session_Manager& client_ses,
                                 Botan::TLS::Session_Manager& server_ses)
   {
   return test_dtls_handshake(offer_version, creds, policy, policy, rng, client_ses, server_ses);
   }

class Test_Policy : public Botan::TLS::Text_Policy
   {
   public:
      Test_Policy() : Text_Policy("") {}
      bool acceptable_protocol_version(Botan::TLS::Protocol_Version) const override { return true; }
      bool send_fallback_scsv(Botan::TLS::Protocol_Version) const override { return false; }

      size_t dtls_initial_timeout() const override { return 1; }
      size_t dtls_maximum_timeout() const override { return 8; }

      size_t minimum_rsa_bits() const override { return 1024; }
   };



class TLS_Unit_Tests : public Test
   {
   private:
      void test_with_policy(std::vector<Test::Result>& results,
                            Botan::TLS::Session_Manager& client_ses,
                            Botan::TLS::Session_Manager& server_ses,
                            Botan::Credentials_Manager& creds,
                            const std::vector<Botan::TLS::Protocol_Version>& versions,
                            const Botan::TLS::Policy& policy)
         {
         Botan::RandomNumberGenerator& rng = Test::rng();

         for(auto&& version : versions)
            {
            if(version.is_datagram_protocol())
               results.push_back(test_dtls_handshake(version, creds, policy, rng, client_ses, server_ses));
            else
               results.push_back(test_tls_handshake(version, creds, policy, rng, client_ses, server_ses));
            }
         }

      void test_all_versions(std::vector<Test::Result>& results,
                             Botan::TLS::Session_Manager& client_ses,
                             Botan::TLS::Session_Manager& server_ses,
                             Botan::Credentials_Manager& creds,
                             const std::string& kex_policy,
                             const std::string& cipher_policy,
                             const std::string& mac_policy,
                             const std::string& etm_policy)
         {
         Test_Policy policy;
         policy.set("ciphers", cipher_policy);
         policy.set("macs", mac_policy);
         policy.set("key_exchange_methods", kex_policy);
         policy.set("negotiate_encrypt_then_mac", etm_policy);

         std::vector<Botan::TLS::Protocol_Version> versions = {
            Botan::TLS::Protocol_Version::TLS_V10,
            Botan::TLS::Protocol_Version::TLS_V11,
            Botan::TLS::Protocol_Version::TLS_V12,
            Botan::TLS::Protocol_Version::DTLS_V10,
            Botan::TLS::Protocol_Version::DTLS_V12
         };

         return test_with_policy(results, client_ses, server_ses, creds, versions, policy);
         }

      void test_modern_versions(std::vector<Test::Result>& results,
                                Botan::TLS::Session_Manager& client_ses,
                                Botan::TLS::Session_Manager& server_ses,
                                Botan::Credentials_Manager& creds,
                                const std::string& kex_policy,
                                const std::string& cipher_policy,
                                const std::string& mac_policy = "AEAD",
                                const std::map<std::string, std::string>& extra_policies = {})
         {
         Test_Policy policy;
         policy.set("ciphers", cipher_policy);
         policy.set("macs", mac_policy);
         policy.set("key_exchange_methods", kex_policy);

         for(auto&& kv : extra_policies)
            policy.set(kv.first, kv.second);

         std::vector<Botan::TLS::Protocol_Version> versions = {
            Botan::TLS::Protocol_Version::TLS_V12,
            Botan::TLS::Protocol_Version::DTLS_V12
         };

         return test_with_policy(results, client_ses, server_ses, creds, versions, policy);
         }

   public:
      std::vector<Test::Result> run() override
         {
         Botan::RandomNumberGenerator& rng = Test::rng();

         std::unique_ptr<Botan::TLS::Session_Manager> client_ses;
         std::unique_ptr<Botan::TLS::Session_Manager> server_ses;

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
         client_ses.reset(
            new Botan::TLS::Session_Manager_SQLite("pass", rng, ":memory:", 5,
                                                   std::chrono::seconds(2)));
         server_ses.reset(
            new Botan::TLS::Session_Manager_SQLite("pass", rng, ":memory:", 10,
                                                   std::chrono::seconds(4)));
#else
         client_ses.reset(new Botan::TLS::Session_Manager_In_Memory(rng));
         server_ses.reset(new Botan::TLS::Session_Manager_In_Memory(rng));
#endif

         std::unique_ptr<Botan::Credentials_Manager> creds(create_creds(rng));
         std::vector<Test::Result> results;

#if defined(BOTAN_HAS_TLS_CBC)
         for(std::string etm_setting : { "false", "true" })
            {
            test_all_versions(results, *client_ses, *server_ses, *creds, "RSA", "AES-128", "SHA-256 SHA-1", etm_setting);
            test_all_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-128", "SHA-256 SHA-1", etm_setting);

            test_all_versions(results, *client_ses, *server_ses, *creds, "RSA", "AES-256", "SHA-1", etm_setting);
            test_all_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-256", "SHA-1", etm_setting);

#if defined(BOTAN_HAS_CAMELLIA)
            test_all_versions(results, *client_ses, *server_ses, *creds, "RSA", "Camellia-128", "SHA-256", etm_setting);
            test_all_versions(results, *client_ses, *server_ses, *creds, "ECDH", "Camellia-256", "SHA-256 SHA-384", etm_setting);
#endif

#if defined(BOTAN_HAS_DES)
            test_all_versions(results, *client_ses, *server_ses, *creds, "RSA", "3DES", "SHA-1", etm_setting);
            test_all_versions(results, *client_ses, *server_ses, *creds, "ECDH", "3DES", "SHA-1", etm_setting);
#endif

#if defined(BOTAN_HAS_SEED)
            test_all_versions(results, *client_ses, *server_ses, *creds, "RSA", "SEED", "SHA-1", etm_setting);
#endif

            server_ses->remove_all();
            }

         test_modern_versions(results, *client_ses, *server_ses, *creds, "DH", "AES-128", "SHA-256");
#endif

         Botan::TLS::Strict_Policy strict_policy;
         test_with_policy(results, *client_ses, *server_ses, *creds,
                          {Botan::TLS::Protocol_Version::TLS_V12}, strict_policy);

         test_modern_versions(results, *client_ses, *server_ses, *creds, "RSA", "AES-128/GCM");
         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM");

         client_ses->remove_all();

         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "signature_methods", "RSA" } });

         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "use_ecc_point_compression", "true" } });
         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "ecc_curves", "secp384r1" } });

#if defined(BOTAN_HAS_CURVE_25519)
         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "ecc_curves", "x25519" } });
#endif

         std::unique_ptr<Botan::Credentials_Manager> creds_with_client_cert(create_creds(rng, true));
         test_modern_versions(results, *client_ses, *server_ses, *creds_with_client_cert, "ECDH", "AES-256/GCM");

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
         client_ses.reset(new Botan::TLS::Session_Manager_In_Memory(rng));
         server_ses.reset(new Botan::TLS::Session_Manager_In_Memory(rng));
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/OCB(12)");
#endif

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDH", "ChaCha20Poly1305");
#endif

         test_modern_versions(results, *client_ses, *server_ses, *creds, "PSK", "AES-128/GCM");

#if defined(BOTAN_HAS_CCM)
         test_modern_versions(results, *client_ses, *server_ses, *creds, "PSK", "AES-128/CCM");
         test_modern_versions(results, *client_ses, *server_ses, *creds, "PSK", "AES-128/CCM(8)");
#endif

#if defined(BOTAN_HAS_TLS_CBC)
         // For whatever reason no (EC)DHE_PSK GCM ciphersuites are defined
         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDHE_PSK", "AES-128", "SHA-256");
         test_modern_versions(results, *client_ses, *server_ses, *creds, "DHE_PSK", "AES-128", "SHA-1");
#endif

#if defined(BOTAN_HOUSE_ECC_CURVE_NAME)
         test_modern_versions(results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                                       { { "ecc_curves", BOTAN_HOUSE_ECC_CURVE_NAME } });
#endif
         return results;
         }

   };

BOTAN_REGISTER_TEST("tls", TLS_Unit_Tests);

#endif

}

}

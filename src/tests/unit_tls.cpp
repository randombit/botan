/*
* (C) 2014,2015,2018 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <vector>
#include <memory>

#if defined(BOTAN_HAS_TLS)

   #include <botan/tls_client.h>
   #include <botan/tls_server.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_extensions.h>
   #include <botan/internal/tls_reader.h>

   #include <botan/ec_group.h>
   #include <botan/hex.h>
   #include <botan/oids.h>
   #include <botan/pkcs10.h>
   #include <botan/rsa.h>
   #include <botan/ecdsa.h>
   #include <botan/x509_ca.h>
   #include <botan/x509self.h>

   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
      #include <botan/tls_session_manager_sqlite.h>
   #endif

#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)
class Credentials_Manager_Test final : public Botan::Credentials_Manager
   {
   public:
      Credentials_Manager_Test(bool with_client_certs,
                               const Botan::X509_Certificate& rsa_cert,
                               Botan::Private_Key* rsa_key,
                               const Botan::X509_Certificate& rsa_ca,
                               const Botan::X509_CRL& rsa_crl,
                               const Botan::X509_Certificate& ecdsa_cert,
                               Botan::Private_Key* ecdsa_key,
                               const Botan::X509_Certificate& ecdsa_ca,
                               const Botan::X509_CRL& ecdsa_crl) :
         m_rsa_cert(rsa_cert),
         m_rsa_ca(rsa_ca),
         m_rsa_key(rsa_key),
         m_ecdsa_cert(ecdsa_cert),
         m_ecdsa_ca(ecdsa_ca),
         m_ecdsa_key(ecdsa_key)
         {
         std::unique_ptr<Botan::Certificate_Store_In_Memory> store(new Botan::Certificate_Store_In_Memory);
         store->add_certificate(m_rsa_ca);
         store->add_certificate(m_ecdsa_ca);
         store->add_crl(rsa_crl);
         store->add_crl(ecdsa_crl);

         m_stores.push_back(std::move(store));
         m_provides_client_certs = with_client_certs;
         }

      std::vector<Botan::Certificate_Store*>
      trusted_certificate_authorities(const std::string& /*type*/,
                                      const std::string& /*context*/) override
         {
         std::vector<Botan::Certificate_Store*> v;
         for(auto const& store : m_stores)
            {
            v.push_back(store.get());
            }
         return v;
         }

      std::vector<Botan::X509_Certificate> find_cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::X509_DN>& acceptable_CAs,
         const std::string& type,
         const std::string& context) override
         {
         BOTAN_UNUSED(context);
         std::vector<Botan::X509_Certificate> chain;

         if(m_acceptable_cas.empty())
            m_acceptable_cas = acceptable_CAs;

         if(type == "tls-server" || (type == "tls-client" && m_provides_client_certs))
            {
            for(auto const& key_type : cert_key_types)
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

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& crt,
                                          const std::string& /*type*/,
                                          const std::string& /*context*/) override
         {
         if(crt == m_rsa_cert)
            {
            return m_rsa_key.get();
            }
         if(crt == m_ecdsa_cert)
            {
            return m_ecdsa_key.get();
            }
         return nullptr;
         }

      Botan::SymmetricKey psk(const std::string& type,
                              const std::string& context,
                              const std::string& /*identity*/) override
         {
         if(type == "tls-server" && context == "session-ticket")
            {
            return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");
            }

         if(type == "tls-server" && context == "dtls-cookie-secret")
            {
            return Botan::SymmetricKey("4AEA5EAD279CADEB537A594DA0E9DE3A");
            }

         if(context == "server.example.com" && type == "tls-client")
            {
            return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");
            }

         if(context == "server.example.com" && type == "tls-server")
            {
            return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");
            }

         throw Test_Error("No PSK set for " + type + "/" + context);
         }

      const std::vector<Botan::X509_DN>& get_acceptable_cas() const { return m_acceptable_cas; }

   private:
      Botan::X509_Certificate m_rsa_cert, m_rsa_ca;
      std::unique_ptr<Botan::Private_Key> m_rsa_key;

      Botan::X509_Certificate m_ecdsa_cert, m_ecdsa_ca;
      std::unique_ptr<Botan::Private_Key> m_ecdsa_key;

      std::vector<std::unique_ptr<Botan::Certificate_Store>> m_stores;
      bool m_provides_client_certs;
      std::vector<Botan::X509_DN> m_acceptable_cas;
   };

Botan::Credentials_Manager*
create_creds(Botan::RandomNumberGenerator& rng,
             bool with_client_certs = false)
   {
   // rsa and ecdsa are required for the tls module
   const Botan::EC_Group ecdsa_params("secp256r1");
   const size_t rsa_params = 1024;

   auto rsa_ca_key = std::make_unique<Botan::RSA_PrivateKey>(rng, rsa_params);
   auto rsa_srv_key = std::make_unique<Botan::RSA_PrivateKey>(rng, rsa_params);

   auto ecdsa_ca_key = std::make_unique<Botan::ECDSA_PrivateKey>(rng, ecdsa_params);
   auto ecdsa_srv_key = std::make_unique<Botan::ECDSA_PrivateKey>(rng, ecdsa_params);

   Botan::X509_Cert_Options rsa_ca_opts("RSA Test CA/VT");
   Botan::X509_Cert_Options ecdsa_ca_opts("ECDSA Test CA/VT");
   rsa_ca_opts.CA_key(1);
   ecdsa_ca_opts.CA_key(1);

   const Botan::X509_Certificate rsa_ca_cert =
      Botan::X509::create_self_signed_cert(rsa_ca_opts, *rsa_ca_key, "SHA-256", rng);
   const Botan::X509_Certificate ecdsa_ca_cert =
      Botan::X509::create_self_signed_cert(ecdsa_ca_opts, *ecdsa_ca_key, "SHA-256", rng);

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

   Botan::X509_CRL rsa_crl = rsa_ca.new_crl(rng);
   Botan::X509_CRL ecdsa_crl = ecdsa_ca.new_crl(rng);

   // dsa support is optional
   std::unique_ptr<Botan::Private_Key> dsa_ca_key;
   std::unique_ptr<Botan::Private_Key> dsa_srv_key;
   std::unique_ptr<Botan::X509_CRL> dsa_crl;
   std::unique_ptr<Botan::X509_Certificate> dsa_srv_cert;
   std::unique_ptr<Botan::X509_Certificate> dsa_ca_cert;

   Credentials_Manager_Test* cmt = new Credentials_Manager_Test(
      with_client_certs,
      rsa_srv_cert, rsa_srv_key.release(), rsa_ca_cert, rsa_crl,
      ecdsa_srv_cert, ecdsa_srv_key.release(), ecdsa_ca_cert, ecdsa_crl);

   return cmt;
   }

class TLS_Handshake_Test final
   {
   public:
      TLS_Handshake_Test(const std::string& test_descr,
                         Botan::TLS::Protocol_Version offer_version,
                         Botan::Credentials_Manager& creds,
                         const Botan::TLS::Policy& client_policy,
                         const Botan::TLS::Policy& server_policy,
                         Botan::RandomNumberGenerator& rng,
                         Botan::TLS::Session_Manager& client_sessions,
                         Botan::TLS::Session_Manager& server_sessions,
                         bool expect_client_auth) :
         m_offer_version(offer_version),
         m_results(test_descr),
         m_creds(creds),
         m_client_policy(client_policy),
         m_client_sessions(client_sessions),
         m_rng(rng),
         m_client_auth(expect_client_auth)
         {
         m_server_cb.reset(new Test_Callbacks(m_results, offer_version, m_s2c, m_server_recv));
         m_client_cb.reset(new Test_Callbacks(m_results, offer_version, m_c2s, m_client_recv));

         m_server.reset(
            new Botan::TLS::Server(*m_server_cb, server_sessions, m_creds, server_policy, m_rng,
                                   offer_version.is_datagram_protocol())
            );

         }

      void go();

      const Test::Result& results() const { return m_results; }
   private:

      class Test_Extension : public Botan::TLS::Extension
         {
         public:
            static Botan::TLS::Handshake_Extension_Type static_type()
               { return static_cast<Botan::TLS::Handshake_Extension_Type>(666); }

            Botan::TLS::Handshake_Extension_Type type() const override { return static_type(); }

            std::vector<uint8_t> serialize(Botan::TLS::Connection_Side /*whoami*/) const override { return m_buf; }

            const std::vector<uint8_t>& value() const { return m_buf; }

            bool empty() const override { return false; }

            explicit Test_Extension(Botan::TLS::Connection_Side side)
               {
               const uint8_t client_extn[6] = { 'c', 'l', 'i', 'e', 'n', 't' };
               const uint8_t server_extn[6] = { 's', 'e', 'r', 'v', 'e', 'r' };

               Botan::TLS::append_tls_length_value(m_buf,
                                                   (side == Botan::TLS::CLIENT) ? client_extn : server_extn,
                                                   6, 1);
               }
         private:
            std::vector<uint8_t> m_buf;
         };

      class Test_Callbacks : public Botan::TLS::Callbacks
         {
         public:
            Test_Callbacks(Test::Result& results,
                           Botan::TLS::Protocol_Version expected_version,
                           std::vector<uint8_t>& outbound,
                           std::vector<uint8_t>& recv_buf) :
               m_results(results),
               m_expected_version(expected_version),
               m_outbound(outbound),
               m_recv(recv_buf)
               {}

            void tls_emit_data(const uint8_t bits[], size_t len) override
               {
               m_outbound.insert(m_outbound.end(), bits, bits + len);
               }

            void tls_record_received(uint64_t /*seq*/, const uint8_t bits[], size_t len) override
               {
               m_recv.insert(m_recv.end(), bits, bits + len);
               }

            void tls_alert(Botan::TLS::Alert /*alert*/) override
               {
               // TODO test that it is a no_renegotiation alert
               // ignore
               }

            void tls_modify_extensions(Botan::TLS::Extensions& extn, Botan::TLS::Connection_Side which_side) override
               {
               extn.add(new Test_Extension(which_side));

               // Insert an unsupported signature scheme as highest prio, to ensure we are tolerant of this
               if(auto sig_algs = extn.take<Botan::TLS::Signature_Algorithms>())
                  {
                  std::vector<Botan::TLS::Signature_Scheme> schemes = sig_algs->supported_schemes();
                  // 0x0301 is RSA PKCS1/SHA-224, which is not supported anymore
                  schemes.insert(schemes.begin(), 0x0301);
                  // This replaces the previous extension value
                  extn.add(new Botan::TLS::Signature_Algorithms(schemes));
                  }
               }

            void tls_examine_extensions(const Botan::TLS::Extensions& extn, Botan::TLS::Connection_Side which_side) override
               {
               Botan::TLS::Extension* test_extn = extn.get(static_cast<Botan::TLS::Handshake_Extension_Type>(666));

               if(test_extn == nullptr)
                  {
                  m_results.test_failure("Did not receive test extension from peer");
                  }
               else
                  {
                  Botan::TLS::Unknown_Extension* unknown_ext = dynamic_cast<Botan::TLS::Unknown_Extension*>(test_extn);

                  if(unknown_ext)
                     {
                     const std::vector<uint8_t> val = unknown_ext->value();

                     if(m_results.test_eq("Expected size for test extn", val.size(), 7))
                        {
                        if(which_side == Botan::TLS::CLIENT)
                           m_results.test_eq("Expected extension value", val, "06636C69656E74");
                        else
                           m_results.test_eq("Expected extension value", val, "06736572766572");
                        }
                     }
                  else
                     {
                     m_results.test_failure("Unknown extension type had unexpected type at runtime");
                     }
                  }
               }

            bool tls_session_established(const Botan::TLS::Session& session) override
               {
               const std::string session_report =
                  "Session established " + session.version().to_string() + " " +
                  session.ciphersuite().to_string() + " " +
                  Botan::hex_encode(session.session_id());

               m_results.test_note(session_report);

               if(session.version() != m_expected_version)
                  {
                  m_results.test_failure("Expected " + m_expected_version.to_string() +
                                         " negotiated " + session.version().to_string());
                  }

               return true;
               }

            std::string tls_server_choose_app_protocol(const std::vector<std::string>& protos) override
               {
               m_results.test_eq("ALPN protocol count", protos.size(), 2);
               m_results.test_eq("ALPN protocol 1", protos[0], "test/1");
               m_results.test_eq("ALPN protocol 2", protos[1], "test/2");
               return "test/3";
               }

            std::string tls_decode_group_param(Botan::TLS::Group_Params group_param) override
               {
               if(static_cast<uint16_t>(group_param) == 0xFEE1)
                  return "secp112r1";

               return Botan::TLS::Callbacks::tls_decode_group_param(group_param);
               }

         private:
            Test::Result& m_results;
            const Botan::TLS::Protocol_Version m_expected_version;
            std::vector<uint8_t>& m_outbound;
            std::vector<uint8_t>& m_recv;
         };

      const Botan::TLS::Protocol_Version m_offer_version;
      Test::Result m_results;

      Botan::Credentials_Manager& m_creds;
      const Botan::TLS::Policy& m_client_policy;
      Botan::TLS::Session_Manager& m_client_sessions;
      Botan::RandomNumberGenerator& m_rng;

      std::unique_ptr<Test_Callbacks> m_client_cb;

      std::unique_ptr<Test_Callbacks> m_server_cb;
      std::unique_ptr<Botan::TLS::Server> m_server;

      const bool m_client_auth;

      std::vector<uint8_t> m_c2s, m_s2c, m_client_recv, m_server_recv;
   };

void TLS_Handshake_Test::go()
   {
   m_results.start_timer();

   Botan::RandomNumberGenerator& rng = Test::rng();

   const std::vector<std::string> protocols_offered = { "test/1", "test/2" };

   // Choose random application data to send
   const size_t c_len = 1 + ((static_cast<size_t>(rng.next_byte()) << 4) ^ rng.next_byte());
   std::vector<uint8_t> client_msg(c_len);
   Test::rng().randomize(client_msg.data(), client_msg.size());
   bool client_has_written = false;

   const size_t s_len = 1 + ((static_cast<size_t>(rng.next_byte()) << 4) ^ rng.next_byte());
   std::vector<uint8_t> server_msg(s_len);
   Test::rng().randomize(server_msg.data(), server_msg.size());
   bool server_has_written = false;

   std::unique_ptr<Botan::TLS::Client> client;
   client.reset(
      new Botan::TLS::Client(*m_client_cb, m_client_sessions, m_creds,
                             m_client_policy, m_rng,
                             Botan::TLS::Server_Information("server.example.com"),
                             m_offer_version,
                             protocols_offered));

   size_t rounds = 0;

   bool client_handshake_completed = false;
   bool server_handshake_completed = false;

   while(true)
      {
      ++rounds;

      if(rounds > 25)
         {
         m_results.test_failure("Still here after many rounds, deadlock?");
         break;
         }

      if(client_handshake_completed == false && client->is_active())
         client_handshake_completed = true;

      if(server_handshake_completed == false && m_server->is_active())
         server_handshake_completed = true;

      if(client->is_closed() || m_server->is_closed())
         {
         break;
         }

      if(client->is_active() && client_has_written == false)
         {
         m_results.test_eq("client ALPN protocol", client->application_protocol(), "test/3");

         size_t sent_so_far = 0;
         while(sent_so_far != client_msg.size())
            {
            const size_t left = client_msg.size() - sent_so_far;
            const size_t rnd12 = (rng.next_byte() << 4) ^ rng.next_byte();
            const size_t sending = std::min(left, rnd12);

            client->send(&client_msg[sent_so_far], sending);
            sent_so_far += sending;
            }
         client->send_warning_alert(Botan::TLS::Alert::NO_RENEGOTIATION);
         client_has_written = true;
         }

      if(m_server->is_active() && server_has_written == false)
         {
         m_results.test_eq("server ALPN protocol", m_server->application_protocol(), "test/3");

         size_t sent_so_far = 0;
         while(sent_so_far != server_msg.size())
            {
            const size_t left = server_msg.size() - sent_so_far;
            const size_t rnd12 = (rng.next_byte() << 4) ^ rng.next_byte();
            const size_t sending = std::min(left, rnd12);

            m_server->send(&server_msg[sent_so_far], sending);
            sent_so_far += sending;
            }

         m_server->send_warning_alert(Botan::TLS::Alert::NO_RENEGOTIATION);
         server_has_written = true;
         }

      if(!m_c2s.empty())
         {
         /*
         * Use this as a temp value to hold the queues as otherwise they
         * might end up appending more in response to messages during the
         * handshake.
         */
         std::vector<uint8_t> input;
         std::swap(m_c2s, input);

         size_t needed = m_server->received_data(input.data(), input.size());
         m_results.test_eq("full packet received", needed, 0);

         continue;
         }

      if(!m_s2c.empty())
         {
         std::vector<uint8_t> input;
         std::swap(m_s2c, input);

         size_t needed = client->received_data(input.data(), input.size());
         m_results.test_eq("full packet received", needed, 0);

         continue;
         }

      if(!m_client_recv.empty())
         {
         m_results.test_eq("client recv", m_client_recv, server_msg);
         }

      if(!m_server_recv.empty())
         {
         m_results.test_eq("server recv", m_server_recv, client_msg);
         }

      if(client->is_closed() && m_server->is_closed())
         {
         break;
         }

      if(m_server->is_active())
         {
         std::vector<Botan::X509_Certificate> certs = m_server->peer_cert_chain();
         if(m_client_auth)
            {
            m_results.test_eq("got client certs", certs.size(), 2);

            Credentials_Manager_Test& test_creds = dynamic_cast<Credentials_Manager_Test&>(m_creds);

            std::vector<Botan::X509_DN> acceptable_CAs = test_creds.get_acceptable_cas();

            m_results.test_eq("client got CA list", acceptable_CAs.size(), 2); // RSA + ECDSA

            for(const Botan::X509_DN& dn : acceptable_CAs)
               {
               m_results.test_eq("Expected CA country field",
                                 dn.get_first_attribute("C"), "VT");
               }
            }
         else
            {
            m_results.test_eq("no client certs", certs.size(), 0);
            }
         }

      if(!m_server_recv.empty() && !m_client_recv.empty())
         {
         Botan::SymmetricKey client_key = client->key_material_export("label", "context", 32);
         Botan::SymmetricKey server_key = m_server->key_material_export("label", "context", 32);

         m_results.test_eq("TLS key material export", client_key.bits_of(), server_key.bits_of());

         m_results.confirm("Client is active", client->is_active());
         m_results.confirm("Client is not closed", !client->is_closed());
         client->close();
         m_results.confirm("Client is no longer active", !client->is_active());
         m_results.confirm("Client is closed", client->is_closed());
         }
      }

   m_results.end_timer();
   }

class Test_Policy final : public Botan::TLS::Text_Policy
   {
   public:
      Test_Policy() : Text_Policy("") {}
      bool acceptable_protocol_version(Botan::TLS::Protocol_Version /*version*/) const override
         {
         return true;
         }

      size_t dtls_initial_timeout() const override
         {
         return 1;
         }
      size_t dtls_maximum_timeout() const override
         {
         return 8;
         }

      size_t minimum_rsa_bits() const override
         {
         return 1024;
         }

      size_t minimum_signature_strength() const override
         {
         return 80;
         }
   };

class TLS_Unit_Tests final : public Test
   {
   private:
      static void test_with_policy(const std::string& test_descr,
                            std::vector<Test::Result>& results,
                            Botan::TLS::Session_Manager& client_ses,
                            Botan::TLS::Session_Manager& server_ses,
                            Botan::Credentials_Manager& creds,
                            const std::vector<Botan::TLS::Protocol_Version>& versions,
                            const Botan::TLS::Policy& policy,
                            bool client_auth = false)
         {
         Botan::RandomNumberGenerator& rng = Test::rng();

         try
            {
            for(auto const& version : versions)
               {
               TLS_Handshake_Test test(
                  version.to_string() + " " + test_descr,
                  version, creds, policy, policy, rng, client_ses, server_ses, client_auth);
               test.go();
               results.push_back(test.results());

               TLS_Handshake_Test test_resumption(
                  version.to_string() + " " + test_descr,
                  version, creds, policy, policy, rng, client_ses, server_ses, client_auth);
               test_resumption.go();
               results.push_back(test_resumption.results());
               }
            }
         catch(std::exception& e)
            {
            results.push_back(Test::Result::Failure(test_descr, e.what()));
            }
         }

      static void test_all_versions(
         const std::string& test_descr,
         std::vector<Test::Result>& results,
         Botan::TLS::Session_Manager& client_ses,
         Botan::TLS::Session_Manager& server_ses,
         Botan::Credentials_Manager& creds,
         const std::string& kex_policy,
         const std::string& cipher_policy,
         const std::string& mac_policy,
         const std::string& etm_policy,
         bool client_auth = false)
         {
         Test_Policy policy;
         policy.set("ciphers", cipher_policy);
         policy.set("macs", mac_policy);
         policy.set("key_exchange_methods", kex_policy);
         policy.set("negotiate_encrypt_then_mac", etm_policy);

         policy.set("allow_tls12", "true");
         policy.set("allow_dtls12", "true");

         if(kex_policy.find("RSA") != std::string::npos)
            {
            policy.set("signature_methods", "IMPLICIT");
            }

         std::vector<Botan::TLS::Protocol_Version> versions =
            {
            Botan::TLS::Protocol_Version::TLS_V12,
            Botan::TLS::Protocol_Version::DTLS_V12
            };

         return test_with_policy(test_descr, results, client_ses, server_ses, creds, versions, policy, client_auth);
         }

      static void test_modern_versions(
         const std::string& test_descr,
         std::vector<Test::Result>& results,
         Botan::TLS::Session_Manager& client_ses,
         Botan::TLS::Session_Manager& server_ses,
         Botan::Credentials_Manager& creds,
         const std::string& kex_policy,
         const std::string& cipher_policy,
         const std::string& mac_policy = "AEAD",
         bool client_auth = false)
         {
         std::map<std::string, std::string> no_extra_policies;
         return test_modern_versions(test_descr, results, client_ses, server_ses, creds,
                                     kex_policy, cipher_policy, mac_policy, no_extra_policies, client_auth);
         }

      static void test_modern_versions(
         const std::string& test_descr,
         std::vector<Test::Result>& results,
         Botan::TLS::Session_Manager& client_ses,
         Botan::TLS::Session_Manager& server_ses,
         Botan::Credentials_Manager& creds,
         const std::string& kex_policy,
         const std::string& cipher_policy,
         const std::string& mac_policy,
         const std::map<std::string, std::string>& extra_policies,
         bool client_auth = false)
         {
         Test_Policy policy;
         policy.set("ciphers", cipher_policy);
         policy.set("macs", mac_policy);
         policy.set("key_exchange_methods", kex_policy);
         policy.set("allow_tls12", "true");
         policy.set("allow_dtls12", "true");

         if(kex_policy.find("RSA") != std::string::npos)
            {
            policy.set("signature_methods", "IMPLICIT");
            }

         for(auto const& kv : extra_policies)
            {
            policy.set(kv.first, kv.second);
            }

         std::vector<Botan::TLS::Protocol_Version> versions =
            {
            Botan::TLS::Protocol_Version::TLS_V12,
            Botan::TLS::Protocol_Version::DTLS_V12
            };

         return test_with_policy(test_descr, results, client_ses, server_ses, creds, versions, policy, client_auth);
         }

   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         Botan::RandomNumberGenerator& rng = Test::rng();

         std::unique_ptr<Botan::TLS::Session_Manager> client_ses;
         std::unique_ptr<Botan::TLS::Session_Manager> server_ses;

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
         client_ses.reset(
            new Botan::TLS::Session_Manager_SQLite("client pass", rng, ":memory:", 5, std::chrono::seconds(2)));
         server_ses.reset(
            new Botan::TLS::Session_Manager_SQLite("server pass", rng, ":memory:", 10, std::chrono::seconds(4)));

#else
         client_ses.reset(new Botan::TLS::Session_Manager_In_Memory(rng));
         server_ses.reset(new Botan::TLS::Session_Manager_In_Memory(rng));
#endif

         std::unique_ptr<Botan::Credentials_Manager> creds(create_creds(rng));

#if defined(BOTAN_HAS_TLS_CBC)
         for(std::string etm_setting : { "false", "true" })
            {
            test_all_versions("AES-128 RSA", results, *client_ses, *server_ses, *creds, "RSA", "AES-128", "SHA-256 SHA-1", etm_setting);
            test_all_versions("AES-128 ECDH", results, *client_ses, *server_ses, *creds, "ECDH", "AES-128", "SHA-256 SHA-1", etm_setting);

#if defined(BOTAN_HAS_DES)
            test_all_versions("3DES RSA", results, *client_ses, *server_ses, *creds, "RSA", "3DES", "SHA-1", etm_setting);
            test_all_versions("3DES ECDH", results, *client_ses, *server_ses, *creds, "ECDH", "3DES", "SHA-1", etm_setting);
#endif

            server_ses->remove_all();
            }
         client_ses->remove_all();

         test_modern_versions("AES-128 DH", results, *client_ses, *server_ses, *creds, "DH", "AES-128", "SHA-256");

#endif

         Botan::TLS::Strict_Policy strict_policy;
         test_with_policy("Strict policy", results, *client_ses, *server_ses, *creds,
            {Botan::TLS::Protocol_Version::TLS_V12}, strict_policy);

         Botan::TLS::NSA_Suite_B_128 suiteb_128;
         test_with_policy("Suite B", results, *client_ses, *server_ses, *creds,
            {Botan::TLS::Protocol_Version::TLS_V12}, suiteb_128);

         // Remove server sessions before client, so clients retry with session server doesn't know
         server_ses->remove_all();

         test_modern_versions("AES-128/GCM RSA", results, *client_ses, *server_ses, *creds, "RSA", "AES-128/GCM");
         test_modern_versions("AES-128/GCM ECDH", results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM");

         test_modern_versions("AES-128/GCM ECDH RSA",
                              results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "signature_methods", "RSA" } });

         test_modern_versions("AES-128/GCM ECDH no OCSP",
                              results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "support_cert_status_message", "false" } });

         client_ses->remove_all();

#if defined(BOTAN_HAS_CAMELLIA) && defined(BOTAN_HAS_AEAD_GCM)
         test_modern_versions("Camellia-128/GCM ECDH", results, *client_ses, *server_ses, *creds, "ECDH", "Camellia-128/GCM", "AEAD");
#endif

#if defined(BOTAN_HAS_ARIA)
         test_modern_versions("ARIA/GCM ECDH", results, *client_ses, *server_ses, *creds, "ECDH", "ARIA-128/GCM", "AEAD");
#endif

#if defined(BOTAN_HAS_CECPQ1)

#if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM)
         test_modern_versions("AES-256/GCM CECPQ1", results, *client_ses, *server_ses, *creds, "CECPQ1", "AES-256/GCM", "AEAD");
#endif

#if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_OCB)
         test_modern_versions("AES-256/OCB CECPQ1", results, *client_ses, *server_ses, *creds,
                              "CECPQ1", "AES-256/OCB(12)", "AEAD");
         test_modern_versions("AES-256/OCB CECPQ1 RSA", results, *client_ses, *server_ses, *creds,
                              "CECPQ1", "AES-256/OCB(12)", "AEAD",
                              {{ "signature_methods", "RSA" }});
#endif

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
         test_modern_versions("ChaCha20Poly1305 CECPQ1", results, *client_ses, *server_ses, *creds,
                              "CECPQ1", "ChaCha20Poly1305", "AEAD",
                              { { "signature_methods", "RSA" }});
#endif

#endif

         test_modern_versions("AES-128/GCM point compression", results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "use_ecc_point_compression", "true" } });
         test_modern_versions("AES-256/GCM p521", results, *client_ses, *server_ses, *creds, "ECDH", "AES-256/GCM", "AEAD",
                              { { "groups", "secp521r1" } });
         test_modern_versions("AES-128/GCM bp256r1", results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "groups", "brainpool256r1" } });

#if defined(BOTAN_HAS_CURVE_25519)
         test_modern_versions("AES-128/GCM x25519", results, *client_ses, *server_ses, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "groups", "x25519" } });
#endif

         test_modern_versions("AES-128/GCM FFDHE-2048",
                              results, *client_ses, *server_ses, *creds, "DH", "AES-128/GCM", "AEAD",
                              { { "groups", "ffdhe/ietf/2048" } });

         std::unique_ptr<Botan::Credentials_Manager> creds_with_client_cert(create_creds(rng, true));

         client_ses->remove_all();
         test_modern_versions("AES-256/GCM client certs",
                              results, *client_ses, *server_ses, *creds_with_client_cert, "ECDH", "AES-256/GCM", "AEAD", true);

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
         client_ses.reset(new Botan::TLS::Session_Manager_In_Memory(rng));
         server_ses.reset(new Botan::TLS::Session_Manager_In_Memory(rng));
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
         test_modern_versions("AES-256/OCB ECDH", results, *client_ses, *server_ses, *creds, "ECDH", "AES-256/OCB(12)");
#endif

         server_ses->remove_all();

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
         test_modern_versions("ChaCha20Poly1305 ECDH", results, *client_ses, *server_ses, *creds, "ECDH", "ChaCha20Poly1305");
#endif

         test_modern_versions("AES-128/GCM PSK", results, *client_ses, *server_ses, *creds, "PSK", "AES-128/GCM");

#if defined(BOTAN_HAS_AEAD_CCM)
         test_modern_versions("AES-128/CCM PSK", results, *client_ses, *server_ses, *creds, "PSK", "AES-128/CCM");
         test_modern_versions("AES-128/CCM-8 PSK", results, *client_ses, *server_ses, *creds, "PSK", "AES-128/CCM(8)");
#endif

         test_modern_versions("AES-128/GCM ECDHE_PSK", results, *client_ses, *server_ses, *creds, "ECDHE_PSK", "AES-128/GCM");

         // Test with a custom curve

         /*
         * First register a curve, in this case secp112r1
         */
         const Botan::BigInt p("0xDB7C2ABF62E35E668076BEAD208B");
         const Botan::BigInt a("0xDB7C2ABF62E35E668076BEAD2088");
         const Botan::BigInt b("0x659EF8BA043916EEDE8911702B22");

         const Botan::BigInt g_x("0x09487239995A5EE76B55F9C2F098");
         const Botan::BigInt g_y("0xA89CE5AF8724C0A23E0E0FF77500");
         const Botan::BigInt order("0xDB7C2ABF62E35E7628DFAC6561C5");

         const Botan::OID oid("1.3.132.0.6");

         // Creating this object implicitly registers the curve for future use ...
         Botan::EC_Group reg_secp112r1(p, a, b, g_x, g_y, order, 1, oid);

         Botan::OIDS::add_oid(oid, "secp112r1");

         test_modern_versions("AES-256/GCM secp112r1", results, *client_ses, *server_ses, *creds, "ECDH", "AES-256/GCM", "AEAD",
                              { { "groups", "0xFEE1" }, { "minimum_ecdh_group_size", "112" } });

         return results;
         }

   };

BOTAN_REGISTER_TEST("tls", "tls", TLS_Unit_Tests);

class DTLS_Reconnection_Test : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         class Test_Callbacks : public Botan::TLS::Callbacks
            {
            public:
               Test_Callbacks(Test::Result& results,
                              std::vector<uint8_t>& outbound,
                              std::vector<uint8_t>& recv_buf) :
                  m_results(results),
                  m_outbound(outbound),
                  m_recv(recv_buf)
                  {}

               void tls_emit_data(const uint8_t bits[], size_t len) override
                  {
                  m_outbound.insert(m_outbound.end(), bits, bits + len);
                  }

               void tls_record_received(uint64_t /*seq*/, const uint8_t bits[], size_t len) override
                  {
                  m_recv.insert(m_recv.end(), bits, bits + len);
                  }

               void tls_alert(Botan::TLS::Alert /*alert*/) override
                  {
                  // ignore
                  }

               bool tls_session_established(const Botan::TLS::Session& /*session*/) override
                  {
                  m_results.test_success("Established a session");
                  return true;
                  }

            private:
               Test::Result& m_results;
               std::vector<uint8_t>& m_outbound;
               std::vector<uint8_t>& m_recv;
            };

         class Credentials_PSK : public Botan::Credentials_Manager
            {
            public:
               Botan::SymmetricKey psk(const std::string& type,
                                       const std::string& context,
                                       const std::string& /*identity*/) override
                  {
                  if(type == "tls-server" && context == "session-ticket")
                     {
                     return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");
                     }

                  if(type == "tls-server" && context == "dtls-cookie-secret")
                     {
                     return Botan::SymmetricKey("4AEA5EAD279CADEB537A594DA0E9DE3A");
                     }

                  if(context == "localhost" && type == "tls-client")
                     {
                     return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");
                     }

                  if(context == "localhost" && type == "tls-server")
                     {
                     return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");
                     }

                  throw Test_Error("No PSK set for " + type + "/" + context);
                  }
            };

         class Datagram_PSK_Policy : public Botan::TLS::Policy
            {
            public:
               std::vector<std::string> allowed_macs() const override
                  { return std::vector<std::string>({"AEAD"}); }

               std::vector<std::string> allowed_key_exchange_methods() const override
                  { return {"PSK"}; }

               bool allow_tls12()  const override { return false; }
               bool allow_dtls12() const override { return true;  }

               bool allow_dtls_epoch0_restart() const override { return true; }
            };

         Test::Result result("DTLS reconnection");

         Datagram_PSK_Policy server_policy;
         Datagram_PSK_Policy client_policy;
         Credentials_PSK creds;
         Botan::TLS::Session_Manager_In_Memory server_sessions(rng());
         //Botan::TLS::Session_Manager_In_Memory client_sessions(rng());
         Botan::TLS::Session_Manager_Noop client_sessions;

         std::vector<uint8_t> s2c, server_recv;
         Test_Callbacks server_callbacks(result, s2c, server_recv);
         Botan::TLS::Server server(server_callbacks, server_sessions, creds, server_policy, rng(), true);

         std::vector<uint8_t> c1_c2s, client1_recv;
         Test_Callbacks client1_callbacks(result, c1_c2s, client1_recv);
         Botan::TLS::Client client1(client1_callbacks, client_sessions, creds, client_policy, rng(),
                                    Botan::TLS::Server_Information("localhost"),
                                    Botan::TLS::Protocol_Version::latest_dtls_version());

         bool c1_to_server_sent = false;
         bool server_to_c1_sent = false;

         const std::vector<uint8_t> c1_to_server_magic(16, 0xC1);
         const std::vector<uint8_t> server_to_c1_magic(16, 0x42);

         size_t c1_rounds = 0;
         for(;;)
            {
            c1_rounds++;

            if(c1_rounds > 64)
               {
               result.test_failure("Still spinning in client1 loop after 64 rounds");
               return {result};
               }

            if(!c1_c2s.empty())
               {
               std::vector<uint8_t> input;
               std::swap(c1_c2s, input);
               server.received_data(input.data(), input.size());
               continue;
               }

            if(!s2c.empty())
               {
               std::vector<uint8_t> input;
               std::swap(s2c, input);
               client1.received_data(input.data(), input.size());
               continue;
               }

            if(!c1_to_server_sent && client1.is_active())
               {
               client1.send(c1_to_server_magic);
               c1_to_server_sent = true;
               }

            if(!server_to_c1_sent && server.is_active())
               {
               server.send(server_to_c1_magic);
               }

            if(!server_recv.empty() && !client1_recv.empty())
               {
               result.test_eq("Expected message from client1", server_recv, c1_to_server_magic);
               result.test_eq("Expected message to client1", client1_recv, server_to_c1_magic);
               break;
               }
            }

         // Now client1 "goes away" (goes silent) and new client
         // connects to same server context (ie due to reuse of client source port)
         // See RFC 6347 section 4.2.8

         server_recv.clear();
         s2c.clear();

         std::vector<uint8_t> c2_c2s, client2_recv;
         Test_Callbacks client2_callbacks(result, c2_c2s, client2_recv);
         Botan::TLS::Client client2(client2_callbacks, client_sessions, creds, client_policy, rng(),
                                    Botan::TLS::Server_Information("localhost"),
                                    Botan::TLS::Protocol_Version::latest_dtls_version());

         bool c2_to_server_sent = false;
         bool server_to_c2_sent = false;

         const std::vector<uint8_t> c2_to_server_magic(16, 0xC2);
         const std::vector<uint8_t> server_to_c2_magic(16, 0x66);

         size_t c2_rounds = 0;

         for(;;)
            {
            c2_rounds++;

            if(c2_rounds > 64)
               {
               result.test_failure("Still spinning in client2 loop after 64 rounds");
               return {result};
               }

            if(!c2_c2s.empty())
               {
               std::vector<uint8_t> input;
               std::swap(c2_c2s, input);
               server.received_data(input.data(), input.size());
               continue;
               }

            if(!s2c.empty())
               {
               std::vector<uint8_t> input;
               std::swap(s2c, input);
               client2.received_data(input.data(), input.size());
               continue;
               }

            if(!c2_to_server_sent && client2.is_active())
               {
               client2.send(c2_to_server_magic);
               c2_to_server_sent = true;
               }

            if(!server_to_c2_sent && server.is_active())
               {
               server.send(server_to_c2_magic);
               }

            if(!server_recv.empty() && !client2_recv.empty())
               {
               result.test_eq("Expected message from client2", server_recv, c2_to_server_magic);
               result.test_eq("Expected message to client2", client2_recv, server_to_c2_magic);
               break;
               }
            }

         return {result};
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_dtls_reconnect", DTLS_Reconnection_Test);

#endif

}

}

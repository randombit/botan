/*
* (C) 2014,2015,2018,2026 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2023 René Meusel, Rohde & Schwarz Cybersecurity
*     2026 René Meusel, Rohde & Schwarz Networks and Cybersecurity
*     2025 Lars Dürkop, CARIAD SE
*     2026 Thiesius
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   #include <thread>
#endif

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_TLS_12)

   #include <botan/credentials_manager.h>
   #include <botan/rng.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_client.h>
   #include <botan/tls_exceptn.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_server.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/tls_session_manager_noop.h>

#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_TLS_12)

class Dtls_Test_Callbacks final : public Botan::TLS::Callbacks {
   public:
      Dtls_Test_Callbacks(Test::Result& result, std::vector<uint8_t>& outbound, std::vector<uint8_t>& received) :
            m_result(result), m_outbound(outbound), m_received(received) {}

      void tls_emit_data(std::span<const uint8_t> bits) override {
         m_outbound.insert(m_outbound.end(), bits.begin(), bits.end());
      }

      void tls_record_received(uint64_t /*seq*/, std::span<const uint8_t> bits) override {
         m_received.insert(m_received.end(), bits.begin(), bits.end());
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         if(alert.is_fatal()) {
            m_result.test_failure("unexpected fatal alert: " + alert.type_string());
         }
      }

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         m_session_was_resumption = session.was_resumption();
         ++m_sessions_established;
      }

      size_t sessions_established() const { return m_sessions_established; }

      std::optional<bool> session_was_resumption() const { return m_session_was_resumption; }

   private:
      Test::Result& m_result;
      std::vector<uint8_t>& m_outbound;
      std::vector<uint8_t>& m_received;
      size_t m_sessions_established = 0;
      std::optional<bool> m_session_was_resumption;
};

class Dtls_PSK_Credentials final : public Botan::Credentials_Manager {
   public:
      Botan::SymmetricKey psk(const std::string& type,
                              const std::string& context,
                              const std::string& /*identity*/) override {
         if(type == "tls-server" && context == "session-ticket") {
            return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");
         }

         if(type == "tls-server" && context == "dtls-cookie-secret") {
            ++m_dtls_cookie_secret_requests;
            return Botan::SymmetricKey("4AEA5EAD279CADEB537A594DA0E9DE3A");
         }

         if(context == "localhost" && (type == "tls-client" || type == "tls-server")) {
            return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");
         }

         throw Test_Error("No PSK set for " + type + "/" + context);
      }

      size_t dtls_cookie_secret_requests() const { return m_dtls_cookie_secret_requests; }

   private:
      size_t m_dtls_cookie_secret_requests = 0;
};

class Dtls_PSK_Policy final : public Botan::TLS::Policy {
   public:
      std::vector<std::string> allowed_macs() const override { return {"AEAD"}; }

      std::vector<std::string> allowed_key_exchange_methods() const override { return {"PSK"}; }

      bool allow_tls12() const override { return false; }

      bool allow_dtls12() const override { return true; }

      bool allow_dtls_epoch0_restart() const override { return true; }

      bool allow_server_initiated_renegotiation() const override { return true; }

      bool allow_client_initiated_renegotiation() const override { return true; }

      size_t dtls_initial_timeout() const override { return 1; }

      size_t dtls_maximum_timeout() const override { return 8; }
};

/*
These tests exercise the DTLS core without opening real UDP sockets. The test
callbacks collect bytes emitted by TLS::Client/TLS::Server, and deliver() feeds
those bytes into the peer's received_data(). Clearing, splitting, copying, or
delaying those buffers simulates datagram loss, retransmission, duplicates, and
partial flights while still running the real DTLS record, handshake, epoch, and
retransmission logic.
*/
class DTLS_Core_Regression_Tests final : public Test {
   private:
      static void deliver(Test::Result& result,
                          const std::string& label,
                          std::vector<uint8_t>& outbound,
                          Botan::TLS::Channel& peer) {
         if(!result.test_is_true(label + " has data", !outbound.empty())) {
            return;
         }

         std::vector<uint8_t> input;
         std::swap(input, outbound);
         result.test_no_throw(label, [&] { peer.received_data(input.data(), input.size()); });
      }

      static void deliver_copy(Test::Result& result,
                               const std::string& label,
                               const std::vector<uint8_t>& outbound,
                               Botan::TLS::Channel& peer) {
         if(!result.test_is_true(label + " has data", !outbound.empty())) {
            return;
         }

         result.test_no_throw(label, [&] { peer.received_data(outbound.data(), outbound.size()); });
      }

      static bool split_first_dtls_record(Test::Result& result,
                                          const std::vector<uint8_t>& records,
                                          std::vector<uint8_t>& first_record,
                                          std::vector<uint8_t>& remaining_records) {
         constexpr size_t dtls_header_len = 13;

         if(!result.test_is_true("DTLS records include a complete header", records.size() >= dtls_header_len)) {
            return false;
         }

         const size_t record_len = static_cast<size_t>((static_cast<uint16_t>(records[11]) << 8) | records[12]);
         const size_t total_len = dtls_header_len + record_len;

         if(!result.test_is_true("DTLS records include a complete first record", records.size() >= total_len)) {
            return false;
         }

         first_record.assign(records.begin(), records.begin() + total_len);
         remaining_records.assign(records.begin() + total_len, records.end());
         return result.test_is_true("DTLS server flight has more than one record", !remaining_records.empty());
      }

      static std::vector<Botan::TLS::Handshake_Type> dtls_handshake_types(const std::vector<uint8_t>& records) {
         // Lightweight test-only DTLS record inspection. This deliberately
         // looks only at unencrypted handshake records, so labels like
         // "retransmitted HelloVerifyRequest" are backed by wire data without
         // turning the test into a second DTLS implementation.
         constexpr size_t dtls_header_len = 13;
         constexpr size_t dtls_handshake_header_len = 12;

         std::vector<Botan::TLS::Handshake_Type> types;

         size_t offset = 0;
         while(offset + dtls_header_len <= records.size()) {
            const auto record_type = static_cast<Botan::TLS::Record_Type>(records[offset]);
            const size_t record_len =
               static_cast<size_t>((static_cast<uint16_t>(records[offset + 11]) << 8) | records[offset + 12]);
            const size_t record_end = offset + dtls_header_len + record_len;

            if(record_end > records.size()) {
               break;
            }

            if(record_type == Botan::TLS::Record_Type::Handshake) {
               size_t hs_offset = offset + dtls_header_len;
               while(hs_offset + dtls_handshake_header_len <= record_end) {
                  const auto handshake_type = static_cast<Botan::TLS::Handshake_Type>(records[hs_offset]);
                  const size_t fragment_len = (static_cast<size_t>(records[hs_offset + 9]) << 16) |
                                              (static_cast<size_t>(records[hs_offset + 10]) << 8) |
                                              records[hs_offset + 11];
                  const size_t handshake_end = hs_offset + dtls_handshake_header_len + fragment_len;

                  if(handshake_end > record_end) {
                     break;
                  }

                  types.push_back(handshake_type);
                  hs_offset = handshake_end;
               }
            }

            offset = record_end;
         }

         return types;
      }

      static std::vector<Botan::TLS::Record_Type> dtls_record_types(const std::vector<uint8_t>& records) {
         constexpr size_t dtls_header_len = 13;

         std::vector<Botan::TLS::Record_Type> types;

         size_t offset = 0;
         while(offset + dtls_header_len <= records.size()) {
            const auto record_type = static_cast<Botan::TLS::Record_Type>(records[offset]);
            const size_t record_len =
               static_cast<size_t>((static_cast<uint16_t>(records[offset + 11]) << 8) | records[offset + 12]);
            const size_t record_end = offset + dtls_header_len + record_len;

            if(record_end > records.size()) {
               break;
            }

            types.push_back(record_type);
            offset = record_end;
         }

         return types;
      }

      static bool contains_dtls_handshake_type(const std::vector<uint8_t>& records,
                                               Botan::TLS::Handshake_Type expected) {
         for(auto type : dtls_handshake_types(records)) {
            if(type == expected) {
               return true;
            }
         }

         return false;
      }

      static bool contains_dtls_record_type(const std::vector<uint8_t>& records, Botan::TLS::Record_Type expected) {
         for(auto type : dtls_record_types(records)) {
            if(type == expected) {
               return true;
            }
         }

         return false;
      }

      static std::vector<uint8_t> empty_dtls_handshake_fragment(Botan::TLS::Handshake_Type type,
                                                                size_t message_length,
                                                                uint16_t message_sequence) {
         std::vector<uint8_t> record;
         record.reserve(25);

         record.push_back(static_cast<uint8_t>(Botan::TLS::Record_Type::Handshake));
         record.push_back(0xFE);
         record.push_back(0xFD);
         record.insert(record.end(), 8, 0);  // epoch 0, sequence number 0
         record.push_back(0);
         record.push_back(12);

         record.push_back(static_cast<uint8_t>(type));
         record.push_back(static_cast<uint8_t>((message_length >> 16) & 0xFF));
         record.push_back(static_cast<uint8_t>((message_length >> 8) & 0xFF));
         record.push_back(static_cast<uint8_t>(message_length & 0xFF));
         record.push_back(static_cast<uint8_t>((message_sequence >> 8) & 0xFF));
         record.push_back(static_cast<uint8_t>(message_sequence & 0xFF));
         record.insert(record.end(), 6, 0);  // fragment offset 0, fragment length 0

         return record;
      }

      static std::vector<uint8_t> unprotected_dtls_record(Botan::TLS::Record_Type type,
                                                          uint64_t sequence,
                                                          std::span<const uint8_t> payload) {
         std::vector<uint8_t> record;
         record.reserve(13 + payload.size());

         record.push_back(static_cast<uint8_t>(type));
         record.push_back(0xFE);
         record.push_back(0xFD);
         for(size_t i = 0; i != 8; ++i) {
            record.push_back(static_cast<uint8_t>(sequence >> (56 - 8 * i)));
         }
         record.push_back(static_cast<uint8_t>(payload.size() >> 8));
         record.push_back(static_cast<uint8_t>(payload.size()));
         record.insert(record.end(), payload.begin(), payload.end());

         return record;
      }

      template <typename Predicate>
      static bool wait_until(Predicate predicate) {
         // DTLS timeouts are clock based. Poll briefly instead of sleeping for
         // an exact duration so slow/debug builds and timer granularity do not
         // make retransmission tests flaky.
         const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);

         while(std::chrono::steady_clock::now() < deadline) {
            if(predicate()) {
               return true;
            }

   #if defined(BOTAN_TARGET_OS_HAS_THREADS)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
   #endif
         }

         return predicate();
      }

      static void wait_for_timeout_retransmit(Test::Result& result,
                                              Botan::TLS::Channel& channel,
                                              std::vector<uint8_t>& outbound) {
         if(!wait_until([&] {
               const auto timeout = channel.next_retransmission_timeout();
               return timeout.has_value() && timeout->count() == 0 && channel.timeout_check() && !outbound.empty();
            })) {
            result.test_failure("DTLS retransmit was not produced");
         }
      }

      static Test::Result test_timeout_check_paces_retransmissions() {
         Test::Result result("DTLS timeout_check retransmit pacing");

         auto rng = Test::new_shared_rng("dtls-core-timeout-pacing");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         if(!result.test_is_true("hello verify request was produced", !s2c.empty())) {
            return result;
         }
         s2c.clear();  // simulate losing the HelloVerifyRequest

         wait_for_timeout_retransmit(result, client, c2s);
         const auto retransmit_size = c2s.size();

         result.test_is_true("next retransmission timeout remains available",
                             client.next_retransmission_timeout().has_value());
         result.test_is_false("immediate second timeout is suppressed", client.timeout_check());
         result.test_sz_eq("no immediate second retransmit", c2s.size(), retransmit_size);

         return result;
      }

      static Test::Result test_retransmitted_epoch_transition_flight_includes_ccs() {
         Test::Result result("DTLS retransmitted epoch-1 flight includes CCS");

         auto rng = Test::new_shared_rng("dtls-core-retransmitted-ccs");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);

         result.test_is_true("server became active", server.is_active());
         if(!result.test_is_true("server final flight was produced", !s2c.empty())) {
            return result;
         }
         s2c.clear();  // simulate losing the server final flight

         wait_for_timeout_retransmit(result, client, c2s);
         deliver(result, "retransmitted client final flight", c2s, server);

         result.test_is_true("retransmitted final flight includes CCS",
                             contains_dtls_record_type(s2c, Botan::TLS::Record_Type::ChangeCipherSpec));
         result.test_is_true("retransmitted final flight includes Finished record",
                             contains_dtls_record_type(s2c, Botan::TLS::Record_Type::Handshake));

         deliver(result, "retransmitted server final flight", s2c, client);
         result.test_is_true("client became active", client.is_active());

         return result;
      }

      static Test::Result test_lost_hello_verify_request_retransmits() {
         Test::Result result("DTLS lost HelloVerifyRequest retransmits");

         auto rng = Test::new_shared_rng("dtls-core-lost-hvr");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         if(!result.test_is_true("hello verify request was produced", !s2c.empty())) {
            return result;
         }
         result.test_is_true("server response is HelloVerifyRequest",
                             contains_dtls_handshake_type(s2c, Botan::TLS::Handshake_Type::HelloVerifyRequest));
         result.test_is_false("server does not arm a HelloVerifyRequest retransmission timer",
                              server.next_retransmission_timeout().has_value());
         s2c.clear();  // simulate losing the HelloVerifyRequest

         wait_for_timeout_retransmit(result, client, c2s);
         deliver(result, "client hello 1 retransmit", c2s, server);
         if(!result.test_is_true("server retransmitted hello verify request", !s2c.empty())) {
            return result;
         }
         result.test_is_true("server retransmission is HelloVerifyRequest",
                             contains_dtls_handshake_type(s2c, Botan::TLS::Handshake_Type::HelloVerifyRequest));

         deliver(result, "retransmitted hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);
         deliver(result, "server final flight", s2c, client);

         result.test_is_true("client became active", client.is_active());
         result.test_is_true("server became active", server.is_active());

         return result;
      }

      static Test::Result test_duplicate_hello_verify_request_is_tolerated() {
         Test::Result result("DTLS duplicate HelloVerifyRequest is tolerated");

         auto rng = Test::new_shared_rng("dtls-core-duplicate-hvr");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);

         const std::vector<uint8_t> hello_verify = s2c;
         if(!result.test_is_true("hello verify request was produced", !hello_verify.empty())) {
            return result;
         }
         result.test_is_true(
            "server response is HelloVerifyRequest",
            contains_dtls_handshake_type(hello_verify, Botan::TLS::Handshake_Type::HelloVerifyRequest));
         s2c.clear();

         deliver_copy(result, "hello verify request", hello_verify, client);
         if(!result.test_is_true("client hello 2 was produced", !c2s.empty())) {
            return result;
         }
         std::vector<uint8_t> client_hello_2;
         std::swap(client_hello_2, c2s);

         deliver_copy(result, "duplicate hello verify request", hello_verify, client);
         result.test_is_true("duplicate hello verify request is ignored", c2s.empty());

         deliver_copy(result, "client hello 2 after duplicate hvr", client_hello_2, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);
         deliver(result, "server final flight", s2c, client);

         result.test_is_true("client became active", client.is_active());
         result.test_is_true("server became active", server.is_active());

         return result;
      }

      static Test::Result test_partial_server_flight_does_not_advance_client() {
         Test::Result result("DTLS partial server flight waits for ServerHelloDone");

         auto rng = Test::new_shared_rng("dtls-core-partial-server-flight");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);

         std::vector<uint8_t> first_record;
         std::vector<uint8_t> remaining_records;
         if(!split_first_dtls_record(result, s2c, first_record, remaining_records)) {
            return result;
         }
         s2c.clear();

         result.test_is_true("partial server flight starts with ServerHello",
                             contains_dtls_handshake_type(first_record, Botan::TLS::Handshake_Type::ServerHello));
         result.test_is_true(
            "partial server flight remainder has ServerHelloDone",
            contains_dtls_handshake_type(remaining_records, Botan::TLS::Handshake_Type::ServerHelloDone));

         deliver_copy(result, "partial server flight first record", first_record, client);
         result.test_is_false("client waits for the rest of the server flight", client.is_active());
         result.test_is_true("client does not send final flight early", c2s.empty());

         deliver_copy(result, "partial server flight remaining records", remaining_records, client);
         if(!result.test_is_true("client final flight was produced after ServerHelloDone", !c2s.empty())) {
            return result;
         }

         deliver(result, "client final flight", c2s, server);
         deliver(result, "server final flight", s2c, client);

         result.test_is_true("client became active", client.is_active());
         result.test_is_true("server became active", server.is_active());

         return result;
      }

      static Test::Result test_lost_server_flight_retransmits() {
         Test::Result result("DTLS lost server flight retransmits");

         auto rng = Test::new_shared_rng("dtls-core-lost-server-flight");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);

         if(!result.test_is_true("server handshake flight was produced", !s2c.empty())) {
            return result;
         }
         s2c.clear();  // simulate losing the server flight

         wait_for_timeout_retransmit(result, client, c2s);
         deliver(result, "client hello 2 retransmit", c2s, server);
         if(!result.test_is_true("server retransmitted handshake flight", !s2c.empty())) {
            return result;
         }

         deliver(result, "retransmitted server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);
         deliver(result, "server final flight", s2c, client);

         result.test_is_true("client became active", client.is_active());
         result.test_is_true("server became active", server.is_active());

         return result;
      }

      static Test::Result test_duplicate_server_flight_defers_to_timer() {
         Test::Result result("DTLS duplicate server flight defers replay to timer");

         auto rng = Test::new_shared_rng("dtls-core-retransmitted-server-flight");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         if(!result.test_is_true("client final flight was produced", !c2s.empty())) {
            return result;
         }
         c2s.clear();  // simulate losing the client's response flight

         wait_for_timeout_retransmit(result, server, s2c);

         std::vector<uint8_t> first_server_record;
         std::vector<uint8_t> remaining_server_records;
         if(!split_first_dtls_record(result, s2c, first_server_record, remaining_server_records)) {
            return result;
         }
         s2c.clear();

         result.test_is_true(
            "first retransmitted server record is ServerHello",
            contains_dtls_handshake_type(first_server_record, Botan::TLS::Handshake_Type::ServerHello));
         result.test_is_true(
            "remaining retransmitted records include ServerHelloDone",
            contains_dtls_handshake_type(remaining_server_records, Botan::TLS::Handshake_Type::ServerHelloDone));

         deliver_copy(result, "retransmitted ServerHello record", first_server_record, client);
         result.test_is_true("non-terminal record does not replay client flight", c2s.empty());

         deliver_copy(result, "rest of retransmitted server flight", remaining_server_records, client);
         result.test_is_true("duplicated server flight does not immediately replay client flight", c2s.empty());

         // The response flight is still recoverable. Deferring to the timer
         // avoids injecting an epoch-0 replay after the peer has progressed.
         wait_for_timeout_retransmit(result, client, c2s);
         result.test_is_true("client timer replays the lost response flight", !c2s.empty());

         return result;
      }

      static Test::Result test_lost_server_final_flight_retransmits() {
         Test::Result result("DTLS lost server final flight retransmits");

         auto rng = Test::new_shared_rng("dtls-core-lost-server-final");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);

         result.test_is_true("server became active", server.is_active());
         result.test_is_false("client is waiting for server final flight", client.is_active());
         if(!result.test_is_true("server final flight was produced", !s2c.empty())) {
            return result;
         }

         std::vector<uint8_t> delayed_ccs;
         std::vector<uint8_t> delayed_finished;
         if(!split_first_dtls_record(result, s2c, delayed_ccs, delayed_finished)) {
            return result;
         }
         s2c.clear();  // simulate delaying the original server final flight

         result.test_is_false("finished server has no proactive retransmission timer",
                              server.next_retransmission_timeout().has_value());
         wait_for_timeout_retransmit(result, client, c2s);
         deliver(result, "retransmitted client final flight", c2s, server);
         deliver(result, "retransmitted server final flight", s2c, client);

         result.test_is_true("client became active", client.is_active());
         result.test_is_false("active client has no retransmission timer",
                              client.next_retransmission_timeout().has_value());

         // The original Finished may arrive after the retransmitted flight
         // activated the client. It has an unseen DTLS record sequence number
         // but an old handshake message_seq and must be discarded silently.
         deliver(result, "delayed original server Finished", delayed_finished, client);
         result.test_is_true("client remains active after delayed Finished", client.is_active());
         result.test_is_true("client does not respond to delayed Finished", c2s.empty());

         return result;
      }

      static Test::Result test_stale_client_hello_does_not_replace_active_handshake() {
         Test::Result result("DTLS stale ClientHello after server activation");

         auto rng = Test::new_shared_rng("dtls-core-stale-client-hello");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         const auto cookie_client_hello = c2s;
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);

         result.test_is_true("server became active", server.is_active());
         result.test_is_false("client is waiting for server final flight", client.is_active());
         s2c.clear();  // simulate losing the server final flight

         // A delayed retransmission of the cookie-bearing ClientHello has
         // message_seq 1. It belongs to the completed handshake, whereas a
         // genuinely new association starts at message_seq 0.
         deliver_copy(result, "stale client hello 2", cookie_client_hello, server);
         result.test_is_true("server remains active", server.is_active());
         result.test_is_true("stale ClientHello replays the final server flight", !s2c.empty());
         s2c.clear();

         wait_for_timeout_retransmit(result, client, c2s);
         deliver(result, "retransmitted client final flight", c2s, server);
         result.test_is_true("client final flight still receives a response", !s2c.empty());

         return result;
      }

      static Test::Result test_epoch0_client_hello_retransmit_while_restart_pending() {
         Test::Result result("DTLS epoch-zero ClientHello retransmit while restart pending");

         auto rng = Test::new_shared_rng("dtls-core-pending-epoch0-restart");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_Noop>();

         std::vector<uint8_t> s2c;
         std::vector<uint8_t> server_recv;
         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);

         std::vector<uint8_t> c1_c2s;
         std::vector<uint8_t> client1_recv;
         auto client1_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c1_c2s, client1_recv);
         Botan::TLS::Client client1(client1_callbacks,
                                    client_sessions,
                                    creds,
                                    policy,
                                    rng,
                                    Botan::TLS::Server_Information("localhost"),
                                    Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client 1 hello", c1_c2s, server);
         deliver(result, "client 1 hello verify request", s2c, client1);
         deliver(result, "client 1 cookie-bearing hello", c1_c2s, server);
         deliver(result, "client 1 server handshake flight", s2c, client1);
         deliver(result, "client 1 final flight", c1_c2s, server);
         deliver(result, "client 1 server final flight", s2c, client1);

         result.test_is_true("first client became active", client1.is_active());
         result.test_is_true("server became active for first client", server.is_active());
         result.test_sz_eq("server established one session", server_callbacks->sessions_established(), 1);

         std::vector<uint8_t> c2_c2s;
         std::vector<uint8_t> client2_recv;
         auto client2_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2_c2s, client2_recv);
         Botan::TLS::Client client2(client2_callbacks,
                                    client_sessions,
                                    creds,
                                    policy,
                                    rng,
                                    Botan::TLS::Server_Information("localhost"),
                                    Botan::TLS::Protocol_Version::latest_dtls_version());

         const auto epoch0_client_hello = c2_c2s;
         deliver(result, "client 2 epoch-zero hello", c2_c2s, server);
         const auto hello_verify_request = s2c;
         const auto cookie_secret_requests = creds->dtls_cookie_secret_requests();
         s2c.clear();

         // HelloVerifyRequest is not retained as retransmittable flight data.
         // A repeated initial ClientHello recreates the cookie response.
         deliver_copy(result, "retransmitted client 2 epoch-zero hello", epoch0_client_hello, server);
         result.test_is_true("pending restart replays HelloVerifyRequest",
                             contains_dtls_handshake_type(s2c, Botan::TLS::Handshake_Type::HelloVerifyRequest));
         result.test_sz_eq("retransmitted ClientHello does not establish another session",
                           server_callbacks->sessions_established(),
                           1);
         result.test_sz_eq("retransmitted ClientHello recreates the cookie response",
                           creds->dtls_cookie_secret_requests(),
                           cookie_secret_requests + 1);
         result.test_is_true("previous association remains active during restart", server.is_active());
         s2c.clear();

         deliver_copy(result, "client 2 hello verify request", hello_verify_request, client2);
         deliver(result, "client 2 cookie-bearing hello", c2_c2s, server);
         deliver(result, "client 2 server handshake flight", s2c, client2);
         deliver(result, "client 2 final flight", c2_c2s, server);
         deliver(result, "client 2 server final flight", s2c, client2);

         result.test_is_true("second client became active", client2.is_active());
         result.test_is_true("server became active for second client", server.is_active());
         result.test_sz_eq("server established the replacement session", server_callbacks->sessions_established(), 2);

         return result;
      }

      static Test::Result test_retransmitted_final_flight_then_application_data(bool expect_resumption) {
         Test::Result result(expect_resumption ? "DTLS resumed handshake accepts app data"
                                               : "DTLS final flight retransmit before app data");

         auto rng = Test::new_shared_rng(expect_resumption ? "dtls-core-resumption" : "dtls-core-full");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         if(expect_resumption) {
            run_handshake(result, rng, policy, creds, client_sessions, server_sessions, false);
         }

         return run_handshake(result, rng, policy, creds, client_sessions, server_sessions, expect_resumption);
      }

      static Test::Result test_resumed_client_final_flight_retransmits_after_activation() {
         Test::Result result("DTLS resumed client final flight retransmits after activation");

         auto rng = Test::new_shared_rng("dtls-core-resumed-client-active");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         run_handshake(result, rng, policy, creds, client_sessions, server_sessions, false);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "resumed client hello 1", c2s, server);
         deliver(result, "resumed hello verify request", s2c, client);
         deliver(result, "resumed client hello 2", c2s, server);
         deliver(result, "resumed server handshake flight", s2c, client);

         result.test_is_true("client is active after resumed server flight", client.is_active());
         result.test_is_false("server is still waiting for client final flight", server.is_active());
         if(!result.test_is_true("client final flight was produced", !c2s.empty())) {
            return result;
         }

         std::vector<uint8_t> discarded_ccs;
         std::vector<uint8_t> delayed_finished;
         if(!split_first_dtls_record(result, c2s, discarded_ccs, delayed_finished)) {
            return result;
         }
         c2s.clear();  // simulate delaying the original client final flight

         result.test_is_false("finished client has no proactive retransmission timer",
                              client.next_retransmission_timeout().has_value());
         wait_for_timeout_retransmit(result, server, s2c);
         deliver(result, "retransmitted resumed server flight", s2c, client);
         deliver(result, "retransmitted resumed client final flight", c2s, server);

         result.test_is_true("server became active from retransmitted client final flight", server.is_active());

         // As in the full handshake, a delayed copy of the original terminal
         // Finished must not turn normal DTLS reordering into a fatal alert.
         deliver(result, "delayed original client Finished", delayed_finished, server);
         result.test_is_true("server remains active after delayed Finished", server.is_active());
         result.test_is_true("server does not respond to delayed Finished", s2c.empty());

         const std::vector<uint8_t> app_data = {0xB0, 0x7A, 0x11};
         result.test_no_throw("server sends application data after completing resumed handshake",
                              [&] { server.send(app_data); });
         deliver(result, "server application data", s2c, client);
         result.test_bin_eq("client received server application data", client_recv, app_data);

         return result;
      }

      static Test::Result test_reordered_retransmitted_final_flight() {
         Test::Result result("DTLS reordered retransmitted final flight");

         auto rng = Test::new_shared_rng("dtls-core-reordered-retransmitted-final");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);

         result.test_is_true("server became active", server.is_active());
         result.test_is_false("client is waiting for server final flight", client.is_active());
         s2c.clear();  // simulate losing the server's last flight

         wait_for_timeout_retransmit(result, client, c2s);

         std::vector<uint8_t> client_key_exchange;
         std::vector<uint8_t> ccs_and_finished;
         if(!split_first_dtls_record(result, c2s, client_key_exchange, ccs_and_finished)) {
            return result;
         }

         std::vector<uint8_t> ccs;
         std::vector<uint8_t> finished;
         if(!split_first_dtls_record(result, ccs_and_finished, ccs, finished)) {
            return result;
         }
         c2s.clear();

         result.test_is_true(
            "first retransmitted record is ClientKeyExchange",
            contains_dtls_handshake_type(client_key_exchange, Botan::TLS::Handshake_Type::ClientKeyExchange));
         result.test_is_true("second retransmitted record is CCS",
                             contains_dtls_record_type(ccs, Botan::TLS::Record_Type::ChangeCipherSpec));
         result.test_is_true("third retransmitted record is Finished",
                             contains_dtls_record_type(finished, Botan::TLS::Record_Type::Handshake));

         deliver_copy(result, "retransmitted ClientKeyExchange", client_key_exchange, server);
         result.test_is_true("non-terminal retransmitted record produces no response", s2c.empty());

         deliver_copy(result, "retransmitted Finished before CCS", finished, server);
         result.test_is_true("partial retransmitted flight produces no response", s2c.empty());

         deliver_copy(result, "retransmitted CCS after Finished", ccs, server);
         result.test_is_true("complete reordered flight retransmits server flight", !s2c.empty());

         return result;
      }

      static Test::Result test_renegotiation(bool server_initiated) {
         Test::Result result(server_initiated ? "DTLS server-initiated renegotiation"
                                              : "DTLS client-initiated renegotiation");

         auto rng = Test::new_shared_rng(server_initiated ? "dtls-core-server-renegotiation"
                                                          : "dtls-core-client-renegotiation");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);
         deliver(result, "server final flight", s2c, client);

         if(server_initiated) {
            result.test_no_throw("server requests renegotiation", [&] { server.renegotiate(true); });
            deliver(result, "hello request", s2c, client);
         } else {
            result.test_no_throw("client requests renegotiation", [&] { client.renegotiate(true); });
         }

         // A renegotiation ClientHello is already protected under the active
         // epoch. Replaying it must not infer a preceding CCS merely because
         // the cached handshake message has a non-zero epoch.
         c2s.clear();  // simulate losing the renegotiation ClientHello
         wait_for_timeout_retransmit(result, client, c2s);
         result.test_is_false("retransmitted renegotiation ClientHello does not include CCS",
                              contains_dtls_record_type(c2s, Botan::TLS::Record_Type::ChangeCipherSpec));
         deliver(result, "renegotiation client hello", c2s, server);
         deliver(result, "renegotiation server handshake flight", s2c, client);
         deliver(result, "renegotiation client final flight", c2s, server);
         deliver(result, "renegotiation server final flight", s2c, client);

         result.test_is_true("client remains active after renegotiation", client.is_active());
         result.test_is_true("server remains active after renegotiation", server.is_active());
         result.test_is_false("finished client has no proactive retransmission timer",
                              client.next_retransmission_timeout().has_value());
         result.test_is_false("finished server has no proactive retransmission timer",
                              server.next_retransmission_timeout().has_value());

         return result;
      }

      static Test::Result test_empty_old_handshake_fragment_does_not_retransmit() {
         Test::Result result("DTLS empty old handshake fragment does not retransmit");

         auto rng = Test::new_shared_rng("dtls-core-empty-old-fragment");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);
         deliver(result, "server final flight", s2c, client);

         result.test_is_true("client became active", client.is_active());
         result.test_is_true("server became active", server.is_active());

         const auto empty_fragment = empty_dtls_handshake_fragment(Botan::TLS::Handshake_Type::Finished, 12, 0);

         result.test_no_throw("empty old fragment is ignored",
                              [&] { server.received_data(empty_fragment.data(), empty_fragment.size()); });
         result.test_is_true("server did not retransmit final flight", s2c.empty());

         return result;
      }

      static Test::Result test_spoofed_epoch0_records_do_not_abort_or_poison_retransmission() {
         Test::Result result("DTLS spoofed epoch 0 records do not abort or poison retransmission");

         auto rng = Test::new_shared_rng("dtls-core-spoofed-epoch0");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);

         result.test_is_true("server became active", server.is_active());
         result.test_is_false("client is waiting for server final flight", client.is_active());
         s2c.clear();  // simulate losing the server's final flight

         const std::array<uint8_t, 2> fatal_alert = {2, 40};
         const auto spoofed_alert =
            unprotected_dtls_record(Botan::TLS::Record_Type::Alert, 0x0000FFFFFFFFFFFF, fatal_alert);
         result.test_no_throw("spoofed epoch 0 fatal alert is ignored",
                              [&] { server.received_data(spoofed_alert.data(), spoofed_alert.size()); });
         result.test_is_true("server remains active after spoofed alert", server.is_active());
         result.test_is_true("server does not respond to spoofed alert", s2c.empty());

         std::array<uint8_t, 12> invalid_handshake = {};
         invalid_handshake[0] = 0xFF;
         const auto spoofed_handshake =
            unprotected_dtls_record(Botan::TLS::Record_Type::Handshake, 0x0000FFFFFFFFFFFE, invalid_handshake);
         result.test_no_throw("invalid epoch 0 handshake is ignored",
                              [&] { server.received_data(spoofed_handshake.data(), spoofed_handshake.size()); });
         result.test_is_true("server remains active after invalid handshake", server.is_active());
         result.test_is_true("server does not respond to invalid handshake", s2c.empty());

         wait_for_timeout_retransmit(result, client, c2s);
         deliver(result, "genuine client final flight retransmit", c2s, server);
         result.test_is_true("server retransmits final flight", !s2c.empty());
         deliver(result, "retransmitted server final flight", s2c, client);

         result.test_is_true("client became active", client.is_active());
         result.test_is_true("server remains active", server.is_active());

         return result;
      }

      static Test::Result test_resumed_final_flight_and_app_data_in_one_receive() {
         Test::Result result("DTLS resumed final flight and app data in one receive");

         auto rng = Test::new_shared_rng("dtls-core-resumed-final-and-app-data");
         auto policy = std::make_shared<Dtls_PSK_Policy>();
         auto creds = std::make_shared<Dtls_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         run_handshake(result, rng, policy, creds, client_sessions, server_sessions, false);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "resumed client hello 1", c2s, server);
         deliver(result, "resumed hello verify request", s2c, client);
         deliver(result, "resumed client hello 2", c2s, server);
         deliver(result, "resumed server handshake flight", s2c, client);

         result.test_is_true("client is active after resumed server flight", client.is_active());
         result.test_is_false("server is still waiting for client final flight", server.is_active());
         if(!result.test_is_true("client final flight was produced", !c2s.empty())) {
            return result;
         }

         const std::vector<uint8_t> app_data = {0x47, 0x82, 0x01};
         result.test_no_throw("client sends application data before server processes final flight",
                              [&] { client.send(app_data); });

         deliver(result, "resumed client final flight and application data", c2s, server);

         result.test_is_true("server became active", server.is_active());
         result.test_bin_eq("server received client application data", server_recv, app_data);

         return result;
      }

      static Test::Result run_handshake(Test::Result& result,
                                        const std::shared_ptr<Botan::RandomNumberGenerator>& rng,
                                        const std::shared_ptr<Botan::TLS::Policy>& policy,
                                        const std::shared_ptr<Botan::Credentials_Manager>& creds,
                                        const std::shared_ptr<Botan::TLS::Session_Manager>& client_sessions,
                                        const std::shared_ptr<Botan::TLS::Session_Manager>& server_sessions,
                                        bool expect_resumption) {
         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<Dtls_Test_Callbacks>(result, c2s, client_recv);

         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);
         Botan::TLS::Client client(client_callbacks,
                                   client_sessions,
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);

         // For a full handshake this is the client's final flight. The server's
         // response is intentionally withheld to make the client retransmit it with
         // fresh DTLS record sequence numbers, matching the scenario in #2498.
         deliver(result, "client final flight", c2s, server);
         result.test_is_true("server became active", server.is_active());

         if(expect_resumption) {
            result.test_is_true("client became active during resumed handshake", client.is_active());
         } else {
            if(!result.test_is_true("server final flight is pending", !s2c.empty())) {
               return result;
            }

            wait_for_timeout_retransmit(result, client, c2s);
            deliver(result, "client final flight retransmit", c2s, server);

            deliver(result, "server final flight", s2c, client);
         }

         result.test_is_true("client became active", client.is_active());

         if(client_callbacks->session_was_resumption().has_value()) {
            result.test_bool_eq(
               "client resumption state", client_callbacks->session_was_resumption().value(), expect_resumption);
         }
         if(server_callbacks->session_was_resumption().has_value()) {
            result.test_bool_eq(
               "server resumption state", server_callbacks->session_was_resumption().value(), expect_resumption);
         }

         const std::vector<uint8_t> app_data = {0xD7, 0x15, 0xA9};
         result.test_no_throw("client sends application data after retransmitted final flight",
                              [&] { client.send(app_data); });
         deliver(result, "application data", c2s, server);
         result.test_bin_eq("server received application data", server_recv, app_data);

         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         return {test_timeout_check_paces_retransmissions(),
                 test_retransmitted_epoch_transition_flight_includes_ccs(),
                 test_lost_hello_verify_request_retransmits(),
                 test_duplicate_hello_verify_request_is_tolerated(),
                 test_partial_server_flight_does_not_advance_client(),
                 test_lost_server_flight_retransmits(),
                 test_duplicate_server_flight_defers_to_timer(),
                 test_lost_server_final_flight_retransmits(),
                 test_stale_client_hello_does_not_replace_active_handshake(),
                 test_epoch0_client_hello_retransmit_while_restart_pending(),
                 test_reordered_retransmitted_final_flight(),
                 test_empty_old_handshake_fragment_does_not_retransmit(),
                 test_spoofed_epoch0_records_do_not_abort_or_poison_retransmission(),
                 test_retransmitted_final_flight_then_application_data(false),
                 test_retransmitted_final_flight_then_application_data(true),
                 test_resumed_client_final_flight_retransmits_after_activation(),
                 test_resumed_final_flight_and_app_data_in_one_receive(),
                 test_renegotiation(false),
                 test_renegotiation(true)};
      }
};

BOTAN_REGISTER_TEST("tls", "tls_dtls_core_regressions", DTLS_Core_Regression_Tests);

class DTLS_Reconnection_Test : public Test {
   public:
      std::vector<Test::Result> run() override {
         class Test_Callbacks : public Botan::TLS::Callbacks {
            public:
               Test_Callbacks(Test::Result& results, std::vector<uint8_t>& outbound, std::vector<uint8_t>& recv_buf) :
                     m_results(results), m_outbound(outbound), m_recv(recv_buf) {}

               void tls_emit_data(std::span<const uint8_t> bits) override {
                  m_outbound.insert(m_outbound.end(), bits.begin(), bits.end());
               }

               void tls_record_received(uint64_t /*seq*/, std::span<const uint8_t> bits) override {
                  m_recv.insert(m_recv.end(), bits.begin(), bits.end());
               }

               void tls_alert(Botan::TLS::Alert /*alert*/) override {
                  // ignore
               }

               void tls_session_established(const Botan::TLS::Session_Summary& /*session*/) override {
                  m_results.test_success("Established a session");
               }

            private:
               Test::Result& m_results;
               std::vector<uint8_t>& m_outbound;
               std::vector<uint8_t>& m_recv;
         };

         class Credentials_PSK : public Botan::Credentials_Manager {
            public:
               Botan::SymmetricKey psk(const std::string& type,
                                       const std::string& context,
                                       const std::string& /*identity*/) override {
                  if(type == "tls-server" && context == "session-ticket") {
                     return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");
                  }

                  if(type == "tls-server" && context == "dtls-cookie-secret") {
                     return Botan::SymmetricKey("4AEA5EAD279CADEB537A594DA0E9DE3A");
                  }

                  if(context == "localhost" && type == "tls-client") {
                     return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");
                  }

                  if(context == "localhost" && type == "tls-server") {
                     return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");
                  }

                  throw Test_Error("No PSK set for " + type + "/" + context);
               }
         };

         class Datagram_PSK_Policy : public Botan::TLS::Policy {
            public:
               std::vector<std::string> allowed_macs() const override { return std::vector<std::string>({"AEAD"}); }

               std::vector<std::string> allowed_key_exchange_methods() const override { return {"PSK"}; }

               bool allow_tls12() const override { return false; }

               bool allow_dtls12() const override { return true; }

               bool allow_dtls_epoch0_restart() const override { return true; }
         };

         Test::Result result("DTLS reconnection");

         auto rng = Test::new_shared_rng(this->test_name());

         auto server_policy = std::make_shared<Datagram_PSK_Policy>();
         auto client_policy = std::make_shared<Datagram_PSK_Policy>();
         auto creds = std::make_shared<Credentials_PSK>();
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_Noop>();

         std::vector<uint8_t> s2c;
         std::vector<uint8_t> server_recv;
         auto server_callbacks = std::make_shared<Test_Callbacks>(result, s2c, server_recv);
         Botan::TLS::Server server(server_callbacks, server_sessions, creds, server_policy, rng, true);

         std::vector<uint8_t> c1_c2s;
         std::vector<uint8_t> client1_recv;
         auto client1_callbacks = std::make_shared<Test_Callbacks>(result, c1_c2s, client1_recv);
         Botan::TLS::Client client1(client1_callbacks,
                                    client_sessions,
                                    creds,
                                    client_policy,
                                    rng,
                                    Botan::TLS::Server_Information("localhost"),
                                    Botan::TLS::Protocol_Version::latest_dtls_version());

         bool c1_to_server_sent = false;
         const bool server_to_c1_sent = false;

         const std::vector<uint8_t> c1_to_server_magic(16, 0xC1);
         const std::vector<uint8_t> server_to_c1_magic(16, 0x42);

         size_t c1_rounds = 0;
         for(;;) {
            c1_rounds++;

            if(c1_rounds > 64) {
               result.test_failure("Still spinning in client1 loop after 64 rounds");
               return {result};
            }

            if(!c1_c2s.empty()) {
               std::vector<uint8_t> input;
               std::swap(c1_c2s, input);
               server.received_data(input.data(), input.size());
               continue;
            }

            if(!s2c.empty()) {
               std::vector<uint8_t> input;
               std::swap(s2c, input);
               client1.received_data(input.data(), input.size());
               continue;
            }

            if(!c1_to_server_sent && client1.is_active()) {
               client1.send(c1_to_server_magic);
               c1_to_server_sent = true;
            }

            if(!server_to_c1_sent && server.is_active()) {
               server.send(server_to_c1_magic);
            }

            if(!server_recv.empty() && !client1_recv.empty()) {
               result.test_bin_eq("Expected message from client1", server_recv, c1_to_server_magic);
               result.test_bin_eq("Expected message to client1", client1_recv, server_to_c1_magic);
               break;
            }
         }

         // Now client1 "goes away" (goes silent) and new client
         // connects to same server context (ie due to reuse of client source port)
         // See RFC 6347 section 4.2.8

         server_recv.clear();
         s2c.clear();

         std::vector<uint8_t> c2_c2s;
         std::vector<uint8_t> client2_recv;
         auto client2_callbacks = std::make_shared<Test_Callbacks>(result, c2_c2s, client2_recv);
         Botan::TLS::Client client2(client2_callbacks,
                                    client_sessions,
                                    creds,
                                    client_policy,
                                    rng,
                                    Botan::TLS::Server_Information("localhost"),
                                    Botan::TLS::Protocol_Version::latest_dtls_version());

         bool c2_to_server_sent = false;
         const bool server_to_c2_sent = false;

         const std::vector<uint8_t> c2_to_server_magic(16, 0xC2);
         const std::vector<uint8_t> server_to_c2_magic(16, 0x66);

         size_t c2_rounds = 0;

         for(;;) {
            c2_rounds++;

            if(c2_rounds > 64) {
               result.test_failure("Still spinning in client2 loop after 64 rounds");
               return {result};
            }

            if(!c2_c2s.empty()) {
               std::vector<uint8_t> input;
               std::swap(c2_c2s, input);
               server.received_data(input.data(), input.size());
               continue;
            }

            if(!s2c.empty()) {
               std::vector<uint8_t> input;
               std::swap(s2c, input);
               client2.received_data(input.data(), input.size());
               continue;
            }

            if(!c2_to_server_sent && client2.is_active()) {
               client2.send(c2_to_server_magic);
               c2_to_server_sent = true;
            }

            if(!server_to_c2_sent && server.is_active()) {
               server.send(server_to_c2_magic);
            }

            if(!server_recv.empty() && !client2_recv.empty()) {
               result.test_bin_eq("Expected message from client2", server_recv, c2_to_server_magic);
               result.test_bin_eq("Expected message to client2", client2_recv, server_to_c2_magic);
               break;
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls_dtls_reconnect", DTLS_Reconnection_Test);

#endif

}  // namespace

}  // namespace Botan_Tests

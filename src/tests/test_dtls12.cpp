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
#include <memory>
#include <optional>
#include <string>
#include <vector>

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
   #include <botan/tls_session_manager_stateless.h>

#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_TLS_12)

/*
These tests exercise the DTLS core without opening real UDP sockets. The test
callbacks collect bytes emitted by TLS::Client/TLS::Server, and deliver() feeds
those bytes into the peer's received_data(). Clearing, splitting, copying, or
delaying those buffers simulates datagram loss, retransmission, duplicates, and
partial flights while still running the real DTLS record, handshake, epoch, and
retransmission logic.
*/

class DTLS_Test_Callbacks final : public Botan::TLS::Callbacks {
   public:
      DTLS_Test_Callbacks(Test::Result& result, std::vector<uint8_t>& outbound, std::vector<uint8_t>& received) :
            m_result(result), m_outbound(outbound), m_received(received) {}

      void tls_emit_data(std::span<const uint8_t> bits) override {
         m_outbound.insert(m_outbound.end(), bits.begin(), bits.end());
      }

      void tls_record_received(uint64_t /*seq*/, std::span<const uint8_t> bits) override {
         m_received.insert(m_received.end(), bits.begin(), bits.end());
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         ++m_alerts;
         m_last_alert = alert;

         if(alert.is_fatal() && !m_tolerate_fatal_alerts) {
            m_result.test_failure("unexpected fatal alert: " + alert.type_string());
         }
      }

      // A DTLS server requires a non-empty peer identity to bind the cookie to.
      std::string tls_peer_network_identity() override { return "test-peer"; }

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         m_session_was_resumption = session.was_resumption();
         ++m_sessions_established;
      }

      // All DTLS timers in these tests run on this synthetic clock, which
      // moves only when a test calls advance_clock_ms. Retransmission
      // behavior is therefore independent of real scheduling delays.
      uint64_t tls_current_monotonic_clock_ms() override { return m_now_ms; }

      void advance_clock_ms(uint64_t delta) { m_now_ms += delta; }

      // For endpoints a test expects to fail; without this a fatal alert marks
      // the whole result failed.
      void tolerate_fatal_alerts() { m_tolerate_fatal_alerts = true; }

      size_t sessions_established() const { return m_sessions_established; }

      size_t alerts_received() const { return m_alerts; }

      std::optional<Botan::TLS::Alert> last_alert() const { return m_last_alert; }

      std::optional<bool> session_was_resumption() const { return m_session_was_resumption; }

   private:
      Test::Result& m_result;
      std::vector<uint8_t>& m_outbound;
      std::vector<uint8_t>& m_received;
      size_t m_sessions_established = 0;
      size_t m_alerts = 0;
      std::optional<Botan::TLS::Alert> m_last_alert;
      std::optional<bool> m_session_was_resumption;
      uint64_t m_now_ms = 0;
      bool m_tolerate_fatal_alerts = false;
};

class DTLS_PSK_Credentials final : public Botan::Credentials_Manager {
   public:
      Botan::SymmetricKey psk(const std::string& type,
                              const std::string& context,
                              const std::string& /*identity*/) override {
         if(type == "tls-server" && context == "session-ticket") {
            return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");
         }

         if(type == "tls-server" && context == "dtls-cookie-secret") {
            ++m_dtls_cookie_secret_requests;
            return m_cookie_secret_rotated ? Botan::SymmetricKey("0123456789ABCDEF0123456789ABCDEF")
                                           : Botan::SymmetricKey("4AEA5EAD279CADEB537A594DA0E9DE3A");
         }

         if(context == "localhost" && (type == "tls-client" || type == "tls-server")) {
            return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");
         }

         throw Test_Error("No PSK set for " + type + "/" + context);
      }

      size_t dtls_cookie_secret_requests() const { return m_dtls_cookie_secret_requests; }

      void rotate_cookie_secret() { m_cookie_secret_rotated = true; }

   private:
      size_t m_dtls_cookie_secret_requests = 0;
      bool m_cookie_secret_rotated = false;
};

// Settings a test wants to differ from the shared PSK-over-DTLS baseline. The
// timeouts are measured against the synthetic clock in DTLS_Test_Callbacks;
// everything else follows Botan::TLS::Policy, which the unset optionals
// below defer to.
struct DTLS_Policy_Options final {
      std::optional<size_t> max_retransmissions;
      std::optional<std::string> cipher;
      bool allow_epoch0_restart = true;
      bool reuse_session_tickets = false;
      size_t initial_timeout_ms = 1;
      size_t maximum_timeout_ms = 8;
};

class DTLS_PSK_Policy final : public Botan::TLS::Policy {
   public:
      DTLS_PSK_Policy() = default;

      explicit DTLS_PSK_Policy(DTLS_Policy_Options opts) : m_opts(std::move(opts)) {}

      std::optional<size_t> dtls_maximum_retransmissions() const override {
         // TODO(C++23) std::optional::or_else
         if(m_opts.max_retransmissions.has_value()) {
            return m_opts.max_retransmissions;
         } else {
            return Botan::TLS::Policy::dtls_maximum_retransmissions();
         }
      }

      std::vector<std::string> allowed_macs() const override { return {"AEAD"}; }

      std::vector<std::string> allowed_key_exchange_methods() const override { return {"PSK"}; }

      std::vector<std::string> allowed_ciphers() const override {
         if(m_opts.cipher.has_value()) {
            return {m_opts.cipher.value()};
         }
         return Botan::TLS::Policy::allowed_ciphers();
      }

      bool allow_tls12() const override { return false; }

      bool allow_dtls12() const override { return true; }

      bool allow_dtls_epoch0_restart() const override { return m_opts.allow_epoch0_restart; }

      bool allow_server_initiated_renegotiation() const override { return true; }

      bool allow_client_initiated_renegotiation() const override { return true; }

      bool reuse_session_tickets() const override { return m_opts.reuse_session_tickets; }

      size_t dtls_initial_timeout() const override { return m_opts.initial_timeout_ms; }

      size_t dtls_maximum_timeout() const override { return m_opts.maximum_timeout_ms; }

   private:
      DTLS_Policy_Options m_opts;
};

// The variants the tests below need. Everything not named here follows the
// baseline above.

std::shared_ptr<DTLS_PSK_Policy> dtls_policy_with_max_retransmissions(size_t limit) {
   DTLS_Policy_Options opts;
   opts.max_retransmissions = limit;
   return std::make_shared<DTLS_PSK_Policy>(std::move(opts));
}

// allow_dtls_epoch0_restart() off, which is the Policy default and the
// configuration every DTLS client runs in.
std::shared_ptr<DTLS_PSK_Policy> dtls_policy_without_epoch0_restart() {
   DTLS_Policy_Options opts;
   opts.allow_epoch0_restart = false;
   return std::make_shared<DTLS_PSK_Policy>(std::move(opts));
}

// So that a test's own find() call does not consume the ticket it is checking
// for.
std::shared_ptr<DTLS_PSK_Policy> dtls_policy_reusing_session_tickets() {
   DTLS_Policy_Options opts;
   opts.reuse_session_tickets = true;
   return std::make_shared<DTLS_PSK_Policy>(std::move(opts));
}

std::unique_ptr<Botan::TLS::Client> make_dtls_client(const std::shared_ptr<Botan::TLS::Callbacks>& callbacks,
                                                     const std::shared_ptr<Botan::TLS::Session_Manager>& sessions,
                                                     const std::shared_ptr<Botan::Credentials_Manager>& creds,
                                                     const std::shared_ptr<const Botan::TLS::Policy>& policy,
                                                     const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
   return std::make_unique<Botan::TLS::Client>(callbacks,
                                               sessions,
                                               creds,
                                               policy,
                                               rng,
                                               Botan::TLS::Server_Information("localhost"),
                                               Botan::TLS::Protocol_Version::latest_dtls_version());
}

std::unique_ptr<Botan::TLS::Server> make_dtls_server(const std::shared_ptr<Botan::TLS::Callbacks>& callbacks,
                                                     const std::shared_ptr<Botan::TLS::Session_Manager>& sessions,
                                                     const std::shared_ptr<Botan::Credentials_Manager>& creds,
                                                     const std::shared_ptr<const Botan::TLS::Policy>& policy,
                                                     const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
   return std::make_unique<Botan::TLS::Server>(callbacks, sessions, creds, policy, rng, true /* is_datagram */);
}

void deliver(Test::Result& result,
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

void deliver_copy(Test::Result& result,
                  const std::string& label,
                  const std::vector<uint8_t>& outbound,
                  Botan::TLS::Channel& peer) {
   if(!result.test_is_true(label + " has data", !outbound.empty())) {
      return;
   }

   result.test_no_throw(label, [&] { peer.received_data(outbound.data(), outbound.size()); });
}

// Hand each waiting buffer to its peer until `done` holds or both run dry.
// Bounded so that a regression cannot hang the suite.
template <typename Predicate>
bool pump_records(std::vector<uint8_t>& c2s,
                  Botan::TLS::Channel& server,
                  std::vector<uint8_t>& s2c,
                  Botan::TLS::Channel& client,
                  Predicate done,
                  size_t max_rounds = 64) {
   for(size_t i = 0; i != max_rounds; ++i) {
      if(done()) {
         return true;
      }

      if(!c2s.empty()) {
         std::vector<uint8_t> in;
         std::swap(c2s, in);
         server.received_data(in.data(), in.size());
      } else if(!s2c.empty()) {
         std::vector<uint8_t> in;
         std::swap(s2c, in);
         client.received_data(in.data(), in.size());
      } else {
         break;
      }
   }

   return done();
}

// One client/server pair plus the buffers carrying records between them. The
// buffers are declared ahead of the callbacks that write into them.
struct DTLS_Association final {
      // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
      std::vector<uint8_t> c2s;
      std::vector<uint8_t> s2c;
      std::vector<uint8_t> client_recv;
      std::vector<uint8_t> server_recv;
      std::shared_ptr<DTLS_Test_Callbacks> client_cb;
      std::shared_ptr<DTLS_Test_Callbacks> server_cb;
      std::shared_ptr<Botan::TLS::Session_Manager> client_sessions;
      std::shared_ptr<Botan::TLS::Session_Manager> server_sessions;
      std::shared_ptr<DTLS_PSK_Credentials> creds;
      // Retained so that a test can attach a further client to this server.
      std::shared_ptr<const Botan::TLS::Policy> client_policy;
      std::unique_ptr<Botan::TLS::Server> server;
      std::unique_ptr<Botan::TLS::Client> client;

      // NOLINTEND(misc-non-private-member-variables-in-classes)

      bool both_active() const { return client->is_active() && server->is_active(); }

      // Hand one waiting buffer to its peer. Returns false when both are empty.
      bool pump_one() {
         if(!c2s.empty()) {
            std::vector<uint8_t> in;
            std::swap(c2s, in);
            server->received_data(in.data(), in.size());
            return true;
         }
         if(!s2c.empty()) {
            std::vector<uint8_t> in;
            std::swap(s2c, in);
            client->received_data(in.data(), in.size());
            return true;
         }
         return false;
      }

      template <typename Predicate>
      bool pump_until(Predicate done, size_t max_rounds = 64) {
         return pump_records(c2s, *server, s2c, *client, done, max_rounds);
      }

      bool pump(size_t max_rounds = 64) {
         return pump_until([this] { return both_active(); }, max_rounds);
      }
};

// Options for the association builder. `stateless_tickets` selects a server
// that issues session tickets rather than session IDs, which is the case the
// ServerHello session ID cannot identify.
struct DTLS_Association_Options final {
      std::shared_ptr<const Botan::TLS::Policy> policy;
      std::shared_ptr<const Botan::TLS::Policy> client_policy;
      std::shared_ptr<Botan::TLS::Session_Manager> client_sessions;
      bool stateless_tickets = false;
      // For tests whose subject is a fatal alert, which otherwise fails the
      // result the moment the callbacks see it.
      bool tolerate_fatal_alerts = false;
};

std::unique_ptr<DTLS_Association> make_association(Test::Result& result,
                                                   const std::shared_ptr<Botan::RandomNumberGenerator>& rng,
                                                   DTLS_Association_Options opts = {}) {
   auto assoc = std::make_unique<DTLS_Association>();

   auto policy = opts.policy ? opts.policy : std::make_shared<DTLS_PSK_Policy>();
   assoc->client_policy = opts.client_policy ? opts.client_policy : policy;
   assoc->creds = std::make_shared<DTLS_PSK_Credentials>();

   if(opts.stateless_tickets) {
      assoc->server_sessions = std::make_shared<Botan::TLS::Session_Manager_Stateless>(assoc->creds, rng);
   } else {
      assoc->server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
   }

   assoc->client_sessions = opts.client_sessions ? std::move(opts.client_sessions)
                                                 : std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

   assoc->server_cb = std::make_shared<DTLS_Test_Callbacks>(result, assoc->s2c, assoc->server_recv);
   assoc->server = make_dtls_server(assoc->server_cb, assoc->server_sessions, assoc->creds, policy, rng);

   assoc->client_cb = std::make_shared<DTLS_Test_Callbacks>(result, assoc->c2s, assoc->client_recv);
   assoc->client = make_dtls_client(assoc->client_cb, assoc->client_sessions, assoc->creds, assoc->client_policy, rng);

   if(opts.tolerate_fatal_alerts) {
      assoc->server_cb->tolerate_fatal_alerts();
      assoc->client_cb->tolerate_fatal_alerts();
   }

   return assoc;
}

// Both endpoints under a policy other than the baseline, which is by far the
// most common reason to reach for the options above.
std::unique_ptr<DTLS_Association> make_association(Test::Result& result,
                                                   const std::shared_ptr<Botan::RandomNumberGenerator>& rng,
                                                   std::shared_ptr<const Botan::TLS::Policy> policy) {
   DTLS_Association_Options opts;
   opts.policy = std::move(policy);
   return make_association(result, rng, std::move(opts));
}

// The full cookie exchange and handshake, step by step, so that a failure names
// the flight it stalled on. Tests that only need an established association can
// use DTLS_Association::pump() instead.
bool complete_dtls_handshake(Test::Result& result, DTLS_Association& assoc, const std::string& prefix = "") {
   deliver(result, prefix + "client hello 1", assoc.c2s, *assoc.server);
   deliver(result, prefix + "hello verify request", assoc.s2c, *assoc.client);
   deliver(result, prefix + "client hello 2", assoc.c2s, *assoc.server);
   deliver(result, prefix + "server handshake flight", assoc.s2c, *assoc.client);
   deliver(result, prefix + "client final flight", assoc.c2s, *assoc.server);
   deliver(result, prefix + "server final flight", assoc.s2c, *assoc.client);

   return result.test_is_true(prefix + "handshake completed", assoc.both_active());
}

// A DTLS record with a plaintext body, ie one the record layer will either
// reject or (at epoch 0) hand straight to the handshake layer.
std::vector<uint8_t> unprotected_dtls_record(Botan::TLS::Record_Type type,
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

// A 12-byte DTLS handshake header followed by `fragment`, which may be a piece
// of the message or all of it.
std::vector<uint8_t> dtls_handshake_fragment(Botan::TLS::Handshake_Type type,
                                             size_t message_length,
                                             uint16_t message_sequence,
                                             size_t fragment_offset,
                                             std::span<const uint8_t> fragment) {
   const auto push_be24 = [](std::vector<uint8_t>& out, size_t value) {
      out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
      out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
      out.push_back(static_cast<uint8_t>(value & 0xFF));
   };

   std::vector<uint8_t> msg;
   msg.reserve(12 + fragment.size());

   msg.push_back(static_cast<uint8_t>(type));
   push_be24(msg, message_length);
   msg.push_back(static_cast<uint8_t>(message_sequence >> 8));
   msg.push_back(static_cast<uint8_t>(message_sequence));
   push_be24(msg, fragment_offset);
   push_be24(msg, fragment.size());
   msg.insert(msg.end(), fragment.begin(), fragment.end());

   return msg;
}

// A complete, unfragmented DTLS handshake message.
std::vector<uint8_t> dtls_handshake_message(Botan::TLS::Handshake_Type type,
                                            uint16_t message_sequence,
                                            std::span<const uint8_t> body) {
   return dtls_handshake_fragment(type, body.size(), message_sequence, 0, body);
}

// A record carrying only a handshake header: it declares `message_length` bytes
// but delivers none of them.
std::vector<uint8_t> empty_dtls_handshake_fragment(Botan::TLS::Handshake_Type type,
                                                   size_t message_length,
                                                   uint16_t message_sequence) {
   return unprotected_dtls_record(
      Botan::TLS::Record_Type::Handshake, 0, dtls_handshake_fragment(type, message_length, message_sequence, 0, {}));
}

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

      // Pack the handshake payloads of two DTLS records into a single record,
      // reusing the first record's header. RFC 6347 4.2.3 allows this for
      // messages "part of the same flight"; a stale duplicate is not, which is
      // the point of the test using it.
      static std::vector<uint8_t> coalesce_dtls_records(const std::vector<uint8_t>& first,
                                                        const std::vector<uint8_t>& second) {
         constexpr size_t dtls_header_len = 13;

         const size_t first_len = (static_cast<size_t>(first[11]) << 8) | first[12];
         const size_t second_len = (static_cast<size_t>(second[11]) << 8) | second[12];

         std::vector<uint8_t> record(first.begin(), first.begin() + dtls_header_len);
         record[11] = static_cast<uint8_t>((first_len + second_len) >> 8);
         record[12] = static_cast<uint8_t>(first_len + second_len);
         record.insert(record.end(), first.begin() + dtls_header_len, first.begin() + dtls_header_len + first_len);
         record.insert(record.end(), second.begin() + dtls_header_len, second.begin() + dtls_header_len + second_len);
         return record;
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

      // Time comes solely from the synthetic clock, so advancing it by the
      // reported remaining time must expire the retransmission timer.
      static void fire_retransmission_timer(Test::Result& result,
                                            DTLS_Test_Callbacks& cb,
                                            Botan::TLS::Channel& channel,
                                            std::vector<uint8_t>& outbound) {
         const auto remaining = channel.next_retransmission_timeout();
         if(!remaining.has_value()) {
            result.test_failure("DTLS retransmission timer was not armed");
            return;
         }

         cb.advance_clock_ms(static_cast<uint64_t>(remaining->count()));

         if(!channel.timeout_check() || outbound.empty()) {
            result.test_failure("DTLS retransmit was not produced");
         }
      }

      static Test::Result test_timeout_check_paces_retransmissions() {
         Test::Result result("DTLS timeout_check retransmit pacing");

         auto rng = Test::new_shared_rng("dtls-core-timeout-pacing");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& cb = *assoc->client_cb;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         deliver(result, "client hello 1", c2s, server);
         if(!result.test_is_true("hello verify request was produced", !s2c.empty())) {
            return result;
         }
         s2c.clear();  // simulate losing the HelloVerifyRequest

         // The ClientHello went out at synthetic time 0 under a 1 ms initial timeout
         result.test_is_false("timer does not fire before the initial timeout", client.timeout_check());
         result.test_is_true("no retransmit before the initial timeout", c2s.empty());

         cb.advance_clock_ms(1);
         result.test_is_true("timer fires once the initial timeout elapses", client.timeout_check());
         const auto retransmit_size = c2s.size();
         result.test_is_true("retransmission was produced", retransmit_size > 0);

         const auto rearmed = client.next_retransmission_timeout();
         if(result.test_is_true("next retransmission timeout remains available", rearmed.has_value())) {
            // RFC 6347 4.2.4.1: "double the value at each retransmission"
            result.test_sz_eq("re-armed timeout doubles the initial timeout", size_t(rearmed->count()), 2);
         }

         result.test_is_false("immediate second timeout is suppressed", client.timeout_check());
         result.test_sz_eq("no immediate second retransmit", c2s.size(), retransmit_size);

         cb.advance_clock_ms(1);
         result.test_is_false("initial interval no longer expires the timer", client.timeout_check());
         result.test_sz_eq("still no second retransmit", c2s.size(), retransmit_size);

         cb.advance_clock_ms(1);
         result.test_is_true("timer fires once the doubled timeout elapses", client.timeout_check());
         result.test_sz_eq("second retransmit was produced", c2s.size(), 2 * retransmit_size);

         return result;
      }

      static Test::Result test_retransmitted_epoch_transition_flight_includes_ccs() {
         Test::Result result("DTLS retransmitted epoch-1 flight includes CCS");

         auto rng = Test::new_shared_rng("dtls-core-retransmitted-ccs");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

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

         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);
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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         deliver(result, "client hello 1", c2s, server);
         if(!result.test_is_true("hello verify request was produced", !s2c.empty())) {
            return result;
         }
         result.test_is_true("server response is HelloVerifyRequest",
                             contains_dtls_handshake_type(s2c, Botan::TLS::Handshake_Type::HelloVerifyRequest));
         result.test_is_false("server does not arm a HelloVerifyRequest retransmission timer",
                              server.next_retransmission_timeout().has_value());
         s2c.clear();  // simulate losing the HelloVerifyRequest

         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);
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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);

         if(!result.test_is_true("server handshake flight was produced", !s2c.empty())) {
            return result;
         }
         s2c.clear();  // simulate losing the server flight

         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);
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

      // RFC 5246 7.4.1.1 says a HelloRequest is ignored by a client that is
      // already negotiating. Answering with a fatal alert instead killed a
      // server whose own HelloRequest merely crossed with our renegotiation.
      static Test::Result test_hello_request_during_handshake_is_ignored() {
         Test::Result result("DTLS HelloRequest crossing a client renegotiation");

         auto rng = Test::new_shared_rng("dtls-core-crossed-hello-request");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         if(!complete_dtls_handshake(result, *assoc)) {
            return result;
         }

         // Both sides ask to renegotiate at once. Hold the client's ClientHello
         // back so the two requests genuinely cross.
         result.test_no_throw("client starts renegotiation", [&] { client.renegotiate(true); });
         c2s.clear();

         result.test_no_throw("server sends its own HelloRequest", [&] { server.renegotiate(false); });
         result.test_is_true("server emitted a HelloRequest", !s2c.empty());

         result.test_no_throw("crossed HelloRequest is ignored", [&] {
            std::vector<uint8_t> in;
            std::swap(s2c, in);
            client.received_data(in.data(), in.size());
         });
         result.test_is_true("client produced no response to HelloRequest", c2s.empty());
         result.test_is_true("client remains active", client.is_active());
         result.test_is_false("client did not close", client.is_closed());

         return result;
      }

      // RFC 6347 4.2.1: "Note to implementors: This may result in clients
      // receiving multiple HelloVerifyRequest messages with different cookies.
      // Clients SHOULD handle this by sending a new ClientHello with a cookie
      // in response to the new HelloVerifyRequest."
      static Test::Result test_rotated_cookie_secret_produces_fresh_hello_verify_request() {
         Test::Result result("DTLS fresh HelloVerifyRequest after cookie secret rotation");

         auto rng = Test::new_shared_rng("dtls-core-rotated-cookie-secret");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         deliver(result, "client hello 1", c2s, server);
         result.test_is_true("server sent HelloVerifyRequest",
                             contains_dtls_handshake_type(s2c, Botan::TLS::Handshake_Type::HelloVerifyRequest));
         deliver(result, "hello verify request", s2c, client);

         // The cookie the client is about to present is now signed under a
         // secret the server no longer uses.
         assoc->creds->rotate_cookie_secret();

         deliver(result, "client hello 2 carrying the stale cookie", c2s, server);
         result.test_is_true("server re-challenges with a fresh HelloVerifyRequest",
                             contains_dtls_handshake_type(s2c, Botan::TLS::Handshake_Type::HelloVerifyRequest));

         deliver(result, "fresh hello verify request", s2c, client);
         if(!result.test_is_true("client answers the fresh HelloVerifyRequest", !c2s.empty())) {
            return result;
         }

         deliver(result, "client hello 3 carrying the rotated cookie", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);
         deliver(result, "server final flight", s2c, client);

         result.test_is_true("client became active", client.is_active());
         result.test_is_true("server became active", server.is_active());

         return result;
      }

      // Refusing a renegotiation is implemented by discarding the pending
      // state, which is safe only before a ChangeCipherSpec: the association
      // still owns both epochs, so dropping the handshake leaves it as it was.
      static Test::Result test_no_renegotiation_before_ccs_is_accepted() {
         Test::Result result("DTLS no_renegotiation before ChangeCipherSpec");

         auto rng = Test::new_shared_rng("dtls-core-no-reneg-pre-ccs");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         if(!complete_dtls_handshake(result, *assoc)) {
            return result;
         }

         client.renegotiate(true);
         c2s.clear();

         assoc->server->send_warning_alert(Botan::TLS::Alert::NoRenegotiation);
         deliver(result, "pre-CCS refusal is accepted", s2c, client);
         result.test_is_true("association survives the refusal", client.is_active());

         // The pending handshake is gone, so another can be started.
         result.test_no_throw("a further renegotiation can start", [&] { client.renegotiate(true); });
         result.test_is_true("it emitted a ClientHello", !c2s.empty());

         return result;
      }

      // Past a ChangeCipherSpec the pending state is all that keeps application
      // data under the new, un-Finished keys from being delivered, and there is
      // no rollback, so the association ends instead.
      static Test::Result test_no_renegotiation_after_ccs_ends_the_association() {
         Test::Result result("DTLS no_renegotiation after ChangeCipherSpec");

         auto rng = Test::new_shared_rng("dtls-core-no-reneg-post-ccs");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         if(!complete_dtls_handshake(result, *assoc)) {
            return result;
         }

         client.renegotiate(true);
         deliver(result, "renegotiation client hello", c2s, server);
         deliver(result, "renegotiation server flight", s2c, client);

         // The client has now sent its own CCS and Finished.
         result.test_is_true("client produced its final flight", !c2s.empty());
         c2s.clear();
         s2c.clear();

         server.send_warning_alert(Botan::TLS::Alert::NoRenegotiation);
         result.test_throws("post-CCS refusal ends the association", [&] {
            std::vector<uint8_t> in;
            std::swap(s2c, in);
            client.received_data(in.data(), in.size());
         });
         result.test_is_false("client is no longer active", client.is_active());

         return result;
      }

      // A HelloVerifyRequest is unauthenticated and resets the retransmission
      // counter, so without a bound a forged stream of them makes a client
      // re-send its ClientHello forever.
      static Test::Result test_hello_verify_request_flood_is_bounded() {
         Test::Result result("DTLS HelloVerifyRequest flood is bounded");

         auto rng = Test::new_shared_rng("dtls-core-hvr-flood");
         auto policy = std::make_shared<DTLS_PSK_Policy>();
         auto creds = std::make_shared<DTLS_PSK_Credentials>();

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> client_recv;
         // This client is expected to fail, so do not fail the test on its alert.
         Test::Result ignored_alerts("ignored");
         auto client_callbacks = std::make_shared<DTLS_Test_Callbacks>(ignored_alerts, c2s, client_recv);
         Botan::TLS::Client client(client_callbacks,
                                   std::make_shared<Botan::TLS::Session_Manager_Noop>(),
                                   creds,
                                   policy,
                                   rng,
                                   Botan::TLS::Server_Information("localhost"),
                                   Botan::TLS::Protocol_Version::latest_dtls_version());

         const size_t first_client_hello = c2s.size();
         result.test_is_true("client sent an initial ClientHello", first_client_hello > 0);

         const std::optional<size_t> max_hvr = policy->dtls_maximum_hello_verify_requests();
         if(!result.test_is_true("policy bounds HelloVerifyRequests", max_hvr.has_value())) {
            return result;
         }
         const size_t limit = max_hvr.value();

         size_t answered = 0;
         size_t emitted = 0;
         for(size_t i = 0; i != limit + 20; ++i) {
            // Body of a HelloVerifyRequest: version, then a cookie.
            std::vector<uint8_t> body = {0xFE, 0xFD, 0x08};
            body.insert(body.end(), 8, static_cast<uint8_t>(i));

            const auto forged = unprotected_dtls_record(
               Botan::TLS::Record_Type::Handshake,
               1000 + i,
               dtls_handshake_message(Botan::TLS::Handshake_Type::HelloVerifyRequest, static_cast<uint16_t>(i), body));
            c2s.clear();
            try {
               client.received_data(forged.data(), forged.size());
            } catch(const Botan::TLS::TLS_Exception&) {
               break;
            }
            if(!c2s.empty()) {
               answered += 1;
               emitted += c2s.size();
            }
         }

         result.test_sz_eq("client answered at most the configured number", answered, limit);
         result.test_is_true("client abandoned the handshake", client.is_closed());
         result.test_is_true("outbound traffic stayed bounded", emitted <= limit * 2 * first_client_hello);

         return result;
      }

      // Epoch numbers restart after an epoch-0 restart, so a retirement time
      // recorded for the first association's epoch 1 must not expire the second
      // association's epoch 1. Regression test: it previously did, and past the
      // retention window the restarted handshake could not complete at all.
      static Test::Result test_epoch_retirement_does_not_outlive_a_restart() {
         Test::Result result("DTLS epoch retention window survives an association restart");

         auto rng = Test::new_shared_rng("dtls-core-epoch-retirement-restart");
         auto policy = std::make_shared<DTLS_PSK_Policy>();
         auto creds = std::make_shared<DTLS_PSK_Credentials>();
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         std::vector<uint8_t> s2c;
         std::vector<uint8_t> server_recv;
         auto server_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, s2c, server_recv);
         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);

         // Drive a full handshake plus a renegotiation, which advances the
         // server to epoch 2 and so retires its epoch 1.
         auto associate = [&](const std::string& label, bool renegotiate) {
            std::vector<uint8_t> c2s;
            std::vector<uint8_t> client_recv;
            auto client_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, c2s, client_recv);
            auto client = std::make_shared<Botan::TLS::Client>(client_callbacks,
                                                               std::make_shared<Botan::TLS::Session_Manager_Noop>(),
                                                               creds,
                                                               policy,
                                                               rng,
                                                               Botan::TLS::Server_Information("localhost"),
                                                               Botan::TLS::Protocol_Version::latest_dtls_version());

            deliver(result, label + " client hello 1", c2s, server);
            deliver(result, label + " hello verify request", s2c, *client);
            deliver(result, label + " client hello 2", c2s, server);
            deliver(result, label + " server handshake flight", s2c, *client);
            deliver(result, label + " client final flight", c2s, server);
            deliver(result, label + " server final flight", s2c, *client);

            result.test_is_true(label + " client became active", client->is_active());
            result.test_is_true(label + " server became active", server.is_active());

            if(renegotiate) {
               result.test_no_throw(label + " renegotiates", [&] { client->renegotiate(true); });
               deliver(result, label + " renegotiation client hello", c2s, server);
               deliver(result, label + " renegotiation server flight", s2c, *client);
               deliver(result, label + " renegotiation client final flight", c2s, server);
               deliver(result, label + " renegotiation server final flight", s2c, *client);
               result.test_is_true(label + " still active after renegotiation",
                                   client->is_active() && server.is_active());
            }

            return client;
         };

         associate("first association", true);

         // The renegotiation is what retires epoch 1, so the test is only
         // meaningful if it actually happened.
         result.test_sz_eq(
            "handshake plus renegotiation established two sessions", server_callbacks->sessions_established(), 2);

         // Well past the RFC 6347 4.1 retention window for the retired epoch 1.
         server_callbacks->advance_clock_ms(5 * 60 * 1000);

         s2c.clear();
         associate("restarted association", false);

         result.test_sz_eq("the restart established a third session", server_callbacks->sessions_established(), 3);

         return result;
      }

      // Poll the retransmission timer forward until the handshake gives up.
      static bool run_out_the_clock(DTLS_Test_Callbacks& cb, Botan::TLS::Channel& channel) {
         for(int i = 0; i < 200; ++i) {
            cb.advance_clock_ms(50);
            try {
               channel.timeout_check();
            } catch(const Botan::TLS::TLS_Exception&) {
               return true;
            }
         }
         return false;
      }

      // Reaching the retransmission limit left the expired timer and its IO
      // installed, so every later timeout check threw again from unchanged
      // state and renegotiate() could never start another attempt.
      static Test::Result test_timed_out_initial_handshake_closes_the_channel() {
         Test::Result result("DTLS unanswered handshake closes the channel");

         auto rng = Test::new_shared_rng("dtls-core-timeout-abandon");
         auto assoc = make_association(result, rng, dtls_policy_with_max_retransmissions(2));
         auto& client = *assoc->client;

         // Nothing is ever delivered to the server, so the client retransmits
         // until its budget is spent.
         result.test_is_true("initial handshake gave up", run_out_the_clock(*assoc->client_cb, client));
         result.test_is_true("channel is closed", client.is_closed());
         result.test_no_throw("later polls are quiet", [&] { client.timeout_check(); });

         return result;
      }

      // A renegotiation that dies before any ChangeCipherSpec leaves the
      // established association intact, and another attempt can be made.
      static Test::Result test_timed_out_renegotiation_keeps_the_association() {
         Test::Result result("DTLS timed out renegotiation keeps the association");

         auto rng = Test::new_shared_rng("dtls-core-timeout-abandon-reneg");
         auto assoc = make_association(result, rng, dtls_policy_with_max_retransmissions(2));
         auto& client = *assoc->client;
         auto& c2s = assoc->c2s;

         if(!complete_dtls_handshake(result, *assoc)) {
            return result;
         }

         client.renegotiate(true);
         c2s.clear();  // the renegotiation ClientHello never arrives

         result.test_is_true("renegotiation gave up", run_out_the_clock(*assoc->client_cb, client));
         result.test_is_true("association survived", client.is_active());
         result.test_is_false("channel not closed", client.is_closed());

         result.test_no_throw("another renegotiation can start", [&] { client.renegotiate(true); });
         result.test_is_true("it emitted a ClientHello", !c2s.empty());

         return result;
      }

      // A bare handshake header declaring a zero-length message reassembles
      // completely, so it is not rejected by add_record; it fails later, when
      // the message is parsed or offered to the state machine. That route
      // reached the same teardown until the guard was widened to cover
      // delivery. The client is the exposed side: its pending IO has received
      // nothing, so the stale-epoch check cannot help it.
      static Test::Result test_forged_epoch0_message_during_renegotiation() {
         Test::Result result("DTLS forged epoch-zero message during renegotiation");

         auto rng = Test::new_shared_rng("dtls-core-forged-epoch0-message");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& server_recv = assoc->server_recv;

         if(!complete_dtls_handshake(result, *assoc)) {
            return result;
         }

         result.test_no_throw("client starts renegotiation", [&] { client.renegotiate(true); });

         // Drop the ClientHello. The client's pending IO has now received
         // nothing at all, which is the state it spends the renegotiation in.
         c2s.clear();

         // ServerHello and Certificate: the first fails in the message parser,
         // the second in the state machine. Each carries the message_seq the
         // pending IO is waiting for, so each reaches dispatch.
         const std::array<uint8_t, 2> forged_types = {0x02, 0x0B};

         for(size_t i = 0; i != forged_types.size(); ++i) {
            std::array<uint8_t, 12> header = {};
            header[0] = forged_types[i];          // msg_type
            header[5] = static_cast<uint8_t>(i);  // message_seq, in sequence
                                                  // msg_len, fragment_offset, fragment_length all zero
            const auto forged = unprotected_dtls_record(Botan::TLS::Record_Type::Handshake, 9 + i, header);

            result.test_no_throw("forged epoch-zero message is absorbed",
                                 [&] { client.received_data(forged.data(), forged.size()); });
            result.test_is_true("client remains active", client.is_active());
            result.test_is_false("client did not close", client.is_closed());
            result.test_is_true("client said nothing in reply", c2s.empty());
         }

         // The association still carries data under the established epoch. The
         // pending renegotiation may not survive being desynchronized this way,
         // but nothing unauthenticated may destroy what is already running.
         client.send("still alive");
         result.test_is_true("client can still write", !c2s.empty());
         deliver(result, "application data after the forgery", c2s, server);
         result.test_is_true("server received it", server_recv.size() == 11);

         return result;
      }

      // Plaintext epoch-zero application data is dropped before the pending
      // handshake application data gate ever sees it, on either side of a
      // renegotiation. Regression test for a review claim that it could reach
      // the gate and fatally close the association.
      static Test::Result test_forged_epoch0_appdata_during_renegotiation() {
         Test::Result result("DTLS forged epoch-zero application data during renegotiation");

         auto rng = Test::new_shared_rng("dtls-core-forged-epoch0-appdata");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;
         auto& client_recv = assoc->client_recv;
         auto& server_recv = assoc->server_recv;

         if(!complete_dtls_handshake(result, *assoc)) {
            return result;
         }

         // Both sides sit mid-renegotiation: the server has the ClientHello,
         // the client's pending IO has received nothing at all.
         result.test_no_throw("client starts renegotiation", [&] { client.renegotiate(true); });
         deliver(result, "renegotiation client hello", c2s, server);
         s2c.clear();  // hold back the server's renegotiation flight

         const std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
         const auto forged = unprotected_dtls_record(Botan::TLS::Record_Type::ApplicationData, 50, payload);

         result.test_no_throw("client absorbs the forged record",
                              [&] { client.received_data(forged.data(), forged.size()); });
         result.test_is_true("client remains active", client.is_active());
         result.test_is_true("client said nothing in reply", c2s.empty());
         result.test_is_true("client delivered nothing to the application", client_recv.empty());

         result.test_no_throw("server absorbs the forged record",
                              [&] { server.received_data(forged.data(), forged.size()); });
         result.test_is_true("server remains active", server.is_active());
         result.test_is_true("server said nothing in reply", s2c.empty());
         result.test_is_true("server delivered nothing to the application", server_recv.empty());

         // The association still carries data under the established epoch.
         client.send("still alive");
         result.test_is_true("client can still write", !c2s.empty());
         deliver(result, "application data after the forgery", c2s, server);
         result.test_is_true("server received it", server_recv.size() == 11);

         return result;
      }

      // A single forged epoch-zero record must not tear down an established
      // association while a handshake is pending, whether it is malformed at the
      // record layer or only once the new handshake IO reassembles it.
      static Test::Result test_forged_epoch0_record_during_renegotiation() {
         Test::Result result("DTLS forged epoch-zero record during renegotiation");

         auto rng = Test::new_shared_rng("dtls-core-forged-epoch0-reneg");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         if(!complete_dtls_handshake(result, *assoc)) {
            return result;
         }

         result.test_no_throw("client starts renegotiation", [&] { client.renegotiate(true); });
         deliver(result, "renegotiation client hello", c2s, server);

         // Hold the server's renegotiation flight back so that anything it emits
         // in response to the forged records below is visible on its own.
         std::vector<uint8_t> renegotiation_flight;
         std::swap(renegotiation_flight, s2c);
         result.test_is_true("server produced a renegotiation flight", !renegotiation_flight.empty());

         // A ChangeCipherSpec payload must be 0x01, so this one is malformed.
         const std::vector<uint8_t> bad_ccs_body = {0x02};
         const auto bad_ccs = unprotected_dtls_record(Botan::TLS::Record_Type::ChangeCipherSpec, 7, bad_ccs_body);
         result.test_no_throw("forged epoch-zero CCS is ignored",
                              [&] { server.received_data(bad_ccs.data(), bad_ccs.size()); });
         result.test_is_true("server remains active", server.is_active());
         result.test_is_false("server did not close", server.is_closed());
         result.test_is_true("server said nothing in reply", s2c.empty());

         // A malformed handshake fragment must be equally harmless.
         std::array<uint8_t, 12> bogus_handshake = {};
         bogus_handshake[0] = 0xFF;
         const auto forged_handshake = unprotected_dtls_record(Botan::TLS::Record_Type::Handshake, 8, bogus_handshake);
         result.test_no_throw("forged epoch-zero handshake record is ignored",
                              [&] { server.received_data(forged_handshake.data(), forged_handshake.size()); });
         result.test_is_true("server still active", server.is_active());

         // The renegotiation itself survived and can still complete.
         deliver_copy(result, "renegotiation server flight", renegotiation_flight, client);
         deliver(result, "renegotiation client final flight", c2s, server);
         deliver(result, "renegotiation server final flight", s2c, client);
         result.test_is_true("client active after renegotiation", client.is_active());
         result.test_is_true("server active after renegotiation", server.is_active());

         return result;
      }

      // RFC 6347 4.2.4: "Implementations MUST either discard or buffer all
      // application data packets for the new epoch until they have received the
      // Finished message for that epoch." Ordinary reordering produces exactly
      // that whenever a peer writes immediately after activating, so it must not
      // be fatal either.
      static Test::Result test_app_data_reordered_before_finished_is_discarded() {
         Test::Result result("DTLS application data ahead of Finished is discarded");

         auto rng = Test::new_shared_rng("dtls-core-appdata-before-finished");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;
         auto& client_recv = assoc->client_recv;

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);
         result.test_is_true("server became active", server.is_active());
         result.test_is_false("client is still waiting for Finished", client.is_active());

         // The server writes as soon as it activates, which is ordinary practice
         // from tls_session_activated().
         const std::vector<uint8_t> app_data = {0xAA, 0xBB, 0xCC};
         result.test_no_throw("server sends application data", [&] { server.send(app_data); });

         // Reorder so the application data overtakes the Finished.
         std::vector<uint8_t> ccs;
         std::vector<uint8_t> finished;
         std::vector<uint8_t> application;
         if(!split_first_dtls_record(result, s2c, ccs, finished)) {
            return result;
         }
         std::vector<uint8_t> remainder;
         if(!split_first_dtls_record(result, finished, remainder, application)) {
            return result;
         }
         finished = remainder;
         s2c.clear();

         deliver_copy(result, "change cipher spec", ccs, client);
         result.test_no_throw("application data ahead of Finished is not fatal",
                              [&] { client.received_data(application.data(), application.size()); });
         result.test_is_false("client did not close", client.is_closed());
         result.test_is_true("nothing was delivered to the application", client_recv.empty());

         // The handshake still completes, and traffic flows afterwards.
         deliver_copy(result, "finished", finished, client);
         result.test_is_true("client became active", client.is_active());

         client_recv.clear();
         result.test_no_throw("server sends again", [&] { server.send(app_data); });
         deliver(result, "application data after activation", s2c, client);
         result.test_bin_eq("delivered once the handshake completed", client_recv, app_data);

         return result;
      }

      // RFC 6347 4.1 keeps the previous epoch usable, so a peer that keeps
      // writing during a renegotiation must still be heard.
      static Test::Result test_old_epoch_app_data_during_renegotiation() {
         Test::Result result("DTLS old-epoch application data during renegotiation");

         auto rng = Test::new_shared_rng("dtls-core-appdata-old-epoch");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;
         auto& client_recv = assoc->client_recv;

         if(!complete_dtls_handshake(result, *assoc)) {
            return result;
         }

         // Server writes under the established epoch, held back.
         s2c.clear();
         const std::vector<uint8_t> app_data = {0x44, 0x55};
         result.test_no_throw("server sends application data", [&] { server.send(app_data); });
         std::vector<uint8_t> old_epoch_data;
         std::swap(old_epoch_data, s2c);

         // The client opens a renegotiation, so it has a pending handshake.
         result.test_no_throw("client starts renegotiation", [&] { client.renegotiate(true); });
         result.test_is_true("client emitted a renegotiation ClientHello", !c2s.empty());

         client_recv.clear();
         result.test_no_throw("old-epoch application data is accepted",
                              [&] { client.received_data(old_epoch_data.data(), old_epoch_data.size()); });
         result.test_bin_eq("delivered to the application", client_recv, app_data);
         result.test_is_true("client remains active", client.is_active());
         result.test_is_false("client did not close", client.is_closed());

         return result;
      }

      static Test::Result test_duplicate_server_flight_defers_to_timer() {
         Test::Result result("DTLS duplicate server flight defers replay to timer");

         auto rng = Test::new_shared_rng("dtls-core-retransmitted-server-flight");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         if(!result.test_is_true("client final flight was produced", !c2s.empty())) {
            return result;
         }
         c2s.clear();  // simulate losing the client's response flight

         fire_retransmission_timer(result, *assoc->server_cb, server, s2c);

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

         // A pending handshake deliberately does not take RFC 6347 4.2.4's
         // "read retransmit" exit; see process_previous_handshake_fragment for
         // why reordering makes that unsafe. The flight is still recoverable
         // from the local timer.
         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);
         result.test_is_true("client timer replays the lost response flight", !c2s.empty());

         return result;
      }

      static Test::Result test_lost_server_final_flight_retransmits() {
         Test::Result result("DTLS lost server final flight retransmits");

         auto rng = Test::new_shared_rng("dtls-core-lost-server-final");
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

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
         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);
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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

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
         //
         // It draws no response. Once the server has completed, the peer's last
         // flight is the one ending in its Finished, so a peer still
         // retransmitting a ClientHello cannot be asking for the final flight.
         // Answering would also let a replayed epoch-zero record pull a flight
         // out of the server without limit.
         deliver_copy(result, "stale client hello 2", cookie_client_hello, server);
         result.test_is_true("server remains active", server.is_active());
         result.test_is_true("stale ClientHello draws no response", s2c.empty());

         // Recovery still works: the client's own retransmitted final flight is
         // what asks for the server's final flight, and it is authenticated.
         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);
         deliver(result, "retransmitted client final flight", c2s, server);
         result.test_is_true("client final flight still receives a response", !s2c.empty());
         deliver(result, "server final flight", s2c, client);
         result.test_is_true("client became active", client.is_active());

         return result;
      }

      static Test::Result test_epoch0_client_hello_retransmit_while_restart_pending() {
         Test::Result result("DTLS epoch-zero ClientHello retransmit while restart pending");

         auto rng = Test::new_shared_rng("dtls-core-pending-epoch0-restart");
         auto policy = std::make_shared<DTLS_PSK_Policy>();
         auto creds = std::make_shared<DTLS_PSK_Credentials>();
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_Noop>();

         std::vector<uint8_t> s2c;
         std::vector<uint8_t> server_recv;
         auto server_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, s2c, server_recv);
         Botan::TLS::Server server(server_callbacks, server_sessions, creds, policy, rng, true);

         std::vector<uint8_t> c1_c2s;
         std::vector<uint8_t> client1_recv;
         auto client1_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, c1_c2s, client1_recv);
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
         auto client2_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, c2_c2s, client2_recv);
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
         auto policy = std::make_shared<DTLS_PSK_Policy>();
         auto creds = std::make_shared<DTLS_PSK_Credentials>();
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
         auto policy = std::make_shared<DTLS_PSK_Policy>();
         auto creds = std::make_shared<DTLS_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         run_handshake(result, rng, policy, creds, client_sessions, server_sessions, false);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, c2s, client_recv);

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
         fire_retransmission_timer(result, *server_callbacks, server, s2c);
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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         deliver(result, "client hello 1", c2s, server);
         deliver(result, "hello verify request", s2c, client);
         deliver(result, "client hello 2", c2s, server);
         deliver(result, "server handshake flight", s2c, client);
         deliver(result, "client final flight", c2s, server);

         result.test_is_true("server became active", server.is_active());
         result.test_is_false("client is waiting for server final flight", client.is_active());
         s2c.clear();  // simulate losing the server's last flight

         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);

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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

         complete_dtls_handshake(result, *assoc);

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
         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);
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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& s2c = assoc->s2c;

         complete_dtls_handshake(result, *assoc);

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
         auto assoc = make_association(result, rng);
         auto& client = *assoc->client;
         auto& server = *assoc->server;
         auto& c2s = assoc->c2s;
         auto& s2c = assoc->s2c;

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

         fire_retransmission_timer(result, *assoc->client_cb, client, c2s);
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
         auto policy = std::make_shared<DTLS_PSK_Policy>();
         auto creds = std::make_shared<DTLS_PSK_Credentials>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

         run_handshake(result, rng, policy, creds, client_sessions, server_sessions, false);

         std::vector<uint8_t> c2s;
         std::vector<uint8_t> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;

         auto server_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, c2s, client_recv);

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

         auto server_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, s2c, server_recv);
         auto client_callbacks = std::make_shared<DTLS_Test_Callbacks>(result, c2s, client_recv);

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

            fire_retransmission_timer(result, *client_callbacks, client, c2s);
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
                 test_rotated_cookie_secret_produces_fresh_hello_verify_request(),
                 test_partial_server_flight_does_not_advance_client(),
                 test_lost_server_flight_retransmits(),
                 test_duplicate_server_flight_defers_to_timer(),
                 test_hello_request_during_handshake_is_ignored(),
                 test_forged_epoch0_record_during_renegotiation(),
                 test_forged_epoch0_message_during_renegotiation(),
                 test_forged_epoch0_appdata_during_renegotiation(),
                 test_no_renegotiation_before_ccs_is_accepted(),
                 test_no_renegotiation_after_ccs_ends_the_association(),
                 test_hello_verify_request_flood_is_bounded(),
                 test_epoch_retirement_does_not_outlive_a_restart(),
                 test_timed_out_initial_handshake_closes_the_channel(),
                 test_timed_out_renegotiation_keeps_the_association(),
                 test_app_data_reordered_before_finished_is_discarded(),
                 test_old_epoch_app_data_during_renegotiation(),
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

// RFC 6347 4.2.8: a client that goes silent may be replaced by a new one
// arriving on the same 5-tuple, which the server has to take up as a fresh
// association rather than as traffic on the old one.
class DTLS_Reconnection_Test : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("DTLS reconnection");

         auto rng = Test::new_shared_rng(this->test_name());

         // Neither client caches sessions, so the second one starts a genuinely
         // new handshake rather than trying to resume.
         DTLS_Association_Options opts;
         opts.client_sessions = std::make_shared<Botan::TLS::Session_Manager_Noop>();
         auto assoc = make_association(result, rng, opts);

         auto& server = *assoc->server;

         // Run one client to completion against the shared server and exchange a
         // datagram in each direction. Bounded so a regression cannot hang.
         const auto exchange = [&](Botan::TLS::Client& client,
                                   std::vector<uint8_t>& c2s,
                                   std::vector<uint8_t>& client_recv,
                                   uint8_t to_server_byte,
                                   uint8_t to_client_byte,
                                   const std::string& label) {
            const std::vector<uint8_t> to_server(16, to_server_byte);
            const std::vector<uint8_t> to_client(16, to_client_byte);
            bool client_sent = false;
            bool server_sent = false;

            for(size_t round = 0; round != 64; ++round) {
               if(!c2s.empty()) {
                  std::vector<uint8_t> input;
                  std::swap(c2s, input);
                  server.received_data(input.data(), input.size());
               } else if(!assoc->s2c.empty()) {
                  std::vector<uint8_t> input;
                  std::swap(assoc->s2c, input);
                  client.received_data(input.data(), input.size());
               } else if(!client_sent && client.is_active()) {
                  client.send(to_server);
                  client_sent = true;
               } else if(!server_sent && server.is_active()) {
                  server.send(to_client);
                  server_sent = true;
               } else if(!assoc->server_recv.empty() && !client_recv.empty()) {
                  result.test_bin_eq("message from " + label, assoc->server_recv, to_server);
                  result.test_bin_eq("message to " + label, client_recv, to_client);
                  return true;
               } else {
                  break;  // out of input with nothing left to send
               }
            }

            result.test_failure("the " + label + " exchange did not complete");
            return false;
         };

         if(!exchange(*assoc->client, assoc->c2s, assoc->client_recv, 0xC1, 0x42, "client1")) {
            return {result};
         }
         result.test_sz_eq("client1 established a session", assoc->client_cb->sessions_established(), size_t(1));
         result.test_sz_eq("server established a session", assoc->server_cb->sessions_established(), size_t(1));

         // Now client1 goes silent and a new client connects to the same server
         // context, as happens when a client source port is reused.
         assoc->server_recv.clear();
         assoc->s2c.clear();

         std::vector<uint8_t> c2_c2s;
         std::vector<uint8_t> client2_recv;
         auto client2_cb = std::make_shared<DTLS_Test_Callbacks>(result, c2_c2s, client2_recv);
         auto client2 = make_dtls_client(client2_cb, assoc->client_sessions, assoc->creds, assoc->client_policy, rng);

         if(!exchange(*client2, c2_c2s, client2_recv, 0xC2, 0x66, "client2")) {
            return {result};
         }
         result.test_sz_eq("client2 established a session", client2_cb->sessions_established(), size_t(1));
         result.test_sz_eq("server established a second session", assoc->server_cb->sessions_established(), size_t(2));

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls_dtls_reconnect", DTLS_Reconnection_Test);

// One unauthenticated epoch-0 record, from anyone able to target the
// connection's 5-tuple, must not be able to end an established association.
class DTLS_Epoch0_Inject_Test : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(run_one("server target", true));
         results.push_back(run_one("client target", false));
         return results;
      }

   private:
      Test::Result run_one(const std::string& subtest, bool target_server) {
         Test::Result result("DTLS epoch-0 inject: " + subtest);

         auto rng = Test::new_shared_rng(this->test_name() + "/" + subtest);

         // allow_dtls_epoch0_restart() is off, which is the vulnerable
         // configuration and the default for every DTLS endpoint.
         auto assoc = make_association(result, rng, dtls_policy_without_epoch0_restart());

         result.test_is_true("DTLS handshake completed", assoc->pump());

         // The sequence number is chosen so that, immediately after handshake
         // completion, the bit at (m_window_highest - sequence) is unset and
         // already_seen() returns false. With m_window_highest = 2^48 and
         // m_window_bits = 0b1, sequence = 2^48 - 1 lands at offset 1 in the
         // window, where the bit is zero.
         const std::vector<uint8_t> body = {0xAA};
         const auto attack = unprotected_dtls_record(Botan::TLS::Record_Type::Handshake, (uint64_t(1) << 48) - 1, body);

         auto& target = target_server ? static_cast<Botan::TLS::Channel&>(*assoc->server)
                                      : static_cast<Botan::TLS::Channel&>(*assoc->client);
         result.test_no_throw("epoch-0 inject does not throw",
                              [&] { target.received_data(attack.data(), attack.size()); });

         result.test_is_true("target still active after inject", target.is_active());
         result.test_is_false("target not closed after inject", target.is_closed());

         // App data must still flow on the live keys.
         const std::vector<uint8_t> ping(8, 0xAA);
         const std::vector<uint8_t> pong(8, 0x55);
         assoc->server_recv.clear();
         assoc->client_recv.clear();
         assoc->client->send(ping);
         assoc->server->send(pong);
         result.test_is_true("app data still flows after inject", assoc->pump_until([&] {
            return assoc->server_recv == ping && assoc->client_recv == pong;
         }));

         return result;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_dtls_epoch0_inject", DTLS_Epoch0_Inject_Test);

// A spoofed epoch-0 record at the top of the 48-bit sequence space must not
// advance the read replay window past anything the legitimate peer can still
// reach, which would silently drop every later record of its handshake.
class DTLS_Epoch0_Window_Tampering_Test : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("DTLS epoch-0 window tampering");

         auto rng = Test::new_shared_rng(this->test_name());
         auto assoc = make_association(result, rng, dtls_policy_without_epoch0_restart());

         // One round-trip so the server has processed the first ClientHello and
         // its sequence numbers exist with the window highest at 0.
         result.test_is_true("client produced initial CH", !assoc->c2s.empty());
         assoc->pump_one();

         // Recentering the replay window here would drop every later
         // ClientHello and key exchange from the legitimate client.
         const std::vector<uint8_t> body = {0xAA};
         const auto attack = unprotected_dtls_record(Botan::TLS::Record_Type::Handshake, (uint64_t(1) << 48) - 1, body);
         result.test_no_throw("epoch-0 inject does not throw",
                              [&] { assoc->server->received_data(attack.data(), attack.size()); });

         result.test_is_true("handshake completed despite epoch-0 inject", assoc->pump());

         const std::vector<uint8_t> ping(8, 0xAA);
         const std::vector<uint8_t> pong(8, 0x55);
         assoc->server_recv.clear();
         assoc->client_recv.clear();
         assoc->client->send(ping);
         assoc->server->send(pong);
         result.test_is_true("app data flows after recovery", assoc->pump_until([&] {
            return assoc->server_recv == ping && assoc->client_recv == pong;
         }));

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls_dtls_epoch0_window_tamper", DTLS_Epoch0_Window_Tampering_Test);

/*
* RFC 5246 7.2.2 requires a fatally terminated connection to forget its keys and
* to become unresumable, and 7.2.1 says data arriving after a closure alert is
* ignored. These check the receive side of both, which previously only tore down
* on locally generated alerts.
*/
class TLS_Closure_Teardown_Test : public Test {
   private:
      // Session_Manager::remove() reaches application storage and is not
      // noexcept. A failure there must not be able to abort a fatal-alert
      // teardown partway through.
      class Throwing_Session_Manager final : public Botan::TLS::Session_Manager {
         public:
            explicit Throwing_Session_Manager(const std::shared_ptr<Botan::RandomNumberGenerator>& rng) :
                  Session_Manager(rng) {}

            void store(const Botan::TLS::Session& /*session*/, const Botan::TLS::Session_Handle& /*handle*/) override {}

            size_t remove(const Botan::TLS::Session_Handle& /*handle*/) override {
               throw Botan::Invalid_State("session storage is unavailable");
            }

            size_t remove_all() override { return 0; }

         protected:
            std::optional<Botan::TLS::Session> retrieve_one(const Botan::TLS::Session_Handle& /*handle*/) override {
               return std::nullopt;
            }

            std::vector<Botan::TLS::Session_with_Handle> find_some(const Botan::TLS::Server_Information& /*info*/,
                                                                   size_t /*max_sessions_hint*/) override {
               return {};
            }
      };

      Test::Result fatal_alert_teardown(const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
         Test::Result result("received fatal alert destroys connection state");

         DTLS_Association_Options opts;
         opts.tolerate_fatal_alerts = true;
         auto assoc = make_association(result, rng, opts);
         if(!result.test_is_true("handshake completed", assoc->pump())) {
            return result;
         }

         result.test_no_throw("exporter works while active",
                              [&] { assoc->client->key_material_export("test label", "", 32); });

         assoc->server->send_fatal_alert(Botan::TLS::Alert::InternalError);
         result.test_is_true("server emitted the alert", !assoc->s2c.empty());

         std::vector<uint8_t> alert;
         std::swap(assoc->s2c, alert);
         result.test_no_throw("client accepts the alert record",
                              [&] { assoc->client->received_data(alert.data(), alert.size()); });

         result.test_sz_eq("the application saw the alert", assoc->client_cb->alerts_received(), size_t(1));
         result.test_is_true("client is closed", assoc->client->is_closed());
         result.test_is_true("client is no longer active", !assoc->client->is_active());
         result.test_is_true("handshake state is gone", !assoc->client->is_handshake_complete());

         result.test_throws("exporter is refused after a fatal alert",
                            [&] { assoc->client->key_material_export("test label", "", 32); });

         return result;
      }

      // RFC 5246 7.2.2 makes a fatally terminated connection's secrets unusable,
      // but a clean close_notify does not, and TLS 1.3 keeps its exporter
      // working across one. Keying the refusal on is_closed() broke both.
      Test::Result exporter_after_clean_close(const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
         Test::Result result("exporter survives close_notify but not a fatal alert");

         DTLS_Association_Options opts;
         opts.tolerate_fatal_alerts = true;
         auto assoc = make_association(result, rng, opts);
         if(!result.test_is_true("handshake completed", assoc->pump())) {
            return result;
         }

         assoc->client->close();
         result.test_is_true("client is closed", assoc->client->is_closed());
         result.test_no_throw("exporter still works after close_notify",
                              [&] { assoc->client->key_material_export("test label", "", 32); });

         // A fatal alert is different: the teardown clears the active state, so
         // the exporter refuses on that ground too.
         auto fatal = make_association(result, rng, opts);
         if(!result.test_is_true("second handshake completed", fatal->pump())) {
            return result;
         }
         fatal->server->send_fatal_alert(Botan::TLS::Alert::InternalError);
         std::vector<uint8_t> alert;
         std::swap(fatal->s2c, alert);
         fatal->client->received_data(alert.data(), alert.size());
         result.test_throws("exporter refuses after a fatal alert",
                            [&] { fatal->client->key_material_export("test label", "", 32); });

         return result;
      }

      // The teardown touches application storage. If that throws before the
      // keys are destroyed, the channel is left half closed: inbound records
      // dropped, but is_active() still true and the write side still usable.
      Test::Result teardown_survives_a_throwing_session_manager(
         const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
         Test::Result result("fatal teardown completes despite a throwing session manager");

         DTLS_Association_Options opts;
         opts.client_sessions = std::make_shared<Throwing_Session_Manager>(rng);
         opts.tolerate_fatal_alerts = true;
         auto assoc = make_association(result, rng, opts);
         if(!result.test_is_true("handshake completed", assoc->pump())) {
            return result;
         }

         // Locally generated fatal alert, which invalidates cached sessions
         // before the channel state is torn down.
         result.test_no_throw("local fatal alert does not surface the storage failure",
                              [&] { assoc->client->send_fatal_alert(Botan::TLS::Alert::InternalError); });

         result.test_is_true("client is closed", assoc->client->is_closed());
         result.test_is_true("client is not active", !assoc->client->is_active());
         result.test_is_true("connection state is gone", !assoc->client->is_handshake_complete());
         result.test_throws("writes are refused", [&] { assoc->client->send("nope"); });
         result.test_throws("exporter is refused", [&] { assoc->client->key_material_export("test label", "", 32); });

         // And the receive side, where the callback also runs before teardown.
         DTLS_Association_Options received_opts;
         received_opts.client_sessions = std::make_shared<Throwing_Session_Manager>(rng);
         received_opts.tolerate_fatal_alerts = true;
         auto received = make_association(result, rng, received_opts);
         if(!result.test_is_true("second handshake completed", received->pump())) {
            return result;
         }
         received->server->send_fatal_alert(Botan::TLS::Alert::InternalError);
         std::vector<uint8_t> alert;
         std::swap(received->s2c, alert);
         result.test_no_throw("received fatal alert does not surface the storage failure",
                              [&] { received->client->received_data(alert.data(), alert.size()); });
         result.test_is_true("client is closed", received->client->is_closed());
         result.test_is_true("connection state is gone", !received->client->is_handshake_complete());

         return result;
      }

      Test::Result ticket_invalidated(const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
         Test::Result result("received fatal alert invalidates a ticket-backed session");

         DTLS_Association_Options opts;
         opts.policy = dtls_policy_reusing_session_tickets();
         opts.stateless_tickets = true;
         opts.tolerate_fatal_alerts = true;
         auto assoc = make_association(result, rng, opts);
         if(!result.test_is_true("handshake completed", assoc->pump())) {
            return result;
         }

         // Without reuse allowed, find() itself consumes the ticket and the
         // final check below would pass vacuously.
         const auto policy = dtls_policy_reusing_session_tickets();
         const auto cached =
            assoc->client_sessions->find(Botan::TLS::Server_Information("localhost"), *assoc->client_cb, *policy);
         if(!result.test_is_true("client cached a resumable session", !cached.empty())) {
            return result;
         }
         // The ServerHello session ID, which is all the channel used to track,
         // does not identify this session.
         result.test_is_true("the session is ticket-backed, not ID-backed", cached[0].handle.is_ticket());

         const auto recheck =
            assoc->client_sessions->find(Botan::TLS::Server_Information("localhost"), *assoc->client_cb, *policy);
         result.test_is_true("find() did not consume the ticket", !recheck.empty());

         assoc->server->send_fatal_alert(Botan::TLS::Alert::InternalError);
         std::vector<uint8_t> alert;
         std::swap(assoc->s2c, alert);
         assoc->client->received_data(alert.data(), alert.size());

         const auto after =
            assoc->client_sessions->find(Botan::TLS::Server_Information("localhost"), *assoc->client_cb, *policy);
         result.test_is_true("the ticket was removed from the client cache", after.empty());

         return result;
      }

      Test::Result data_after_close_notify(const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
         Test::Result result("data reordered behind a close_notify is ignored");

         DTLS_Association_Options opts;
         opts.tolerate_fatal_alerts = true;
         auto assoc = make_association(result, rng, opts);
         if(!result.test_is_true("handshake completed", assoc->pump())) {
            return result;
         }

         // Send application data and then close, but hand the client the
         // close_notify first. Reordering is ordinary for DTLS, and it must not
         // turn a clean shutdown into a fatal error.
         const std::string payload = "reordered";
         assoc->server->send(payload);
         std::vector<uint8_t> app_data;
         std::swap(assoc->s2c, app_data);
         result.test_is_true("app data record captured", !app_data.empty());

         assoc->server->close();
         std::vector<uint8_t> close_notify;
         std::swap(assoc->s2c, close_notify);
         result.test_is_true("close_notify record captured", !close_notify.empty());

         result.test_no_throw("client accepts the close_notify",
                              [&] { assoc->client->received_data(close_notify.data(), close_notify.size()); });
         result.test_is_true("client is closed", assoc->client->is_closed());

         result.test_no_throw("late application data is ignored, not rejected",
                              [&] { assoc->client->received_data(app_data.data(), app_data.size()); });
         result.test_is_true("the ignored data was not delivered", assoc->client_recv.empty());

         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         auto rng = Test::new_shared_rng(this->test_name());

         return {fatal_alert_teardown(rng),
                 ticket_invalidated(rng),
                 data_after_close_notify(rng),
                 exporter_after_clean_close(rng),
                 teardown_survives_a_throwing_session_manager(rng)};
      }
};

BOTAN_REGISTER_TEST("tls", "tls_closure_teardown", TLS_Closure_Teardown_Test);

#endif

}  // namespace

}  // namespace Botan_Tests

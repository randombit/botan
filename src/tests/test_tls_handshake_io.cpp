/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_12)

   #include <botan/rng.h>
   #include <botan/tls_exceptn.h>
   #include <botan/tls_handshake_msg.h>
   #include <botan/tls_magic.h>
   #include <botan/tls_policy.h>
   #include <botan/internal/concat_util.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/tls_handshake_io.h>
   #include <botan/internal/tls_seq_numbers.h>

   #include <algorithm>
   #include <cstring>
   #include <vector>

namespace Botan_Tests {

namespace {

using namespace Botan::TLS;

// Build a DTLS handshake record (12-byte header + payload). This is the
// stream-of-bytes that Datagram_Handshake_IO::add_record consumes; the
// outer DTLS record-layer header is stripped before this call.
std::vector<uint8_t> dtls_hs_record(Handshake_Type msg_type,
                                    uint32_t msg_len,
                                    uint16_t message_seq,
                                    uint32_t fragment_offset,
                                    std::span<const uint8_t> fragment_bytes) {
   const auto msg_len_bytes = Botan::store_be(msg_len);
   const auto fragment_offset_bytes = Botan::store_be(fragment_offset);
   const auto fragment_length_bytes = Botan::store_be(fragment_bytes.size());

   return Botan::concat<std::vector<uint8_t>>(Botan::store_be(msg_type),
                                              std::span{msg_len_bytes}.last<3>(),
                                              Botan::store_be(message_seq),
                                              std::span{fragment_offset_bytes}.last<3>(),
                                              std::span{fragment_length_bytes}.last<3>(),
                                              fragment_bytes);
}

class Datagram_IO_Fixture {
   public:
      static constexpr size_t k_max_handshake_msg_size = 65536;  // default TLS::Policy value

      explicit Datagram_IO_Fixture(uint64_t initial_timeout_ms = 1000,
                                   uint64_t max_timeout_ms = 60000,
                                   std::optional<size_t> max_retransmissions = std::nullopt,
                                   uint16_t mtu = 1500,
                                   size_t max_handshake_msg_size = k_max_handshake_msg_size) :
            m_io(
               [this](uint16_t, Record_Type type, const std::vector<uint8_t>& record) {
                  if(type == Record_Type::Handshake) {
                     ++m_handshake_records_sent;
                     m_sent_record_sizes.push_back(record.size());
                  }
               },
               [this]() -> uint64_t { return m_clock_ms; },
               m_seqs,
               mtu,
               initial_timeout_ms,
               max_timeout_ms,
               max_retransmissions,
               max_handshake_msg_size) {}

      void feed(std::span<const uint8_t> record, uint16_t epoch = 0) {
         const uint64_t record_seq = static_cast<uint64_t>(epoch) << 48;
         m_io.add_record(record.data(), record.size(), Record_Type::Handshake, record_seq);
      }

      std::pair<Handshake_Type, std::vector<uint8_t>> next_message() {
         return m_io.get_next_record(false, k_max_handshake_msg_size);
      }

      Datagram_Handshake_IO& io() { return m_io; }

      void advance_clock_ms(uint64_t delta) { m_clock_ms += delta; }

      uint64_t clock_ms() const { return m_clock_ms; }

      size_t handshake_records_sent() const { return m_handshake_records_sent; }

      // Sizes of the handshake payloads handed to the record layer, before
      // record framing and cipher expansion are added.
      const std::vector<size_t>& sent_record_sizes() const { return m_sent_record_sizes; }

      void reset_send_counter() {
         m_handshake_records_sent = 0;
         m_sent_record_sizes.clear();
      }

   private:
      uint64_t m_clock_ms = 0;
      size_t m_handshake_records_sent = 0;
      std::vector<size_t> m_sent_record_sizes;
      Datagram_Sequence_Numbers m_seqs;
      Datagram_Handshake_IO m_io;
};

// Minimal Handshake_Message stub for tests that need to drive sends through
// Datagram_Handshake_IO::send (and therefore exercise the timer state).
class Stub_Handshake_Message final : public Botan::TLS::Handshake_Message {
   public:
      Stub_Handshake_Message(Handshake_Type type, std::vector<uint8_t> bytes) :
            m_type(type), m_bytes(std::move(bytes)) {}

      Handshake_Type type() const override { return m_type; }

      std::vector<uint8_t> serialize() const override { return m_bytes; }

   private:
      Handshake_Type m_type;
      std::vector<uint8_t> m_bytes;
};

std::vector<Test::Result> dtls12_handshake_io_tests() {
   const auto rng = Test::new_rng("dtls12_handshake_io_tests");

   auto make_payload = [&rng](size_t len) { return rng->random_vec<std::vector<uint8_t>>(len); };

   return {
      CHECK(
         "protected handshake records respect MTU",
         [&](Test::Result& result) {
            constexpr uint16_t mtu = 1232;           // the default policy value
            constexpr size_t cipher_expansion = 48;  // matches NULL_WITH_SHA384 overhead
            constexpr size_t dtls_header = Botan::TLS::DTLS_HEADER_SIZE;

            size_t largest = 0;
            size_t largest_body = 0;

            for(size_t body = 900; body <= 1300; ++body) {
               Datagram_IO_Fixture fix(1000, 60000, std::nullopt, mtu);
               const Stub_Handshake_Message msg(Handshake_Type::Certificate, std::vector<uint8_t>(body, 0xAB));
               fix.io().send_under_epoch(msg, 1);

               for(const size_t fragment : fix.sent_record_sizes()) {
                  const size_t on_the_wire = dtls_header + fragment + cipher_expansion;
                  if(on_the_wire > largest) {
                     largest = on_the_wire;
                     largest_body = body;
                  }
               }
            }

            result.test_is_true("Something was sent", largest > 0);
            result.test_sz_lte(Botan::fmt("Largest protected record ({} bytes from {} byte body) fits within MTU ({})",
                                          largest,
                                          largest_body,
                                          mtu),
                               largest,
                               mtu);

            // Epoch zero is unprotected, so the full MTU stays available there.
            Datagram_IO_Fixture plaintext(1000, 60000, std::nullopt, mtu);
            const Stub_Handshake_Message big(Handshake_Type::ClientHello, std::vector<uint8_t>(1150, 0xCD));
            plaintext.io().send_under_epoch(big, 0);
            result.test_sz_eq(
               "unprotected message of that size is not fragmented", plaintext.sent_record_sizes().size(), size_t(1));
         }),

      CHECK("single in-order ClientHello is delivered",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               const auto payload = make_payload(64);
               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 64, 0, 0, payload));

               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("delivered ClientHello", type, Handshake_Type::ClientHello);
               result.test_bin_eq("payload matches", bytes, payload);
            }),

      CHECK("multi-fragment reassembly in order",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               const auto payload = make_payload(100);

               const std::vector<uint8_t> p1(payload.begin(), payload.begin() + 40);
               const std::vector<uint8_t> p2(payload.begin() + 40, payload.begin() + 75);
               const std::vector<uint8_t> p3(payload.begin() + 75, payload.end());

               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 100, 0, 0, p1));
               result.test_is_true("not yet complete", fix.next_message().first == Handshake_Type::None);

               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 100, 0, 40, p2));
               result.test_is_true("still not complete", fix.next_message().first == Handshake_Type::None);

               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 100, 0, 75, p3));

               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("delivered after final fragment", type, Handshake_Type::ClientHello);
               result.test_bin_eq("reassembled payload", bytes, payload);
            }),

      CHECK("out-of-order msg_seq waits for in-sequence message",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               const auto p_seq0 = make_payload(50);
               const auto p_seq1 = make_payload(60);

               // Deliver message_seq=1 first
               fix.feed(dtls_hs_record(Handshake_Type::Certificate, 60, 1, 0, p_seq1));
               result.test_is_true("seq=1 not delivered while waiting for seq=0",
                                   fix.next_message().first == Handshake_Type::None);

               // Now deliver message_seq=0; both should come out in order.
               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 50, 0, 0, p_seq0));
               auto [t0, b0] = fix.next_message();
               result.test_enum_eq("first delivery is seq=0", t0, Handshake_Type::ClientHello);
               result.test_bin_eq("seq=0 payload", b0, p_seq0);

               auto [t1, b1] = fix.next_message();
               result.test_enum_eq("second delivery is seq=1", t1, Handshake_Type::Certificate);
               result.test_bin_eq("seq=1 payload", b1, p_seq1);
            }),

      // Regression test for the asymmetric DoS reported against the
      // claim-based reassembly budget: an attacker sends header-only records
      // for future message_seq values with a large declared msg_len. Before
      // the fix, those records reserved the entire claimed msg_len against
      // m_pending_reassembly_bytes and starved the legitimate ClientHello
      // arriving at message_seq=0.
      CHECK("header-only future-seq records do not block legit ClientHello",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;

               // Enough claims to exhaust the cap: 4 * 65536 == max_pending.
               for(uint16_t seq = 1; seq <= 4; ++seq) {
                  fix.feed(dtls_hs_record(
                     Handshake_Type::ClientHello, Datagram_IO_Fixture::k_max_handshake_msg_size, seq, 0, {}));
               }
               result.test_is_true("attacker records yield no in-sequence message",
                                   fix.next_message().first == Handshake_Type::None);

               // The legit ClientHello must still get through.
               const auto payload = make_payload(40);
               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 40, 0, 0, payload));
               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("legit ClientHello delivered", type, Handshake_Type::ClientHello);
               result.test_bin_eq("legit payload intact", bytes, payload);
            }),

      // A slot's charge is fixed by its claimed msg_length no matter how few of
      // its bytes actually arrive. These fragments also arrive out of sequence,
      // and out-of-sequence slots may only use part of the budget, so however
      // many are sent the message actually being waited on still gets through.
      CHECK("sparse one-byte segments cannot starve the expected message",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;

               const std::vector<uint8_t> one_byte = {0x42};
               const uint32_t big = Datagram_IO_Fixture::k_max_handshake_msg_size;

               for(uint32_t offset = 0; offset < 40000; offset += 2) {
                  fix.feed(dtls_hs_record(Handshake_Type::Certificate, big, 1, offset, one_byte));
               }

               const auto payload = make_payload(40);
               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 40, 0, 0, payload));

               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("expected message still delivered", type, Handshake_Type::ClientHello);
               result.test_bin_eq("its body is intact", bytes, payload);
            }),

      CHECK("tiny future-seq fragments do not exhaust the reassembly budget",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;

               const std::vector<uint8_t> fragment = {0x42};

               // Saturate the reassembly window with 1-byte fragments
               // claiming max msg_len at out-of-order msg_seq values.
               for(uint16_t seq = 1; seq <= 8; ++seq) {
                  fix.feed(dtls_hs_record(
                     Handshake_Type::ClientHello, Datagram_IO_Fixture::k_max_handshake_msg_size, seq, 0, fragment));
               }
               result.test_is_true("no in-sequence delivery yet", fix.next_message().first == Handshake_Type::None);

               // The legit msg_seq=0 ClientHello must still go through.
               const std::vector<uint8_t> legit = make_payload(40);
               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 40, 0, 0, legit));
               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("legit msg_seq=0 delivered", type, Handshake_Type::ClientHello);
               result.test_bin_eq("legit body intact", bytes, legit);
            }),

      // A fragment at the far end of the message can arrive before the start;
      // filling the gap afterwards still completes the message.
      CHECK("reassembly tolerates fragments at high offset",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               const size_t big = Datagram_IO_Fixture::k_max_handshake_msg_size;
               const auto payload = make_payload(big);

               // First the trailing 1 byte at offset big-1, then the
               // leading big-1 bytes at offset 0.
               const std::vector<uint8_t> tail(payload.end() - 1, payload.end());
               const std::vector<uint8_t> head(payload.begin(), payload.end() - 1);

               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, static_cast<uint32_t>(big), 0, big - 1, tail));
               result.test_is_true("not yet complete", fix.next_message().first == Handshake_Type::None);

               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, static_cast<uint32_t>(big), 0, 0, head));
               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("delivered after gap fill", type, Handshake_Type::ClientHello);
               result.test_bin_eq("reassembled payload intact", bytes, payload);
            }),

      // Sibling check to the "tiny future-seq" test above using fully
      // delivered payloads instead of one-byte fragments; confirms the cap
      // is enforced symmetrically regardless of how much of each message
      // the attacker actually sends.
      CHECK("legitimately-large future-seq fragments are capped",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               const size_t big = Datagram_IO_Fixture::k_max_handshake_msg_size;

               // max_pending = min(4 * 65536, 16 MiB) = 256 KiB with half of it
               // available to future-seq slots, and each of these is charged
               // its claimed 64 KiB, so only two fit. Whichever exceeds the cap
               // must be dropped silently rather than throwing.
               for(uint16_t seq = 1; seq <= 5; ++seq) {
                  result.test_no_throw("oversize future-seq fragment dropped without exception", [&] {
                     fix.feed(dtls_hs_record(
                        Handshake_Type::ClientHello, static_cast<uint32_t>(big), seq, 0, make_payload(big)));
                  });
               }

               // The future-seq half of the budget is already full, so one-byte
               // fragments claiming yet another large message are refused
               // outright.
               const std::vector<uint8_t> one_byte = {0x42};
               for(uint32_t offset = 0; offset < 4000; offset += 2) {
                  fix.feed(
                     dtls_hs_record(Handshake_Type::Certificate, static_cast<uint32_t>(big), 6, offset, one_byte));
               }

               // Whatever those slots consumed, the message being waited on keeps
               // its own share of the budget.
               const auto expected = make_payload(16);
               result.test_no_throw("expected msg_seq=0 is still admitted",
                                    [&] { fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 16, 0, 0, expected)); });

               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("expected message delivered", type, Handshake_Type::ClientHello);
               result.test_bin_eq("its body is intact", bytes, expected);
            }),

      // A whole-message retransmission overlapping an already-buffered partial
      // copy adds nothing to the slot's charge, which its claimed length fixed
      // at the first fragment. Charging retransmitted bytes as new would drop,
      // near the budget ceiling, the one fragment able to complete the message,
      // stalling reassembly permanently.
      CHECK("overlapping retransmission is admitted near the budget ceiling",
            [&](Test::Result& result) {
               // max_pending = 4 * 512 = 2048, future-seq slots limited to half
               Datagram_IO_Fixture fix(1000, 60000, std::nullopt, 1500, 512);

               const auto msg = make_payload(512);

               // Consume most of the out-of-sequence half of the budget
               fix.feed(dtls_hs_record(Handshake_Type::Certificate, 512, 1, 0, make_payload(300)));
               fix.feed(dtls_hs_record(Handshake_Type::Certificate, 512, 2, 0, make_payload(300)));
               fix.feed(dtls_hs_record(Handshake_Type::Certificate, 512, 3, 0, make_payload(100)));

               // All but the tail of the awaited message
               fix.feed(dtls_hs_record(Handshake_Type::Certificate, 512, 0, 0, std::span(msg).first(500)));
               result.test_is_true("partial message not yet complete",
                                   fix.next_message().first == Handshake_Type::None);

               // The peer retransmits the message unfragmented. Were its bytes
               // charged as new this would exceed the ceiling; the slot's fixed
               // charge admits it.
               fix.feed(dtls_hs_record(Handshake_Type::Certificate, 512, 0, 0, msg));

               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("retransmitted message delivered", type, Handshake_Type::Certificate);
               result.test_bin_eq("its body is intact", bytes, msg);
            }),

      // Empty handshake messages (msg_len == 0, e.g. ServerHelloDone) use a
      // single record with fragment_length == 0; the zero-length filter must
      // not eat them.
      CHECK("empty handshake message is delivered",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               fix.feed(dtls_hs_record(Handshake_Type::ServerHelloDone, 0, 0, 0, {}));
               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("delivered ServerHelloDone", type, Handshake_Type::ServerHelloDone);
               result.test_sz_eq("no payload bytes", bytes.size(), size_t(0));
            }),

      CHECK("fragment past end of message is rejected",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               // msg_len=10 but fragment claims offset=0, length=20.
               result.template test_throws<Botan::Decoding_Error>("overflow rejected", [&] {
                  fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 10, 0, 0, make_payload(20)));
               });
            }),

      CHECK("inconsistent fragment metadata is rejected",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 50, 0, 0, make_payload(20)));
               result.template test_throws<Botan::Decoding_Error>("metadata mismatch rejected", [&] {
                  // Same message_seq but advertise a different msg_type.
                  fix.feed(dtls_hs_record(Handshake_Type::Certificate, 50, 0, 20, make_payload(10)));
               });
            }),

      // RFC 6347 4.2.3 permits overlapping retransmissions, and overlapping bytes
      // that disagree are a protocol error. For anything other than a
      // ClientHello that stays an error.
      CHECK("inconsistent overlapping bytes are rejected",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               // Partial first fragment so the slot is not yet complete; a
               // completed slot silently ignores retransmissions.
               const auto base = make_payload(50);
               const std::vector<uint8_t> first(base.begin(), base.begin() + 30);
               fix.feed(dtls_hs_record(Handshake_Type::Certificate, 50, 0, 0, first));

               auto bad = first;
               bad[10] ^= 0xFF;
               result.template test_throws<Botan::Decoding_Error>("overlap mismatch rejected", [&] {
                  fix.feed(dtls_hs_record(Handshake_Type::Certificate, 50, 0, 0, bad));
               });
            }),

      CHECK("consistent retransmits are tolerated",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               const auto p = make_payload(100);
               const std::vector<uint8_t> half1(p.begin(), p.begin() + 50);
               const std::vector<uint8_t> half2(p.begin() + 50, p.end());

               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 100, 0, 0, half1));
               // Same first half, repeated. Must not throw or alter state.
               result.test_no_throw("retransmit accepted",
                                    [&] { fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 100, 0, 0, half1)); });
               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 100, 0, 50, half2));

               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("delivered after retransmit", type, Handshake_Type::ClientHello);
               result.test_bin_eq("payload unchanged by retransmit", bytes, p);
            }),

      CHECK("msg_len above policy max is rejected",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               result.template test_throws<TLS_Exception>("oversize msg_len rejected", [&] {
                  fix.feed(dtls_hs_record(
                     Handshake_Type::ClientHello, Datagram_IO_Fixture::k_max_handshake_msg_size + 1, 0, 0, {}));
               });
            }),

      CHECK("message_seq beyond reassembly window is dropped",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;
               // Window is 16 starting at m_in_message_seq=0, so seq=16 is
               // out of window and should be silently ignored.
               result.test_no_throw("out-of-window seq is silently dropped", [&] {
                  fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 32, 16, 0, make_payload(32)));
               });
               // The legit in-sequence message still works.
               const auto p = make_payload(20);
               fix.feed(dtls_hs_record(Handshake_Type::ClientHello, 20, 0, 0, p));
               auto [type, bytes] = fix.next_message();
               result.test_enum_eq("legit message delivered", type, Handshake_Type::ClientHello);
               result.test_bin_eq("payload intact", bytes, p);
            }),

      // Once the backoff saturates at m_max_timeout, the elapsed time since the
      // last write keeps growing, so a retransmit must re-anchor it. Otherwise
      // every subsequent poll fires another one. Verify that only one retransmit
      // fires per max_timeout interval once saturated.
      CHECK(
         "timeout_check does not refire on every poll once backoff saturates",
         [&](Test::Result& result) {
            // Tight initial / max so saturation happens in 3 doublings.
            constexpr uint64_t initial_timeout = 100;
            constexpr uint64_t max_timeout = 800;
            Datagram_IO_Fixture fix(initial_timeout, max_timeout);

            // Drive a send to seed m_last_write and m_next_timeout. Step
            // the clock first so m_last_write is non-zero (the IO uses
            // m_last_write == 0 as a "nothing sent yet" sentinel).
            fix.advance_clock_ms(1);
            const Stub_Handshake_Message ch(Handshake_Type::ClientHello, std::vector<uint8_t>(32, 0xAA));
            fix.io().send(ch);
            result.test_sz_eq("one record on initial send", fix.handshake_records_sent(), size_t(1));
            fix.reset_send_counter();

            // Step the timer through the back-off ladder until it saturates.
            // Each step waits for the CURRENT m_next_timeout, which doubles
            // after every fire: 100, 200, 400, 800 ms. After the 4th fire
            // m_next_timeout caps at 800.
            for(const uint64_t step :
                {initial_timeout, 2 * initial_timeout, 4 * initial_timeout, 8 * initial_timeout}) {
               fix.advance_clock_ms(step);
               result.test_is_true("timeout_check fires at scheduled tick", fix.io().timeout_check());
            }

            result.test_sz_eq("4 retransmits during backoff ladder", fix.handshake_records_sent(), size_t(4));
            fix.reset_send_counter();

            // Now we are saturated. Without the fix, calling timeout_check
            // repeatedly without advancing the clock would refire every
            // time. With the fix, m_last_write was reset on the last fire,
            // so subsequent polls within the same max_timeout window must
            // be no-ops.
            for(int i = 0; i < 10; ++i) {
               result.test_is_true("no refire while clock is stationary", !fix.io().timeout_check());
            }
            result.test_sz_eq("no extra retransmits during stationary polls", fix.handshake_records_sent(), size_t(0));

            // Advance well past max_timeout: one more retransmit should
            // fire, then polls are quiet again until the next max_timeout
            // interval elapses.
            fix.advance_clock_ms(max_timeout + 50);
            result.test_is_true("retransmit fires once after max_timeout elapses", fix.io().timeout_check());
            result.test_sz_eq("exactly one retransmit on the post-cap fire", fix.handshake_records_sent(), size_t(1));
            fix.reset_send_counter();

            for(int i = 0; i < 10; ++i) {
               result.test_is_true("post-cap refire is also quiet on stationary clock", !fix.io().timeout_check());
            }
            result.test_sz_eq("zero refires after the post-cap fire", fix.handshake_records_sent(), size_t(0));
         }),

      // With a non-zero retransmission cap, timeout_check fires the configured
      // number of retransmits and then throws to abandon the handshake (RFC
      // 6347 4.2.4.1). This is the mechanism behind BoGo's DTLS-Retransmit-
      // Timeout tests and Policy::dtls_maximum_retransmissions().
      CHECK("timeout_check abandons the handshake after the retransmit cap",
            [&](Test::Result& result) {
               constexpr uint64_t initial_timeout = 100;
               constexpr uint64_t max_timeout = 800;
               constexpr size_t max_retransmits = 3;
               Datagram_IO_Fixture fix(initial_timeout, max_timeout, max_retransmits);

               fix.advance_clock_ms(1);
               const Stub_Handshake_Message ch(Handshake_Type::ClientHello, std::vector<uint8_t>(32, 0xAA));
               fix.io().send(ch);
               fix.reset_send_counter();

               uint64_t next = initial_timeout;
               for(size_t i = 0; i < max_retransmits; ++i) {
                  fix.advance_clock_ms(next);
                  result.test_is_true("retransmit fires while under the cap", fix.io().timeout_check());
                  next = std::min<uint64_t>(2 * next, max_timeout);
               }
               result.test_sz_eq(
                  "exactly max_retransmits retransmits fired", fix.handshake_records_sent(), max_retransmits);

               // The next expiry exceeds the cap: the handshake is abandoned.
               fix.advance_clock_ms(next);
               result.test_throws("timeout_check throws once the cap is exceeded", [&] { fix.io().timeout_check(); });
            }),

      // Forward progress (sending a new flight) resets the per-flight
      // retransmission budget, so a long handshake is not penalized for
      // retransmits it needed on earlier flights.
      CHECK("sending a new flight resets the retransmit budget",
            [&](Test::Result& result) {
               constexpr uint64_t initial_timeout = 100;
               constexpr uint64_t max_timeout = 800;
               constexpr size_t max_retransmits = 3;
               Datagram_IO_Fixture fix(initial_timeout, max_timeout, max_retransmits);

               fix.advance_clock_ms(1);
               const Stub_Handshake_Message ch(Handshake_Type::ClientHello, std::vector<uint8_t>(32, 0xAA));
               fix.io().send(ch);

               // Burn two of the three allowed retransmits.
               fix.advance_clock_ms(initial_timeout);
               result.test_is_true("first retransmit", fix.io().timeout_check());
               fix.advance_clock_ms(2 * initial_timeout);
               result.test_is_true("second retransmit", fix.io().timeout_check());

               // Forward progress: send the next flight. This resets the budget
               // and re-anchors the timer at the initial timeout.
               const Stub_Handshake_Message ch2(Handshake_Type::ClientHello, std::vector<uint8_t>(32, 0xBB));
               fix.io().send(ch2);

               // A full fresh budget of max_retransmits is now available.
               uint64_t next = initial_timeout;
               for(size_t i = 0; i < max_retransmits; ++i) {
                  fix.advance_clock_ms(next);
                  result.test_is_true("retransmit fires after budget reset", fix.io().timeout_check());
                  next = std::min<uint64_t>(2 * next, max_timeout);
               }
               fix.advance_clock_ms(next);
               result.test_throws("give-up only after the reset budget is exhausted",
                                  [&] { fix.io().timeout_check(); });
            }),

      // message_seq is 16 bits, and no legitimate handshake delivers 65536
      // messages. Once the counter wraps all further handshake input is
      // refused: a fresh message at a wrapped sequence number must not be
      // mistaken for one of the long-delivered ones.
      CHECK("message_seq wrapping onto a delivered slot does not assert",
            [&](Test::Result& result) {
               Datagram_IO_Fixture fix;

               const std::vector<uint8_t> body(4, 0x5A);
               bool all_delivered = true;
               for(size_t i = 0; i <= 0xFFFF && all_delivered; ++i) {
                  fix.feed(dtls_hs_record(Handshake_Type::Certificate, 4, static_cast<uint16_t>(i), 0, body));
                  all_delivered = (fix.next_message().first == Handshake_Type::Certificate);
               }
               result.test_is_true("every message_seq up to the wrap was delivered", all_delivered);

               // m_in_message_seq is back at 0, but the wrap refuses the record.
               fix.feed(dtls_hs_record(Handshake_Type::Certificate, 4, 0, 0, body));

               std::pair<Handshake_Type, std::vector<uint8_t>> after;
               result.test_no_throw("wrapped slot is not mistaken for a complete message",
                                    [&] { after = fix.next_message(); });
               result.test_is_true("nothing is delivered from the released slot", after.first == Handshake_Type::None);

               // format() names the message just delivered, so its guard is
               // that one exists rather than that the counter is non-zero.
               // Those differ here, and the difference used to be a reachable
               // assertion. The subtraction wraps to 65535 of its own accord,
               // which is the right sequence number for that message.
               std::vector<uint8_t> formatted;
               result.test_no_throw("format does not assert after the wrap",
                                    [&] { formatted = fix.io().format(body, Handshake_Type::Certificate); });
               if(result.test_is_true("format produced a header", formatted.size() >= 12)) {
                  const uint16_t msg_seq = (static_cast<uint16_t>(formatted[4]) << 8) | formatted[5];
                  result.test_sz_eq("it names the wrapped sequence number", msg_seq, size_t(0xFFFF));
               }
            }),

      // A caller's monotonic clock may legitimately read zero, so sending the
      // first flight at that instant must still arm the retransmission timer.
      CHECK("retransmission timer arms for a flight sent at time zero",
            [&](Test::Result& result) {
               constexpr uint64_t initial_timeout = 1000;
               Datagram_IO_Fixture fix(initial_timeout, 60000);

               result.test_sz_eq("the fixture clock starts at zero", size_t(fix.clock_ms()), size_t(0));
               result.test_is_true("no timer before anything is sent",
                                   !fix.io().next_retransmission_timeout().has_value());

               const Stub_Handshake_Message ch(Handshake_Type::ClientHello, std::vector<uint8_t>(32, 0xAA));
               fix.io().send(ch);

               const auto armed = fix.io().next_retransmission_timeout();
               result.require("timer armed by a send at time zero", armed.has_value());
               result.test_sz_eq("the full initial timeout remains", size_t(armed->count()), size_t(initial_timeout));

               fix.advance_clock_ms(initial_timeout);
               result.test_is_true("retransmit fires once the timeout elapses", fix.io().timeout_check());
               result.test_sz_eq("the flight was resent", fix.handshake_records_sent(), size_t(2));
            }),

   };
}

BOTAN_REGISTER_TEST_FN("tls", "dtls12_handshake_io", dtls12_handshake_io_tests);

}  // namespace

}  // namespace Botan_Tests

#endif

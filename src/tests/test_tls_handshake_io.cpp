/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_12)

   #include <botan/tls_handshake_msg.h>
   #include <botan/tls_magic.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/tls_handshake_io.h>
   #include <botan/internal/tls_seq_numbers.h>

   #include <algorithm>
   #include <vector>

namespace Botan_Tests {

namespace {

using namespace Botan::TLS;

class Datagram_IO_Fixture {
   public:
      explicit Datagram_IO_Fixture(uint64_t initial_timeout_ms = 1000,
                                   uint64_t max_timeout_ms = 60000,
                                   std::optional<size_t> max_retransmissions = std::nullopt,
                                   uint16_t mtu = 1500) :
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
               65536) {}

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

      // RFC 6347 4.1: "implementations MUST NOT allow the epoch to wrap, but
      // instead MUST establish a new association". Reaching 0xFFFF is legal;
      // the increment past it is refused without disturbing the counter.
      CHECK("DTLS epoch counters refuse to wrap",
            [&](Test::Result& result) {
               Datagram_Sequence_Numbers seqs;

               for(size_t i = 0; i != 0xFFFF; ++i) {
                  seqs.new_write_cipher_state();
                  seqs.new_read_cipher_state();
               }
               result.test_sz_eq("write epoch reaches the maximum", seqs.current_write_epoch(), size_t(0xFFFF));
               result.test_sz_eq("read epoch reaches the maximum", seqs.current_read_epoch(), size_t(0xFFFF));

               result.test_throws("write epoch will not wrap", [&] { seqs.new_write_cipher_state(); });
               result.test_throws("read epoch will not wrap", [&] { seqs.new_read_cipher_state(); });

               // Refusing left the counters where they were, rather than
               // rolling over onto the retained epoch 0 and reusing its keys.
               result.test_sz_eq("write epoch unchanged by the refusal", seqs.current_write_epoch(), size_t(0xFFFF));
               result.test_sz_eq("read epoch unchanged by the refusal", seqs.current_read_epoch(), size_t(0xFFFF));
               result.test_is_true("the final epoch is still writable",
                                   seqs.next_write_sequence(0xFFFF) == (uint64_t(0xFFFF) << 48));
            }),

      // Write sequence counters and replay windows are pruned as the
      // association rekeys, so a long-lived connection does not accumulate an
      // entry per epoch. Epoch 0 is exempt: a HelloVerifyRequest is written
      // under it at any point in the association's life.
      CHECK("stale DTLS epoch state is pruned",
            [&](Test::Result& result) {
               Datagram_Sequence_Numbers seqs;

               seqs.new_write_cipher_state();  // epoch 1
               seqs.next_write_sequence(1);
               seqs.new_write_cipher_state();  // epoch 2
               result.test_is_true("epoch 1 still writable one rekey later",
                                   seqs.next_write_sequence(1) == ((uint64_t(1) << 48) | 1));

               seqs.new_write_cipher_state();  // epoch 3
               result.test_throws("epoch 1 dropped two rekeys later", [&] { seqs.next_write_sequence(1); });
               result.test_is_true("epoch 2 retained", seqs.next_write_sequence(2) == (uint64_t(2) << 48));
               result.test_is_true("epoch 0 retained for HelloVerifyRequest", seqs.next_write_sequence(0) == 0);

               // Replay windows follow the same schedule. By the time a window
               // is released the epoch's cipher state is gone as well, so no
               // record under it can be decrypted to be replayed.
               const uint64_t epoch1_seq = (uint64_t(1) << 48) | 7;

               seqs.new_read_cipher_state();  // epoch 1
               seqs.read_accept(epoch1_seq);
               result.test_is_true("replay caught while the window is live", seqs.already_seen(epoch1_seq));

               seqs.new_read_cipher_state();  // epoch 2
               result.test_is_true("window survives one rekey", seqs.already_seen(epoch1_seq));

               seqs.new_read_cipher_state();  // epoch 3
               result.test_is_true("window released two rekeys later", !seqs.already_seen(epoch1_seq));
            }),

   };
}

BOTAN_REGISTER_TEST_FN("tls", "dtls12_handshake_io", dtls12_handshake_io_tests);

}  // namespace

}  // namespace Botan_Tests

#endif

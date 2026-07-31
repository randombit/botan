/*
* TLS Handshake Serialization
* (C) 2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_IO_H_
#define BOTAN_TLS_HANDSHAKE_IO_H_

#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace Botan::TLS {

class Handshake_Message;

/**
* Handshake IO Interface
*
* This interface abstracts over stream and datagram processing of handshake
* messages. It receives individual records from the channel via `add_record` and provides a
* sending interface via a callback function provided by the channel.
*
* Handshake message headers are parsed and removed in `get_next_record`. The
* result is provided back to the channel via
* `Handshake_State::get_next_handshake_msg`.
*
* `send` is used by individual handshake message implementations, which send
* themselves, as well as both client and server to dispatch CCS messaged (and
* Hello_Verify_Request in the server case). Before calling the `writer_fn`,
* `format` is called to add the handshake message header (except for CCS).
*
* The buffer returned by `send` is used to update the transcript record hash
* (where desired).
*/
class Handshake_IO {
   public:
      virtual Protocol_Version initial_record_version() const = 0;

      virtual std::vector<uint8_t> send(const Handshake_Message& msg) = 0;

      virtual std::vector<uint8_t> send_under_epoch(const Handshake_Message& msg, uint16_t epoch) = 0;

      virtual bool timeout_check() = 0;

      virtual std::optional<std::chrono::milliseconds> next_retransmission_timeout() const = 0;

      virtual bool have_more_data() const = 0;

      virtual std::vector<uint8_t> format(const std::vector<uint8_t>& handshake_msg,
                                          Handshake_Type handshake_type) const = 0;

      virtual void add_record(const uint8_t record[],
                              size_t record_len,
                              Record_Type type,
                              uint64_t sequence_number) = 0;

      /**
      * Returns (HANDSHAKE_NONE, std::vector<>()) if no message currently available
      */
      virtual std::pair<Handshake_Type, std::vector<uint8_t>> get_next_record(bool expecting_ccs,
                                                                              size_t max_message_size) = 0;

      Handshake_IO() = default;

      Handshake_IO(const Handshake_IO&) = delete;
      Handshake_IO(Handshake_IO&&) = delete;
      Handshake_IO& operator=(const Handshake_IO&) = delete;
      Handshake_IO& operator=(Handshake_IO&&) = delete;

      virtual ~Handshake_IO() = default;
};

/**
* Handshake IO for stream-based handshakes
*/
class Stream_Handshake_IO final : public Handshake_IO {
   public:
      typedef std::function<void(Record_Type, const std::vector<uint8_t>&)> writer_fn;

      explicit Stream_Handshake_IO(writer_fn writer) : m_send_hs(std::move(writer)) {}

      Protocol_Version initial_record_version() const override;

      bool timeout_check() override { return false; }

      std::optional<std::chrono::milliseconds> next_retransmission_timeout() const override { return std::nullopt; }

      bool have_more_data() const override { return !m_queue.empty(); }

      std::vector<uint8_t> send(const Handshake_Message& msg) override;

      std::vector<uint8_t> send_under_epoch(const Handshake_Message& msg, uint16_t epoch) override;

      std::vector<uint8_t> format(const std::vector<uint8_t>& handshake_msg,
                                  Handshake_Type handshake_type) const override;

      void add_record(const uint8_t record[], size_t record_len, Record_Type type, uint64_t sequence_number) override;

      std::pair<Handshake_Type, std::vector<uint8_t>> get_next_record(bool expecting_ccs,
                                                                      size_t max_message_size) override;

   private:
      std::deque<uint8_t> m_queue;
      writer_fn m_send_hs;
};

/**
* Handshake IO for datagram-based handshakes
*/
class BOTAN_TEST_API Datagram_Handshake_IO final : public Handshake_IO {
   public:
      using writer_fn = std::function<void(uint16_t, Record_Type, const std::vector<uint8_t>&)>;

      // Lambda pointing to clock function (normally TLS::Callbacks::tls_current_monotonic_clock_ms)
      using steady_clock_fn = std::function<uint64_t()>;

      // client_version(2) + random(32) + session_id length(1) + cookie length(1)
      // + cipher_suites length(2) + one suite(2) + compression_methods
      // length(1) + one method(1). RFC 6347 4.2.1 gives the DTLS ClientHello
      // layout. A shorter declared length cannot be a real ClientHello.
      static constexpr size_t MIN_CLIENT_HELLO_SIZE = 42;

      // msg_type(1) + length(3) + message_seq(2) + fragment_offset(3) +
      // fragment_length(3)
      static constexpr size_t DTLS_HANDSHAKE_HEADER_SIZE = 12;

      Datagram_Handshake_IO(writer_fn writer,
                            steady_clock_fn clock_ms,
                            class Connection_Sequence_Numbers& seq,
                            uint16_t mtu,
                            uint64_t initial_timeout_ms,
                            uint64_t max_timeout_ms,
                            std::optional<size_t> max_retransmissions,
                            size_t max_handshake_msg_size,
                            bool is_server = false,
                            uint16_t initial_epoch = 0);

      Protocol_Version initial_record_version() const override;

      bool timeout_check() override;

      std::optional<std::chrono::milliseconds> next_retransmission_timeout() const override;

      bool have_more_data() const override;

      std::vector<uint8_t> send(const Handshake_Message& msg) override;

      std::vector<uint8_t> send_under_epoch(const Handshake_Message& msg, uint16_t epoch) override;

      std::vector<uint8_t> format(const std::vector<uint8_t>& handshake_msg,
                                  Handshake_Type handshake_type) const override;

      void add_record(const uint8_t record[], size_t record_len, Record_Type type, uint64_t sequence_number) override;

      // Process previous-flight records after this IO object was retained by
      // an active DTLS association for final-flight recovery.
      void add_retransmitted_record(const uint8_t record[],
                                    size_t record_len,
                                    Record_Type type,
                                    uint64_t sequence_number);

      std::pair<Handshake_Type, std::vector<uint8_t>> get_next_record(bool expecting_ccs,
                                                                      size_t max_message_size) override;

      /**
      * Enter FINISHED after channel activation. Intermediate outgoing flights
      * are finalized implicitly when the peer's next handshake message is
      * requested. The terminal-flight sender retains reactive replay behavior.
      */
      void finalize_handshake(bool retransmit_terminal_flight);

      // Sequence number of the next handshake message to be delivered upward.
      // Zero until at least one full message has been reassembled and consumed
      // by get_next_record.
      uint16_t in_message_seq() const { return m_in_message_seq; }

   private:
      void add_record(const uint8_t record[],
                      size_t record_len,
                      Record_Type record_type,
                      uint64_t record_sequence,
                      bool retransmitted_flight);

      // Handle one fragment parsed out of an incoming record, returning true
      // if it cues a replay of our last flight.
      bool process_handshake_fragment(const uint8_t fragment[],
                                      size_t fragment_length,
                                      size_t fragment_offset,
                                      uint16_t epoch,
                                      Handshake_Type msg_type,
                                      size_t msg_length,
                                      uint16_t message_seq,
                                      bool retransmitted_flight);

      bool reassemble_retransmitted_fragment(const uint8_t fragment[],
                                             size_t fragment_length,
                                             size_t fragment_offset,
                                             uint16_t epoch,
                                             Handshake_Type msg_type,
                                             size_t msg_length,
                                             uint16_t message_seq);

      bool process_previous_handshake_fragment(const uint8_t fragment[],
                                               size_t fragment_length,
                                               size_t fragment_offset,
                                               uint16_t epoch,
                                               Handshake_Type msg_type,
                                               size_t msg_length,
                                               uint16_t message_seq,
                                               bool retransmitted_flight);

      // Drop buffered messages left over from an earlier handshake, identified
      // by an epoch below the most recently delivered one.
      void discard_stale_epoch_messages();

      void retransmit_flight(size_t flight);
      void retransmit_last_flight();
      void replay_last_flight_for_peer();

      // Index of the last completed outgoing flight, or nullopt when no
      // flight has been sent yet.
      std::optional<size_t> last_completed_flight_index() const;

      // Drop delivered reassembly slots, keeping the lowest as the epoch
      // sentinel the expecting_ccs branch of get_next_record reads.
      void prune_delivered_messages();

      // Whether this is a server that has yet to send a flight. Since a
      // HelloVerifyRequest is not retained as one, that is exactly the window
      // before a cookie has validated. Restricted to servers because a client
      // legitimately receives a HelloRequest into a fresh IO that has not sent
      // anything either.
      bool server_awaiting_first_flight() const {
         return m_is_server && m_flights.size() == 1 && m_flights.front().empty();
      }

      std::vector<uint8_t> format_fragment(const uint8_t fragment[],
                                           size_t fragment_len,
                                           uint32_t frag_offset,
                                           uint32_t msg_len,
                                           Handshake_Type type,
                                           uint16_t msg_sequence) const;

      std::vector<uint8_t> format_w_seq(const std::vector<uint8_t>& handshake_msg,
                                        Handshake_Type handshake_type,
                                        uint16_t msg_sequence) const;

      std::vector<uint8_t> send_message(uint16_t msg_seq,
                                        uint16_t epoch,
                                        Handshake_Type msg_type,
                                        const std::vector<uint8_t>& msg);

      class Handshake_Reassembly final {
         public:
            // Approximate real cost of one segment: red-black tree node holding
            // the offset key and an inline std::vector, plus that vector's own
            // heap allocation. Rounded up, since under-charging is what charging
            // for segments at all is meant to prevent.
            static constexpr size_t SEGMENT_OVERHEAD = 96;

            // Callers charge the change in charged_bytes() against the per-IO
            // reassembly budget; see recharge_reassembly_bytes.
            void add_fragment(const uint8_t fragment[],
                              size_t fragment_length,
                              size_t fragment_offset,
                              uint16_t epoch,
                              Handshake_Type msg_type,
                              size_t msg_length);

            bool complete() const;

            uint16_t epoch() const { return m_epoch; }

            // 0 until the first fragment has set the declared msg_length.
            size_t msg_length() const { return m_msg_length; }

            size_t bytes_received() const { return m_bytes_received; }

            // What this reassembly costs against the budget. Payload alone is a
            // poor proxy: a sparse segment costs far more in allocator and map
            // overhead than it holds, so 1-byte fragments at alternating offsets
            // would otherwise buy roughly a hundred times the memory the budget
            // believes it has handed out.
            // Zero once delivered: the buffers are gone, and m_bytes_received is
            // kept only as a record of what the slot held.
            size_t charged_bytes() const {
               return m_delivered ? 0 : m_bytes_received + SEGMENT_OVERHEAD * m_segments.size();
            }

            // What charged_bytes() would report after add_fragment of this
            // fragment: mirrors the merge walk without mutating, so overlap with
            // already-buffered segments is not counted twice. On paths where
            // add_fragment stores nothing it can only overestimate.
            size_t charged_bytes_after_add(size_t fragment_length, size_t fragment_offset) const;

            std::pair<Handshake_Type, std::vector<uint8_t>> message() const;

            // Release the memory buffers; called after reassembly has completed
            void release_buffers();

            bool delivered() const { return m_delivered; }

         private:
            Handshake_Type m_msg_type = Handshake_Type::None;
            size_t m_msg_length = 0;
            size_t m_bytes_received = 0;
            uint16_t m_epoch = 0;

            // Set by release_buffers. The entry lives on as an epoch sentinel
            // with its metadata intact but no bytes behind it.
            bool m_delivered = false;

            // Sparse store of received fragments keyed by offset, with the
            // invariant that segments are non-overlapping and eagerly merged
            // (no two adjacent segments). Total memory is proportional to
            // bytes actually received: a 1-byte fragment at any offset costs
            // ~1 byte of payload + std::map node overhead, never the claimed
            // msg_length. complete() iff the segments form a single span
            // [0, m_msg_length).
            std::map<size_t, std::vector<uint8_t>> m_segments;
      };

      // Add a fragment to a reassembly slot, keeping the pending-reassembly
      // budget in step with the slot's charged_bytes(). Returns false, adding
      // nothing, if the budget ceiling would be exceeded.
      bool charged_add_fragment(Handshake_Reassembly& reassembly,
                                size_t ceiling,
                                const uint8_t fragment[],
                                size_t fragment_length,
                                size_t fragment_offset,
                                uint16_t epoch,
                                Handshake_Type msg_type,
                                size_t msg_length);

      // Uncommit a reassembly buffer's bytes from the pending-reassembly budget.
      void release_reassembly_bytes(const Handshake_Reassembly& reassembly);

      // Apply the change in a reassembly's charged_bytes() to the running total.
      // Merging adjacent segments can lower it, so this goes both ways.
      void recharge_reassembly_bytes(size_t charged_before, const Handshake_Reassembly& reassembly);

      struct Message_Info final {
            Message_Info(uint16_t e, Handshake_Type mt, const std::vector<uint8_t>& msg) :
                  epoch(e), msg_type(mt), msg_bits(msg) {}

            uint16_t epoch;                 // NOLINT(*non-private-member-variable*)
            Handshake_Type msg_type;        // NOLINT(*non-private-member-variable*)
            std::vector<uint8_t> msg_bits;  // NOLINT(*non-private-member-variable*)
      };

      class Connection_Sequence_Numbers& m_seqs;
      std::map<uint16_t, Handshake_Reassembly> m_messages;
      size_t m_pending_reassembly_bytes = 0;
      std::set<uint16_t> m_ccs_epochs;

      // A retransmitted final flight may deliver CCS and Finished in either
      // order. Other terminal messages may themselves be fragmented.
      std::optional<uint16_t> m_retransmitted_ccs_epoch;
      std::optional<uint16_t> m_retransmitted_finished_epoch;
      std::map<Handshake_Type, std::pair<uint16_t, Handshake_Reassembly>> m_retransmitted_messages;
      std::vector<std::vector<uint16_t>> m_flights;
      // Each entry records where in the corresponding flight a CCS was sent
      // and the epoch under which it was transmitted.
      std::vector<std::vector<std::pair<size_t, uint16_t>>> m_flight_ccs;
      std::map<uint16_t, Message_Info> m_flight_data;

      std::optional<std::pair<uint16_t, Handshake_Reassembly>> m_retransmitted_client_hello;
      bool m_awaiting_cookie_client_hello = false;

      // message_seq of the most recently delivered ClientHello, which is what a
      // HelloVerifyRequest answering it must carry.
      std::optional<uint16_t> m_last_client_hello_msg_seq;
      bool m_finished = false;
      bool m_retransmit_terminal_flight = false;

      uint64_t m_initial_timeout = 0;
      uint64_t m_max_timeout = 0;

      // Maximum timer-driven retransmissions of the current flight before the
      // handshake is abandoned (nullopt unlimited). m_retransmit_count tracks the
      // number fired for the in-flight wait; it resets to 0 whenever a new
      // flight is sent (forward progress) and is incremented on each timeout.
      std::optional<size_t> m_max_retransmissions = 0;
      size_t m_retransmit_count = 0;

      // Time the current flight was last written, unset until one has been.
      // A caller's clock may legitimately read zero, so the absence of a write
      // cannot be spelled as a reserved timestamp.
      std::optional<uint64_t> m_last_write;

      // Flight replays the peer has cued since the current flight was sent.
      // Kept apart from the timer's own budget because the cue for it is
      // unauthenticated. See replay_last_flight_for_peer.
      size_t m_peer_replay_count = 0;

      uint64_t m_next_timeout = 0;

      uint16_t m_in_message_seq = 0;
      uint16_t m_out_message_seq = 0;

      // Whether any incoming message has been delivered. Not the same as
      // m_in_message_seq being non-zero once that counter wraps; see format().
      bool m_any_message_delivered = false;

      // Epoch in force when this handshake began. Records from the previous one
      // sit at or below it, and a Finished has to sit above it.
      uint16_t m_initial_epoch;

      // Epoch of the most recently delivered incoming handshake message. Used
      // to reject records held over from a previous handshake.
      uint16_t m_last_delivered_epoch = 0;

      writer_fn m_send_hs;
      steady_clock_fn m_steady_clock_ms;
      uint16_t m_mtu;
      size_t m_max_handshake_msg_size;
      size_t m_max_pending_reassembly;
      bool m_is_server;
};

}  // namespace Botan::TLS

#endif

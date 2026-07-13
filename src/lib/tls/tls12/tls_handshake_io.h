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
class Datagram_Handshake_IO final : public Handshake_IO {
   public:
      typedef std::function<void(uint16_t, Record_Type, const std::vector<uint8_t>&)> writer_fn;

      Datagram_Handshake_IO(writer_fn writer,
                            class Connection_Sequence_Numbers& seq,
                            uint16_t mtu,
                            uint64_t initial_timeout_ms,
                            uint64_t max_timeout_ms,
                            size_t max_handshake_msg_size) :
            m_seqs(seq),
            m_flights(1),
            m_flight_ccs(1),
            m_initial_timeout(initial_timeout_ms),
            m_max_timeout(max_timeout_ms),
            m_send_hs(std::move(writer)),
            m_mtu(mtu),
            m_max_handshake_msg_size(max_handshake_msg_size) {}

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

   private:
      void add_record(const uint8_t record[],
                      size_t record_len,
                      Record_Type record_type,
                      uint64_t record_sequence,
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

      void retransmit_flight(size_t flight);
      void retransmit_last_flight();

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

            std::pair<Handshake_Type, std::vector<uint8_t>> message() const;

            // Release the memory buffers; called after reassembly has completed
            void release_buffers();

         private:
            Handshake_Type m_msg_type = Handshake_Type::None;
            size_t m_msg_length = 0;
            size_t m_bytes_received = 0;
            uint16_t m_epoch = 0;

            // Reassembly buffer (sized to m_msg_length once known) and a parallel
            // byte-mask marking which positions have already been seen.
            std::vector<uint8_t> m_received_mask;
            std::vector<uint8_t> m_message;
      };

      struct Message_Info final {
            Message_Info(uint16_t e, Handshake_Type mt, const std::vector<uint8_t>& msg) :
                  epoch(e), msg_type(mt), msg_bits(msg) {}

            Message_Info() : epoch(0xFFFF), msg_type(Handshake_Type::None) {}

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
      bool m_retransmitted_server_hello_complete = false;
      bool m_retransmitted_server_hello_done_complete = false;
      std::vector<std::vector<uint16_t>> m_flights;
      // Each entry records where in the corresponding flight a CCS was sent
      // and the epoch under which it was transmitted.
      std::vector<std::vector<std::pair<size_t, uint16_t>>> m_flight_ccs;
      std::map<uint16_t, Message_Info> m_flight_data;

      std::optional<std::pair<uint16_t, Handshake_Reassembly>> m_retransmitted_client_hello;
      bool m_awaiting_cookie_client_hello = false;
      bool m_recreating_hello_verify_request = false;
      bool m_finished = false;
      bool m_retransmit_terminal_flight = false;

      uint64_t m_initial_timeout = 0;
      uint64_t m_max_timeout = 0;

      uint64_t m_last_write = 0;
      uint64_t m_next_timeout = 0;

      uint16_t m_in_message_seq = 0;
      uint16_t m_out_message_seq = 0;

      writer_fn m_send_hs;
      uint16_t m_mtu;
      size_t m_max_handshake_msg_size;
};

}  // namespace Botan::TLS

#endif

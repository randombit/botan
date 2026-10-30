/*
* (D)TLS Channel IO
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IO_BASE_H_
#define BOTAN_TLS_CHANNEL_IO_BASE_H_

#include <botan/internal/stl_util.h>
#include <botan/internal/tls_flight_13.h>
#include <botan/internal/tls_record_13.h>
#include <optional>

namespace Botan::TLS {

class Alert;
class Record_Layer;
class Handshake_Layer;
class Cipher_State;
struct RecordNumber;

/**
 * Channel_IO owns the record layer and handshake layer of a (D)TLS 1.3
 * channel and handles all wire-format I/O: incoming bytes are ingested via
 * copy_data() and surfaced as a stream of events via next_pending_event();
 * outgoing handshake flights, application data and alerts are emitted via the
 * send() overloads.
 */
class BOTAN_TEST_API Channel_IO {
   protected:
      /// Records that the I/O object just passes out to the channel for further
      /// processing. These records are not processed by the I/O object itself,
      /// they may be used for validation of protocol invariants, though.
      using TransparentRecords = std::variant<ChangeCipherSpec_Record,  //
                                              Alert_Record,
                                              ApplicationData_Record>;

   public:
      using ReceiveEvent = variant_append_t<TransparentRecords,  //
                                            BytesNeeded,
                                            Handshake_Message_13,
                                            Post_Handshake_Message_13>;

      static std::shared_ptr<Channel_IO> create(Connection_Side side,
                                                TLS_Flavor flavor,
                                                std::shared_ptr<const Policy> policy,
                                                std::shared_ptr<Callbacks> callbacks);

   protected:
      Channel_IO(Connection_Side side, std::shared_ptr<const Policy> policy, std::shared_ptr<Callbacks> callbacks) :
            m_policy(std::move(policy)), m_callbacks(std::move(callbacks)), m_side(side) {}

   public:
      Channel_IO(const Channel_IO&) = delete;
      Channel_IO& operator=(const Channel_IO&) = delete;
      Channel_IO(Channel_IO&&) = delete;
      Channel_IO& operator=(Channel_IO&&) = delete;

      virtual ~Channel_IO() = default;

      /// @name Ingestion of incoming data
      /// @{

      /**
       * Ingests incoming data from the network and processes it into a stream
       * of events. @sa next_pending_event().
       */
      void copy_data(std::span<const uint8_t> data);

      /**
       * Retrieves the next pending event from the processed incoming data. If
       * no more events are available, this will return a BytesNeeded event
       * indicating how many more bytes are needed to continue processing.
       */
      ReceiveEvent next_pending_event(std::optional<Transcript_Hash_State>& transcript_hash, bool handshake_complete);

      /// @}

      /// @name Emission of outgoing data
      /// @{

      /// Sends a flight of handshake messages to the peer.
      void send(std::vector<Flight::Message> flight);

      /// Sends application data to the peer.
      void send(std::span<const uint8_t> payload);

      /// Sends an alert to the peer.
      void send(const Alert& alert, bool handle_compat_mode);

      /// @}

      /// @name Traffic key updates (RFC 8446 4.6.3, RFC 9147 8.)
      /// @{

      /**
       * Processes a KeyUpdate message received from the peer: updates the read
       * keys, and schedules a reciprocal KeyUpdate if the peer requested one.
       */
      virtual void handle_key_update(const Key_Update& key_update);

      /**
       * Sends a KeyUpdate message to the peer and updates the write keys once
       * the transport allows it. Note that this assumes that post-handshake
       * messages are allowed to be sent when this is invoked.
       *
       * @param request_peer_update  whether to request a reciprocal KeyUpdate
       */
      void update_traffic_keys(bool request_peer_update);

      /// @}

      /// @name DTLS-specific state management
      /// @{

      /**
       * Whether it is currently possible to send post-handshake messages like
       * KeyUpdate or NewSessionTicket. Note that DTLS might intermittently deny
       * sending such messages while a recent KeyUpdate is not yet acknowledged.
       *
       * @returns true if post-handshake messages may be sent, false otherwise
       */
      virtual bool can_send_post_handshake_messages() const;

      /**
       * Notifies that the TLS state machine is sure that we're talking to a
       * peer using (D)TLS 1.3. Typically that is the case after receiving and
       * processing a ServerHello or a ClientHello indicating support for (D)TLS
       * 1.3.
       *
       * This is relevant for DTLS: before this point, lost records must be
       * recovered by retransmitting entire flights (1.2-style); only afterwards
       * may the ACK mechanism (RFC 9147 7.) be relied upon.
       *
       * For the case of receiving a HelloRetryRequest, use
       * notify_protocol_version_committed_and_flight_superseded().
       */
      virtual void notify_protocol_version_committed() { /* don't care */
      }

      /**
       * Like notify_protocol_version_committed(), but for the case where
       * committing message additionally supersedes the flight currently held
       * for retransmission. This is the case exactly for a HelloRetryRequest.
       *
       * This difference is only relevant for DTLS: Since the buffered flight
       * (the initial ClientHello) is superseded by the response about to be
       * sent, retransmitting it would be wrong. So in addition to committing the
       * protocol version, this method also clears the resend buffer and
       * retransmission timer.
       */
      virtual void notify_protocol_version_committed_and_flight_superseded() { /* don't care */
      }

      /**
       * Notifies that the last message completing a flight was received.
       *
       * This is relevant for DTLS: At that point, everything we need
       * was received and the ACK mechanism is no longer needed.
       */
      virtual void notify_received_complete_flight() { /* don't care */
      }

      /**
       * Notifies that a complete flight was received that expects no response,
       * i.e., the final flight of the peer (the client's Finished).
       *
       * This is relevant for DTLS: since there is no response flight
       * that would implicitly acknowledge it, the flight must be acknowledged
       * explicitly with an ACK message.
       */
      virtual void notify_received_final_flight() { /* don't care */
      }

      std::optional<Epoch0_SequenceNumbers> epoch0_sequence_numbers() const;

      /// @}

      /**
       * Notifies that the channel is closed for reading (close_notify received).
       * The IO can discard any read-side state; no further data will be processed.
       */
      void notify_closed_for_reading();

      void set_cipher_state(std::weak_ptr<Cipher_State> cipher_state) { m_cipher_state = std::move(cipher_state); }

      void set_record_size_limits(uint16_t out, uint16_t in);
      void set_selected_certificate_type(Certificate_Type cert_type);

   protected:
      std::optional<ReceiveEvent> next_pending_handshake_message(std::optional<Transcript_Hash_State>& transcript_hash,
                                                                 bool handshake_complete);

      /// Sends a dummy ChangeCipherSpec record to the peer.
      void send_dummy_change_cipher_spec();

      virtual void process(const Handshake_Record& record) = 0;
      virtual void process(const ACK_Record& ack_record) = 0;
      virtual void validate(const TransparentRecords& record) const;

      virtual void send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) = 0;

      virtual void send_flight(std::vector<Flight::Message> flight) = 0;

      /// Marshalls and sends the given KeyUpdate message, then advances the
      /// write epoch.
      virtual void send_key_update(const Key_Update& msg) = 0;

      virtual Record_Layer& record_layer() = 0;

      virtual Handshake_Layer& handshake_layer() = 0;

      virtual const Record_Layer& record_layer() const = 0;

      virtual const Handshake_Layer& handshake_layer() const = 0;

      std::shared_ptr<const Cipher_State> cipher_state() const;
      std::shared_ptr<Cipher_State> cipher_state();

      const Policy& policy() const { return *m_policy; }

      const Callbacks& callbacks() const { return *m_callbacks; }

      Callbacks& callbacks() { return *m_callbacks; }

   private:
      void maybe_send_opportunistic_key_update();

   private:
      bool m_first_message_delivered = false;

      /**
       * True once the peer sent close_notify and notify_closed_for_reading()
       * was called. From then on, any further incoming data is ignored.
       * See RFC 9846 6.1.
       */
      bool m_closed_for_reading = false;

      /**
       * True if a dummy CCS record has been sent to the peer already.
       * See RFC 9846 E.4 for details.
       */
      bool m_dummy_ccs_emitted = false;

      /**
       * True if the peer requested a KeyUpdate that we have yet to reciprocate
       * before sending our next application data record.
       */
      bool m_key_update_reciprocation_pending = false;

      /**
       * True while a KeyUpdate with "update_requested" is outstanding, i.e.
       * the peer has not yet replied with a KeyUpdate of its own.
       */
      bool m_key_update_requested = false;

      uint64_t m_last_peer_key_update_ms = 0;

      std::weak_ptr<Cipher_State> m_cipher_state;
      std::shared_ptr<const Policy> m_policy;
      std::shared_ptr<Callbacks> m_callbacks;
      Connection_Side m_side;
};

}  // namespace Botan::TLS

#endif

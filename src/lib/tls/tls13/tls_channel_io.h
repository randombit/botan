/*
* TLS Channel IO
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IO_BASE_H_
#define BOTAN_TLS_CHANNEL_IO_BASE_H_

#include <botan/internal/tls_flight_13.h>
#include <botan/internal/tls_record_13.h>
#include <optional>

namespace Botan::TLS {

class Alert;
class Record_Layer;
class Handshake_Layer;
class Cipher_State;

/**
 * Channel_IO owns the record layer and handshake layer of a (D)TLS 1.3
 * channel and handles all wire-format I/O: incoming bytes are ingested via
 * copy_data() and surfaced as a stream of events via next_pending_event();
 * outgoing handshake flights, application data and alerts are emitted via the
 * send() overloads.
 */
class Channel_IO {
   public:
      using ReceiveEvent = std::variant<BytesNeeded,
                                        Handshake_Message_13,
                                        Post_Handshake_Message_13,
                                        ChangeCipherSpec_Record,
                                        Alert_Record,
                                        ApplicationData_Record>;

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

      /// Sends a dummy ChangeCipherSpec record to the peer.
      void send_dummy_change_cipher_spec();

      /// @}

      /// @name Traffic key updates (RFC 8446 4.6.3)
      /// @{

      /**
       * Processes a KeyUpdate message received from the peer: updates the read
       * keys, and schedules a reciprocal KeyUpdate if the peer requested one.
       */
      void handle_key_update(const Key_Update& key_update);

      /**
       * Sends a KeyUpdate message to the peer and updates the write keys.
       *
       * @param request_peer_update  whether to request a reciprocal KeyUpdate
       */
      void update_traffic_keys(bool request_peer_update);

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

      virtual void process(const Handshake_Record& record) = 0;

      virtual void send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) = 0;

      virtual void send_flight(std::vector<Flight::Message> flight) = 0;

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
      bool needs_traffic_based_key_update() const;

   private:
      bool m_first_message_delivered = false;

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

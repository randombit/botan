/*
* TLS Channel I/O
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_io.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_record_layer_13.h>
#include <botan/internal/tls_transcript_hash_13.h>

namespace Botan::TLS {

std::optional<Channel_IO::ReceiveEvent> Channel_IO::next_pending_handshake_message(
   std::optional<Transcript_Hash_State>& transcript_hash, bool handshake_complete) {
   auto& hs_layer = handshake_layer();
   auto& rec_layer = record_layer();

   if(!handshake_complete) {
      BOTAN_ASSERT_NOMSG(transcript_hash.has_value());

      // TODO(C++23): use std::optional::transform() here
      auto handshake_msg = hs_layer.next_message(policy(), *transcript_hash);
      if(!handshake_msg.has_value()) {
         return std::nullopt;
      }

      // After the initial handshake message is received, the record
      // layer must be more restrictive.
      // See RFC 9846 5.1 regarding "legacy_record_version"
      if(!m_first_message_delivered) {
         // TODO: Consider always calling disable_receiving_compat_mode
         // to get rid of m_first_message_delivered
         rec_layer.disable_receiving_compat_mode();
         m_first_message_delivered = true;
      }

      return std::move(handshake_msg).value();
   } else {
      auto cs = cipher_state();
      BOTAN_ASSERT_NONNULL(cs);

      // TODO(C++23): use std::optional::transform() here
      auto post_handshake_msg = hs_layer.next_post_handshake_message(policy(), cs->current_read_epoch_number());
      if(!post_handshake_msg.has_value()) {
         return std::nullopt;
      }

      return std::move(post_handshake_msg).value();
   }
}

void Channel_IO::copy_data(std::span<const uint8_t> data) {
   // RFC 9846 6.1
   //    Any data received after a closure alert has been received MUST
   //    be ignored.
   if(m_closed_for_reading) {
      return;
   }

   const auto cs = cipher_state();
   const auto has_cryptographic_association = (cs != nullptr) && cs->has_cryptographic_association();

   record_layer().copy_data(data, has_cryptographic_association);
}

Channel_IO::ReceiveEvent Channel_IO::next_pending_event(std::optional<Transcript_Hash_State>& transcript_hash,
                                                        bool handshake_complete) {
   const auto cs = cipher_state();

   while(true) {
      // First we check if the handshake layer has any complete messages ready
      // to be consumed by the channel. If yes, we return that message....
      if(auto event = next_pending_handshake_message(transcript_hash, handshake_complete)) {
         // Handshake messages can be directly consumed by the channel
         return std::move(event).value();
      }

      // ... otherwise we check if the record layer has any complete records
      // ready to be processed. If yes, we dispatch the record to the
      // appropriate handler or return it to the channel (e.g. application data,
      // alerts, etc.). If no complete record is available, we return a
      // BytesNeeded event which indicates that no more events are available and
      // the channel needs to wait for the application to provide more data.
      auto res = std::visit(  //
         overloaded{
            [](BytesNeeded bytes) -> std::optional<Channel_IO::ReceiveEvent> { return bytes; },
            [&](const Handshake_Record& record) -> std::optional<Channel_IO::ReceiveEvent> {
               process(record);
               return std::nullopt;  // continue looping, the handshake layer may have progressed...
            },
            [&](TransparentRecord anything_else) -> std::optional<Channel_IO::ReceiveEvent> {
               validate(anything_else);
               return generalize_to<Channel_IO::ReceiveEvent>(std::move(anything_else));
            },
         },
         record_layer().next_record(cs.get()));

      if(res.has_value()) {
         return std::move(res).value();
      }
   }
}

void Channel_IO::send(std::vector<Flight::Message> flight) {
   send_flight(std::move(flight));
}

void Channel_IO::send(std::span<const uint8_t> payload) {
   const auto cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);
   maybe_send_opportunistic_key_update();
   send_data(Record_Type::ApplicationData, payload, cs.get());
}

void Channel_IO::maybe_send_opportunistic_key_update() {
   // In DTLS we cannot send KeyUpdates while a previous one is not yet
   // acknowledged. In that case, we skip the opportunistic update silently and
   // try again whenever the application sends more data.
   if(!can_send_post_handshake_messages()) {
      return;
   }

   const auto cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);

   // RFC 9846 5.5
   //    There are cryptographic limits on the amount of plaintext which can be
   //    safely encrypted under a given set of keys. [...] Implementations MUST
   //    either close the connection or do a key update as described in Section
   //    4.7.3 prior to reaching these limits.
   //
   // The ChaCha-based suites don't have any practical usage limit but we apply
   // the limit for all suites for simplicity. A limit of 0 means that the
   // policy disabled traffic-based key updates altogether.
   const uint64_t write_limit = policy().records_per_traffic_key();

   const bool write_limit_reached = write_limit > 0 && cs->current_write_sequence_number() >= write_limit;

   const auto read_limit_reached = [&] {
      // The read threshold is set above the write-side limit so that a peer
      // which tracks its own write limit will normally have rotated its keys
      // already, avoiding a redundant key update crossing ours in flight.
      const uint64_t read_limit = write_limit + write_limit / 2;
      return write_limit > 0 && cs->current_read_sequence_number() >= read_limit;
   };

   // RFC 9846 4.7.3
   //    If the request_update field [of a received KeyUpdate] is set to
   //    "update_requested", then the receiver MUST send a KeyUpdate of its own
   //    with request_update set to "update_not_requested" prior to sending its
   //    next Application Data record. This mechanism allows either side to
   //    force an update to the entire connection, but causes an implementation
   //    which receives multiple KeyUpdates while it is silent to respond with
   //    a single update.
   //
   //    Until receiving a subsequent KeyUpdate from the peer, the sender MUST
   //    NOT send another KeyUpdate with [...] "update_requested".
   //
   // Requesting an update is also pointless if the peer half-closed its
   // connection already, as it won't send any more records anyway.
   const bool may_request_peer_update =
      !m_key_update_reciprocation_pending && !m_key_update_requested && cs->can_decrypt_application_traffic();

   // We cannot update the read keys ourselves, all we can do is request the
   // peer to update its write keys. We do that alongside any update of our own
   // write keys, provided that we are allowed to request one.
   const bool request_peer_update = may_request_peer_update &&  //
                                    (write_limit_reached ||     //
                                     read_limit_reached());

   if(m_key_update_reciprocation_pending || write_limit_reached || request_peer_update) {
      update_traffic_keys(request_peer_update);
   }
}

void Channel_IO::handle_key_update(const Key_Update& key_update) {
   const auto cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);

   // A non-requesting KeyUpdate received while our own request is outstanding
   // is the reciprocation we solicited. It is exempt from rate limiting (and
   // invisible to it), so that a peer whose own key update crossed ours in
   // flight is not penalized for the resulting back to back KeyUpdates.
   const bool solicited_reciprocation = m_key_update_requested && !key_update.expects_reciprocation();

   if(const uint64_t min_interval = policy().minimum_key_update_interval_ms();
      min_interval > 0 && !solicited_reciprocation) {
      const uint64_t now = callbacks().tls_current_monotonic_clock_ms();

      if(m_last_peer_key_update_ms != 0 && (now - m_last_peer_key_update_ms) < min_interval) {
         throw TLS_Exception(Alert::UnexpectedMessage, "Peer is requesting KeyUpdates too frequently");
      }

      m_last_peer_key_update_ms = now;
   }

   cs->update_read_keys();

   if(key_update.expects_reciprocation() && cs->can_encrypt_application_traffic()) {
      // RFC 9846 4.7.3
      //    If the request_update field is set to "update_requested", then the
      //    receiver MUST send a KeyUpdate of its own with request_update set to
      //    "update_not_requested" prior to sending its next Application Data
      //    record.
      //
      // This happens opportunistically in send(), and only if we can (still)
      // encrypt application data. If we half-closed the connection on our side
      // we cannot reciprocate the key update any longer.
      m_key_update_reciprocation_pending = true;
   } else {
      // Only an actual reciprocation settles our outstanding request. RFC 9846
      // 4.7.3 would allow requesting again after any KeyUpdate from the peer,
      // but waiting for the reciprocation keeps the exemption above one-shot.
      m_key_update_requested = false;
   }
}

void Channel_IO::update_traffic_keys(bool request_peer_update) {
   BOTAN_ASSERT_NOMSG(can_send_post_handshake_messages());

   const auto cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);

   const auto key_update = Key_Update(request_peer_update);
   callbacks().tls_inspect_handshake_msg(key_update);
   send_key_update(key_update);

   if(request_peer_update) {
      m_key_update_requested = true;
   } else {
      // Any KeyUpdate with "update_not_requested" satisfies a pending request
      // of the peer (RFC 9846 4.7.3).
      m_key_update_reciprocation_pending = false;
   }
}

bool Channel_IO::can_send_post_handshake_messages() const {
   // RFC 9846 4.7
   //    TLS also allows other messages to be sent after the main handshake.
   //    These messages use a handshake content type and are encrypted under the
   //    appropriate application traffic key.
   auto cs = cipher_state();
   return cs != nullptr && cs->is_handshake_complete() && cs->can_encrypt_application_traffic();
}

void Channel_IO::send(const Alert& alert, bool handle_compat_mode) {
   const auto cs = cipher_state();

   // RFC 9846 E.4
   //    [...] the client sends a dummy change_cipher_spec record [...]
   //    immediately before its second flight. [...]
   //    The server sends a dummy change_cipher_spec record immediately after
   //    its first handshake message.
   //
   // For the client, the "second flight" might be an alert that aborts the
   // handshake (e.g., from a failing certificate verification or a throwing
   // callback). The server isn't expected to emit an alert immediately after
   // its first handshake message, hence it is not handled here.
   //
   // Also, the dummy CCS is only sent if the handshake actually produced a
   // cipher state: i.e., only if we would actually encrypt now.
   if(handle_compat_mode && !m_dummy_ccs_emitted && m_side == Connection_Side::Client && cs != nullptr) {
      send_dummy_change_cipher_spec();
   }

   send_data(Record_Type::Alert, alert.serialize(), cs.get());
}

void Channel_IO::send_dummy_change_cipher_spec() {
   // RFC 9846 5.
   //    An implementation which [...] receives a protected change_cipher_spec
   //    record MUST abort the handshake [...].
   //
   // I.e. Change Cipher Spec records must always be sent unprotected, even if
   // the cipher state is already set up for handshake message encryption.
   constexpr auto ccs = std::array<uint8_t, 1>{0x01};
   send_data(Record_Type::ChangeCipherSpec, ccs, nullptr);
   m_dummy_ccs_emitted = true;
}

void Channel_IO::notify_closed_for_reading() {
   record_layer().clear_read_buffer();
   m_closed_for_reading = true;
}

void Channel_IO::notify_closed_for_writing() {}

void Channel_IO::set_record_size_limits(uint16_t out, uint16_t in) {
   record_layer().set_record_size_limits(out, in);
}

void Channel_IO::set_selected_certificate_type(Certificate_Type cert_type) {
   handshake_layer().set_selected_certificate_type(cert_type);
}

std::optional<Epoch0_SequenceNumbers> Channel_IO::epoch0_sequence_numbers() const {
   return record_layer().epoch0_sequence_numbers();
}

std::shared_ptr<const Cipher_State> Channel_IO::cipher_state() const {
   return m_cipher_state.lock();
}

std::shared_ptr<Cipher_State> Channel_IO::cipher_state() {
   return m_cipher_state.lock();
}

namespace {

// Once the write buffer grew beyond this size (e.g. due to a single large
// application write), it is released rather than kept for the lifetime of the
// connection.
constexpr size_t max_retained_write_buffer_size = 4 * (TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE_TLS13);

class TLS_Channel_IO final : public Channel_IO {
   public:
      TLS_Channel_IO(Connection_Side side, std::shared_ptr<const Policy> policy, std::shared_ptr<Callbacks> callbacks) :
            Channel_IO(side, std::move(policy), std::move(callbacks)), m_record_layer(side), m_handshake_layer(side) {}

      void send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) override {
         const size_t max_plaintext_payload_size = record_layer().record_payload_size_limit(policy(), cipher_state);

         // RFC 9846 5.1
         //    Handshake messages MAY be [...] fragmented across several records.
         //    [...] Application Data fragments MAY be split across multiple records
         //    [...].
         //
         // In TLS, we may fragment application data and handshake data into multiple
         // records. Other record types are not allowed to be fragmented.
         BOTAN_ASSERT_IMPLICATION(payload.size() > max_plaintext_payload_size,
                                  record_type == Record_Type::ApplicationData || record_type == Record_Type::Handshake,
                                  "Only Handshake and Application Data records may be fragmented");

         auto& output = m_write_buffer;
         output.clear();
         if(output.capacity() > max_retained_write_buffer_size) {
            output.shrink_to_fit();
         }

         const auto records = ceil_division(payload.size(), max_plaintext_payload_size);

         if(cipher_state == nullptr) {
            output.reserve(records * TLS_HEADER_SIZE + payload.size());
         } else if(records > 1) {
            const auto max_record_size =
               cipher_state != nullptr
                  ? cipher_state->encrypt_output_length(record_layer().outgoing_record_size_limit())
                  : max_plaintext_payload_size;
            output.reserve(records * (TLS_HEADER_SIZE + max_record_size));
         }

         BufferSlicer bs(payload);

         // RFC 9846 5.1
         //    Zero-length fragments of Application Data [...] MAY be sent, as they
         //    are potentially useful as a traffic analysis countermeasure.
         //
         // We're using a do-while loop to ensure that we process at least one slice
         // of the payload, even if that first slice is empty.
         do /* NOLINT(*-avoid-do-while) */ {
            const size_t pt_size = std::min(bs.remaining(), max_plaintext_payload_size);
            const auto pt_fragment = bs.take(pt_size);

            m_record_layer.prepare_record(record_type, pt_fragment, policy(), cipher_state, output);
         } while(!bs.empty());

         callbacks().tls_emit_data(output);
      }

      void send_flight(std::vector<Flight::Message> flight) override {
         // Go through all messages of the flight, grouping them into (at
         // most) two runs: one for the unprotected messages and one for the
         // protected messages. Each run is sent in as little records as
         // possible.
         bool protect_current_msgs = false;
         auto msgs = MarshalledHandshakeMessageFlight();
         const auto cs = cipher_state();

         auto prepare_and_flush_current_prepared = [&](bool protect) {
            if(msgs.get().empty()) {
               return;
            }

            BOTAN_ASSERT_IMPLICATION(
               protect, cs != nullptr, "Cipher State is available when messages require protection");

            send_data(Record_Type::Handshake, msgs.get(), protect ? cs.get() : nullptr);

            msgs.get().clear();

            if(!protect) {
               // RFC 9846 5.1
               //    To maximize backward compatibility, a record containing an
               //    initial ClientHello SHOULD have version 0x0301.
               //
               // We just sent the flight's unprotected messages (e.g. the
               // initial ClientHello of a TLS client). All subsequent records
               // MUST carry version 0x0303.
               m_record_layer.disable_sending_compat_mode();
            }
         };

         for(const auto& message_info : flight) {
            std::visit(  //
               overloaded{
                  [&](const Flight::Dummy_ChangeCipherSpec&) {
                     // We reached a dummy CCS. Before that only unprotected
                     // messages were allowed. Flush those (if any).
                     BOTAN_STATE_CHECK(!protect_current_msgs);
                     prepare_and_flush_current_prepared(false /* no protection */);

                     // Then send the dummy CCS record.
                     send_dummy_change_cipher_spec();
                  },
                  [&](const Flight::Message_Info& msg_info) {
                     const bool protect = !msg_info.epoch.has_value() || msg_info.epoch->is_protected();

                     if(!protect) {
                        // Once we have reached the first protected message, all
                        // subsequent messages must be protected as well.
                        BOTAN_ASSERT_NOMSG(!protect_current_msgs);
                     } else if(!protect_current_msgs) {
                        // We reached the first protected message. Flush the
                        // unprotected ones (if any).
                        prepare_and_flush_current_prepared(false /* no protection */);
                        BOTAN_DEBUG_ASSERT(msgs.get().empty());
                        protect_current_msgs = true;
                     }

                     // Collect marshalled messages into the current run.
                     append(msgs.get(), msg_info.header);
                     append(msgs.get(), msg_info.serialized);
                  },
               },
               message_info);
         }

         // After we have processed all messages of the given flight, flush the
         // last run of messages (if any).
         prepare_and_flush_current_prepared(protect_current_msgs);
      }

      void process(const Handshake_Record& record) override {
         std::ignore = m_handshake_layer.copy_data(policy(), record);
      }

      void validate(const TransparentRecord& record) override {
         BOTAN_UNUSED(record);

         // RFC 9846 5.1
         //   Handshake messages MUST NOT be interleaved with other record types.
         //   That is, if a handshake message is split over two or more records,
         //   there MUST NOT be any other records between them.
         //
         // If there is any pending data currently stored in the handshake layer
         // it must be an incomplete handshake message. The event loop in
         // Channel_IO::next_pending_event() ensures that all completed messages
         // are drained to the channel before any other records are processed.
         if(handshake_layer().has_pending_data()) {
            throw Unexpected_Message("Expected remainder of a handshake message");
         }
      }

      Record_Layer& record_layer() override { return m_record_layer; }

      const Record_Layer& record_layer() const override { return m_record_layer; }

      Handshake_Layer& handshake_layer() override { return m_handshake_layer; }

      const Handshake_Layer& handshake_layer() const override { return m_handshake_layer; }

   private:
      void send_key_update(const Key_Update& msg) override {
         const auto cs = cipher_state();
         BOTAN_ASSERT_NONNULL(cs);
         send_data(Record_Type::Handshake, m_handshake_layer.marshal(msg), cs.get());
         cs->update_write_keys();
      }

   private:
      TLS_Record_Layer m_record_layer;
      TLS_Handshake_Layer m_handshake_layer;

      secure_vector<uint8_t> m_write_buffer;
};

}  // namespace

std::shared_ptr<Channel_IO> Channel_IO::create(Connection_Side side,
                                               TLS_Flavor flavor,
                                               std::shared_ptr<const Policy> policy,
                                               std::shared_ptr<Callbacks> callbacks) {
   if(flavor == TLS_Flavor::DTLS) {
      throw Not_Implemented("DTLS 1.3 is not yet supported");
   } else {
      return std::make_shared<TLS_Channel_IO>(side, std::move(policy), std::move(callbacks));
   }
}

}  // namespace Botan::TLS

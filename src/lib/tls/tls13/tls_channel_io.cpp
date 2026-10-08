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
      // This is a temporary shim to allow the predicate of the while-loop
      // below to run after the transcript hash state has been destroyed
      // at the end of the handshake.
      //
      // TODO: remove when integrating the re-vamped data influx routine.
      auto transcript_hash_reference = [&]() -> std::optional<std::reference_wrapper<Transcript_Hash_State>> {
         if(transcript_hash.has_value()) {
            return *transcript_hash;
         } else {
            return std::nullopt;
         }
      };

      auto handshake_msg = hs_layer.next_message(policy(), transcript_hash_reference());
      if(!handshake_msg.has_value()) {
         return std::nullopt;
      }

      // RFC 9846 5.1
      //    Handshake messages MUST NOT span key changes.  Implementations
      //    MUST verify that all messages immediately preceding a key change
      //    align with a record boundary; if not, then they MUST terminate the
      //    connection with an "unexpected_message" alert.  Because the
      //    ClientHello, EndOfEarlyData, ServerHello, Finished, and KeyUpdate
      //    messages can immediately precede a key change, implementations
      //    MUST send these messages in alignment with a record boundary.
      //
      // Note: Hello_Retry_Request was added to the list below although it
      //       cannot immediately precede a key change. However, there cannot be
      //       any further sensible messages in the record after HRR.
      //
      // Note: Server_Hello_12 was deliberately not included in the check below
      //       because in TLS 1.2 Server Hello and other handshake messages can
      //       be legally coalesced in a single record.
      //
      if(holds_any_of<Client_Hello_12_Shim,
                      Client_Hello_13 /*, EndOfEarlyData,*/,
                      Server_Hello_13,
                      Hello_Retry_Request,
                      Finished_13>(handshake_msg.value()) &&
         hs_layer.has_pending_data()) {
         throw Unexpected_Message("Unexpected additional handshake message data found in record");
      }

      // After the initial handshake message is received, the record
      // layer must be more restrictive.
      // See RFC 9846 5.1 regarding "legacy_record_version"
      if(!m_first_message_delivered) {
         rec_layer.disable_receiving_compat_mode();
         m_first_message_delivered = true;
      }

      return std::move(handshake_msg).value();
   } else {
      auto post_handshake_msg = hs_layer.next_post_handshake_message(policy());
      if(!post_handshake_msg.has_value()) {
         return std::nullopt;
      }

      // make sure Key_Update appears only at the end of a record; see RFC
      // 9846 5.1 description above
      if(std::holds_alternative<Key_Update>(post_handshake_msg.value()) && hs_layer.has_pending_data()) {
         throw Unexpected_Message("Unexpected additional post-handshake message data found in record");
      }

      return std::move(post_handshake_msg).value();
   }
}

void Channel_IO::copy_data(std::span<const uint8_t> data) {
   record_layer().copy_data(data);
}

Channel_IO::ReceiveEvent Channel_IO::next_pending_event(std::optional<Transcript_Hash_State>& transcript_hash,
                                                        bool handshake_complete) {
   auto cs = cipher_state();

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
            [&](auto anything_else) -> std::optional<Channel_IO::ReceiveEvent> {
               // RFC 8446 5.1
               //   Handshake messages MUST NOT be interleaved with other record types.
               if(handshake_layer().has_pending_data()) {
                  throw Unexpected_Message("Expected remainder of a handshake message");
               }
               return anything_else;
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
   // RFC 9846 4.7.3
   //    If the request_update field [of a received KeyUpdate] is set to
   //    "update_requested", then the receiver MUST send a KeyUpdate of its own
   //    with request_update set to "update_not_requested" prior to sending its
   //    next Application Data record. This mechanism allows either side to
   //    force an update to the entire connection, but causes an implementation
   //    which receives multiple KeyUpdates while it is silent to respond with
   //    a single update.
   if(m_key_update_reciprocation_pending) {
      update_traffic_keys(false /* update_requested */);
      m_key_update_reciprocation_pending = false;
   } else if(needs_traffic_based_key_update()) {
      // If approaching traffic limits request the peer update their own keys
      // as well, unless an earlier request is still unanswered:
      //
      // RFC 9846 4.7.3
      //    Until receiving a subsequent KeyUpdate from the peer, the sender
      //    MUST NOT send another KeyUpdate with request_update set to
      //    "update_requested".
      update_traffic_keys(!m_key_update_requested);
   }

   auto cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);
   send_data(Record_Type::ApplicationData, payload, cs.get());
}

/**
 * RFC 9846 Section 5.5
 *    Implementations MUST either close the connection or do a key update as
 *    described in Section 4.7.3 prior to reaching these limits.
 *
 * [This is a SHOULD in RFC 8446]
 *
 * The ChaCha-based suites don't have any practical usage limit but we
 * apply the limit for all suites for simplicity.
 */
bool Channel_IO::needs_traffic_based_key_update() const {
   // RFC 9846 5.5
   //    There are cryptographic limits on the amount of plaintext which can be
   //    safely encrypted under a given set of keys. [...] Implementations MUST
   //    either close the connection or do a key update as described in Section
   //    4.7.3 prior to reaching these limits.
   //
   // The ChaCha-based suites don't have any practical usage limit but we apply
   // the limit for all suites for simplicity.
   const uint64_t limit = policy().records_per_traffic_key();
   auto cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);

   // Have to skip this if the handshake is not yet completed since we can't
   // send a KeyUpdate in the (unlikely) case that the limit is hit with
   // half-RTT data. If it is we just defer until the handshake completes.
   if(limit == 0 || !cs->is_handshake_complete()) {
      return false;
   }

   if(cs->records_encrypted_with_current_key() >= limit) {
      return true;
   }

   // For the read side all we can do is ask the peer to update its keys,
   // and only if no earlier request is still outstanding. The threshold is
   // set above the write-side limit so that a peer which tracks its own
   // write limit will normally have rotated its keys already, avoiding a
   // redundant key update crossing ours in flight.
   const uint64_t read_limit = limit + limit / 2;
   return !m_key_update_requested && cs->records_decrypted_with_current_key() >= read_limit;
}

void Channel_IO::handle_key_update(const Key_Update& key_update) {
   auto cs = cipher_state();
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

   if(key_update.expects_reciprocation()) {
      // RFC 9846 4.7.3
      //    If the request_update field is set to "update_requested", then the
      //    receiver MUST send a KeyUpdate of its own with request_update set to
      //    "update_not_requested" prior to sending its next Application Data
      //    record.
      //
      // This happens opportunistically in send().
      m_key_update_reciprocation_pending = true;
   } else {
      // Only an actual reciprocation settles our outstanding request. RFC 9846
      // 4.7.3 would allow requesting again after any KeyUpdate from the peer,
      // but waiting for the reciprocation keeps the exemption above one-shot.
      m_key_update_requested = false;
   }
}

void Channel_IO::update_traffic_keys(bool request_peer_update) {
   auto cs = cipher_state();
   BOTAN_ASSERT_NONNULL(cs);

   send_flight(PostHandshakeFlight(callbacks())  //
                  .add(Key_Update(request_peer_update))
                  .commit());

   cs->update_write_keys();
   if(request_peer_update) {
      m_key_update_requested = true;
   }
}

void Channel_IO::send(const Alert& alert, bool handle_compat_mode) {
   auto cs = cipher_state();

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
}

void Channel_IO::set_record_size_limits(uint16_t out, uint16_t in) {
   record_layer().set_record_size_limits(out, in);
}

void Channel_IO::set_selected_certificate_type(Certificate_Type cert_type) {
   handshake_layer().set_selected_certificate_type(cert_type);
}

std::shared_ptr<const Cipher_State> Channel_IO::cipher_state() const {
   return m_cipher_state.lock();
}

std::shared_ptr<Cipher_State> Channel_IO::cipher_state() {
   return m_cipher_state.lock();
}

namespace {

class TLS_Channel_IO final : public Channel_IO {
   public:
      TLS_Channel_IO(Connection_Side side, std::shared_ptr<const Policy> policy, std::shared_ptr<Callbacks> callbacks) :
            Channel_IO(side, policy, std::move(callbacks)),
            m_record_layer(side, std::move(policy)),
            m_handshake_layer(side) {}

      void send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) override {
         auto to_write = m_record_layer.prepare_records(record_type, payload, cipher_state);

         // After the initial handshake message is sent, the record layer must
         // adhere to a more strict record specification. Note that for the
         // server case this is a NOOP.
         // See (RFC 9846 5.1. regarding "legacy_record_version")
         if(record_type == Record_Type::Handshake && !m_first_message_sent) {
            m_record_layer.disable_sending_compat_mode();
            m_first_message_sent = true;
         }

         callbacks().tls_emit_data(to_write);
      }

      void send_flight(std::vector<Flight::Message> flight) override {
         auto cs = cipher_state();
         auto msgs = MarshalledHandshakeMessageFlight();

         // This isn't very efficient or elegant, but it is a simple way to send
         // the collected messages and dummy CCSs in as little records as
         // possible. It will be replaced with a more efficient implementation
         // with upcoming patches towards DTLS 1.3 support anyway.
         //
         // TODO: Replace this with a more efficient implementation

         for(const auto& msg_info : flight) {
            std::visit(  //
               overloaded{
                  [&](const Flight::Dummy_ChangeCipherSpec&) {
                     // Flush pending handshake messages, then send the dummy
                     // CCS record. Note that messages preceding a dummy CCS
                     // (i.e. a HelloRetryRequest) are always unprotected
                     // because no cipher state is available, yet.
                     if(!msgs.get().empty()) {
                        send_data(Record_Type::Handshake, msgs.get(), cs.get());
                        msgs.get().clear();
                     }
                     send_dummy_change_cipher_spec();
                  },
                  [&](const Flight::Message_Info& info) {
                     // Collect marshalled messages into the flight's buffer.
                     msgs.get().insert(msgs.get().end(), info.header.begin(), info.header.end());
                     msgs.get().insert(msgs.get().end(), info.serialized.begin(), info.serialized.end());
                  },
               },
               msg_info);
         }

         if(!msgs.get().empty()) {
            send_data(Record_Type::Handshake, msgs.get(), cs.get());
         }
      }

      void process(const Handshake_Record& record) override { m_handshake_layer.copy_data(record.payload); }

      Record_Layer& record_layer() override { return m_record_layer; }

      const Record_Layer& record_layer() const override { return m_record_layer; }

      Handshake_Layer& handshake_layer() override { return m_handshake_layer; }

      const Handshake_Layer& handshake_layer() const override { return m_handshake_layer; }

   private:
      bool m_first_message_sent = false;

      Record_Layer m_record_layer;
      Handshake_Layer m_handshake_layer;
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

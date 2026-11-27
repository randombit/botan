/*
* TLS handshake state (machine) implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 René Meusel, Amos Treiber - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_layer_13.h>

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_messages_internal.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_transcript_hash_13.h>

namespace Botan::TLS {

namespace {

constexpr size_t HEADER_LENGTH = 4;

}  // namespace

Handshake_Type Handshake_Layer::read_handshake_message_type(uint8_t msg_type_byte) const {
   const auto msg_type = static_cast<Handshake_Type>(msg_type_byte);

   struct Type_Validation {
         bool tls12 = false;
         bool tls13 = false;
         bool dtls_only = false;
   };

   const auto v = [&]() -> Type_Validation {
      switch(msg_type) {
         using enum Handshake_Type;

         case CertificateStatus:
         case CertificateUrl:
         case ClientKeyExchange:
         case HelloRequest:
         case ServerHelloDone:
         case ServerKeyExchange:
            return {.tls12 = true};

         case HelloVerifyRequest:
            return {.tls12 = true, .dtls_only = true};

         case Certificate:
         case CertificateRequest:
         case CertificateVerify:
         case ClientHello:
         case Finished:
         case NewSessionTicket:
         case ServerHello:
            return {.tls12 = true, .tls13 = true};

         case EncryptedExtensions:
         case EndOfEarlyData:
         case KeyUpdate:
            return {.tls13 = true};

         // Those are added to avoid a 'default' case in the switch statement.
         // They aren't valid wire values and must not appear in handshake
         // message headers.
         case HandshakeCCS:
         case HelloRetryRequest:
         case MessageHash:
         case None:
            return {};
      }

      return {};
   }();

   const bool unknown = !v.tls12 && !v.tls13;
   const bool tls12_only = v.tls12 && !v.tls13;

   if(unknown) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Unknown handshake message received");
   }

   if(tls12_only && m_peer_speaks_tls13) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Unexpected TLS 1.2 message received");
   }

   if(v.dtls_only && tls_flavor().is_streaming()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Unexpected DTLS message received");
   }

   // TODO: Validate post-handshake messages.
   // The handshake layer currently isn't aware of handshake completion. Thus,
   // this validation is currently done after buffering the message but before
   // parsing it. See `parse[_post]_handshake_message()`.

   // TODO: Validate server-only and client-only handshake messages based on the
   //       information in m_peer.
   // That would allow to early-reject messages that cannot originate from the
   // given peer (e.g., a CertificateRequest coming from a Client). Currently,
   // this validation is done as part of the handshake state machine.

   return msg_type;
}

class TLS_Handshake_Layer::PendingMessage final {
   public:
      enum Header_Completion_State : uint8_t {
         Empty,
         Partial,
         Complete,
      };

   public:
      Header_Completion_State append_to_header(std::span<const uint8_t> bytes) {
         BOTAN_ASSERT_NOMSG(bytes.size() <= missing_bytes_in_header());
         copy_mem(std::span{m_message.header}.subspan(m_header_bytes_consumed, bytes.size()), bytes);
         m_header_bytes_consumed += bytes.size();

         if(m_header_bytes_consumed == 0) {
            return Header_Completion_State::Empty;
         } else if(m_header_bytes_consumed < HEADER_LENGTH) {
            return Header_Completion_State::Partial;
         } else {
            return Header_Completion_State::Complete;
         }
      }

      bool append_to_payload(std::span<const uint8_t> bytes) {
         BOTAN_ASSERT_NOMSG(bytes.size() <= missing_bytes().value_or(0));
         m_message.payload.get().insert(m_message.payload.get().end(), bytes.begin(), bytes.end());
         return completed();
      }

      void set_type(Handshake_Type type) {
         BOTAN_STATE_CHECK(m_header_bytes_consumed > 0);
         BOTAN_DEBUG_ASSERT(type_byte() == to_underlying(type));
         m_message.type = type;
      }

      bool completed() const {
         if(auto msg_len = message_length()) {
            return m_message.payload.size() == *msg_len;
         } else {
            return false;
         }
      }

      uint8_t type_byte() const {
         BOTAN_STATE_CHECK(m_header_bytes_consumed > 0);
         return m_message.header[0];
      }

      size_t missing_bytes_in_header() const {
         BOTAN_DEBUG_ASSERT(m_header_bytes_consumed <= HEADER_LENGTH);
         return HEADER_LENGTH - m_header_bytes_consumed;
      }

      /// @returns the number of bytes missing to complete the entire message
      ///          (std::nullopt if the header is not yet complete and we thus
      ///          cannot determine the full message length)
      std::optional<size_t> missing_bytes() const {
         if(auto msg_len = message_length()) {
            BOTAN_DEBUG_ASSERT(*msg_len >= m_message.payload.size());
            return *msg_len - m_message.payload.size();
         } else {
            return std::nullopt;
         }
      }

      /// @returns the total length of the handshake message (w/o header)
      std::optional<size_t> message_length() const {
         if(missing_bytes_in_header() > 0) {
            return std::nullopt;
         }

         return load_be<uint32_t>(m_message.header) & 0x00FFFFFF;
      }

      /// Extract the collected complete handshake message. The message must be
      /// fully received before calling this method.
      Handshake_Layer::Message take() {
         BOTAN_STATE_CHECK(completed());
         return std::exchange(m_message, {});
      }

   private:
      Handshake_Layer::Message m_message;
      size_t m_header_bytes_consumed = 0;
};

TLS_Handshake_Layer::TLS_Handshake_Layer(Connection_Side whoami) :
      Handshake_Layer(whoami), m_pending_messages(std::make_unique<std::deque<PendingMessage>>()) {}

TLS_Handshake_Layer::~TLS_Handshake_Layer() = default;

TLS_Handshake_Layer::CopyDataResult TLS_Handshake_Layer::copy_data(const Policy& policy,
                                                                   const Handshake_Record& data_from_peer) {
   BufferSlicer slicer(data_from_peer.payload);

   while(!slicer.empty()) {
      // Get the latest (incomplete) pending handshake message or create a fresh
      // one to hold the received handshake message bytes.
      auto& pending_msg = [&]() -> PendingMessage& {
         if(m_pending_messages->empty() || m_pending_messages->back().completed()) {
            return m_pending_messages->emplace_back();
         } else {
            return m_pending_messages->back();
         }
      }();

      // First consume the header bytes if the header is not completed yet.
      auto missing_in_header = pending_msg.missing_bytes_in_header();
      if(missing_in_header > 0) {
         const auto header_state =
            pending_msg.append_to_header(slicer.take(std::min(slicer.remaining(), missing_in_header)));

         using enum PendingMessage::Header_Completion_State;

         if(header_state != Empty) {
            // We received at least the type byte of the handshake message and
            // can check its sanity
            pending_msg.set_type(read_handshake_message_type(pending_msg.type_byte()));
         }

         if(header_state == Complete) {
            // We just completed reading the header, so we can...

            // ... obtain the expected message length
            const auto msg_size = pending_msg.message_length();
            BOTAN_DEBUG_ASSERT(msg_size.has_value());

            // ... (optionally) check that length against the policy
            const auto max_size = policy.maximum_handshake_message_size();
            if(max_size > 0 && *msg_size > max_size) {
               throw TLS_Exception(
                  Alert::HandshakeFailure,
                  Botan::fmt("Handshake message is {} bytes, policy maximum is {}", *msg_size, max_size));
            }
         }
      }

      const auto missing_overall = pending_msg.missing_bytes();
      if(missing_overall.has_value() && *missing_overall > 0) {
         // Here the header is fully parsed and we can now consume the payload.
         pending_msg.append_to_payload(slicer.take(std::min(slicer.remaining(), *missing_overall)));
      }
   }

   return CopyDataResult::Consumed;
}

std::optional<Handshake_Message_13> Handshake_Layer::next_message(const Policy& policy,
                                                                  Transcript_Hash_State& transcript_hash) {
   const auto raw_msg = take_next_message();
   if(!raw_msg.has_value()) {
      return std::nullopt;
   }

   auto msg = parse_handshake_message(*raw_msg, policy);

   // RFC 9846 5.1
   //    Handshake messages MUST NOT span key changes.  Implementations
   //    MUST verify that all messages immediately preceding a key change
   //    align with a record boundary; if not, then they MUST terminate the
   //    connection with an "unexpected_message" alert.  Because the
   //    ClientHello, EndOfEarlyData, ServerHello, Finished, and KeyUpdate
   //    messages can immediately precede a key change, implementations
   //    MUST send these messages in alignment with a record boundary.
   //
   // Note: Hello_Retry_Request and Hello_Verify_Request were added to the list
   //       below although they cannot immediately precede a key change.
   //       However, there cannot be any further sensible messages in the record
   //       after them.
   //
   // Note: Server_Hello_12 was deliberately not included in the check below
   //       because in TLS 1.2 Server Hello and other handshake messages can be
   //       legally coalesced in a single record.
   //
   // These messages don't only "precede" a key change, they are the only
   // mechanism that can cause the key change to happen once the TLS state
   // machine processes them downstream from here. Therefore, any such message
   // must always be the last available handshake message in the queue of
   // available handshake messages. (Any legal follow-up handshake message
   // cannot be present in the queue yet, because we can successfully deprotect
   // it only after said key change.)
   if(holds_any_of<Client_Hello_12_Shim, Client_Hello_13, Server_Hello_13, Hello_Retry_Request, Finished_13>(msg) &&
      has_pending_data()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Unexpected additional handshake data at epoch boundary");
   }

   // The peer just proved that it speaks TLS 1.3 by sending a handshake message
   // that only exists in TLS 1.3 (or a ServerHello that was parsed as TLS 1.3).
   if(holds_any_of<Client_Hello_13, Server_Hello_13, Hello_Retry_Request>(msg)) {
      BOTAN_ASSERT_NOMSG(!has_pending_data());
      m_peer_speaks_tls13 = true;
   }

   transcript_hash.update(raw_msg->header, raw_msg->payload);
   return msg;
}

std::optional<Post_Handshake_Message_13> Handshake_Layer::next_post_handshake_message(
   const Policy& policy, EpochNumber latest_read_epoch_number) {
   BOTAN_UNUSED(policy);

   const auto raw_msg = take_next_message();
   if(!raw_msg.has_value()) {
      return std::nullopt;
   }

   // RFC 9147 8.
   //    As with other handshake messages with no built-in response, KeyUpdates
   //    MUST be acknowledged. In order to facilitate epoch reconstruction,
   //    implementations MUST NOT send records with the new keys or send a new
   //    KeyUpdate until the previous KeyUpdate has been acknowledged [...].
   //
   // Note that this is only relevant for DTLS, where the KeyUpdate becomes
   // effective only after receiving its acknowledgment. For TLS, the check is
   // trivially true because the sender switches its write keys immediately
   // after sending a KeyUpdate.
   //
   // Technically, the check below could be scoped to KeyUpdate messages only.
   // However, by enforcing it for all post-handshake messages, we harmonize the
   // strong epoch ordering semantics of post-handshake messages across TLS and
   // DTLS. The same restriction is applied by BoringSSL, making us compatible
   // to them.
   //
   // Note that we currently enforce this by throwing Invalid_State when the
   // user explicitly requests sending any post-handshake message while a
   // KeyUpdate is pending in DTLS.
   if(raw_msg->epoch_number.has_value() && raw_msg->epoch_number.value() != latest_read_epoch_number) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received a new post-handshake message under an outdated epoch");
   }

   auto msg = parse_post_handshake_message(*raw_msg);

   // RFC 9846 5.1
   //    Handshake messages MUST NOT span key changes.  Implementations
   //    MUST verify that all messages immediately preceding a key change
   //    align with a record boundary; if not, then they MUST terminate the
   //    connection with an "unexpected_message" alert.  Because the
   //    ClientHello, EndOfEarlyData, ServerHello, Finished, and KeyUpdate
   //    messages can immediately precede a key change, implementations
   //    MUST send these messages in alignment with a record boundary.
   //
   // See above (Handshake_Layer::next_handshake_message) for a rationale. Note
   // that in DTLS this rationale only holds because of the strong epoch
   // ordering enforced by the check above. RFC 9147 does not strictly prohibit
   // protecting post-handshake messages with an epoch that is about to be
   // retired by a pending KeyUpdate.
   if(std::holds_alternative<Key_Update>(msg) && has_pending_data()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Unexpected additional post-handshake data at epoch boundary");
   }

   return msg;
}

bool TLS_Handshake_Layer::has_pending_data() const {
   return !m_pending_messages->empty();
}

std::optional<Handshake_Layer::Message> TLS_Handshake_Layer::take_next_message() {
   if(m_pending_messages->empty() || !m_pending_messages->front().completed()) {
      return std::nullopt;
   }

   auto msg = m_pending_messages->front().take();
   m_pending_messages->erase(m_pending_messages->begin());

   return msg;
}

Handshake_Message_13 Handshake_Layer::parse_handshake_message(const Message& message, const Policy& policy) const {
   switch(message.type) {
      // Client Hello and Server Hello messages are ambiguous. Both may come
      // from non-TLS 1.3 peers. Hence, their parsing is somewhat different.
      case Handshake_Type::ClientHello:
         // ... might be TLS 1.2 Client Hello or TLS 1.3 Client Hello
         return generalize_to<Handshake_Message_13>(Client_Hello_13::parse(message.payload, tls_flavor()));
      case Handshake_Type::ServerHello:
         // ... might be TLS 1.2 Server Hello or TLS 1.3 Server Hello or
         // a TLS 1.3 Hello Retry Request disguising as a Server Hello
         return generalize_to<Handshake_Message_13>(Server_Hello_13::parse(message.payload, tls_flavor()));
      // case Handshake_Type::EndOfEarlyData:
      //    return End_Of_Early_Data(msg);
      case Handshake_Type::EncryptedExtensions:
         return Encrypted_Extensions(message.payload);
      case Handshake_Type::Certificate:
         return Certificate_13(message.payload, policy, peer(), certificate_type());
      case Handshake_Type::CertificateRequest:
         return Certificate_Request_13(message.payload, peer());
      case Handshake_Type::CertificateVerify:
         return Certificate_Verify_13(message.payload, peer());
      case Handshake_Type::Finished:
         return Finished_13(message.payload.get());
      default:
         throw TLS_Exception(AlertType::UnexpectedMessage, "Unexpected handshake message received");
   }
}

Post_Handshake_Message_13 Handshake_Layer::parse_post_handshake_message(const Message& message) const {
   switch(message.type) {
      case Handshake_Type::NewSessionTicket:
         return New_Session_Ticket_13(message.payload, peer());
      case Handshake_Type::KeyUpdate:
         return Key_Update(message.payload);
      default:
         throw TLS_Exception(AlertType::UnexpectedMessage, "Unexpected post-handshake message received");
   }
}

void Handshake_Layer::update_transcript_for_psk_binder_calc(const Client_Hello_13& message,
                                                            Transcript_Hash_State& transcript_hash) {
   const auto msg_bytes = serialize(message);
   transcript_hash.update(TLS_Handshake_Layer::prepare_header(message.wire_type(), msg_bytes.size()), msg_bytes);
}

}  // namespace Botan::TLS

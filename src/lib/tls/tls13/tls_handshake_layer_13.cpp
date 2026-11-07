/*
* TLS handshake state (machine) implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
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

void verify_handshake_message_size(size_t msg_len, size_t max_size) {
   if(max_size > 0 && msg_len > max_size) {
      throw TLS_Exception(Alert::HandshakeFailure,
                          Botan::fmt("Handshake message is {} bytes, policy maximum is {}", msg_len, max_size));
   }
}

}  // namespace

std::optional<Handshake_Type> Handshake_Layer::read_handshake_message_type(uint8_t value) {
   const auto type = static_cast<Handshake_Type>(value);
   switch(type) {
      using enum Handshake_Type;

      case ClientHello:
      case ServerHello:
      case HelloVerifyRequest:
      // NYI: needs PSK/resumption support -- won't be offered in Client Hello for now
      // case EndOfEarlyData:
      case EncryptedExtensions:
      case Certificate:
      case CertificateRequest:
      case CertificateVerify:
      case Finished:
      case NewSessionTicket:
      case KeyUpdate:
         return type;
      default:
         return std::nullopt;
   }
}

TLS_Handshake_Layer::CopyDataResult TLS_Handshake_Layer::copy_data(const Policy& policy,
                                                                   const Handshake_Record& data_from_peer) {
   BOTAN_UNUSED(policy);

   // Compact consumed data before appending new data
   BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());
   if(m_read_offset > 0) {
      m_read_buffer.erase(m_read_buffer.begin(), m_read_buffer.begin() + m_read_offset);
      m_read_offset = 0;
   }

   m_read_buffer.insert(m_read_buffer.end(), data_from_peer.payload.begin(), data_from_peer.payload.end());
   return CopyDataResult::Consumed;
}

std::optional<Handshake_Layer::MessageBufferView> Handshake_Layer::next_message_buffer_view(const Policy& policy) {
   auto buffer_view = fetch_next_message_buffer_view();
   if(!buffer_view.has_value()) {
      return std::nullopt;
   }

   // TODO(Botan4) this is split out due to a GCC 11 ICE, can be inlined
   verify_handshake_message_size(buffer_view->payload_size(), policy.maximum_handshake_message_size());

   return buffer_view;
}

std::optional<Handshake_Message_13> Handshake_Layer::next_message(const Policy& policy,
                                                                  Transcript_Hash_State& transcript_hash) {
   const auto buffer_view = next_message_buffer_view(policy);
   if(!buffer_view.has_value()) {
      return std::nullopt;
   }

   auto msg = parse_handshake_message(buffer_view->type(), buffer_view->payload(), policy);

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
   if(holds_any_of<Client_Hello_12_Shim,
                   Client_Hello_13,
                   Server_Hello_13,
                   Hello_Verify_Request,  // DTLS 1.3 -> 1.2 downgrade
                   Hello_Retry_Request,
                   Finished_13>(msg) &&
      !buffer_view->was_final_message_in_queue()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Unexpected additional handshake data at epoch boundary");
   }

   transcript_hash.update(buffer_view->header(), buffer_view->payload());
   return msg;
}

std::optional<Post_Handshake_Message_13> Handshake_Layer::next_post_handshake_message(
   const Policy& policy, EpochNumber latest_read_epoch_number) {
   const auto buffer_view = next_message_buffer_view(policy);
   if(!buffer_view.has_value()) {
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
   if(buffer_view->epoch_number().has_value() && buffer_view->epoch_number().value() != latest_read_epoch_number) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received a new post-handshake message under an outdated epoch");
   }

   auto msg = parse_post_handshake_message(buffer_view->type(), buffer_view->payload());

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
   if(std::holds_alternative<Key_Update>(msg) && !buffer_view->was_final_message_in_queue()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Unexpected additional post-handshake data at epoch boundary");
   }

   return msg;
}

std::optional<Handshake_Layer::MessageBufferView> TLS_Handshake_Layer::fetch_next_message_buffer_view() {
   BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());

   BufferSlicer bs(m_read_buffer);
   bs.skip(m_read_offset);

   if(bs.empty()) {
      return std::nullopt;
   }

   // Validate the message type early, before committing to wait for a
   // potentially bogus and huge message body.
   if(!read_handshake_message_type(bs.peek_byte()).has_value()) {
      throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown handshake message received");
   }

   if(bs.remaining() < HEADER_LENGTH) {
      return std::nullopt;
   }

   const auto header = typecast_copy<HandshakeProtocolHeader>(bs.take<HEADER_LENGTH>());
   const auto msg_len = load_be<uint32_t>(header) & 0x00FFFFFF;

   if(bs.remaining() < msg_len) {
      return std::nullopt;
   }

   const bool is_final_message = bs.remaining() == msg_len;
   return MessageBufferView(std::nullopt,  // TLS 1.3 does not have epochs
                            is_final_message,
                            header,
                            bs.take<SerializedHandshakeMessage>(msg_len),
                            [this, msg_len]() {
                               m_read_offset += HEADER_LENGTH + msg_len;
                               BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());

                               if(m_read_offset == m_read_buffer.size()) {
                                  m_read_buffer.clear();
                                  m_read_offset = 0;
                               }
                            });
}

Handshake_Layer::MessageBufferView::MessageBufferView(std::optional<EpochNumber> epoch_number,
                                                      bool final_message,
                                                      HandshakeProtocolHeader header,
                                                      StrongSpan<const SerializedHandshakeMessage> payload,
                                                      CleanupFunction cleanup) :
      m_epoch_number(epoch_number),
      m_final_message(final_message),
      m_header(header),
      m_payload(payload),
      m_cleanup(std::move(cleanup)) {
   if(auto type = read_handshake_message_type(header[0])) {
      m_type = *type;
   } else {
      throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown handshake message received");
   }
}

Handshake_Message_13 Handshake_Layer::parse_handshake_message(Handshake_Type type,
                                                              std::span<const uint8_t> msg,
                                                              const Policy& policy) const {
   switch(type) {
      // Client Hello and Server Hello messages are ambiguous. Both may come
      // from non-TLS 1.3 peers. Hence, their parsing is somewhat different.
      case Handshake_Type::ClientHello:
         // ... might be TLS 1.2 Client Hello or TLS 1.3 Client Hello
         return generalize_to<Handshake_Message_13>(Client_Hello_13::parse(msg));
      case Handshake_Type::ServerHello:
         // ... might be TLS 1.2 Server Hello or TLS 1.3 Server Hello or
         // a TLS 1.3 Hello Retry Request disguising as a Server Hello
         return generalize_to<Handshake_Message_13>(Server_Hello_13::parse(msg, tls_flavor()));
      // case Handshake_Type::EndOfEarlyData:
      //    return End_Of_Early_Data(msg);
      case Handshake_Type::EncryptedExtensions:
         return Encrypted_Extensions(msg);
      case Handshake_Type::Certificate:
         return Certificate_13(msg, policy, peer(), certificate_type());
      case Handshake_Type::CertificateRequest:
         return Certificate_Request_13(msg, peer());
      case Handshake_Type::CertificateVerify:
         return Certificate_Verify_13(msg, peer());
      case Handshake_Type::Finished:
         return Finished_13({msg.begin(), msg.end()});
      default:
         throw TLS_Exception(AlertType::UnexpectedMessage, "Unexpected handshake message received");
   }
}

Post_Handshake_Message_13 Handshake_Layer::parse_post_handshake_message(Handshake_Type type,
                                                                        std::span<const uint8_t> msg) const {
   switch(type) {
      case Handshake_Type::NewSessionTicket:
         return New_Session_Ticket_13(msg, peer());
      case Handshake_Type::KeyUpdate:
         return Key_Update(msg);
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

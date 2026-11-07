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
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
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

Handshake_Type Handshake_Layer::read_handshake_message_type(uint8_t value, Handshake_Phase phase) const {
   const auto type = static_cast<Handshake_Type>(value);

   switch(type) {
      // Handshake message types
      case Handshake_Type::ClientHello:
      case Handshake_Type::ServerHello:
      case Handshake_Type::EncryptedExtensions:
      case Handshake_Type::Certificate:
      case Handshake_Type::CertificateRequest:
      case Handshake_Type::CertificateVerify:
      case Handshake_Type::Finished:
         if(phase == Handshake_Phase::Handshake) {
            return type;
         }
         break;

      // Post-handshake message types
      case Handshake_Type::NewSessionTicket:
      case Handshake_Type::KeyUpdate:
         if(phase == Handshake_Phase::PostHandshake) {
            return type;
         }
         break;

      // DTLS-specific: a HelloVerifyRequest may legally appear within a DTLS 1.3
      // handshake when the peer turns out to support only DTLS 1.2 (downgrade)
      case Handshake_Type::HelloVerifyRequest:
         if(phase == Handshake_Phase::Handshake && tls_flavor() == TLS_Flavor::DTLS) {
            return type;
         }
         break;

      // TODO(0-RTT): implement handling for EndOfEarlyData
      case Handshake_Type::EndOfEarlyData:

      // TLS 1.2 specific handshake messages
      case Handshake_Type::HelloRequest:
      case Handshake_Type::ServerKeyExchange:
      case Handshake_Type::ClientKeyExchange:
      case Handshake_Type::ServerHelloDone:
      case Handshake_Type::CertificateUrl:
      case Handshake_Type::CertificateStatus:

      // Pseudo handshake messages that aren't actually expected on the wire
      case Handshake_Type::HandshakeCCS:
      case Handshake_Type::HelloRetryRequest:
      case Handshake_Type::MessageHash:
      case Handshake_Type::None:
         break;
   };

   if(phase == Handshake_Phase::Handshake) {
      throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown handshake message received");
   } else {
      throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown post-handshake message received");
   }
}

HandshakeProtocolHeader TLS_Handshake_Layer::prepare_header(Handshake_Type type, size_t payload_length) {
   BOTAN_ASSERT_NOMSG(payload_length <= 0xFFFFFF);
   auto header = HandshakeProtocolHeader(store_be(static_cast<uint32_t>(payload_length)));
   header[0] = static_cast<uint8_t>(type);
   return header;
}

MarshalledHandshakeMessage TLS_Handshake_Layer::marshal(const Handshake_Message& message) {
   const auto bytes = serialize(message);
   return concat<MarshalledHandshakeMessage>(prepare_header(message.wire_type(), bytes.size()), bytes);
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

std::optional<TLS_Handshake_Layer::NextMessageResult> TLS_Handshake_Layer::next_message_buffer(
   std::span<const uint8_t> bytes, const Policy& policy, Handshake_Phase phase) {
   // read the message header
   if(bytes.size() < HEADER_LENGTH) {
      return std::nullopt;
   }

   const auto type = read_handshake_message_type(bytes[0], phase);
   const auto msg_len = make_uint32(0, bytes[1], bytes[2], bytes[3]);

   // TODO(Botan4) this is split out due to a GCC 11 ICE, can be inlined
   verify_handshake_message_size(msg_len, policy.maximum_handshake_message_size());

   if(bytes.size() < HEADER_LENGTH + msg_len) {
      return std::nullopt;
   }

   return NextMessageResult{
      .type = type,
      .tls_header_bytes = HandshakeProtocolHeader(std::array{bytes[0], bytes[1], bytes[2], bytes[3]}),
      .message_bytes = StrongSpan<const SerializedHandshakeMessage>(bytes.subspan(HEADER_LENGTH, msg_len)),
      .bytes_consumed = HEADER_LENGTH + msg_len,
   };
}

std::optional<Handshake_Message_13> TLS_Handshake_Layer::next_message(const Policy& policy,
                                                                      Transcript_Hash_State& transcript_hash) {
   BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());
   const auto pending = std::span<const uint8_t>{m_read_buffer}.subspan(m_read_offset);

   const auto header_and_msg = next_message_buffer(pending, policy, Handshake_Phase::Handshake);
   if(!header_and_msg.has_value()) {
      return std::nullopt;
   }

   auto msg = parse_handshake_message(header_and_msg->type, header_and_msg->message_bytes, policy);

   transcript_hash.update(header_and_msg->tls_header_bytes, header_and_msg->message_bytes);
   m_read_offset += header_and_msg->bytes_consumed;
   BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());

   if(m_read_offset == m_read_buffer.size()) {
      m_read_buffer.clear();
      m_read_offset = 0;
   }

   return msg;
}

std::optional<Post_Handshake_Message_13> TLS_Handshake_Layer::next_post_handshake_message(const Policy& policy) {
   BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());
   const auto pending = std::span<const uint8_t>{m_read_buffer}.subspan(m_read_offset);

   const auto header_and_msg = next_message_buffer(pending, policy, Handshake_Phase::PostHandshake);
   if(!header_and_msg.has_value()) {
      return std::nullopt;
   }

   auto msg = parse_post_handshake_message(header_and_msg->type, header_and_msg->message_bytes);

   m_read_offset += header_and_msg->bytes_consumed;
   BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());

   if(m_read_offset == m_read_buffer.size()) {
      m_read_buffer.clear();
      m_read_offset = 0;
   }

   return msg;
}

}  // namespace Botan::TLS

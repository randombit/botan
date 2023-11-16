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
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_transcript_hash_13.h>

namespace Botan::TLS {

void Handshake_Layer::copy_data(std::span<const uint8_t> data_from_peer) {
   m_read_buffer.insert(m_read_buffer.end(), data_from_peer.begin(), data_from_peer.end());
}

namespace {

constexpr size_t HEADER_LENGTH = 4;

template <typename Msg_Type>
Handshake_Type handshake_type_from_byte(uint8_t byte_value) {
   const auto type = static_cast<Handshake_Type>(byte_value);

   if constexpr(std::is_same_v<Msg_Type, Handshake_Message_13>) {
      switch(type) {
         case Handshake_Type::ClientHello:
         case Handshake_Type::ServerHello:
         // case Handshake_Type::EndOfEarlyData:  // NYI: needs PSK/resumption support -- won't be offered in Client Hello for now
         case Handshake_Type::EncryptedExtensions:
         case Handshake_Type::Certificate:
         case Handshake_Type::CertificateRequest:
         case Handshake_Type::CertificateVerify:
         case Handshake_Type::Finished:
            return type;
         default:
            throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown handshake message received");
      }
   } else {
      switch(type) {
         case Handshake_Type::NewSessionTicket:
         case Handshake_Type::KeyUpdate:
            // case Handshake_Type::CertificateRequest:  // NYI: post-handshake client auth (RFC 8446 4.6.2) -- won't be offered in Client Hello for now
            return type;
         default:
            throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown post-handshake message received");
      }
   }
}

template <typename Msg_Type>
std::optional<Msg_Type> parse_message(TLS::TLS_Data_Reader& reader,
                                      const Policy& policy,
                                      const Connection_Side peer_side,
                                      const Certificate_Type cert_type) {
   // read the message header
   if(reader.remaining_bytes() < HEADER_LENGTH) {
      return std::nullopt;
   }

   Handshake_Type type = handshake_type_from_byte<Msg_Type>(reader.get_byte());

   // make sure we have received the full message
   const size_t msg_len = reader.get_uint24_t();
   if(reader.remaining_bytes() < msg_len) {
      return std::nullopt;
   }

   // create the message
   const auto msg = reader.get_fixed<uint8_t>(msg_len);
   if constexpr(std::is_same_v<Msg_Type, Handshake_Message_13>) {
      switch(type) {
         // Client Hello and Server Hello messages are ambiguous. Both may come
         // from non-TLS 1.3 peers. Hence, their parsing is somewhat different.
         case Handshake_Type::ClientHello:
            // ... might be TLS 1.2 Client Hello or TLS 1.3 Client Hello
            return generalize_to<Handshake_Message_13>(Client_Hello_13::parse(msg));
         case Handshake_Type::ServerHello:
            // ... might be TLS 1.2 Server Hello or TLS 1.3 Server Hello or
            // a TLS 1.3 Hello Retry Request disguising as a Server Hello
            return generalize_to<Handshake_Message_13>(Server_Hello_13::parse(msg));
         // case Handshake_Type::EndOfEarlyData:
         //    return End_Of_Early_Data(msg);
         case Handshake_Type::EncryptedExtensions:
            return Encrypted_Extensions(msg);
         case Handshake_Type::Certificate:
            return Certificate_13(msg, policy, peer_side, cert_type);
         case Handshake_Type::CertificateRequest:
            return Certificate_Request_13(msg, peer_side);
         case Handshake_Type::CertificateVerify:
            return Certificate_Verify_13(msg, peer_side);
         case Handshake_Type::Finished:
            return Finished_13(msg);
         default:
            BOTAN_ASSERT(false, "cannot be reached");  // make sure to update handshake_type_from_byte
      }
   } else {
      BOTAN_UNUSED(peer_side);

      switch(type) {
         case Handshake_Type::NewSessionTicket:
            return New_Session_Ticket_13(msg, peer_side);
         case Handshake_Type::KeyUpdate:
            return Key_Update(msg);
         default:
            BOTAN_ASSERT(false, "cannot be reached");  // make sure to update handshake_type_from_byte
      }
   }
}

}  // namespace

std::optional<Handshake_Message_13> Handshake_Layer::next_message(const Policy& policy,
                                                                  Transcript_Hash_State& transcript_hash) {
   TLS::TLS_Data_Reader reader("handshake message", m_read_buffer);

   auto msg = parse_message<Handshake_Message_13>(reader, policy, m_peer, m_certificate_type);
   if(msg.has_value()) {
      BOTAN_ASSERT_NOMSG(m_read_buffer.size() >= reader.read_so_far());
      transcript_hash.update(std::span{m_read_buffer.data(), reader.read_so_far()});
      m_read_buffer.erase(m_read_buffer.cbegin(), m_read_buffer.cbegin() + reader.read_so_far());
   }

   return msg;
}

std::optional<Post_Handshake_Message_13> Handshake_Layer::next_post_handshake_message(const Policy& policy) {
   TLS::TLS_Data_Reader reader("post handshake message", m_read_buffer);

   auto msg = parse_message<Post_Handshake_Message_13>(reader, policy, m_peer, m_certificate_type);
   if(msg.has_value()) {
      m_read_buffer.erase(m_read_buffer.cbegin(), m_read_buffer.cbegin() + reader.read_so_far());
   }

   return msg;
}

namespace {

template <typename T>
const T& get(const std::reference_wrapper<T>& v) {
   return v.get();
}

template <typename T>
const T& get(const T& v) {
   return v;
}

template <typename T>
std::vector<uint8_t> marshall_message(const T& message) {
   auto [type, serialized] =
      std::visit([](const auto& msg) { return std::pair(get(msg).wire_type(), get(msg).serialize()); }, message);

   BOTAN_ASSERT_NOMSG(serialized.size() <= 0xFFFFFF);
   const uint32_t msg_size = static_cast<uint32_t>(serialized.size());

   std::vector<uint8_t> header{
      static_cast<uint8_t>(type), get_byte<1>(msg_size), get_byte<2>(msg_size), get_byte<3>(msg_size)};

   return concat(header, serialized);
}

}  //namespace

std::vector<uint8_t> Handshake_Layer::prepare_message(const Handshake_Message_13_Ref message,
                                                      Transcript_Hash_State& transcript_hash) {
   auto msg = marshall_message(message);
   transcript_hash.update(msg);
   return msg;
}

std::vector<uint8_t> Handshake_Layer::prepare_post_handshake_message(const Post_Handshake_Message_13& message) {
   return marshall_message(message);
}

}  // namespace Botan::TLS

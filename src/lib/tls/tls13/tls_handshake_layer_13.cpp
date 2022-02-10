/*
* TLS Client - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>

#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_transcript_hash_13.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/stl_util.h>

namespace {
constexpr size_t HEADER_LENGTH = 4;
}

namespace Botan::TLS {

void Handshake_Layer::copy_data(const std::vector<uint8_t>& data_from_peer)
   {
   m_read_buffer.insert(m_read_buffer.end(), data_from_peer.cbegin(), data_from_peer.cend());
   }

Handshake_Layer::ReadResult<Handshake_Message_13> Handshake_Layer::next_message(const Policy& policy,
      Transcript_Hash_State& transcript_hash)
   {
   TLS::TLS_Data_Reader reader("handshake message", m_read_buffer);

   if(reader.remaining_bytes() < HEADER_LENGTH)
      { return BytesNeeded(HEADER_LENGTH - reader.remaining_bytes()); }

   Handshake_Type type = Handshake_Type(reader.get_byte());
   const size_t msg_len = reader.get_uint24_t();

   if(reader.remaining_bytes() < msg_len)
      { return BytesNeeded(msg_len - reader.remaining_bytes()); }

   auto msg = parse_message(policy, type, reader.get_fixed<uint8_t>(msg_len));

   // TODO: this is inefficient as it copies a part of the buffer just for hashing
   //       C++20 std::span to the rescue.
   transcript_hash.update({m_read_buffer.cbegin(), m_read_buffer.cbegin() + reader.read_so_far()});
   m_read_buffer.erase(m_read_buffer.cbegin(), m_read_buffer.cbegin() + reader.read_so_far());

   return msg;
   }

Handshake_Message_13 Handshake_Layer::parse_message(
   const Policy& policy,
   Handshake_Type type,
   const std::vector<uint8_t>& msg)
   {
   switch(type)
      {
      case CLIENT_HELLO:
         return Client_Hello_13(msg);
      case SERVER_HELLO:
         return Server_Hello_13(msg);
      case NEW_SESSION_TICKET:
         return New_Session_Ticket_13(msg);
      // case END_OF_EARLY_DATA:
      //    return End_Of_Early_Data(msg);
      case ENCRYPTED_EXTENSIONS:
         return Encrypted_Extensions(msg);
      case CERTIFICATE:
         return Certificate_13(msg, policy, m_peer);
      // case CERTIFICATE_REQUEST:
      //    return Certificate_Req_13(msg);
      case CERTIFICATE_VERIFY:
         return Certificate_Verify_13(msg, m_peer);
      case FINISHED:
         return Finished_13(msg);
      // case KEY_UPDATE:
      //    return Key_Update(msg);

      default:
         throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "unexpected handshake message received");
      }
   }

std::vector<uint8_t> Handshake_Layer::prepare_message(const Handshake_Message_13_Ref message,
      Transcript_Hash_State& transcript_hash)
   {
   auto [type, serialized] = std::visit([](auto msg)
      {
      return std::pair(msg.get().type(), msg.get().serialize());
      }, message);

   BOTAN_ASSERT_NOMSG(serialized.size() <= 0xFFFFFF);
   const uint32_t msg_size = static_cast<uint32_t>(serialized.size());

   std::vector<uint8_t> header
      {
      static_cast<uint8_t>(type),
      get_byte<1>(msg_size),
      get_byte<2>(msg_size),
      get_byte<3>(msg_size)
      };

   auto msg = concat(header, serialized);
   transcript_hash.update(msg);
   return msg;
   }
}

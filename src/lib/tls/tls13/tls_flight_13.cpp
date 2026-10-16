/*
* TLS 1.3 Flights
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_flight_13.h>

#include <botan/tls_callbacks.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_transcript_hash_13.h>

#include <utility>

namespace Botan::TLS {

namespace {

Flight::Message_Info make_message_info(const Handshake_Message& message, const Flight::PostHandshake post_handshake) {
   BOTAN_UNUSED(post_handshake);

   auto serialized_message = Handshake_Layer::serialize(message);
   return {
      .wire_type = message.wire_type(),
      .header = Handshake_Layer::prepare_header(message.wire_type(), serialized_message.size()),
      .serialized = std::move(serialized_message),
   };
}

}  // namespace

std::vector<Flight::Message> Flight::commit() {
   BOTAN_STATE_CHECK(m_messages.has_value());
   BOTAN_STATE_CHECK(!m_messages->empty());

   return std::exchange(m_messages, {}).value();
}

void Flight::append(const Handshake_Message& message, PostHandshake post_handshake) {
   BOTAN_STATE_CHECK(m_messages.has_value());

   m_callbacks.tls_inspect_handshake_msg(message);

   auto msg_info = make_message_info(message, post_handshake);
   if(post_handshake == PostHandshake::No) {
      BOTAN_ASSERT_NOMSG(m_transcript_hash.has_value());
      m_transcript_hash->get().update(msg_info.header, msg_info.serialized);
   }
   m_messages->push_back(std::move(msg_info));
}

void Flight::append_ccs() {
   BOTAN_STATE_CHECK(m_messages.has_value());
   m_messages->push_back(Dummy_ChangeCipherSpec{});
}

}  // namespace Botan::TLS

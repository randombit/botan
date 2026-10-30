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

/**
 * @returns the static protection epoch number for a given handshake type as
 *          defined in RFC 9846.
 */
std::optional<EpochNumber> epoch_for_handshake_type(Handshake_Type handshake_type,
                                                    const Flight::PostHandshake post_handshake) {
   // Post-handshake messages are encrypted with whatever application traffic
   // epoch that is currently active, we can't determine this statically.
   if(post_handshake == Flight::PostHandshake::Yes) {
      return std::nullopt;
   }

   // RFC 9846 2.  Figure 1 as well as RFC 9846 2.3 Figure 4
   switch(handshake_type) {
      using enum Handshake_Type;

      case ClientHello:
      case ServerHello:
      case HelloRetryRequest:
         return EpochNumber::Unprotected;

      case EncryptedExtensions:
      case Certificate:
      case CertificateRequest:
      case CertificateVerify:
      case Finished:
         return EpochNumber::HandshakeTraffic;

      case EndOfEarlyData:
         return EpochNumber::EarlyTraffic;

      case NewSessionTicket:
      case KeyUpdate:
         // KeyUpdate and NewSessionTicket are always post-handshake messages,
         // so this function should never reach here (but return early with
         // std::nullopt above).
         BOTAN_ASSERT_UNREACHABLE();

      case HelloRequest:
      case HelloVerifyRequest:
      case ServerKeyExchange:
      case ServerHelloDone:
      case ClientKeyExchange:
      case CertificateUrl:
      case CertificateStatus:
      case HandshakeCCS:
      case MessageHash:
      case None:
         // These messages are not used in TLS 1.3, hence, no TLS 1.3 flight
         // should ever be constructed with one of these messages.
         // (MessageHash is a synthetic transcript-only message, RFC 9846 4.1)
         BOTAN_ASSERT_UNREACHABLE();
   }

   BOTAN_ASSERT_UNREACHABLE();
}

Flight::Message_Info make_message_info(const Handshake_Message& message, const Flight::PostHandshake post_handshake) {
   auto serialized_message = Handshake_Layer::serialize(message);
   return {
      .wire_type = message.wire_type(),
      .epoch = epoch_for_handshake_type(message.type(), post_handshake),
      .header = TLS_Handshake_Layer::prepare_header(message.wire_type(), serialized_message.size()),
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

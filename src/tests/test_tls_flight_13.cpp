/*
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

   #include <botan/exceptn.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_messages_13.h>
   #include <botan/tls_policy.h>
   #include <botan/internal/concat_util.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/tls_flight_13.h>
   #include <botan/internal/tls_transcript_hash_13.h>

using namespace Botan::TLS;

namespace Botan_Tests {

namespace {

// Handshake messages taken from RFC 8448, without their handshake protocol header
constexpr auto client_hello_body =
   "03 03 cb"
   "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
   "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
   "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
   "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
   "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
   "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
   "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
   "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
   "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

constexpr auto server_hello_body =
   "03 03 a6"
   "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14"
   "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
   "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
   "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";

// An (empty) client Certificate message: empty request context and an empty certificate list
constexpr auto empty_certificate_body = "00 00 00 00";

// A NewSessionTicket message with a one-byte nonce, a three-byte ticket and no extensions
constexpr auto new_session_ticket_body = "00 00 1e 00 01 02 03 04 01 42 00 03 aa bb cc 00 00";

Client_Hello_13 make_client_hello() {
   return std::get<Client_Hello_13>(Client_Hello_13::parse(Botan::hex_decode(client_hello_body)));
}

Server_Hello_13 make_server_hello() {
   return std::get<Server_Hello_13>(Server_Hello_13::parse(Botan::hex_decode(server_hello_body)));
}

Certificate_13 make_certificate() {
   return Certificate_13(
      Botan::hex_decode(empty_certificate_body), Policy(), Connection_Side::Client, Certificate_Type::X509);
}

New_Session_Ticket_13 make_new_session_ticket() {
   return New_Session_Ticket_13(Botan::hex_decode(new_session_ticket_body), Connection_Side::Server);
}

/**
 * Callbacks that remember all handshake messages passed to tls_inspect_handshake_msg
 */
class Recording_Callbacks final : public Callbacks {
   public:
      struct Inspected_Message {
            Handshake_Type type;
            const Handshake_Message* address;
      };

      void tls_emit_data(std::span<const uint8_t> /*data*/) override {}

      void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> /*data*/) override {}

      void tls_alert(Alert /*alert*/) override {}

      void tls_inspect_handshake_msg(const Handshake_Message& message) override {
         m_inspected.push_back({message.type(), &message});
      }

      const std::vector<Inspected_Message>& inspected() const { return m_inspected; }

   private:
      std::vector<Inspected_Message> m_inspected;
};

/**
 * Marshals @p message with its handshake protocol header, independently of the
 * production code. See RFC 9846 4.
 */
auto marshal_message(const Handshake_Message& message) {
   const auto body = message.serialize();
   const auto len_bytes = Botan::store_be(body.size());
   return Botan::concat<Botan::TLS::MarshalledHandshakeMessage>(
      Botan::store_be(message.wire_type()), std::span{len_bytes}.last<3>(), body);
}

std::vector<uint8_t> reference_transcript_hash(std::initializer_list<const Handshake_Message*> messages) {
   auto hash = Botan::HashFunction::create_or_throw("SHA-256");
   for(const auto* message : messages) {
      hash->update(marshal_message(*message));
   }
   return hash->final_stdvec();
}

const Flight::Message_Info* as_message_info(const Flight::Message& msg) {
   return std::get_if<Flight::Message_Info>(&msg);
}

/**
 * Checks that @p msg is a Message_Info that represents @p expected on the wire
 */
void check_message_info(Test::Result& result,
                        const std::string& what,
                        const Flight::Message& msg,
                        const Handshake_Message& expected) {
   const auto* info = as_message_info(msg);
   if(!result.test_is_true(what + ": is a handshake message", info != nullptr)) {
      return;
   }

   const auto expected_body = expected.serialize();
   const auto expected_marshalled = marshal_message(expected);

   result.test_enum_eq(what + ": wire type", info->wire_type, expected.wire_type());
   result.test_bin_eq(what + ": serialized message", info->serialized.get(), expected_body);
   result.test_bin_eq(
      what + ": handshake protocol header", info->header.get(), std::span{expected_marshalled}.first<4>());
}

std::vector<Test::Result> test_transcript_hash_update() {
   return {
      CHECK("each added message updates the transcript hash",
            [](Test::Result& result) {
               auto client_hello = make_client_hello();
               auto server_hello = make_server_hello();
               auto certificate = make_certificate();

               Recording_Callbacks callbacks;
               Transcript_Hash_State th(TLS_Flavor::TLS, "SHA-256");
               Flight flight(th, callbacks);

               result.test_throws<Botan::Invalid_State>("transcript hash is empty before adding messages",
                                                        [&] { th.current(); });

               flight.add(client_hello);
               result.test_bin_eq(
                  "transcript hash after Client Hello", th.current(), reference_transcript_hash({&client_hello}));

               flight.add(server_hello);
               result.test_bin_eq("transcript hash after Server Hello",
                                  th.current(),
                                  reference_transcript_hash({&client_hello, &server_hello}));
               result.test_bin_eq("previous transcript hash is the one after Client Hello",
                                  th.previous(),
                                  reference_transcript_hash({&client_hello}));

               flight.add(certificate);
               result.test_bin_eq("transcript hash after Certificate",
                                  th.current(),
                                  reference_transcript_hash({&client_hello, &server_hello, &certificate}));
               result.test_bin_eq("previous transcript hash is the one after Server Hello",
                                  th.previous(),
                                  reference_transcript_hash({&client_hello, &server_hello}));
            }),

      CHECK("dummy ChangeCipherSpec does not update the transcript hash",
            [](Test::Result& result) {
               auto server_hello = make_server_hello();
               auto certificate = make_certificate();

               Recording_Callbacks callbacks;
               Transcript_Hash_State th(TLS_Flavor::TLS, "SHA-256");
               Flight flight(th, callbacks);

               flight.add_dummy_change_cipher_spec();
               result.test_throws<Botan::Invalid_State>("transcript hash is still empty after a dummy CCS",
                                                        [&] { th.current(); });

               flight.add(server_hello);
               const auto after_server_hello = reference_transcript_hash({&server_hello});
               result.test_bin_eq("transcript hash after Server Hello", th.current(), after_server_hello);

               flight.add_dummy_change_cipher_spec();
               result.test_bin_eq("transcript hash is unchanged by a dummy CCS", th.current(), after_server_hello);
               result.test_throws<Botan::Invalid_State>("previous transcript hash is not replaced by a dummy CCS",
                                                        [&] { th.previous(); });

               flight.add(certificate);
               result.test_bin_eq("transcript hash after Certificate ignores the dummy CCS",
                                  th.current(),
                                  reference_transcript_hash({&server_hello, &certificate}));
               result.test_bin_eq("previous transcript hash after Certificate ignores the dummy CCS",
                                  th.previous(),
                                  after_server_hello);
            }),
   };
}

std::vector<Test::Result> test_inspect_callback() {
   return {
      CHECK("tls_inspect_handshake_msg is called for each message but not for dummy CCS",
            [](Test::Result& result) {
               auto client_hello = make_client_hello();
               auto server_hello = make_server_hello();
               auto certificate = make_certificate();

               Recording_Callbacks callbacks;
               Transcript_Hash_State th(TLS_Flavor::TLS, "SHA-256");
               Flight flight(th, callbacks);

               result.test_sz_eq("no callback invocation initially", callbacks.inspected().size(), 0);

               flight.add(client_hello);
               result.test_sz_eq("callback invoked for Client Hello", callbacks.inspected().size(), 1);

               flight.add_dummy_change_cipher_spec();
               result.test_sz_eq("callback not invoked for dummy CCS", callbacks.inspected().size(), 1);

               flight
                  .add(server_hello)  //
                  .add(certificate);
               result.test_sz_eq("callback invoked for every handshake message", callbacks.inspected().size(), 3);

               if(callbacks.inspected().size() == 3) {
                  const auto& inspected = callbacks.inspected();
                  result.test_enum_eq("first inspected message type", inspected[0].type, Handshake_Type::ClientHello);
                  result.test_enum_eq("second inspected message type", inspected[1].type, Handshake_Type::ServerHello);
                  result.test_enum_eq("third inspected message type", inspected[2].type, Handshake_Type::Certificate);

                  result.test_is_true("first inspected message is the added Client Hello",
                                      inspected[0].address == &client_hello);
                  result.test_is_true("second inspected message is the added Server Hello",
                                      inspected[1].address == &server_hello);
                  result.test_is_true("third inspected message is the added Certificate",
                                      inspected[2].address == &certificate);
               }
            }),

      CHECK("tls_inspect_handshake_msg is called for post-handshake messages",
            [](Test::Result& result) {
               Recording_Callbacks callbacks;
               PostHandshakeFlight flight(callbacks);

               flight
                  .add(make_new_session_ticket())  //
                  .add(Key_Update(false));

               const auto& inspected = callbacks.inspected();
               if(result.test_sz_eq("callback invoked for every post-handshake message", inspected.size(), 2)) {
                  result.test_enum_eq(
                     "first inspected message type", inspected[0].type, Handshake_Type::NewSessionTicket);
                  result.test_enum_eq("second inspected message type", inspected[1].type, Handshake_Type::KeyUpdate);
               }
            }),
   };
}

std::vector<Test::Result> test_commit() {
   return {
      CHECK("commit() of an empty flight is rejected",
            [](Test::Result& result) {
               Recording_Callbacks callbacks;
               Transcript_Hash_State th(TLS_Flavor::TLS, "SHA-256");

               Flight flight(th, callbacks);
               result.test_throws<Botan::Invalid_State>("empty flight", [&] { flight.commit(); });

               PostHandshakeFlight post_handshake_flight(callbacks);
               result.test_throws<Botan::Invalid_State>("empty post-handshake flight",
                                                        [&] { post_handshake_flight.commit(); });
            }),

      CHECK("commit() produces the list of message infos in order",
            [](Test::Result& result) {
               auto server_hello = make_server_hello();
               auto certificate = make_certificate();

               Recording_Callbacks callbacks;
               Transcript_Hash_State th(TLS_Flavor::TLS, "SHA-256");
               auto flight = Flight(th, callbacks)  //
                                .add(server_hello)
                                .add_dummy_change_cipher_spec()
                                .add(certificate);

               const auto messages = flight.commit();
               if(!result.test_sz_eq("number of messages", messages.size(), 3)) {
                  return;
               }

               check_message_info(result, "Server Hello", messages[0], server_hello);
               result.test_is_true("dummy CCS is the second message",
                                   std::holds_alternative<Flight::Dummy_ChangeCipherSpec>(messages[1]));
               check_message_info(result, "Certificate", messages[2], certificate);
            }),

      CHECK("commit() of a post-handshake flight produces the list of message infos in order",
            [](Test::Result& result) {
               const auto new_session_ticket = make_new_session_ticket();
               const Key_Update key_update(true);

               Recording_Callbacks callbacks;
               PostHandshakeFlight flight(callbacks);
               flight.add(Key_Update(true));
               flight.add(make_new_session_ticket());

               const auto messages = flight.commit();
               if(!result.test_sz_eq("number of messages", messages.size(), 2)) {
                  return;
               }

               check_message_info(result, "Key Update", messages[0], key_update);
               check_message_info(result, "New Session Ticket", messages[1], new_session_ticket);
            }),

      CHECK("a flight cannot be used after commit()",
            [](Test::Result& result) {
               auto client_hello = make_client_hello();
               auto server_hello = make_server_hello();

               Recording_Callbacks callbacks;
               Transcript_Hash_State th(TLS_Flavor::TLS, "SHA-256");
               Flight flight(th, callbacks);

               flight.add(client_hello);
               const auto hash_before = th.current();
               result.test_sz_eq("one message committed", flight.commit().size(), 1);

               result.test_throws<Botan::Invalid_State>("add() after commit()", [&] { flight.add(server_hello); });
               result.test_throws<Botan::Invalid_State>("add_dummy_change_cipher_spec() after commit()",
                                                        [&] { flight.add_dummy_change_cipher_spec(); });
               result.test_throws<Botan::Invalid_State>("commit() after commit()", [&] { flight.commit(); });

               result.test_sz_eq("callback was not invoked for the rejected message", callbacks.inspected().size(), 1);
               result.test_bin_eq("transcript hash was not updated by the rejected message", th.current(), hash_before);
            }),

      CHECK("a post-handshake flight cannot be used after commit()",
            [](Test::Result& result) {
               Recording_Callbacks callbacks;
               PostHandshakeFlight flight(callbacks);

               flight.add(Key_Update(false));
               result.test_sz_eq("one message committed", flight.commit().size(), 1);

               result.test_throws<Botan::Invalid_State>("add() after commit()", [&] { flight.add(Key_Update(false)); });
               result.test_throws<Botan::Invalid_State>("commit() after commit()", [&] { flight.commit(); });

               result.test_sz_eq("callback was not invoked for the rejected message", callbacks.inspected().size(), 1);
            }),
   };
}

BOTAN_REGISTER_TEST_FN("tls", "tls_flight_13", test_transcript_hash_update, test_inspect_callback, test_commit);

}  // namespace

}  // namespace Botan_Tests

#endif

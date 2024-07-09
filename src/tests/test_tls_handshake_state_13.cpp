/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)
   #include <botan/tls_exceptn.h>
   #include <botan/internal/tls_handshake_state_13.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS_13)

const auto client_hello_message = Botan::hex_decode(  // from RFC 8448
   "03 03 cb"
   "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
   "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
   "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
   "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
   "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
   "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
   "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
   "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
   "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");

const auto server_hello_message = Botan::hex_decode(
   "03 03 a6"
   "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14"
   "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
   "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
   "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04");

const auto server_finished_message = Botan::hex_decode(
   "9b 9b 14 1d 90 63 37 fb"
   "d2 cb dc e7 1d f4 de da 4a b4 2c 30"
   "95 72 cb 7f ff ee 54 54 b7 8f 07 18");

const auto client_finished_message = Botan::hex_decode(
   "a8 ec 43 6d 67 76 34 ae 52 5a c1"
   "fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61");

std::vector<Test::Result> finished_message_handling() {
   return {
      CHECK("Client sends and receives Finished messages",
            [&](auto& result) {
               Botan::TLS::Client_Handshake_State_13 state;

               Botan::TLS::Finished_13 client_finished(client_finished_message);

               [[maybe_unused]]  // just making sure that the return type of .sending is correct
               std::reference_wrapper<Botan::TLS::Finished_13>
                  client_fin = state.sending(std::move(client_finished));
               result.test_throws("not stored as server Finished", [&] { state.server_finished(); });
               result.test_eq(
                  "correct client Finished stored", state.client_finished().serialize(), client_finished_message);

               Botan::TLS::Finished_13 server_finished(server_finished_message);

               auto server_fin = state.received(std::move(server_finished));
               result.require("client can receive server finished",
                              std::holds_alternative<std::reference_wrapper<Botan::TLS::Finished_13>>(server_fin));
               result.test_eq(
                  "correct client Finished stored", state.client_finished().serialize(), client_finished_message);
               result.test_eq(
                  "correct server Finished stored", state.server_finished().serialize(), server_finished_message);
            }),
   };
}

std::vector<Test::Result> handshake_message_filtering() {
   return {
      CHECK("Client with client hello",
            [&](auto& result) {
               Botan::TLS::Client_Handshake_State_13 state;

               auto client_hello =
                  std::get<Botan::TLS::Client_Hello_13>(Botan::TLS::Client_Hello_13::parse(client_hello_message));

               [[maybe_unused]]  // just making sure that the return type of .sending is correct
               std::reference_wrapper<Botan::TLS::Client_Hello_13>
                  filtered = state.sending(std::move(client_hello));
               result.test_eq("correct client hello stored", state.client_hello().serialize(), client_hello_message);

               result.template test_throws<Botan::TLS::TLS_Exception>(
                  "client cannot receive client hello", "received an illegal handshake message", [&] {
                     auto ch =
                        std::get<Botan::TLS::Client_Hello_13>(Botan::TLS::Client_Hello_13::parse(client_hello_message));
                     state.received(std::move(ch));
                  });
            }),
      CHECK("Client with server hello",
            [&](auto& result) {
               Botan::TLS::Client_Handshake_State_13 state;

               auto server_hello =
                  std::get<Botan::TLS::Server_Hello_13>(Botan::TLS::Server_Hello_13::parse(server_hello_message));

               auto filtered = state.received(std::move(server_hello));
               result.confirm("client can receive server hello",
                              std::holds_alternative<std::reference_wrapper<Botan::TLS::Server_Hello_13>>(filtered));

               result.test_eq("correct server hello stored", state.server_hello().serialize(), server_hello_message);
            }),
   };
}

BOTAN_REGISTER_TEST_FN("tls", "tls_handshake_state_13", finished_message_handling, handshake_message_filtering);

#endif

}  // namespace

}  // namespace Botan_Tests

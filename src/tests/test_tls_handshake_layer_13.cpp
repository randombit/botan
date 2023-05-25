/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

   #include <botan/tls_exceptn.h>
   #include <botan/tls_magic.h>

   #include <botan/internal/stl_util.h>
   #include <botan/internal/tls_handshake_layer_13.h>
   #include <botan/internal/tls_handshake_state_13.h>
   #include <botan/internal/tls_transcript_hash_13.h>

using namespace Botan::TLS;

namespace {

using Test = Botan_Tests::Test;

template <typename T>
bool has_message(Test::Result& test_result, const std::optional<Handshake_Message_13>& read_result) {
   test_result.require("has a message", read_result.has_value());
   return std::holds_alternative<T>(read_result.value());
}

template <typename T>
const Handshake_Message_13& get_message(Test::Result& test_result,
                                        const std::optional<Handshake_Message_13>& read_result) {
   test_result.require("has the expected message", has_message<T>(test_result, read_result));
   return std::get<T>(read_result.value());
}

const auto client_hello_message = Botan::hex_decode_locked(  // from RFC 8448
   "01 00 00 c0 03 03 cb"
   "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
   "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
   "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
   "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
   "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
   "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
   "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
   "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
   "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");

const auto server_hello_message = Botan::hex_decode_locked(
   "02 00 00 56 03 03 a6"
   "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14"
   "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
   "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
   "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04");

const auto server_hello_12_message = Botan::hex_decode_locked(
   "02 00 00 3e 03 03 ff ea 0b cf ba 56 4a 4c e1 77 c6 a4 44 b0 eb"
   "df f5 62 9b 27 72 93 c6 18 c1 12 5f 23 1e 86 28 dd 00 c0 30 00"
   "00 16 ff 01 00 01 00 00 0b 00 04 03 00 01 02 00 23 00 00 00 0f"
   "00 01 01");

const auto encrypted_extensions = Botan::hex_decode_locked(
   "08 00 00 24 00 22 00 0a 00 14 00"
   "12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c"
   "00 02 40 01 00 00 00 00");

const auto server_handshake_messages =  // except server hello
   Botan::hex_decode_locked(
      "08 00 00 24 00 22 00 0a 00 14 00 12 00 1d"
      "00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c 00 02 40"
      "01 00 00 00 00 0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30"
      "82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48 86 f7 0d"
      "01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61"
      "30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36"
      "30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06 03 55 04"
      "03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01"
      "01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30"
      "3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a"
      "24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e"
      "aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01"
      "8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80 30 53"
      "0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab"
      "9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01"
      "a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55 1d"
      "0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05"
      "00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17"
      "06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5"
      "8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72"
      "60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63"
      "a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84"
      "e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29"
      "ac 91 87 b4 2b 4d e1 00 00 0f 00 00 84 08 04 00 80 5a 74 7c 5d"
      "88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a b3"
      "ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07 86"
      "53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b be"
      "8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c"
      "9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d"
      "a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3 14 00"
      "00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c"
      "30 95 72 cb 7f ff ee 54 54 b7 8f 07 18");

const auto client_finished_message = Botan::hex_decode_locked(
   "14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1"
   "fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61");

//
// ###################################################################
//

const auto hrr_client_hello_msg = Botan::hex_decode_locked(
   "01 00 00 b0 03 03 b0 b1 c5 a5 aa 37 c5"
   "91 9f 2e d1 d5 c6 ff f7 fc b7 84 97 16 94 5a 2b 8c ee 92 58 a3"
   "46 67 7b 6f 00 00 06 13 01 13 03 13 02 01 00 00 81 00 00 00 0b"
   "00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 08 00"
   "06 00 1d 00 17 00 18 00 33 00 26 00 24 00 1d 00 20 e8 e8 e3 f3"
   "b9 3a 25 ed 97 a1 4a 7d ca cb 8a 27 2c 62 88 e5 85 c6 48 4d 05"
   "26 2f ca d0 62 ad 1f 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04"
   "03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01"
   "04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");

const auto hrr_hello_retry_request_msg = Botan::hex_decode_locked(
   "02 00 00 ac 03 03 cf 21 ad 74 e5 9a 61"
   "11 be 1d 8c 02 1e 65 b8 91 c2 a2 11 16 7a bb 8c 5e 07 9e 09 e2"
   "c8 a8 33 9c 00 13 01 00 00 84 00 33 00 02 00 17 00 2c 00 74 00"
   "72 71 dc d0 4b b8 8b c3 18 91 19 39 8a 00 00 00 00 ee fa fc 76"
   "c1 46 b8 23 b0 96 f8 aa ca d3 65 dd 00 30 95 3f 4e df 62 56 36"
   "e5 f2 1b b2 e2 3f cc 65 4b 1b 5b 40 31 8d 10 d1 37 ab cb b8 75"
   "74 e3 6e 8a 1f 02 5f 7d fa 5d 6e 50 78 1b 5e da 4a a1 5b 0c 8b"
   "e7 78 25 7d 16 aa 30 30 e9 e7 84 1d d9 e4 c0 34 22 67 e8 ca 0c"
   "af 57 1f b2 b7 cf f0 f9 34 b0 00 2b 00 02 03 04");

const std::vector<Botan::secure_vector<uint8_t>> tls_12_only_messages{
   {static_cast<uint8_t>(Handshake_Type::HelloRequest), 0x00, 0x00, 0x02, 0x42, 0x42},
   {static_cast<uint8_t>(Handshake_Type::HelloVerifyRequest), 0x00, 0x00, 0x02, 0x42, 0x42},
   {static_cast<uint8_t>(Handshake_Type::ServerKeyExchange), 0x00, 0x00, 0x02, 0x42, 0x42},
   {static_cast<uint8_t>(Handshake_Type::ServerHelloDone), 0x00, 0x00, 0x02, 0x42, 0x42},
   {static_cast<uint8_t>(Handshake_Type::ClientKeyExchange), 0x00, 0x00, 0x02, 0x42, 0x42},
   {static_cast<uint8_t>(Handshake_Type::CertificateUrl), 0x00, 0x00, 0x02, 0x42, 0x42},
   {static_cast<uint8_t>(Handshake_Type::CertificateStatus), 0x00, 0x00, 0x02, 0x42, 0x42}};

void check_transcript_hash_empty(Test::Result& result, const Transcript_Hash_State& transcript_hash) {
   result.test_throws<Botan::Invalid_State>("empty transcript_hash throws", [&] { transcript_hash.current(); });
}

void check_transcript_hash_filled(Test::Result& result, const Transcript_Hash_State& transcript_hash) {
   result.test_no_throw("non-empty transcript_hash", [&] { transcript_hash.current(); });
}

std::vector<Test::Result> read_handshake_messages() {
   return {
      Botan_Tests::CHECK("empty read",
                         [&](auto& result) {
                            Handshake_Layer hl(Connection_Side::Client);
                            Transcript_Hash_State th("SHA-256");
                            result.confirm("needs header bytes", !hl.next_message(Policy(), th));
                            check_transcript_hash_empty(result, th);
                         }),

      Botan_Tests::CHECK("read incomplete header",
                         [&](auto& result) {
                            Handshake_Layer hl(Connection_Side::Client);
                            Transcript_Hash_State th("SHA-256");
                            hl.copy_data(std::vector<uint8_t>{0x00, 0x01, 0x02});
                            result.confirm("needs more bytes", !hl.next_message(Policy(), th));
                            check_transcript_hash_empty(result, th);
                         }),

      Botan_Tests::CHECK("read client hello",
                         [&](auto& result) {
                            Handshake_Layer hl(Connection_Side::Client);
                            Transcript_Hash_State th("SHA-256");
                            hl.copy_data(client_hello_message);
                            result.confirm("is a client hello",
                                           has_message<Client_Hello_13>(result, hl.next_message(Policy(), th)));
                            check_transcript_hash_filled(result, th);
                         }),

      Botan_Tests::CHECK("read server hello",
                         [&](auto& result) {
                            Handshake_Layer hl(Connection_Side::Client);
                            Transcript_Hash_State th("SHA-256");
                            hl.copy_data(server_hello_message);
                            result.confirm("is a server hello",
                                           has_message<Server_Hello_13>(result, hl.next_message(Policy(), th)));
                            check_transcript_hash_filled(result, th);
                         }),

      Botan_Tests::CHECK("read legacy server hello",
                         [&](auto& result) {
                            Handshake_Layer hl(Connection_Side::Client);
                            Transcript_Hash_State th("SHA-256");
                            hl.copy_data(server_hello_12_message);
                            result.confirm("is a legacy server hello",
                                           has_message<Server_Hello_12>(result, hl.next_message(Policy(), th)));
                            check_transcript_hash_filled(result, th);
                         }),

      Botan_Tests::CHECK("read client hello in two steps",
                         [&](auto& result) {
                            Handshake_Layer hl(Connection_Side::Client);
                            Transcript_Hash_State th("SHA-256");

                            const Botan::secure_vector<uint8_t> partial_client_hello_message(
                               client_hello_message.cbegin(), client_hello_message.cend() - 15);
                            hl.copy_data(partial_client_hello_message);
                            result.confirm("needs more bytes", !hl.next_message(Policy(), th));
                            result.confirm("holds pending message data", hl.has_pending_data());

                            const Botan::secure_vector<uint8_t> remaining_client_hello_message(
                               client_hello_message.cend() - 15, client_hello_message.cend());
                            hl.copy_data(remaining_client_hello_message);
                            result.confirm("is a client hello",
                                           has_message<Client_Hello_13>(result, hl.next_message(Policy(), th)));

                            check_transcript_hash_filled(result, th);
                         }),

      Botan_Tests::CHECK("read multiple messages",
                         [&](auto& result) {
                            Handshake_Layer hl(Connection_Side::Client);
                            Transcript_Hash_State th("SHA-256");
                            hl.copy_data(Botan::concat(server_hello_message, encrypted_extensions));
                            result.confirm("is a server hello",
                                           has_message<Server_Hello_13>(result, hl.next_message(Policy(), th)));
                            result.confirm("is encrypted extensions",
                                           has_message<Encrypted_Extensions>(result, hl.next_message(Policy(), th)));
                            check_transcript_hash_filled(result, th);
                         }),

      Botan_Tests::CHECK("reject TLS 1.2 messages",
                         [&](auto& result) {
                            for(const auto& msg : tls_12_only_messages) {
                               Handshake_Layer hl(Connection_Side::Client);
                               Transcript_Hash_State th("SHA-256");

                               hl.copy_data(msg);
                               result.template test_throws<TLS_Exception>("message is rejected",
                                                                          "Unknown handshake message received",
                                                                          [&] { hl.next_message(Policy(), th); });

                               check_transcript_hash_empty(result, th);
                            }
                         }),

      Botan_Tests::CHECK(
         "reject incomplete messages with invalid type",
         [&](auto& result) {
            // This is a regression test for BoGo "TLS13-WrongOuterRecord". We receive encrypted handshake messages
            // with the record type set to Handshake rather than Application Data. This exposed our handshake layer
            // to "random data" with an insensible type tag and a long (insensible) length field.
            // This caused a deadlock as we waited to receive the complete message, rather than validating the type
            // tag to exit early.
            const auto data = Botan::hex_decode_locked("D4B028717D0FA310FF8664127B9448D7952E06A4F9EA23");
            // data from the bogo test --          ~~~~~~ <- length
            //                                   ~~ <- bogus message type
            Handshake_Layer hl(Connection_Side::Client);
            Transcript_Hash_State th("SHA-256");
            hl.copy_data(data);
            result.template test_throws<TLS_Exception>(
               "message is rejected", "Unknown handshake message received", [&] { hl.next_message(Policy(), th); });
         }),
   };
}

std::vector<Test::Result> prepare_message() {
   return {
      Botan_Tests::CHECK("prepare client hello",
                         [&](auto& result) {
                            auto hello = std::get<Client_Hello_13>(Client_Hello_13::parse(
                               {client_hello_message.cbegin() + 4, client_hello_message.cend()}));
                            Handshake_Layer hl(Connection_Side::Client);
                            Transcript_Hash_State th("SHA-256");
                            result.test_eq(
                               "produces the same message", hl.prepare_message(hello, th), client_hello_message);
                            check_transcript_hash_filled(result, th);
                         }),

      Botan_Tests::CHECK("prepare server hello",
                         [&](auto& result) {
                            auto hello = std::get<Server_Hello_13>(Server_Hello_13::parse(
                               {server_hello_message.cbegin() + 4, server_hello_message.cend()}));
                            Handshake_Layer hl(Connection_Side::Server);
                            Transcript_Hash_State th("SHA-256");
                            result.test_eq(
                               "produces the same message", hl.prepare_message(hello, th), server_hello_message);
                            check_transcript_hash_filled(result, th);
                         }),
   };
}

std::vector<Test::Result> full_client_handshake() {
   Handshake_Layer hl(Connection_Side::Client);
   Transcript_Hash_State th;

   Text_Policy policy("minimum_rsa_bits = 1024");

   return {
      Botan_Tests::CHECK("client hello",
                         [&](auto& result) {
                            auto hello = std::get<Client_Hello_13>(Client_Hello_13::parse(
                               {client_hello_message.cbegin() + 4, client_hello_message.cend()}));
                            hl.prepare_message(hello, th);
                            check_transcript_hash_empty(result, th);
                         }),

      Botan_Tests::CHECK(
         "server hello",
         [&](auto& result) {
            hl.copy_data(server_hello_message);

            const auto server_hello = hl.next_message(policy, th);
            result.confirm("is a Server Hello", has_message<Server_Hello_13>(result, server_hello));

            // we now know the algorithm from the Server Hello
            th.set_algorithm("SHA-256");

            check_transcript_hash_filled(result, th);

            const auto expected_after_server_hello = Botan::hex_decode(
               "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");

            result.test_eq(
               "correct transcript hash produced after server hello", th.current(), expected_after_server_hello);
         }),

      Botan_Tests::CHECK(
         "server handshake messages",
         [&](auto& result) {
            hl.copy_data(server_handshake_messages);

            const auto enc_exts = hl.next_message(policy, th);
            result.confirm("is Encrypted Extensions", has_message<Encrypted_Extensions>(result, enc_exts));

            const auto cert = hl.next_message(policy, th);
            result.confirm("is Certificate", has_message<Certificate_13>(result, cert));

            const auto expected_after_certificate = Botan::hex_decode(
               "76 4d 66 32 b3 c3 5c 3f 32 05 e3 49 9a c3 ed ba ab b8 82 95 fb a7 51 46 1d 36 78 e2 e5 ea 06 87");

            const auto cert_verify = hl.next_message(policy, th);
            result.confirm("is Certificate Verify", has_message<Certificate_Verify_13>(result, cert_verify));
            result.test_eq("hash before Cert Verify is still available", th.previous(), expected_after_certificate);

            const auto expected_after_server_finished = Botan::hex_decode(
               "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");

            const auto server_finished = hl.next_message(policy, th);
            result.confirm("is Finished", has_message<Finished_13>(result, server_finished));
            result.test_eq("hash is updated after server Finished", th.current(), expected_after_server_finished);
         }),

      Botan_Tests::CHECK(
         "client finished",
         [&](auto& result) {
            const auto expected_after_client_finished = Botan::hex_decode(
               "20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26 84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d");

            Finished_13 client_finished({client_finished_message.cbegin() + 4, client_finished_message.cend()});
            hl.prepare_message(client_finished, th);
            result.test_eq("hash is updated after client Finished", th.current(), expected_after_client_finished);
         }),
   };
}

std::vector<Test::Result> hello_retry_request_handshake() {
   Handshake_Layer hl(Connection_Side::Client);
   Transcript_Hash_State th;

   Text_Policy policy("minimum_rsa_bits = 1024");

   return {
      Botan_Tests::CHECK("client hello 1",
                         [&](auto& result) {
                            auto hello = std::get<Client_Hello_13>(Client_Hello_13::parse(
                               {hrr_client_hello_msg.cbegin() + 4, hrr_client_hello_msg.cend()}));
                            auto msg = hl.prepare_message(hello, th);
                            result.test_eq(
                               "parsing and re-marshalling produces same message", msg, hrr_client_hello_msg);
                            check_transcript_hash_empty(result, th);
                         }),

      Botan_Tests::CHECK("hello retry request",
                         [&](auto& result) {
                            hl.copy_data(hrr_hello_retry_request_msg);

                            const auto hrr = hl.next_message(policy, th);
                            result.confirm("is a Hello Retry Request", has_message<Hello_Retry_Request>(result, hrr));

                            // we now know the algorithm from the Hello Retry Request
                            // which will not change with the future Server Hello anymore (RFC 8446 4.1.4)
                            th = Transcript_Hash_State::recreate_after_hello_retry_request("SHA-256", th);

                            check_transcript_hash_filled(result, th);

                            const auto expected_after_hello_retry_request =
                               Botan::hex_decode("74EEC04D09C926E86C0647C37BA4DC18D277EEC3337E4608C4D829B77E2FD2B3");

                            result.test_eq("correct transcript hash produced after hello retry request",
                                           th.current(),
                                           expected_after_hello_retry_request);
                         }),

      // ... the rest of the handshake will work just like in full_client_handshake
   };
}

}  // namespace

namespace Botan_Tests {
BOTAN_REGISTER_TEST_FN("tls",
                       "tls_handshake_layer_13",
                       read_handshake_messages,
                       prepare_message,
                       full_client_handshake,
                       hello_retry_request_handshake);
}

#endif

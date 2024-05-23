/*
* (C) 2021 Jack Lloyd
* (C) 2021 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

   #include <botan/tls_ciphersuite.h>
   #include <botan/tls_exceptn.h>
   #include <botan/tls_magic.h>
   #include <botan/internal/stl_util.h>
   #include <botan/internal/tls_cipher_state.h>
   #include <botan/internal/tls_reader.h>

   #include <botan/internal/tls_channel_impl_13.h>
   #include <botan/internal/tls_record_layer_13.h>

   #include <array>

namespace Botan_Tests {

namespace {

namespace TLS = Botan::TLS;

using Records = std::vector<TLS::Record>;

TLS::Record_Layer record_layer_client(const bool skip_client_hello = false) {
   auto rl = TLS::Record_Layer(TLS::Connection_Side::Client);

   // this is relevant for tests that rely on the legacy version in the record
   if(skip_client_hello) {
      rl.disable_sending_compat_mode();
   }

   return rl;
}

TLS::Record_Layer record_layer_server(const bool skip_client_hello = false) {
   auto rl = TLS::Record_Layer(TLS::Connection_Side::Server);

   // this is relevant for tests that rely on the legacy version in the record
   if(skip_client_hello) {
      rl.disable_receiving_compat_mode();
   }

   return rl;
}

class Mocked_Secret_Logger : public Botan::TLS::Secret_Logger {
   public:
      void maybe_log_secret(std::string_view, std::span<const uint8_t>) const override {}
};

std::unique_ptr<TLS::Cipher_State> rfc8448_rtt1_handshake_traffic(
   Botan::TLS::Connection_Side side = Botan::TLS::Connection_Side::Client) {
   const auto transcript_hash = Botan::hex_decode(
      "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed"
      "d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
   auto shared_secret = Botan::hex_decode_locked(
      "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d"
      "35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d");
   auto cipher = TLS::Ciphersuite::from_name("AES_128_GCM_SHA256").value();
   Mocked_Secret_Logger logger;
   return TLS::Cipher_State::init_with_server_hello(side, std::move(shared_secret), cipher, transcript_hash, logger);
}

std::vector<Test::Result> read_full_records() {
   const auto client_hello_record = Botan::hex_decode(  // from RFC 8448
      "16 03 01 00 c4 01 00 00 c0 03 03 cb"
      "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
      "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
      "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
      "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
      "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
      "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
      "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
      "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
      "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");
   const auto ccs_record = Botan::hex_decode("14 03 03 00 01 01");

   return {Botan_Tests::CHECK("change cipher spec",
                              [&](auto& result) {
                                 auto rl = record_layer_server();

                                 rl.copy_data(ccs_record);
                                 auto read = rl.next_record();
                                 result.require("received something", std::holds_alternative<TLS::Record>(read));

                                 auto record = std::get<TLS::Record>(read);
                                 result.confirm("received CCS", record.type == TLS::Record_Type::ChangeCipherSpec);
                                 result.test_eq("CCS byte is 0x01", record.fragment, Botan::hex_decode("01"));

                                 result.confirm("no more records",
                                                std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
                              }),

           Botan_Tests::CHECK("two CCS messages",
                              [&](auto& result) {
                                 const auto two_ccs_records = Botan::concat(ccs_record, ccs_record);

                                 auto rl = record_layer_server();

                                 rl.copy_data(two_ccs_records);

                                 auto read = rl.next_record();
                                 result.require("received something", std::holds_alternative<TLS::Record>(read));
                                 auto record = std::get<TLS::Record>(read);

                                 result.confirm("received CCS 1", record.type == TLS::Record_Type::ChangeCipherSpec);
                                 result.test_eq("CCS byte is 0x01", record.fragment, Botan::hex_decode("01"));

                                 read = rl.next_record();
                                 result.require("received something", std::holds_alternative<TLS::Record>(read));
                                 record = std::get<TLS::Record>(read);

                                 result.confirm("received CCS 2", record.type == TLS::Record_Type::ChangeCipherSpec);
                                 result.test_eq("CCS byte is 0x01", record.fragment, Botan::hex_decode("01"));

                                 result.confirm("no more records",
                                                std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
                              }),

           Botan_Tests::CHECK(
              "read full handshake message",
              [&](auto& result) {
                 auto rl = record_layer_server();
                 rl.copy_data(client_hello_record);

                 auto read = rl.next_record();
                 result.confirm("received something", std::holds_alternative<TLS::Record>(read));

                 auto rec = std::get<TLS::Record>(read);
                 result.confirm("received handshake record", rec.type == TLS::Record_Type::Handshake);
                 result.test_eq("contains the full handshake message",
                                Botan::secure_vector<uint8_t>(client_hello_record.begin() + TLS::TLS_HEADER_SIZE,
                                                              client_hello_record.end()),
                                rec.fragment);

                 result.confirm("no more records", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
              }),

           Botan_Tests::CHECK("read full handshake message followed by CCS", [&](auto& result) {
              const auto payload = Botan::concat(client_hello_record, ccs_record);

              auto rl = record_layer_server();
              rl.copy_data(payload);

              auto read = rl.next_record();
              result.require("received something", std::holds_alternative<TLS::Record>(read));

              auto rec = std::get<TLS::Record>(read);
              result.confirm("received handshake record", rec.type == TLS::Record_Type::Handshake);
              result.test_eq("contains the full handshake message",
                             Botan::secure_vector<uint8_t>(client_hello_record.begin() + TLS::TLS_HEADER_SIZE,
                                                           client_hello_record.end()),
                             rec.fragment);

              read = rl.next_record();
              result.require("received something", std::holds_alternative<TLS::Record>(read));

              rec = std::get<TLS::Record>(read);
              result.confirm("received CCS record", rec.type == TLS::Record_Type::ChangeCipherSpec);
              result.test_eq("CCS byte is 0x01", rec.fragment, Botan::hex_decode("01"));

              result.confirm("no more records", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
           })};
}

std::vector<Test::Result> basic_sanitization_parse_records(TLS::Connection_Side side) {
   auto parse_records = [side](const std::vector<uint8_t>& data, TLS::Cipher_State* cs = nullptr) {
      auto rl = ((side == TLS::Connection_Side::Client) ? record_layer_client(true) : record_layer_server());
      rl.copy_data(data);
      return rl.next_record(cs);
   };

   return {
      Botan_Tests::CHECK(
         "'receive' empty data",
         [&](auto& result) {
            auto read = parse_records({});
            result.require("needs bytes", std::holds_alternative<TLS::BytesNeeded>(read));
            result.test_eq("need all the header bytes", std::get<TLS::BytesNeeded>(read), Botan::TLS::TLS_HEADER_SIZE);
         }),

      Botan_Tests::CHECK("incomplete header asks for more data",
                         [&](auto& result) {
                            std::vector<uint8_t> partial_header{'\x23', '\x03', '\x03'};
                            auto read = parse_records(partial_header);
                            result.require("returned 'bytes needed'", std::holds_alternative<TLS::BytesNeeded>(read));

                            result.test_eq("asks for some more bytes",
                                           std::get<TLS::BytesNeeded>(read),
                                           Botan::TLS::TLS_HEADER_SIZE - partial_header.size());
                         }),

      Botan_Tests::CHECK("complete header asks for enough data to finish processing the record",
                         [&](auto& result) {
                            std::vector<uint8_t> full_header{'\x17', '\x03', '\x03', '\x00', '\x42'};
                            auto read = parse_records(full_header);
                            result.require("returned 'bytes needed'", std::holds_alternative<TLS::BytesNeeded>(read));

                            result.test_eq("asks for many more bytes", std::get<TLS::BytesNeeded>(read), 0x42);
                         }),

      Botan_Tests::CHECK("received an empty record (that is not application data)",
                         [&](auto& result) {
                            std::vector<uint8_t> empty_record{'\x16', '\x03', '\x03', '\x00', '\x00'};
                            result.test_throws(
                               "record empty", "empty record received", [&] { parse_records(empty_record); });
                         }),

      Botan_Tests::CHECK("received the maximum size of an unprotected record",
                         [&](auto& result) {
                            std::vector<uint8_t> full_record{'\x16', '\x03', '\x03', '\x40', '\x00'};
                            full_record.resize(TLS::MAX_PLAINTEXT_SIZE + TLS::TLS_HEADER_SIZE);
                            auto read = parse_records(full_record);
                            result.confirm("returned 'record'", !std::holds_alternative<TLS::BytesNeeded>(read));
                         }),

      Botan_Tests::CHECK("received too many bytes in one protected record",
                         [&](auto& result) {
                            std::vector<uint8_t> huge_record{'\x17', '\x03', '\x03', '\x41', '\x01'};
                            huge_record.resize(TLS::MAX_CIPHERTEXT_SIZE_TLS13 + TLS::TLS_HEADER_SIZE + 1);
                            result.test_throws("record too big",
                                               "Received an encrypted record that exceeds maximum size",
                                               [&] { parse_records(huge_record); });
                         }),

      Botan_Tests::CHECK("decryption would result in too large plaintext",
                         [&](auto& result) {
                            // In this case the ciphertext is within the allowed bounds, but the
                            // decrypted plaintext would be too large.
                            std::vector<uint8_t> huge_record{'\x17', '\x03', '\x03', '\x40', '\x12'};
                            huge_record.resize(TLS::MAX_PLAINTEXT_SIZE + TLS::TLS_HEADER_SIZE + 16 /* AES-GCM tag */
                                               + 1                                                 /* encrypted type */
                                               + 1 /* illegal */);

                            auto cs = rfc8448_rtt1_handshake_traffic();
                            result.test_throws("record too big",
                                               "Received an encrypted record that exceeds maximum plaintext size",
                                               [&] { parse_records(huge_record, cs.get()); });
                         }),

      Botan_Tests::CHECK("received too many bytes in one unprotected record",
                         [&](auto& result) {
                            std::vector<uint8_t> huge_record{'\x16', '\x03', '\x03', '\x40', '\x01'};
                            huge_record.resize(TLS::MAX_PLAINTEXT_SIZE + TLS::TLS_HEADER_SIZE + 1);
                            result.test_throws("record too big", "Received a record that exceeds maximum size", [&] {
                               parse_records(huge_record);
                            });
                         }),

      Botan_Tests::CHECK("invalid record type",
                         [&](auto& result) {
                            std::vector<uint8_t> invalid_record_type{'\x42', '\x03', '\x03', '\x41', '\x01'};
                            result.test_throws("invalid record type", "TLS record type had unexpected value", [&] {
                               parse_records(invalid_record_type);
                            });
                         }),

      Botan_Tests::CHECK("invalid record version",
                         [&](auto& result) {
                            std::vector<uint8_t> invalid_record_version{'\x17', '\x13', '\x37', '\x00', '\x01', '\x42'};
                            result.test_throws("invalid record version", "Received unexpected record version", [&] {
                               parse_records(invalid_record_version);
                            });
                         }),

      Botan_Tests::CHECK(
         "initial received record versions might be 0x03XX ",
         [&](auto& result) {
            auto rl = record_layer_client();
            rl.copy_data(std::vector<uint8_t>{0x16, 0x03, 0x00, 0x00, 0x01, 0x42});
            result.test_no_throw("0x03 0x00 should be fine for first records", [&] { rl.next_record(); });

            rl.copy_data(std::vector<uint8_t>{0x16, 0x03, 0x01, 0x00, 0x01, 0x42});
            result.test_no_throw("0x03 0x01 should be fine for first records", [&] { rl.next_record(); });

            rl.copy_data(std::vector<uint8_t>{0x16, 0x03, 0x02, 0x00, 0x01, 0x42});
            result.test_no_throw("0x03 0x02 should be fine for first records", [&] { rl.next_record(); });

            rl.copy_data(std::vector<uint8_t>{0x16, 0x03, 0x03, 0x00, 0x01, 0x42});
            result.test_no_throw("0x03 0x03 should be fine for first records", [&] { rl.next_record(); });

            rl.disable_receiving_compat_mode();

            rl.copy_data(std::vector<uint8_t>{0x16, 0x03, 0x03, 0x00, 0x01, 0x42});
            result.test_no_throw("0x03 0x03 is okay regardless", [&] { rl.next_record(); });

            rl.copy_data(std::vector<uint8_t>{0x16, 0x03, 0x01, 0x00, 0x01, 0x42});
            result.test_throws("0x03 0x01 not okay once client hello was received", [&] { rl.next_record(); });
         }),

      Botan_Tests::CHECK("malformed change cipher spec",
                         [&](auto& result) {
                            std::vector<uint8_t> invalid_ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x02'};
                            result.test_throws("invalid CCS record",
                                               "malformed change cipher spec record received",
                                               [&] { parse_records(invalid_ccs_record); });
                         })

   };
}

std::vector<Test::Result> basic_sanitization_parse_records_client() {
   return basic_sanitization_parse_records(TLS::Connection_Side::Client);
}

std::vector<Test::Result> basic_sanitization_parse_records_server() {
   return basic_sanitization_parse_records(TLS::Connection_Side::Server);
}

std::vector<Test::Result> read_fragmented_records() {
   TLS::Record_Layer rl = record_layer_client(true);

   auto wait_for_more_bytes =
      [](Botan::TLS::BytesNeeded bytes_needed, auto& record_layer, std::vector<uint8_t> bytes, auto& result) {
         record_layer.copy_data(bytes);
         const auto rlr = record_layer.next_record();
         if(result.confirm("waiting for bytes", std::holds_alternative<TLS::BytesNeeded>(rlr))) {
            result.test_eq("right amount", std::get<TLS::BytesNeeded>(rlr), bytes_needed);
         }
      };

   return {Botan_Tests::CHECK("change cipher spec in many small pieces",
                              [&](auto& result) {
                                 std::vector<uint8_t> ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x01'};

                                 wait_for_more_bytes(4, rl, {'\x14'}, result);
                                 wait_for_more_bytes(3, rl, {'\x03'}, result);
                                 wait_for_more_bytes(2, rl, {'\x03'}, result);
                                 wait_for_more_bytes(1, rl, {'\x00'}, result);
                                 wait_for_more_bytes(1, rl, {'\x01'}, result);

                                 rl.copy_data(std::vector<uint8_t>{'\x01'});
                                 auto res1 = rl.next_record();
                                 result.require("received something 1", std::holds_alternative<TLS::Record>(res1));

                                 auto rec1 = std::get<TLS::Record>(res1);
                                 result.confirm("received CCS", rec1.type == TLS::Record_Type::ChangeCipherSpec);
                                 result.test_eq("CCS byte is 0x01", rec1.fragment, Botan::hex_decode("01"));

                                 result.confirm("no more records",
                                                std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
                              }),

           Botan_Tests::CHECK("two change cipher specs in several pieces", [&](auto& result) {
              wait_for_more_bytes(1, rl, {'\x14', '\x03', '\x03', '\x00'}, result);

              rl.copy_data(std::vector<uint8_t>{'\x01', '\x01', /* second CCS starts here */ '\x14', '\x03'});

              auto res2 = rl.next_record();
              result.require("received something 2", std::holds_alternative<TLS::Record>(res2));

              auto rec2 = std::get<TLS::Record>(res2);
              result.confirm("received CCS", rec2.type == TLS::Record_Type::ChangeCipherSpec);
              result.confirm("demands more bytes", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));

              wait_for_more_bytes(2, rl, {'\x03'}, result);

              rl.copy_data(std::vector<uint8_t>{'\x00', '\x01', '\x01'});
              auto res3 = rl.next_record();
              result.require("received something 3", std::holds_alternative<TLS::Record>(res3));

              auto rec3 = std::get<TLS::Record>(res3);
              result.confirm("received CCS", rec3.type == TLS::Record_Type::ChangeCipherSpec);

              result.confirm("no more records", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
           })};
}

std::vector<Test::Result> write_records() {
   auto cs = rfc8448_rtt1_handshake_traffic();
   return {
      Botan_Tests::CHECK(
         "prepare an zero-length application data fragment",
         [&](auto& result) {
            auto record = record_layer_client().prepare_records(Botan::TLS::Record_Type::ApplicationData, {}, cs.get());

            result.require("record header was added",
                           record.size() > Botan::TLS::TLS_HEADER_SIZE + 1 /* encrypted content type */);
         }),
      Botan_Tests::CHECK(
         "prepare a client hello",
         [&](auto& result) {
            const auto client_hello_msg = Botan::hex_decode(  // from RFC 8448
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
            auto record = record_layer_client().prepare_records(Botan::TLS::Record_Type::Handshake, client_hello_msg);

            result.require("record header was added",
                           record.size() == client_hello_msg.size() + Botan::TLS::TLS_HEADER_SIZE);

            const auto header = std::vector<uint8_t>(record.cbegin(), record.cbegin() + Botan::TLS::TLS_HEADER_SIZE);
            result.test_eq("record header is well-formed", header, Botan::hex_decode("16030100c4"));
         }),
      Botan_Tests::CHECK("prepare a dummy CCS",
                         [&](auto& result) {
                            std::array<uint8_t, 1> ccs_content = {0x01};
                            auto record = record_layer_client(true).prepare_records(
                               Botan::TLS::Record_Type::ChangeCipherSpec, ccs_content);
                            result.require("record was created", record.size() == Botan::TLS::TLS_HEADER_SIZE + 1);

                            result.test_eq("CCS record is well-formed", record, Botan::hex_decode("140303000101"));
                         }),
      Botan_Tests::CHECK(
         "cannot prepare non-dummy CCS",
         [&](auto& result) {
            result.test_throws("cannot create non-dummy CCS", "TLS 1.3 deprecated CHANGE_CIPHER_SPEC", [] {
               const auto ccs_content = Botan::hex_decode("de ad be ef");
               record_layer_client().prepare_records(Botan::TLS::Record_Type::ChangeCipherSpec, ccs_content);
            });
         }),
      Botan_Tests::CHECK("large messages are sharded", [&](auto& result) {
         const std::vector<uint8_t> large_client_hello(Botan::TLS::MAX_PLAINTEXT_SIZE + 4096);
         auto record = record_layer_client().prepare_records(Botan::TLS::Record_Type::Handshake, large_client_hello);

         result.test_gte("produces at least two record headers",
                         record.size(),
                         large_client_hello.size() + 2 * Botan::TLS::TLS_HEADER_SIZE);
      })};
}

std::vector<Test::Result> read_encrypted_records() {
   // this is the "complete record" server hello portion
   // from RFC 8448 page 7
   const auto server_hello = Botan::hex_decode(
      "16 03 03 00 5a 02 00 00 56 03 03 a6"
      "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14"
      "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
      "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
      "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04");

   // this is the "complete record" encrypted server hello portion
   // from RFC 8448 page 9
   const auto encrypted_record = Botan::hex_decode(
      "17 03 03 02 a2 d1 ff 33 4a 56 f5 bf"
      "f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df"
      "78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45"
      "cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3"
      "89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b"
      "d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9"
      "b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf"
      "51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d"
      "2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55"
      "cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f"
      "d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6"
      "86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac"
      "66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea"
      "52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e"
      "a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6"
      "54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb"
      "31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59"
      "62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e"
      "92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af"
      "36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37"
      "8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c"
      "f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88"
      "2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80"
      "f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69"
      "18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99"
      "2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11"
      "c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51"
      "56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42"
      "f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f"
      "60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd"
      "d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af"
      "93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da"
      "bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b");

   // the record above padded with 42 zeros
   const auto encrypted_record_with_padding = Botan::hex_decode(
      "17 03 03 02 cc d1 ff 33 4a 56 f5 bf f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45"
      "e4 89 e7 f3 3a f3 5e df 78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61"
      "2e f9 f9 45 cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3"
      "89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b d9 ae fb 0e"
      "57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9 b1 18 3e f3 ab 20 e3 7d"
      "57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf 51 42 73 25 25 0c 7d 0e 50 92 89 44"
      "4c 9b 3a 64 8f 1d 71 03 5d 2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb"
      "b3 60 98 72 55 cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a"
      "8f d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6 86 94 5b"
      "a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac 66 27 2f d8 fb 33 0e"
      "f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea 52 0a 56 a8 d6 50 f5 63 aa d2 74"
      "09 96 0d ca 63 d3 e6 88 61 1e a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42"
      "72 96 8a 26 4e d6 54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a"
      "cb bb 31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59 62 22"
      "45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e 92 ea 33 0f ae ea"
      "6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af 36 87 90 18 e3 f2 52 10 7f 24"
      "3d 24 3d c7 33 9d 56 84 c8 b0 37 8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5"
      "e8 28 0a 2b 48 05 2c f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6"
      "6f 99 88 2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80 f8"
      "5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69 18 a3 96 fa 48"
      "a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99 2f 67 f8 af e6 7f 76 91 3f"
      "a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11 c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b"
      "bf 10 dc 35 ae 69 f5 51 56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30"
      "38 eb ba 42 f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f"
      "60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd d5 02 78 40"
      "16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af 93 98 28 fd 4a e3 79 4e"
      "44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da 04 d8 68 77 bb e0 dc ce f9 01 ed 32"
      "59 50 7a 0c d0 62 3f 90 1b 5c 89 d4 b4 f2 d1 56 f6 da 4f 3e c5 fd 2d e5 e2"
      "fa 44 23 0a e0 c9 dd dd bb a8 be db d9 d7 f6 b8 3d 56 4c a5 47");

   auto parse_records = [](const std::vector<uint8_t>& data) {
      auto rl = record_layer_client(true);
      rl.copy_data(data);
      return rl;
   };

   return {
      Botan_Tests::CHECK(
         "read encrypted server hello extensions",
         [&](Test::Result& result) {
            auto cs = rfc8448_rtt1_handshake_traffic();
            auto rl = parse_records(encrypted_record);

            auto res = rl.next_record(cs.get());
            result.require("some records decrypted", !std::holds_alternative<Botan::TLS::BytesNeeded>(res));
            auto record = std::get<TLS::Record>(res);

            result.test_is_eq("inner type was 'HANDSHAKE'", record.type, Botan::TLS::Record_Type::Handshake);
            result.test_eq("decrypted payload length", record.fragment.size(), 657 /* taken from RFC 8448 */);

            result.confirm("no more records", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
         }),

      Botan_Tests::CHECK("premature application data",
                         [&](Test::Result& result) {
                            auto rl = record_layer_client(true);
                            rl.copy_data(encrypted_record);

                            result.test_throws<Botan::TLS::TLS_Exception>(
                               "cannot process encrypted data with uninitialized cipher state",
                               "premature Application Data received",
                               [&] { auto res = rl.next_record(nullptr); });
                         }),

      Botan_Tests::CHECK("decryption fails due to bad MAC",
                         [&](Test::Result& result) {
                            auto tampered_encrypted_record = encrypted_record;
                            tampered_encrypted_record.back() =
                               '\x42';  // changing one payload byte causes the MAC check to fails

                            result.test_throws<Botan::Invalid_Authentication_Tag>("broken record detected", [&] {
                               auto cs = rfc8448_rtt1_handshake_traffic();
                               auto rl = parse_records(tampered_encrypted_record);
                               rl.next_record(cs.get());
                            });
                         }),

      Botan_Tests::CHECK("decryption fails due to too short record",
                         [&](Test::Result& result) {
                            const auto short_record = Botan::hex_decode("17 03 03 00 08 de ad be ef ba ad f0 0d");

                            result.test_throws<Botan::TLS::TLS_Exception>("too short to decrypt", [&] {
                               auto cs = rfc8448_rtt1_handshake_traffic();
                               auto rl = parse_records(short_record);
                               rl.next_record(cs.get());
                            });
                         }),

      Botan_Tests::CHECK("protected Change Cipher Spec message is illegal",
                         [&](Test::Result& result) {
                            // factored message, encrypted under the same key as `encrypted_record`
                            const auto protected_ccs =
                               Botan::hex_decode("1703030012D8EBBBE055C8167D5690EC67DEA9A525B036");

                            result.test_throws<Botan::TLS::TLS_Exception>(
                               "illegal state causes TLS alert", "protected change cipher spec received", [&] {
                                  auto cs = rfc8448_rtt1_handshake_traffic();
                                  auto rl = parse_records(protected_ccs);
                                  rl.next_record(cs.get());
                               });
                         }),

      Botan_Tests::CHECK("unprotected CCS is legal when encrypted traffic is expected",
                         [&](Test::Result& result) {
                            const auto ccs_record = Botan::hex_decode("14 03 03 00 01 01");

                            result.test_no_throw("CCS is acceptable", [&] {
                               auto cs = rfc8448_rtt1_handshake_traffic();  // expect encrypted traffic
                               auto rl = parse_records(ccs_record);
                               rl.next_record(cs.get());
                            });
                         }),

      Botan_Tests::CHECK("unprotected Alert message might be legal",
                         [&](Test::Result& result) {
                            const auto alert = Botan::hex_decode("15030300020232");  // decode error
                            const auto hsmsg = Botan::hex_decode(  // factored 'certificate_request' message
                               "160303002a0d000027000024000d0020001e040305030603"
                               "020308040805080604010501060102010402050206020202");

                            result.test_no_throw("Server allows unprotected alerts after its first flight", [&] {
                               auto cs = rfc8448_rtt1_handshake_traffic(TLS::Connection_Side::Server);
                               auto rl = parse_records(alert);
                               rl.next_record(cs.get());
                            });

                            result.test_throws<Botan::TLS::TLS_Exception>(
                               "Unprotected handshake messages are not allowed for servers",
                               "unprotected record received where protected traffic was expected",
                               [&] {
                                  auto cs = rfc8448_rtt1_handshake_traffic(TLS::Connection_Side::Server);
                                  auto rl = parse_records(hsmsg);
                                  rl.next_record(cs.get());
                               });

                            result.test_throws<Botan::TLS::TLS_Exception>(
                               "Clients don't allow unprotected alerts after Server Hello",
                               "unprotected record received where protected traffic was expected",
                               [&] {
                                  auto cs = rfc8448_rtt1_handshake_traffic(TLS::Connection_Side::Client);
                                  auto rl = parse_records(alert);
                                  rl.next_record(cs.get());
                               });

                            result.test_throws<Botan::TLS::TLS_Exception>(
                               "Unprotected handshake messages are not allowed for clients",
                               "unprotected record received where protected traffic was expected",
                               [&] {
                                  auto cs = rfc8448_rtt1_handshake_traffic(TLS::Connection_Side::Client);
                                  auto rl = parse_records(hsmsg);
                                  rl.next_record(cs.get());
                               });
                         }),

      Botan_Tests::CHECK("unprotected traffic is illegal when encrypted traffic is expected",
                         [&](Test::Result& result) {
                            result.test_throws("unprotected record is unacceptable", [&] {
                               auto cs = rfc8448_rtt1_handshake_traffic();  // expect encrypted traffic
                               auto rl = parse_records(server_hello);
                               rl.next_record(cs.get());
                            });
                         }),

      Botan_Tests::CHECK(
         "read fragmented application data",
         [&](Test::Result& result) {
            const auto encrypted = Botan::hex_decode(
               "17 03 03 00 1A 90 78 6D 7E 6F A8 F7 67 1F 6D 05 F7 24 18 F5 DB 43 F7 0B 9E 48 A6 96 B6 5B EC"
               "17 03 03 00 28 6C 21 B5 B8 D8 1B 85 5C 17 0E C7 9B 2C 28 85 85 51 29 2F 71 14 F3 D7 BD D5 D1"
               "80 C2 E9 3D EC 84 3B 8D 41 30 D8 C8 C5 D8"
               "17 03 03 00 21 29 9A B0 5A EA 3F 8A DE 05 12 E0 6B 4A 28 C3 E2 69 2F 58 82 F1 A3 45 04 EA 16"
               "14 72 39 6F A1 F3 D3 ");
            const std::vector<std::vector<uint8_t>> plaintext_records = {
               Botan::hex_decode("00 01 02 03 04 05 06 07 08"),
               Botan::hex_decode("09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"),
               Botan::hex_decode("20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f")};

            auto cs = rfc8448_rtt1_handshake_traffic();
            // advance with arbitrary hashes that were used to produce the input data
            Mocked_Secret_Logger logger;
            cs->advance_with_server_finished(
               Botan::hex_decode("e1935a480babfc4403b2517f0ad414bed0ca51fa671e2061804afa78fd71d55c"), logger);
            cs->advance_with_client_finished(
               Botan::hex_decode("305e4a0a7cee581b282c571b251b20138a1a6a21918937a6bb95b1e9ba1b5cac"));

            auto rl = parse_records(encrypted);
            auto res = rl.next_record(cs.get());
            result.require("decrypted a record", std::holds_alternative<TLS::Record>(res));
            auto records = std::get<TLS::Record>(res);
            result.test_eq("first record", records.fragment, plaintext_records.at(0));

            res = rl.next_record(cs.get());
            result.require("decrypted a record", std::holds_alternative<TLS::Record>(res));
            records = std::get<TLS::Record>(res);
            result.test_eq("second record", records.fragment, plaintext_records.at(1));

            res = rl.next_record(cs.get());
            result.require("decrypted a record", std::holds_alternative<TLS::Record>(res));
            records = std::get<TLS::Record>(res);
            result.test_eq("third record", records.fragment, plaintext_records.at(2));

            result.confirm("no more records", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
         }),

      Botan_Tests::CHECK(
         "read coalesced server hello and encrypted extensions",
         [&](Test::Result& result) {
            // contains the plaintext server hello and the encrypted extensions in one go
            auto coalesced = server_hello;
            coalesced.insert(coalesced.end(), encrypted_record.cbegin(), encrypted_record.cend());

            auto client = record_layer_client(true);
            client.copy_data(coalesced);

            const auto srv_hello = client.next_record(nullptr);
            result.confirm("read a record", std::holds_alternative<TLS::Record>(srv_hello));
            result.confirm("is handshake record", std::get<TLS::Record>(srv_hello).type == TLS::Record_Type::Handshake);

            auto cs = rfc8448_rtt1_handshake_traffic();
            const auto enc_exts = client.next_record(cs.get());
            result.confirm("read a record", std::holds_alternative<TLS::Record>(enc_exts));
            result.confirm("is handshake record", std::get<TLS::Record>(enc_exts).type == TLS::Record_Type::Handshake);
         }),

      Botan_Tests::CHECK("read a padded record",
                         [&](Test::Result& result) {
                            auto client = record_layer_client(true);
                            client.copy_data(encrypted_record_with_padding);

                            auto cs = rfc8448_rtt1_handshake_traffic();
                            const auto record = client.next_record(cs.get());
                            result.confirm("read a record with padding", std::holds_alternative<TLS::Record>(record));
                         }),

      Botan_Tests::CHECK("read an empty encrypted record", [&](Test::Result& result) {
         auto client = record_layer_client(true);
         client.copy_data(Botan::hex_decode("1703030011CE43CA0D2F28336715E770071B2D5EE0FE"));

         auto cs = rfc8448_rtt1_handshake_traffic();
         const auto record = client.next_record(cs.get());
         result.confirm("read an empty record", std::holds_alternative<TLS::Record>(record));
      })};
}

std::vector<Test::Result> write_encrypted_records() {
   auto plaintext_msg = Botan::hex_decode(
      "14 00 00 20 a8 ec 43 6d 67 76 34 ae"
      "52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61");

   auto cs = rfc8448_rtt1_handshake_traffic();
   return {Botan_Tests::CHECK("write encrypted client handshake finished",
                              [&](Test::Result& result) {
                                 auto ct = record_layer_client(true).prepare_records(
                                    TLS::Record_Type::Handshake, plaintext_msg, cs.get());
                                 auto expected_ct = Botan::hex_decode(
                                    "17 03 03 00 35 75 ec 4d c2 38 cc e6"
                                    "0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44 d8 7f"
                                    "38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7 26 c4 05 46");
                                 result.test_eq("produced the expected ciphertext", ct, expected_ct);
                              }),

           Botan_Tests::CHECK("write a dummy CCS (that must not be encrypted)",
                              [&](auto& result) {
                                 std::array<uint8_t, 1> ccs_content = {0x01};
                                 auto record = record_layer_client(true).prepare_records(
                                    Botan::TLS::Record_Type::ChangeCipherSpec, ccs_content, cs.get());
                                 result.require("record was created and not encrypted",
                                                record.size() == Botan::TLS::TLS_HEADER_SIZE + 1);

                                 result.test_eq("CCS record is well-formed", record, Botan::hex_decode("140303000101"));
                              }),

           Botan_Tests::CHECK("write a lot of data producing two protected records", [&](Test::Result& result) {
              std::vector<uint8_t> big_data(TLS::MAX_PLAINTEXT_SIZE + TLS::MAX_PLAINTEXT_SIZE / 2);
              auto ct =
                 record_layer_client(true).prepare_records(TLS::Record_Type::ApplicationData, big_data, cs.get());
              result.require("encryption added some MAC and record headers",
                             ct.size() > big_data.size() + Botan::TLS::TLS_HEADER_SIZE * 2);

              auto read_record_header = [&](auto& reader) {
                 result.test_is_eq(
                    "APPLICATION_DATA", reader.get_byte(), static_cast<uint8_t>(TLS::Record_Type::ApplicationData));
                 result.test_is_eq("TLS legacy version", reader.get_uint16_t(), uint16_t(0x0303));

                 const auto fragment_length = reader.get_uint16_t();
                 result.test_lte("TLS limts", fragment_length, TLS::MAX_CIPHERTEXT_SIZE_TLS13);
                 result.require("enough data", fragment_length + Botan::TLS::TLS_HEADER_SIZE < ct.size());
                 return fragment_length;
              };

              TLS::TLS_Data_Reader reader("test reader", ct);
              const auto fragment_length1 = read_record_header(reader);
              reader.discard_next(fragment_length1);

              const auto fragment_length2 = read_record_header(reader);
              reader.discard_next(fragment_length2);

              result.confirm("consumed all bytes", !reader.has_remaining());
           })};
}

std::vector<Test::Result> legacy_version_handling() {
   // RFC 8446 5.1:
   // legacy_record_version:  MUST be set to 0x0303 for all records
   //    generated by a TLS 1.3 implementation other than an initial
   //    ClientHello (i.e., one not generated after a HelloRetryRequest),
   //    where it MAY also be 0x0301 for compatibility purposes.

   auto has_version = [](const auto& record, const uint16_t version) -> bool {
      TLS::TLS_Data_Reader dr("header reader", record);

      while(dr.has_remaining()) {
         dr.discard_next(1);  // record type
         if(dr.get_uint16_t() != version) {
            return false;
         }
         const auto record_size = dr.get_uint16_t();
         dr.discard_next(record_size);
      }

      dr.assert_done();
      return true;
   };

   auto parse_record = [](auto& record_layer, const std::vector<uint8_t>& data) {
      record_layer.copy_data(data);
      return record_layer.next_record();
   };

   return {
      Botan_Tests::CHECK("client side starts with version 0x0301",
                         [&](Test::Result& result) {
                            auto rl = record_layer_client();
                            auto rec = rl.prepare_records(TLS::Record_Type::Handshake, std::vector<uint8_t>(5));
                            result.confirm("first record has version 0x0301", has_version(rec, 0x0301));

                            rl.disable_sending_compat_mode();

                            rec = rl.prepare_records(TLS::Record_Type::Handshake, std::vector<uint8_t>(5));
                            result.confirm("next record has version 0x0303", has_version(rec, 0x0303));
                         }),

      Botan_Tests::CHECK("client side starts with version 0x0301 (even if multiple reconds are required)",
                         [&](Test::Result& result) {
                            auto rl = record_layer_client();
                            auto rec = rl.prepare_records(TLS::Record_Type::Handshake,
                                                          std::vector<uint8_t>(5 * Botan::TLS::MAX_PLAINTEXT_SIZE));
                            result.confirm("first record has version 0x0301", has_version(rec, 0x0301));

                            rl.disable_sending_compat_mode();

                            rec = rl.prepare_records(TLS::Record_Type::Handshake,
                                                     std::vector<uint8_t>(5 * Botan::TLS::MAX_PLAINTEXT_SIZE));
                            result.confirm("next record has version 0x0303", has_version(rec, 0x0303));
                         }),

      Botan_Tests::CHECK("server side starts with version 0x0303",
                         [&](Test::Result& result) {
                            auto rl = record_layer_server(true);
                            auto rec = rl.prepare_records(TLS::Record_Type::Handshake, std::vector<uint8_t>(5));
                            result.confirm("first record has version 0x0303", has_version(rec, 0x0303));
                         }),

      Botan_Tests::CHECK("server side accepts version 0x0301 for the first record",
                         [&](Test::Result& result) {
                            const auto first_record = Botan::hex_decode("16 03 01 00 05 00 00 00 00 00");
                            const auto second_record = Botan::hex_decode("16 03 03 00 05 00 00 00 00 00");
                            auto rl = record_layer_server();
                            result.test_no_throw("parsing initial record", [&] { parse_record(rl, first_record); });
                            result.test_no_throw("parsing second record", [&] { parse_record(rl, second_record); });
                         }),

      Botan_Tests::CHECK("server side accepts version 0x0301 for the first record for partial records",
                         [&](Test::Result& result) {
                            const auto first_part = Botan::hex_decode("16 03 01");
                            const auto second_part = Botan::hex_decode("00 05 00 00 00 00 00");
                            auto rl = record_layer_server();
                            result.test_no_throw("parsing initial part", [&] { parse_record(rl, first_part); });
                            result.test_no_throw("parsing second part", [&] { parse_record(rl, second_part); });
                         }),

      Botan_Tests::CHECK("server side accepts version 0x0303 for the first record",
                         [&](Test::Result& result) {
                            const auto first_record = Botan::hex_decode("16 03 03 00 05 00 00 00 00 00");
                            auto rl = record_layer_server();
                            result.test_no_throw("parsing initial record", [&] { parse_record(rl, first_record); });
                         }),

      Botan_Tests::CHECK("server side does not accept version 0x0301 after receiving client hello",
                         [&](Test::Result& result) {
                            const auto record = Botan::hex_decode("16 03 01 00 05 00 00 00 00 00");
                            auto rl = record_layer_server();
                            result.test_no_throw("parsing initial record", [&] { parse_record(rl, record); });
                            rl.disable_receiving_compat_mode();
                            result.test_throws("parsing second record", [&] { parse_record(rl, record); });
                         }),

      Botan_Tests::CHECK(
         "server side does not accept other versions (after receiving client hello)",
         [&](Test::Result& result) {
            auto rl = record_layer_server(true);
            result.test_throws("does not accept 0x0300",
                               [&] { parse_record(rl, Botan::hex_decode("16 03 00 00 05 00 00 00 00 00")); });
            result.test_throws("does not accept 0x0302",
                               [&] { parse_record(rl, Botan::hex_decode("16 03 02 00 05 00 00 00 00 00")); });
            result.test_throws("does not accept 0x0304",
                               [&] { parse_record(rl, Botan::hex_decode("16 03 04 00 05 00 00 00 00 00")); });
            result.test_throws("does not accept 0x0305",
                               [&] { parse_record(rl, Botan::hex_decode("16 03 05 00 05 00 00 00 00 00")); });
         })

   };
}

std::vector<Test::Result> record_size_limits() {
   const auto count_records = [](auto& records) {
      Botan::TLS::TLS_Data_Reader reader("record counter", records);
      size_t record_count = 0;

      for(; reader.has_remaining(); ++record_count) {
         reader.discard_next(1);                               // record type
         BOTAN_ASSERT_NOMSG(reader.get_uint16_t() == 0x0303);  // record version
         reader.get_tls_length_value(2);                       // record length/content
      }

      return record_count;
   };

   const auto record_length = [](auto& result, auto record) {
      result.require("has record", std::holds_alternative<Botan::TLS::Record>(record));
      const auto& r = std::get<Botan::TLS::Record>(record);
      return r.fragment.size();
   };

   return {
      Botan_Tests::CHECK(
         "no specified limits means protocol defaults",
         [&](Test::Result& result) {
            auto csc = rfc8448_rtt1_handshake_traffic(Botan::TLS::Connection_Side::Client);
            auto rlc = record_layer_client(true);

            const auto r1 = rlc.prepare_records(
               TLS::Record_Type::ApplicationData, std::vector<uint8_t>(Botan::TLS::MAX_PLAINTEXT_SIZE), csc.get());
            result.test_eq("one record generated", count_records(r1), 1);

            const auto r2 = rlc.prepare_records(
               TLS::Record_Type::ApplicationData, std::vector<uint8_t>(Botan::TLS::MAX_PLAINTEXT_SIZE + 1), csc.get());
            result.test_eq("two records generated", count_records(r2), 2);

            auto css = rfc8448_rtt1_handshake_traffic(Botan::TLS::Connection_Side::Server);
            auto rls = record_layer_server(true);
            rls.copy_data(r1);

            result.test_eq("correct length record",
                           record_length(result, rls.next_record(css.get())),
                           Botan::TLS::MAX_PLAINTEXT_SIZE);
         }),

      Botan_Tests::CHECK(
         "outgoing record size limit",
         [&](Test::Result& result) {
            auto cs = rfc8448_rtt1_handshake_traffic();
            auto rl = record_layer_client(true);

            rl.set_record_size_limits(127 + 1 /* content type byte */, Botan::TLS::MAX_PLAINTEXT_SIZE + 1);

            const auto r1 = rl.prepare_records(TLS::Record_Type::ApplicationData, std::vector<uint8_t>(127), cs.get());
            result.test_eq("one record generated", count_records(r1), 1);

            const auto r2 = rl.prepare_records(TLS::Record_Type::ApplicationData, std::vector<uint8_t>(128), cs.get());
            result.test_eq("two records generated", count_records(r2), 2);
         }),

      Botan_Tests::CHECK(
         "outgoing record size limit can be changed",
         [&](Test::Result& result) {
            auto cs = rfc8448_rtt1_handshake_traffic();
            auto rl = record_layer_client(true);

            const auto r1 = rl.prepare_records(
               TLS::Record_Type::ApplicationData, std::vector<uint8_t>(Botan::TLS::MAX_PLAINTEXT_SIZE), cs.get());
            result.test_eq("one record generated", count_records(r1), 1);

            const auto r2 = rl.prepare_records(
               TLS::Record_Type::ApplicationData, std::vector<uint8_t>(Botan::TLS::MAX_PLAINTEXT_SIZE + 1), cs.get());
            result.test_eq("two records generated", count_records(r2), 2);

            rl.set_record_size_limits(127 + 1 /* content type byte */, Botan::TLS::MAX_PLAINTEXT_SIZE + 1);

            const auto r3 = rl.prepare_records(TLS::Record_Type::ApplicationData, std::vector<uint8_t>(127), cs.get());
            result.test_eq("one record generated", count_records(r3), 1);

            const auto r4 = rl.prepare_records(TLS::Record_Type::ApplicationData, std::vector<uint8_t>(128), cs.get());
            result.test_eq("two records generated", count_records(r4), 2);
         }),

      Botan_Tests::CHECK("outgoing record limit does not affect unencrypted records",
                         [&](Test::Result& result) {
                            auto rl = record_layer_client(true);

                            rl.set_record_size_limits(127 + 1 /* content type byte */,
                                                      Botan::TLS::MAX_PLAINTEXT_SIZE + 1);

                            const auto r1 = rl.prepare_records(TLS::Record_Type::Handshake,
                                                               std::vector<uint8_t>(Botan::TLS::MAX_PLAINTEXT_SIZE));
                            result.test_eq("one record generated", count_records(r1), 1);

                            const auto r2 = rl.prepare_records(
                               TLS::Record_Type::Handshake, std::vector<uint8_t>(Botan::TLS::MAX_PLAINTEXT_SIZE + 1));
                            result.test_eq("two records generated", count_records(r2), 2);
                         }),

      Botan_Tests::CHECK("incoming limit is not checked on unprotected records",
                         [&](Test::Result& result) {
                            auto rlc = record_layer_client(true);

                            rlc.set_record_size_limits(Botan::TLS::MAX_PLAINTEXT_SIZE + 1, 95 + 1);

                            rlc.copy_data(
                               Botan::concat(Botan::hex_decode("16 03 03 00 80"), std::vector<uint8_t>(128)));
                            result.test_eq("correct length record", record_length(result, rlc.next_record()), 128);
                         }),

      Botan_Tests::CHECK("incoming limit is checked on protected records",
                         [&](Test::Result& result) {
                            auto css = rfc8448_rtt1_handshake_traffic(Botan::TLS::Connection_Side::Server);
                            auto rls = record_layer_server(true);

                            rls.set_record_size_limits(Botan::TLS::MAX_PLAINTEXT_SIZE + 1, 127 + 1);
                            rls.copy_data(
                               Botan::hex_decode("170303009061ec4de29020a5664ef670094c7b5daa2796aa52e128cfa8808d15c1"
                                                 "ffc97a0aeeed62f9ea690bb753a03d000c5efac53c619face25ad234dffb63e611"
                                                 "4619fb045e3a3a0dde4f22e2399b4891029eccb79ea4a29c45a999e72fc74157f0"
                                                 "21db0afa05601af25b61df82fb728c772ad860081d96c86008c08d0c21f991cf0d"
                                                 "4a0eadc840d1ea8fb1f5dd852980d78fcc"));

                            result.test_eq(
                               "correct length record", record_length(result, rls.next_record(css.get())), 127);

                            rls.copy_data(
                               Botan::hex_decode("1703030091234d4a480092fa6a55f1443345ee8d2250cd9c676370be68f86234db"
                                                 "f5514c6dea8b3fa99c6146fefc780e36230858a53f4c0295b23a77dc5b495e0541"
                                                 "093aa05ee6cf6f4a4996d9ffc829b638c822e4c36e4da50f1cf2845c12e4388d58"
                                                 "e907e181f2dd38e61e78c13ebcbd562a23025fd327eb4db083330314e4641f3b4b"
                                                 "43bf11dbb09f7a82443193dc9ece34dabd15"));

                            result.test_throws("overflow detected",
                                               "Received an encrypted record that exceeds maximum plaintext size",
                                               [&] { rls.next_record(css.get()); });
                         }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls",
                       "tls_record_layer_13",
                       basic_sanitization_parse_records_client,
                       basic_sanitization_parse_records_server,
                       read_full_records,
                       read_fragmented_records,
                       write_records,
                       read_encrypted_records,
                       write_encrypted_records,
                       legacy_version_handling,
                       record_size_limits);

}  // namespace Botan_Tests

#endif

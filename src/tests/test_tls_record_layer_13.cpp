/*
* (C) 2021 Jack Lloyd
* (C) 2021 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

#include <botan/tls_magic.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_ciphersuite.h>

#include <botan/internal/tls_record_layer_13.h>

namespace {

namespace TLS = Botan::TLS;
using Test = Botan_Tests::Test;

using Records = std::vector<TLS::Record>;

template<typename FunT>
Test::Result CHECK(const char* name, FunT check_fun)
   {
   Botan_Tests::Test::Result r(name);
   try
      {
      check_fun(r);
      }
   catch(const Botan_Tests::Test_Aborted&)
      {
      // pass, failure was already noted in the responsible `require`
      }
   catch(const std::exception& ex)
      {
      r.test_failure(std::string("failed with exception: ") + ex.what());
      }
   return r;
   }

TLS::Record_Layer record_layer_client(const bool skip_initial_record=false)
   {
   auto rl = TLS::Record_Layer(TLS::Connection_Side::CLIENT);

   // this is relevant for tests that rely on the legacy version in the record
   if(skip_initial_record)
      rl.prepare_records(TLS::Record_Type::HANDSHAKE, {0, 0, 0});

   return rl;
   }

TLS::Record_Layer record_layer_server(const bool skip_initial_record=false)
   {
   auto rl = TLS::Record_Layer(TLS::Connection_Side::SERVER);

   // this is relevant for tests that rely on the legacy version in the record
   if(skip_initial_record)
      { rl.parse_records(Botan::hex_decode("16 03 01 00 03 00 00 00")); }

   return rl;
   }

std::unique_ptr<TLS::Cipher_State> rfc8448_rtt1_handshake_traffic()
   {
   const auto transcript_hash = Botan::hex_decode_locked(
                                   "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed"
                                   "d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
   auto shared_secret = Botan::hex_decode_locked(
                           "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d"
                           "35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d");
   auto cipher = TLS::Ciphersuite::from_name("AES_128_GCM_SHA256").value();
   return TLS::Cipher_State::init_with_server_hello(
             TLS::Connection_Side::CLIENT, std::move(shared_secret), cipher, transcript_hash);
   }

std::vector<Test::Result> read_full_records()
   {
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

   return
      {
      CHECK("change cipher spec", [&](auto& result)
         {
         auto read = record_layer_server().parse_records(ccs_record);
         result.require("received something", std::holds_alternative<Records>(read));

         auto record = std::get<Records>(read);
         result.test_eq("received 1 record", record.size(), 1);
         result.confirm("received CCS", record.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
         result.test_eq("CCS byte is 0x01", record.front().fragment, Botan::hex_decode("01"));
         }),

      CHECK("two CCS messages", [&](auto& result)
         {
         const auto two_ccs_records = Botan::concat(ccs_record, ccs_record);

         auto read = record_layer_server().parse_records(two_ccs_records);
         result.require("received something", std::holds_alternative<Records>(read));

         auto record = std::get<Records>(read);
         result.test_eq("received 2 records", record.size(), 2);
         result.confirm("received CCS 1", record.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
         result.confirm("received CCS 2", record.back().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
         result.test_eq("CCS byte is 0x01", record.front().fragment, Botan::hex_decode("01"));
         result.test_eq("CCS byte is 0x01", record.back().fragment, Botan::hex_decode("01"));
         }),

      CHECK("read full handshake message", [&](auto& result)
         {
         auto read = record_layer_server().parse_records(client_hello_record);
         result.confirm("received something", std::holds_alternative<Records>(read));

         auto rec = std::get<Records>(read);
         result.test_eq("received 1 record", rec.size(), 1);
         result.confirm("received handshake record", rec.front().type == TLS::Record_Type::HANDSHAKE);
         result.test_eq("contains the full handshake message",
                        Botan::secure_vector<uint8_t>(client_hello_record.begin()+TLS::TLS_HEADER_SIZE,
                              client_hello_record.end()), rec.front().fragment);
         }),

      CHECK("read full handshake message followed by CCS", [&](auto& result)
         {
         const auto payload = Botan::concat(client_hello_record, ccs_record);
         auto read = record_layer_server().parse_records(payload);
         result.require("received something", std::holds_alternative<Records>(read));

         auto rec = std::get<Records>(read);
         result.test_eq("received 2 records", rec.size(), 2);
         result.confirm("received handshake record", rec.front().type == TLS::Record_Type::HANDSHAKE);
         result.test_eq("contains the full handshake message",
                        Botan::secure_vector<uint8_t>(client_hello_record.begin()+TLS::TLS_HEADER_SIZE,
                              client_hello_record.end()), rec.front().fragment);
         result.confirm("received CCS record", rec.back().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
         result.test_eq("CCS byte is 0x01", rec.back().fragment, Botan::hex_decode("01"));
         })
      };
   }

std::vector<Test::Result> basic_sanitization_parse_records(TLS::Connection_Side side)
   {
   auto parse_records = [side](const std::vector<uint8_t>& data, TLS::Cipher_State* cs=nullptr)
      {
      return ((side == TLS::Connection_Side::CLIENT) ? record_layer_client(true) : record_layer_server())
             .parse_records(data, cs);
      };

   return
      {
      CHECK("'receive' empty data", [&](auto& result)
         {
         auto read = parse_records({});
         result.require("needs bytes", std::holds_alternative<TLS::BytesNeeded>(read));
         result.test_eq("need all the header bytes",
                        std::get<TLS::BytesNeeded>(read), Botan::TLS::TLS_HEADER_SIZE);
         }),

      CHECK("incomplete header asks for more data", [&](auto& result)
         {
         std::vector<uint8_t> partial_header{'\x23', '\x03', '\x03'};
         auto read = parse_records(partial_header);
         result.require("returned 'bytes needed'", std::holds_alternative<TLS::BytesNeeded>(read));

         result.test_eq("asks for some more bytes", std::get<TLS::BytesNeeded>(read),
                        Botan::TLS::TLS_HEADER_SIZE - partial_header.size());
         }),

      CHECK("complete header asks for enough data to finish processing the record", [&](auto& result)
         {
         std::vector<uint8_t> full_header{'\x17', '\x03', '\x03', '\x00', '\x42'};
         auto read = parse_records(full_header);
         result.require("returned 'bytes needed'", std::holds_alternative<TLS::BytesNeeded>(read));

         result.test_eq("asks for many more bytes", std::get<TLS::BytesNeeded>(read), 0x42);
         }),

      CHECK("received an empty record (that is not application data)", [&](auto& result)
         {
         std::vector<uint8_t> empty_record{'\x16', '\x03', '\x03', '\x00', '\x00'};
         result.test_throws("record empty", "empty record received", [&]
            {
            parse_records(empty_record);
            });
         }),

      CHECK("tries to decrypt a (protected) application data record "
            "(doesn't exit early as overflow alert)", [&](Test::Result& result)
         {
         std::vector<uint8_t> full_record{'\x17', '\x03', '\x03', '\x41', '\x00'};
         full_record.resize(TLS::MAX_CIPHERTEXT_SIZE_TLS13 + TLS::TLS_HEADER_SIZE);

         auto cs = rfc8448_rtt1_handshake_traffic();
         result.test_throws<Botan::Invalid_Authentication_Tag>("broken record detected", [&]
            {
            parse_records(full_record, cs.get());
            });
         }),

      CHECK("received the maximum size of an unprotected record", [&](auto& result)
         {
         std::vector<uint8_t> full_record{'\x16', '\x03', '\x03', '\x40', '\x00'};
         full_record.resize(TLS::MAX_PLAINTEXT_SIZE + TLS::TLS_HEADER_SIZE);
         auto read = parse_records(full_record);
         result.confirm("returned 'record'", !std::holds_alternative<TLS::BytesNeeded>(read));
         }),

      CHECK("received too many bytes in one protected record", [&](auto& result)
         {
         std::vector<uint8_t> huge_record{'\x17', '\x03', '\x03', '\x41', '\x01'};
         huge_record.resize(TLS::MAX_CIPHERTEXT_SIZE_TLS13 + TLS::TLS_HEADER_SIZE + 1);
         result.test_throws("record too big", "overflowing record received", [&]
            {
            parse_records(huge_record);
            });
         }),

      CHECK("received too many bytes in one unprotected record", [&](auto& result)
         {
         std::vector<uint8_t> huge_record{'\x16', '\x03', '\x03', '\x40', '\x01'};
         huge_record.resize(TLS::MAX_PLAINTEXT_SIZE + TLS::TLS_HEADER_SIZE + 1);
         result.test_throws("record too big", "overflowing record received", [&]
            {
            parse_records(huge_record);
            });
         }),

      CHECK("invalid record type", [&](auto& result)
         {
         std::vector<uint8_t> invalid_record_type{'\x42', '\x03', '\x03', '\x41', '\x01'};
         result.test_throws("invalid record type", "unexpected message received", [&]
            {
            parse_records(invalid_record_type);
            });
         }),

      CHECK("invalid record version", [&](auto& result)
         {
         std::vector<uint8_t> invalid_record_version{'\x17', '\x03', '\x02', '\x00', '\x01', '\x42'};
         result.test_throws("invalid record version", "invalid record version", [&]
            {
            parse_records(invalid_record_version);
            });
         }),

      CHECK("malformed change cipher spec", [&](auto& result)
         {
         std::vector<uint8_t> invalid_ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x02'};
         result.test_throws("invalid CCS record", "malformed change cipher spec record received", [&]
            {
            parse_records(invalid_ccs_record);
            });
         })

      };
   }

std::vector<Test::Result> basic_sanitization_parse_records_client()
   {
   return basic_sanitization_parse_records(TLS::Connection_Side::CLIENT);
   }

std::vector<Test::Result> basic_sanitization_parse_records_server()
   {
   return basic_sanitization_parse_records(TLS::Connection_Side::SERVER);
   }

std::vector<Test::Result> read_fragmented_records()
   {
   TLS::Record_Layer rl = record_layer_client(true);

   auto wait_for_more_bytes = [](Botan::TLS::BytesNeeded bytes_needed, auto rlr, auto& result)
      {
      if(result.confirm("waiting for bytes", std::holds_alternative<TLS::BytesNeeded>(rlr)))
         { result.test_eq("right amount", std::get<TLS::BytesNeeded>(rlr), bytes_needed); }
      };

   return
      {
      CHECK("change cipher spec in many small pieces", [&](auto& result)
         {
         std::vector<uint8_t> ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x01'};

         wait_for_more_bytes(4, rl.parse_records({'\x14'}), result);
         wait_for_more_bytes(3, rl.parse_records({'\x03'}), result);
         wait_for_more_bytes(2, rl.parse_records({'\x03'}), result);
         wait_for_more_bytes(1, rl.parse_records({'\x00'}), result);
         wait_for_more_bytes(1, rl.parse_records({'\x01'}), result);

         auto res1 = rl.parse_records({'\x01'});
         result.require("received something 1", std::holds_alternative<Records>(res1));

         auto rec1 = std::get<Records>(res1);
         result.test_eq("received 1 record", rec1.size(), 1);
         result.confirm("received CCS", rec1.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
         result.test_eq("CCS byte is 0x01", rec1.front().fragment, Botan::hex_decode("01"));
         }),

      CHECK("two change cipher specs in several pieces", [&](auto& result)
         {
         wait_for_more_bytes(1, rl.parse_records({'\x14', '\x03', '\x03', '\x00'}), result);

         auto res2 = rl.parse_records({'\x01', '\x01', /* second CCS starts here */ '\x14', '\x03'});
         result.require("received something 2", std::holds_alternative<Records>(res2));

         auto rec2 = std::get<Records>(res2);
         result.test_eq("received 1 record", rec2.size(), 1);
         result.confirm("received CCS", rec2.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);

         wait_for_more_bytes(2, rl.parse_records({'\x03'}), result);

         auto res3 = rl.parse_records({'\x00', '\x01', '\x01'});
         result.require("received something 3", std::holds_alternative<Records>(res3));

         auto rec3 = std::get<Records>(res3);
         result.test_eq("received 1 record", rec3.size(), 1);
         result.confirm("received CCS", rec3.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
         })
      };
   }

std::vector<Test::Result> write_records()
   {
   auto cs = rfc8448_rtt1_handshake_traffic();
   return
      {
      CHECK("prepare an zero-length application data fragment", [&](auto& result)
         {
         auto record = record_layer_client().prepare_records(Botan::TLS::APPLICATION_DATA, {}, cs.get());

         result.require("record header was added", record.size() > Botan::TLS::TLS_HEADER_SIZE + 1 /* encrypted content type */);
         }),
      CHECK("prepare a client hello", [&](auto& result)
         {
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
         auto record = record_layer_client().prepare_records(Botan::TLS::HANDSHAKE, client_hello_msg);

         result.require("record header was added", record.size() == client_hello_msg.size() + Botan::TLS::TLS_HEADER_SIZE);

         const auto header = std::vector<uint8_t>(record.cbegin(), record.cbegin() + Botan::TLS::TLS_HEADER_SIZE);
         result.test_eq("record header is well-formed", header, Botan::hex_decode("16030100c4"));
         }),
      CHECK("prepare a dummy CCS", [&](auto& result)
         {
         auto record = record_layer_client(true).prepare_dummy_ccs_record();

         result.require("record was created", record.size() == Botan::TLS::TLS_HEADER_SIZE + 1);

         result.test_eq("CCS record is well-formed", record, Botan::hex_decode("140303000101"));
         }),
      CHECK("cannot prepare non-dummy CCS", [&](auto& result)
         {
         result.test_throws("cannot create non-dummy CCS", "TLS 1.3 deprecated CHANGE_CIPHER_SPEC", []
            {
            const auto ccs_content = Botan::hex_decode("de ad be ef");
            record_layer_client().prepare_records(Botan::TLS::Record_Type::CHANGE_CIPHER_SPEC, ccs_content);
            });
         }),
      CHECK("large messages are sharded", [&](auto& result)
         {
         const std::vector<uint8_t> large_client_hello(Botan::TLS::MAX_PLAINTEXT_SIZE + 4096);
         auto record = record_layer_client().prepare_records(Botan::TLS::HANDSHAKE, large_client_hello);

         result.test_gte("produces at least two record headers", record.size(),
                         large_client_hello.size() + 2 * Botan::TLS::TLS_HEADER_SIZE);
         })
      };
   }

std::vector<Test::Result>
read_encrypted_records()
   {
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

   auto parse_records = [](const std::vector<uint8_t>& data, TLS::Cipher_State* cs=nullptr)
      {
      return record_layer_client(true).parse_records(data, cs);
      };

   return
      {
      CHECK("read encrypted server hello extensions", [&](Test::Result &result)
         {
         auto cs = rfc8448_rtt1_handshake_traffic();
         auto res = parse_records(encrypted_record, cs.get());
         result.require("some records decrypted", !std::holds_alternative<Botan::TLS::BytesNeeded>(res));
         auto records = std::get<Records>(res);
         result.require("one record decrypted", records.size() == 1);
         auto record = records.front();

         result.test_is_eq("inner type was 'HANDSHAKE'", record.type, Botan::TLS::Record_Type::HANDSHAKE);
         result.test_eq("decrypted payload length", record.fragment.size(), 657 /* taken from RFC 8448 */);
         }),

      CHECK("decryption fails due to bad MAC", [&](Test::Result &result)
         {
         auto tampered_encrypted_record = encrypted_record;
         tampered_encrypted_record.back() = '\x42';  // changing one payload byte causes the MAC check to fails

         result.test_throws<Botan::Invalid_Authentication_Tag>("broken record detected", [&]
            {
            auto cs = rfc8448_rtt1_handshake_traffic();
            parse_records(tampered_encrypted_record, cs.get());
            });
         }),

      CHECK("decryption fails due to too short record", [&](Test::Result &result)
         {
         const auto short_record = Botan::hex_decode("17 03 03 00 08 de ad be ef ba ad f0 0d");

         result.test_throws<Botan::Invalid_Authentication_Tag>("broken record detected", [&]
            {
            auto cs = rfc8448_rtt1_handshake_traffic();
            parse_records(short_record, cs.get());
            });
         }),

      CHECK("protected Change Cipher Spec message is illegal", [&](Test::Result& result)
         {
         // factored message, encrypted under the same key as `encrypted_record`
         const auto protected_ccs = Botan::hex_decode("1703030012D8EBBBE055C8167D5690EC67DEA9A525B036");

         result.test_throws<Botan::TLS::TLS_Exception>("illegal state causes TLS alert", [&]
            {
            parse_records(protected_ccs);
            });
         }),
      CHECK("read fragmented application data", [&](Test::Result& result)
         {
         const auto encrypted = Botan::hex_decode(
                                   "17 03 03 00 1A 90 78 6D 7E 6F A8 F7 67 1F 6D 05 F7 24 18 F5 DB 43 F7 0B 9E 48 A6 96 B6 5B EC"
                                   "17 03 03 00 28 6C 21 B5 B8 D8 1B 85 5C 17 0E C7 9B 2C 28 85 85 51 29 2F 71 14 F3 D7 BD D5 D1"
                                   "80 C2 E9 3D EC 84 3B 8D 41 30 D8 C8 C5 D8"
                                   "17 03 03 00 21 29 9A B0 5A EA 3F 8A DE 05 12 E0 6B 4A 28 C3 E2 69 2F 58 82 F1 A3 45 04 EA 16"
                                   "14 72 39 6F A1 F3 D3 ") ;
         const std::vector<std::vector<uint8_t>> plaintext_records =
            {
            Botan::hex_decode("00 01 02 03 04 05 06 07 08"),
            Botan::hex_decode("09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"),
            Botan::hex_decode("20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f")
            };

         auto cs = rfc8448_rtt1_handshake_traffic();
         // advance with arbitrary hashes that were used to produce the input data
         cs->advance_with_server_finished(
            Botan::hex_decode_locked("e1935a480babfc4403b2517f0ad414bed0ca51fa671e2061804afa78fd71d55c"));
         cs->advance_with_client_finished(
            Botan::hex_decode_locked("305e4a0a7cee581b282c571b251b20138a1a6a21918937a6bb95b1e9ba1b5cac"));

         auto res = parse_records(encrypted, cs.get());
         result.require("some records decrypted", std::holds_alternative<Records>(res));

         const auto records = std::get<Records>(res);
         result.require("three record decrypted", records.size() == 3);
         result.test_eq("first record", records.at(0).fragment, plaintext_records.at(0));
         result.test_eq("second record", records.at(1).fragment, plaintext_records.at(1));
         result.test_eq("third record", records.at(2).fragment, plaintext_records.at(2));
         })
      };
   }

std::vector<Test::Result> write_encrypted_records()
   {
   auto plaintext_msg = Botan::hex_decode(
                           "14 00 00 20 a8 ec 43 6d 67 76 34 ae"
                           "52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61");

   auto cs = rfc8448_rtt1_handshake_traffic();
   return
      {
      CHECK("write encrypted client handshake finished", [&](Test::Result& result)
         {
         auto ct = record_layer_client(true).prepare_records(TLS::Record_Type::HANDSHAKE,
               plaintext_msg, cs.get());
         auto expected_ct =
         Botan::hex_decode("17 03 03 00 35 75 ec 4d c2 38 cc e6"
                           "0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44 d8 7f"
                           "38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7 26 c4 05 46");
         result.test_eq("produced the expected ciphertext", ct, expected_ct);
         }),

      CHECK("write a lot of data producing two protected records", [&](Test::Result& result)
         {
         std::vector<uint8_t> big_data(TLS::MAX_PLAINTEXT_SIZE + TLS::MAX_PLAINTEXT_SIZE / 2);
         auto ct = record_layer_client(true).prepare_records(TLS::Record_Type::APPLICATION_DATA,
               big_data, cs.get());
         result.require("encryption added some MAC and record headers",
                        ct.size() > big_data.size() + Botan::TLS::TLS_HEADER_SIZE * 2);

         auto read_record_header = [&](auto &reader)
            {
            result.test_is_eq("APPLICATION_DATA", reader.get_byte(), static_cast<uint8_t>(TLS::Record_Type::APPLICATION_DATA));
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
         })
      };
   }

std::vector<Test::Result> legacy_version_handling()
   {
   // RFC 8446 5.1:
   // legacy_record_version:  MUST be set to 0x0303 for all records
   //    generated by a TLS 1.3 implementation other than an initial
   //    ClientHello (i.e., one not generated after a HelloRetryRequest),
   //    where it MAY also be 0x0301 for compatibility purposes.

   auto has_version = [](const auto& record, const uint16_t version) -> bool
      {
      TLS::TLS_Data_Reader dr("header reader", record);
      dr.discard_next(1);
      return dr.get_uint16_t() == version;
      };

   return
      {
      CHECK("client side starts with version 0x0301", [&](Test::Result& result)
         {
         auto rl = record_layer_client();
         auto rec = rl.prepare_records(TLS::Record_Type::HANDSHAKE, std::vector<uint8_t>(5));
         result.confirm("first record has version 0x0301", has_version(rec, 0x0301));

         rec = rl.prepare_records(TLS::Record_Type::HANDSHAKE, std::vector<uint8_t>(5));
         result.confirm("next record has version 0x0303", has_version(rec, 0x0303));
         }),

      CHECK("server side starts with version 0x0303", [&](Test::Result& result)
         {
         auto rl = record_layer_server(true);
         auto rec = rl.prepare_records(TLS::Record_Type::HANDSHAKE, std::vector<uint8_t>(5));
         result.confirm("first record has version 0x0303", has_version(rec, 0x0303));
         }),

      CHECK("server side accepts version 0x0301 for the first record", [&](Test::Result& result)
         {
         const auto first_record = Botan::hex_decode("16 03 01 00 05 00 00 00 00 00");
         const auto second_record = Botan::hex_decode("16 03 03 00 05 00 00 00 00 00");
         auto rl = record_layer_server();
         result.test_no_throw("parsing initial record", [&] {rl.parse_records(first_record);});
         result.test_no_throw("parsing second record", [&] {rl.parse_records(second_record);});
         }),

      CHECK("server side accepts version 0x0301 for the first record for partial records", [&](Test::Result& result)
         {
         const auto first_part = Botan::hex_decode("16 03 01");
         const auto second_part = Botan::hex_decode("00 05 00 00 00 00 00");
         auto rl = record_layer_server();
         result.test_no_throw("parsing initial part", [&] {rl.parse_records(first_part);});
         result.test_no_throw("parsing second part", [&] {rl.parse_records(second_part);});
         }),

      CHECK("server side accepts version 0x0303 for the first record", [&](Test::Result& result)
         {
         const auto first_record = Botan::hex_decode("16 03 03 00 05 00 00 00 00 00");
         auto rl = record_layer_server();
         result.test_no_throw("parsing initial record", [&] {rl.parse_records(first_record);});
         }),

      CHECK("server side does not accept version 0x0301 for the second record", [&](Test::Result& result)
         {
         const auto first_record = Botan::hex_decode("16 03 01 00 05 00 00 00 00 00");
         auto rl = record_layer_server();
         result.test_no_throw("parsing initial record", [&] {rl.parse_records(first_record);});
         result.test_throws("parsing second record", [&] {rl.parse_records(first_record);});
         }),

      CHECK("server side does not accept other versions", [&](Test::Result& result)
         {
         auto rl = record_layer_server();
         result.test_throws("does not accept 0x0300", [&] {rl.parse_records(Botan::hex_decode("16 03 00 00 05 00 00 00 00 00"));});
         result.test_throws("does not accept 0x0302", [&] {rl.parse_records(Botan::hex_decode("16 03 02 00 05 00 00 00 00 00"));});
         result.test_throws("does not accept 0x0304", [&] {rl.parse_records(Botan::hex_decode("16 03 04 00 05 00 00 00 00 00"));});
         result.test_throws("does not accept 0x0305", [&] {rl.parse_records(Botan::hex_decode("16 03 05 00 05 00 00 00 00 00"));});
         })

      };
   }

}  // namespace

namespace Botan_Tests {
BOTAN_REGISTER_TEST_FN("tls", "tls_record_layer_13",
                       basic_sanitization_parse_records_client,
                       basic_sanitization_parse_records_server,
                       read_full_records, read_fragmented_records, write_records,
                       read_encrypted_records, write_encrypted_records,
                       legacy_version_handling);
}

#endif

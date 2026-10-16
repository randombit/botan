/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

   #include <botan/exceptn.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/internal/concat_util.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/stl_util.h>
   #include <botan/internal/tls_transcript_hash_13.h>
   #include <botan/internal/tls_types_13.h>

using namespace Botan::TLS;

namespace Botan_Tests {

namespace {

auto make_header(Handshake_Type type, size_t length) {
   const auto len = Botan::store_be(length);
   return HandshakeProtocolHeader(Botan::concat(Botan::store_be(type), std::span{len}.last<3>()));
}

auto make_header_and_msg(Handshake_Type type, std::span<const uint8_t> data) {
   return std::make_pair(make_header(type, data.size()), SerializedHandshakeMessage(data));
}

auto make_header_and_msg(Handshake_Type type, std::string_view hex_data) {
   auto msg = SerializedHandshakeMessage(Botan::hex_decode(hex_data));
   return std::make_pair(make_header(type, msg.size()), std::move(msg));
}

auto reference_hash(const std::vector<std::pair<Handshake_Type, std::string_view>>& msgs) {
   auto hash = Botan::HashFunction::create_or_throw("SHA-256");
   for(const auto& [type, hex_data] : msgs) {
      const auto [hdr, msg] = make_header_and_msg(type, hex_data);
      hash->update(hdr);
      hash->update(msg);
   }
   return hash->final_stdvec();
}

std::vector<Test::Result> transcript_hash() {
   // Client Hello taken from RFC 8448 0-RTT
   const auto psk_client_hello = Botan::hex_decode(
      /* 01 00 01 fc - handshake message header */
      "03 03 1b c3 ce b6 bb e3 9c ff"
      "93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76"
      "48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00"
      "09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12"
      "00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00"
      "26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34"
      "6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00"
      "00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02"
      "03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02"
      "02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00"
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      "00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00"
      "00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70"
      "ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9"
      "82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6"
      "1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0"
      "37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5"
      "90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5"
      "ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d"
      "e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa"
      "cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d"
      "ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d");

   const auto sha256_truncated_ch =
      Botan::hex_decode("63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
   const auto sha256_full_ch = Botan::hex_decode("08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913");

   const auto client_hello_no_psk = Botan::hex_decode(
      /* 01 00 00 c0 - handshake message header */
      "03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a"
      "8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13"
      "02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff"
      "01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01"
      "01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20"
      "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1"
      "3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00"
      "20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01"
      "06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00"
      "02 40 01");

   const auto sha256_full_ch_no_psk =
      Botan::hex_decode("4db255f30da09a407c841720be831a06a5aa9b3662a5f44267d37706b73c2b8c");

   return {
      CHECK("trying to get 'previous' or 'current' with invalid state",
            [](Test::Result& result) {
               result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
                                                        [] { Transcript_Hash_State(TLS_Flavor::TLS).previous(); });

               result.test_throws<Botan::Invalid_State>("current throws invalid state exception",
                                                        [] { Transcript_Hash_State(TLS_Flavor::TLS).current(); });
            }),

      CHECK("update without an algorithm",
            [](Test::Result& result) {
               Transcript_Hash_State h(TLS_Flavor::TLS);
               result.test_no_throw("update is successful", [&] {
                  const auto [header, msg] = make_header_and_msg(Handshake_Type::EncryptedExtensions, "baadbeef");
                  h.update(header, msg);
               });
               result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
                                                        [&] { h.previous(); });
               result.test_throws<Botan::Invalid_State>("current throws invalid state exception", [&] { h.current(); });
            }),

      CHECK("cannot change algorithm",
            [](Test::Result& result) {
               Transcript_Hash_State h(TLS_Flavor::TLS);
               result.test_no_throw("initial set is successful", [&] { h.set_algorithm("SHA-256"); });
               result.test_no_throw("resetting is successful (NOOP)", [&] { h.set_algorithm("SHA-256"); });
               result.test_throws<Botan::Invalid_State>("set_algorithm throws invalid state exception",
                                                        [&] { h.set_algorithm("SHA-384"); });

               Transcript_Hash_State h2(TLS_Flavor::TLS, "SHA-256");
               result.test_no_throw("resetting is successful (NOOP)", [&] { h2.set_algorithm("SHA-256"); });
               result.test_throws<Botan::Invalid_State>("set_algorithm throws invalid state exception",
                                                        [&] { h2.set_algorithm("SHA-384"); });
            }),

      CHECK("update and result retrieval (algorithm is set)",
            [&](Test::Result& result) {
               Transcript_Hash_State h(TLS_Flavor::TLS, "SHA-256");

               const auto [header, msg] = make_header_and_msg(Handshake_Type::EncryptedExtensions, "baadbeef");
               h.update(header, msg);
               result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
                                                        [&] { h.previous(); });
               result.test_bin_eq("c = SHA-256(baadbeef)",
                                  h.current(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"}}));

               const auto [header2, msg2] = make_header_and_msg(Handshake_Type::Certificate, "600df00d");
               h.update(header2, msg2);
               result.test_bin_eq("p = SHA-256(baadbeef)",
                                  h.previous(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"}}));
               result.test_bin_eq("c = SHA-256(deadbeef | goodfood)",
                                  h.current(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"},
                                                  {Handshake_Type::Certificate, "600df00d"}}));
            }),

      CHECK("update and result retrieval (deferred algorithm specification)",
            [&](Test::Result& result) {
               Transcript_Hash_State h(TLS_Flavor::TLS);

               const auto [header, msg] = make_header_and_msg(Handshake_Type::EncryptedExtensions, "baadbeef");
               h.update(header, msg);
               h.set_algorithm("SHA-256");

               result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
                                                        [&] { h.previous(); });
               result.test_bin_eq("c = SHA-256(baadbeef)",
                                  h.current(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"}}));
            }),

      CHECK("update and result retrieval (deferred algorithm specification multiple updates)",
            [&](Test::Result& result) {
               Transcript_Hash_State h(TLS_Flavor::TLS);

               const auto [header, msg] = make_header_and_msg(Handshake_Type::EncryptedExtensions, "baadbeef");
               const auto [header2, msg2] = make_header_and_msg(Handshake_Type::Certificate, "600df00d");
               h.update(header, msg);
               h.update(header2, msg2);
               h.set_algorithm("SHA-256");

               result.test_bin_eq("c = SHA-256(baadbeef | goodfood)",
                                  h.current(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"},
                                                  {Handshake_Type::Certificate, "600df00d"}}));
            }),

      CHECK("cloning creates independent transcript_hash instances",
            [&](Test::Result& result) {
               Transcript_Hash_State h1(TLS_Flavor::TLS, "SHA-256");

               const auto [header1, msg1] = make_header_and_msg(Handshake_Type::EncryptedExtensions, "baadbeef");
               h1.update(header1, msg1);
               const auto [header2, msg2] = make_header_and_msg(Handshake_Type::Certificate, "600df00d");
               h1.update(header2, msg2);

               const auto h2 = h1.clone();
               result.test_bin_eq("c1 = SHA-256(baadbeef | goodfood)",
                                  h1.current(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"},
                                                  {Handshake_Type::Certificate, "600df00d"}}));
               result.test_bin_eq("c2 = SHA-256(baadbeef | goodfood)",
                                  h2.current(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"},
                                                  {Handshake_Type::Certificate, "600df00d"}}));

               const auto [header3, msg3] = make_header_and_msg(Handshake_Type::CertificateVerify, "cafed00d");
               h1.update(header3, msg3);
               result.test_bin_eq("c1 = SHA-256(baadbeef | goodfood | cafedude)",
                                  h1.current(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"},
                                                  {Handshake_Type::Certificate, "600df00d"},
                                                  {Handshake_Type::CertificateVerify, "cafed00d"}}));
               result.test_bin_eq("c2 = SHA-256(baadbeef | goodfood)",
                                  h2.current(),
                                  reference_hash({{Handshake_Type::EncryptedExtensions, "baadbeef"},
                                                  {Handshake_Type::Certificate, "600df00d"}}));
            }),

      CHECK("recreation after hello retry request",
            [&](Test::Result& result) {
               Transcript_Hash_State h1(TLS_Flavor::TLS);

               const auto [header1, msg1] = make_header_and_msg(Handshake_Type::ClientHello, "c0cac01a");
               const auto [header2, msg2] = make_header_and_msg(Handshake_Type::HelloRetryRequest, "c001f00d");
               h1.update(header1, msg1);
               h1.update(header2, msg2);

               const auto h2 = Transcript_Hash_State::recreate_after_hello_retry_request("SHA-256", h1);

               // RFC 8446 4.4.1
               const auto hash_of_client_hello =
                  Botan::hex_encode(reference_hash({{Handshake_Type::ClientHello, "c0cac01a"}}));
               result.test_bin_eq("transcript hash of hello retry request",
                                  h2.current(),
                                  reference_hash({{Handshake_Type::MessageHash, hash_of_client_hello},
                                                  {Handshake_Type::HelloRetryRequest, "c001f00d"}}));
            }),

      CHECK("truncated transcript hash in client hellos with PSK",
            [&](Test::Result& result) {
               Transcript_Hash_State h1(TLS_Flavor::TLS);

               const size_t truncation_mark = 473;
               auto truncated_ch = psk_client_hello;
               truncated_ch.resize(truncation_mark);

               const auto [header, msg] = make_header_and_msg(Handshake_Type::ClientHello, psk_client_hello);
               h1.update(header, msg);
               h1.set_algorithm("SHA-256");

               result.test_bin_eq("truncated hash", h1.truncated(), sha256_truncated_ch);
               result.test_bin_eq("current hash", h1.current(), sha256_full_ch);

               // truncated hash is cleared as soon as new messages are read
               const auto [header2, msg2] = make_header_and_msg(Handshake_Type::ServerHello, "c0cac01a");
               h1.update(header2, msg2);
               result.test_throws("truncated hash is cleared", [&] { h1.truncated(); });
            }),

      CHECK("transcript hash is not truncated for client hellos without PSK",
            [&](Test::Result& result) {
               Transcript_Hash_State h(TLS_Flavor::TLS, "SHA-256");

               const auto [header1, msg1] = make_header_and_msg(Handshake_Type::ClientHello, client_hello_no_psk);
               h.update(header1, msg1);

               result.test_throws("no truncated hash for non-PSK client hello", [&] { h.truncated(); });
               result.test_bin_eq("current hash is over the full client hello", h.current(), sha256_full_ch_no_psk);

               // subsequent messages must not change that
               const auto [header2, msg2] = make_header_and_msg(Handshake_Type::ServerHello, "c0cac01a");
               h.update(header2, msg2);
               result.test_throws("truncated hash is still unavailable", [&] { h.truncated(); });
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_transcript_hash_13", transcript_hash);

}  // namespace Botan_Tests

#endif

/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

   #include <array>

   #include <botan/hex.h>
   #include <botan/internal/tls_transcript_hash_13.h>

using namespace Botan::TLS;

namespace Botan_Tests {

namespace {

std::vector<Test::Result> transcript_hash() {
   auto sha256 = [](const auto& str) {
      return Botan::unlock(Botan::HashFunction::create_or_throw("SHA-256")->process(Botan::hex_decode(str)));
   };

   // Client Hello taken from RFC 8448 0-RTT
   const auto psk_client_hello = Botan::hex_decode(
      "01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff"
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

   return {
      Botan_Tests::CHECK("trying to get 'previous' or 'current' with invalid state",
                         [](Test::Result& result) {
                            result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
                                                                     [] { Transcript_Hash_State().previous(); });

                            result.test_throws<Botan::Invalid_State>("current throws invalid state exception",
                                                                     [] { Transcript_Hash_State().current(); });
                         }),

      Botan_Tests::CHECK(
         "update without an algorithm",
         [](Test::Result& result) {
            Transcript_Hash_State h;
            result.test_no_throw("update is successful", [&] { h.update(Botan::hex_decode("baadbeef")); });
            result.test_throws<Botan::Invalid_State>("previous throws invalid state exception", [&] { h.previous(); });
            result.test_throws<Botan::Invalid_State>("current throws invalid state exception", [&] { h.current(); });
         }),

      Botan_Tests::CHECK("cannot change algorithm",
                         [](Test::Result& result) {
                            Transcript_Hash_State h;
                            result.test_no_throw("initial set is successful", [&] { h.set_algorithm("SHA-256"); });
                            result.test_no_throw("resetting is successful (NOOP)", [&] { h.set_algorithm("SHA-256"); });
                            result.test_throws<Botan::Invalid_State>("set_algorithm throws invalid state exception",
                                                                     [&] { h.set_algorithm("SHA-384"); });

                            Transcript_Hash_State h2("SHA-256");
                            result.test_no_throw("resetting is successful (NOOP)",
                                                 [&] { h2.set_algorithm("SHA-256"); });
                            result.test_throws<Botan::Invalid_State>("set_algorithm throws invalid state exception",
                                                                     [&] { h2.set_algorithm("SHA-384"); });
                         }),

      Botan_Tests::CHECK("update and result retrieval (algorithm is set)",
                         [&](Test::Result& result) {
                            Transcript_Hash_State h("SHA-256");

                            h.update(Botan::hex_decode("baadbeef"));
                            result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
                                                                     [&] { h.previous(); });
                            result.test_eq("c = SHA-256(baadbeef)", h.current(), sha256("baadbeef"));

                            h.update(Botan::hex_decode("600df00d"));
                            result.test_eq("p = SHA-256(baadbeef)", h.previous(), sha256("baadbeef"));
                            result.test_eq("c = SHA-256(deadbeef | goodfood)", h.current(), sha256("baadbeef600df00d"));
                         }),

      Botan_Tests::CHECK("update and result retrieval (deferred algorithm specification)",
                         [&](Test::Result& result) {
                            Transcript_Hash_State h;

                            h.update(Botan::hex_decode("baadbeef"));
                            h.set_algorithm("SHA-256");

                            result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
                                                                     [&] { h.previous(); });
                            result.test_eq("c = SHA-256(baadbeef)", h.current(), sha256("baadbeef"));
                         }),

      Botan_Tests::CHECK("update and result retrieval (deferred algorithm specification multiple updates)",
                         [&](Test::Result& result) {
                            Transcript_Hash_State h;

                            h.update(Botan::hex_decode("baadbeef"));
                            h.update(Botan::hex_decode("600df00d"));
                            h.set_algorithm("SHA-256");

                            result.test_eq("c = SHA-256(baadbeef | goodfood)", h.current(), sha256("baadbeef600df00d"));
                         }),

      Botan_Tests::CHECK("C-style update interface",
                         [&](Test::Result& result) {
                            Transcript_Hash_State h;

                            std::array<uint8_t, 2> baad{0xba, 0xad};
                            h.update(baad);
                            h.update(std::array<uint8_t, 2>{0xbe, 0xef});

                            h.set_algorithm("SHA-256");

                            std::array<uint8_t, 2> food{0xf0, 0x0d};
                            h.update(std::array<uint8_t, 2>{0x60, 0x0d});
                            h.update(food);

                            result.test_eq("c = SHA-256(baadbeef | goodfood)", h.current(), sha256("baadbeef600df00d"));
                         }),

      Botan_Tests::CHECK(
         "cloning creates independent transcript_hash instances",
         [&](Test::Result& result) {
            Transcript_Hash_State h1("SHA-256");

            h1.update(std::array<uint8_t, 4>{0xba, 0xad, 0xbe, 0xef});
            h1.update(std::array<uint8_t, 4>{0x60, 0x0d, 0xf0, 0x0d});

            auto h2 = h1.clone();
            result.test_eq("c1 = SHA-256(baadbeef | goodfood)", h1.current(), sha256("baadbeef600df00d"));
            result.test_eq("c2 = SHA-256(baadbeef | goodfood)", h2.current(), sha256("baadbeef600df00d"));

            h1.update(std::array<uint8_t, 4>{0xca, 0xfe, 0xd0, 0x0d});
            result.test_eq(
               "c1 = SHA-256(baadbeef | goodfood | cafedude)", h1.current(), sha256("baadbeef600df00dcafed00d"));
            result.test_eq("c2 = SHA-256(baadbeef | goodfood)", h2.current(), sha256("baadbeef600df00d"));
         }),

      Botan_Tests::CHECK("recreation after hello retry request",
                         [&](Test::Result& result) {
                            Transcript_Hash_State h1;

                            h1.update(std::array<uint8_t, 4>{0xc0, 0xca, 0xc0, 0x1a} /* client hello 1 */);
                            h1.update(std::array<uint8_t, 4>{0xc0, 0x01, 0xf0, 0x0d} /* hello retry request */);

                            auto h2 = Transcript_Hash_State::recreate_after_hello_retry_request("SHA-256", h1);

                            // RFC 8446 4.4.1
                            const std::string hash_of_client_hello = Botan::hex_encode(sha256("c0cac01a"));
                            const std::string transcript = "fe000020" + hash_of_client_hello + "c001f00d";
                            result.test_eq("transcript hash of hello retry request", h2.current(), sha256(transcript));
                         }),

      Botan_Tests::CHECK("truncated transcript hash in client hellos with PSK",
                         [&](Test::Result& result) {
                            Transcript_Hash_State h1;

                            const size_t truncation_mark = 477;
                            auto truncated_ch = psk_client_hello;
                            truncated_ch.resize(truncation_mark);

                            h1.update(psk_client_hello);
                            h1.set_algorithm("SHA-256");

                            result.test_eq("truncated hash", h1.truncated(), sha256_truncated_ch);
                            result.test_eq("current hash", h1.current(), sha256_full_ch);

                            // truncated hash is cleared as soon as new messages are read
                            h1.update(std::array<uint8_t, 4>{0xc0, 0xca, 0xc0, 0x1a} /* server hello */);
                            result.test_throws("truncated hash is cleared", [&] { h1.truncated(); });
                         }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_transcript_hash_13", transcript_hash);

}  // namespace Botan_Tests

#endif

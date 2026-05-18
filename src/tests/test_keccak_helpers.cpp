/*
* (C) 2023 Jack Lloyd
*     2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_KECCAK_PERM)

   #include <botan/hex.h>
   #include <botan/internal/keccak_helpers.h>
   #include <botan/internal/mem_utils.h>

   #if defined(BOTAN_HAS_SHAKE_XOF)
      #include <botan/xof.h>
   #endif

namespace Botan_Tests {

namespace {

size_t encode_size(size_t x) {
   return Botan::keccak_int_encoding_size(x);
}

std::vector<uint8_t> left_encode(Test::Result& result, size_t x) {
   const auto expected_length = Botan::keccak_int_encoding_size(x);
   std::vector<uint8_t> out(expected_length);
   result.test_sz_eq("left_encode return value", Botan::keccak_int_left_encode(out, x).size(), expected_length);
   return out;
}

std::vector<uint8_t> right_encode(Test::Result& result, size_t x) {
   const auto expected_length = Botan::keccak_int_encoding_size(x);
   std::vector<uint8_t> out(expected_length);
   result.test_sz_eq("right_encode return value", Botan::keccak_int_right_encode(out, x).size(), expected_length);
   return out;
}

   #if defined(BOTAN_HAS_SHAKE_XOF)

decltype(auto) shake32(std::string_view hex) {
   const auto xof = Botan::XOF::create_or_throw("SHAKE-256");
   xof->update(Botan::hex_decode(hex));
   return xof->output_stdvec(32);
}

   #endif

std::vector<Test::Result> keccak_helpers() {
   return {
      CHECK("keccak_int_encoding_size()",
            [](Test::Result& result) {
               result.test_sz_eq("keccak_int_encoding_size(0)", encode_size(0), 2);
               result.test_sz_eq("keccak_int_encoding_size(255)", encode_size(0xFF), 2);
               result.test_sz_eq("keccak_int_encoding_size(256)", encode_size(0xFF + 1), 3);
               result.test_sz_eq("keccak_int_encoding_size(65.535)", encode_size(0xFFFF), 3);
               result.test_sz_eq("keccak_int_encoding_size(65.536)", encode_size(0xFFFF + 1), 4);
               result.test_sz_eq("keccak_int_encoding_size(16.777.215)", encode_size(0xFFFFFF), 4);
               result.test_sz_eq("keccak_int_encoding_size(16.777.216)", encode_size(0xFFFFFF + 1), 5);
            }),

         CHECK("keccak_int_left_encode()",
               [](Test::Result& result) {
                  result.test_bin_eq("left_encode(0)", left_encode(result, 0), "0100");
                  result.test_bin_eq("left_encode(1)", left_encode(result, 1), "0101");
                  result.test_bin_eq("left_encode(255)", left_encode(result, 255), "01FF");
                  result.test_bin_eq("left_encode(256)", left_encode(result, 0xFF + 1), "020100");
                  result.test_bin_eq("left_encode(65.535)", left_encode(result, 0xFFFF), "02FFFF");
                  result.test_bin_eq("left_encode(65.536)", left_encode(result, 0xFFFF + 1), "03010000");
                  result.test_bin_eq("left_encode(16.777.215)", left_encode(result, 0xFFFFFF), "03FFFFFF");
                  result.test_bin_eq("left_encode(16.777.215)", left_encode(result, 0xFFFFFF), "03FFFFFF");
                  result.test_bin_eq("left_encode(16.777.216)", left_encode(result, 0xFFFFFF + 1), "0401000000");
                  result.test_bin_eq("left_encode(287.454.020)", left_encode(result, 0x11223344), "0411223344");
               }),

         CHECK("keccak_int_right_encode()",
               [](Test::Result& result) {
                  result.test_bin_eq("right_encode(0)", right_encode(result, 0), "0001");
                  result.test_bin_eq("right_encode(1)", right_encode(result, 1), "0101");
                  result.test_bin_eq("right_encode(255)", right_encode(result, 255), "FF01");
                  result.test_bin_eq("right_encode(256)", right_encode(result, 0xFF + 1), "010002");
                  result.test_bin_eq("right_encode(65.535)", right_encode(result, 0xFFFF), "FFFF02");
                  result.test_bin_eq("right_encode(65.536)", right_encode(result, 0xFFFF + 1), "01000003");
                  result.test_bin_eq("right_encode(16.777.215)", right_encode(result, 0xFFFFFF), "FFFFFF03");
                  result.test_bin_eq("right_encode(16.777.215)", right_encode(result, 0xFFFFFF), "FFFFFF03");
                  result.test_bin_eq("right_encode(16.777.216)", right_encode(result, 0xFFFFFF + 1), "0100000004");
                  result.test_bin_eq("right_encode(287.454.020)", right_encode(result, 0x11223344), "1122334404");
               }),

         CHECK(
            "keccak_absorb_padded_strings_encoding() with one byte string (std::vector<>)",
            [](Test::Result& result) {
               std::vector<uint8_t> out;
               const auto padmod = 136 /* SHAKE-256 byte rate */;

               const std::vector<uint8_t> n{'K', 'M', 'A', 'C'};
               const auto bytes_generated = Botan::keccak_absorb_padded_strings_encoding(out, padmod, n);
               result.test_sz_eq("padded bytes", bytes_generated, padmod);

               result.test_bin_eq(
                  "keccak_absorb_padded_strings_encoding",
                  out,
                  "0188"     /* left_encode(perm.byte_rate()) */
                  "0120"     /* left_encode(n.size() * 8) */
                  "4B4D4143" /* "KMAC" */
                  "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            }),

         CHECK("keccak_absorb_padded_strings_encoding() with block-aligned encoded prefix",
               [](Test::Result& result) {
                  // SP.800-185 bytepad appends zero bytes only while the encoded
                  // length is not a multiple of w. When the encoded prefix is
                  // already block-aligned no padding is added. KMAC-128 with a
                  // 163-byte key and KMAC-256 with a 131-byte key both hit this
                  // edge case.

                  std::vector<uint8_t> key128(163);
                  for(size_t i = 0; i < key128.size(); ++i) {
                     key128[i] = static_cast<uint8_t>(i);
                  }
                  std::vector<uint8_t> out128;
                  const auto bytes128 = Botan::keccak_absorb_padded_strings_encoding(out128, 168, key128);
                  result.test_sz_eq("KMAC-128 aligned: bytes absorbed", bytes128, 168);
                  result.test_sz_eq("KMAC-128 aligned: output size", out128.size(), 168);

                  std::vector<uint8_t> key256(131);
                  for(size_t i = 0; i < key256.size(); ++i) {
                     key256[i] = static_cast<uint8_t>(i);
                  }
                  std::vector<uint8_t> out256;
                  const auto bytes256 = Botan::keccak_absorb_padded_strings_encoding(out256, 136, key256);
                  result.test_sz_eq("KMAC-256 aligned: bytes absorbed", bytes256, 136);
                  result.test_sz_eq("KMAC-256 aligned: output size", out256.size(), 136);
               }),

         CHECK(
            "keccak_absorb_padded_strings_encoding() with two byte strings (std::vector<>)",
            [](Test::Result& result) {
               std::vector<uint8_t> out;
               const auto padmod = 136 /* SHAKE-256 byte rate */;

               const std::vector<uint8_t> n{'K', 'M', 'A', 'C'};
               const std::string str =
                  "This is a long salt, that is longer than 128 bytes in order to fill up the first round of the Keccak permutation. That should do it.";
               const auto bytes_generated =
                  Botan::keccak_absorb_padded_strings_encoding(out, padmod, n, Botan::as_span_of_bytes(str));
               result.test_sz_eq("padded bytes", bytes_generated, padmod * 2);

               result.test_bin_eq(
                  "keccak_absorb_padded_strings_encoding",
                  out,
                  "0188"     /* left_encode(perm.byte_rate()) */
                  "0120"     /* left_encode(n.size() * 8) */
                  "4B4D4143" /* "KMAC" */
                  "020420"   /* left_encode(s.size() * 8) */
                  "546869732069732061206c6f6e672073616c742c2074686174206973206c6f6e676572207468616e2031323820627974657320696e206f7264657220746f2066696c6c2075702074686520666972737420726f756e64206f6620746865204b656363616b207065726d75746174696f6e2e20546861742073686f756c6420646f2069742e"
                  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            }),

   #if defined(BOTAN_HAS_SHAKE_XOF)

         CHECK(
            "keccak_absorb_padded_strings_encoding() with one byte string",
            [](Test::Result& result) {
               const std::vector<uint8_t> out(32);
               const auto xof = Botan::XOF::create_or_throw("SHAKE-256");
               const auto padmod = xof->block_size();

               const std::vector<uint8_t> n{'K', 'M', 'A', 'C'};
               const auto bytes_generated = Botan::keccak_absorb_padded_strings_encoding(*xof, padmod, n);
               result.test_sz_eq("padded bytes", bytes_generated, padmod);

               result.test_bin_eq(
                  "keccak_absorb_padded_strings_encoding",
                  xof->output_stdvec(32),
                  shake32(
                     "0188"     /* left_encode(perm.byte_rate()) */
                     "0120"     /* left_encode(n.size() * 8) */
                     "4B4D4143" /* "KMAC" */
                     "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
            }),

         CHECK("keccak_absorb_padded_strings_encoding() with two byte strings", [](Test::Result& result) {
            const std::vector<uint8_t> out(32);
            const auto xof = Botan::XOF::create_or_throw("SHAKE-256");
            const auto padmod = xof->block_size();

            const std::vector<uint8_t> n{'K', 'M', 'A', 'C'};
            const std::string str =
               "This is a long salt, that is longer than 128 bytes in order to fill up the first round of the Keccak permutation. That should do it.";
            const auto bytes_generated =
               Botan::keccak_absorb_padded_strings_encoding(*xof, padmod, n, Botan::as_span_of_bytes(str));
            result.test_sz_eq("padded bytes", bytes_generated, padmod * 2);

            result.test_bin_eq(
               "keccak_absorb_padded_strings_encoding",
               xof->output_stdvec(32),
               shake32(
                  "0188"     /* left_encode(perm.byte_rate()) */
                  "0120"     /* left_encode(n.size() * 8) */
                  "4B4D4143" /* "KMAC" */
                  "020420"   /* left_encode(s.size() * 8) */
                  "546869732069732061206c6f6e672073616c742c2074686174206973206c6f6e676572207468616e2031323820627974657320696e206f7264657220746f2066696c6c2075702074686520666972737420726f756e64206f6620746865204b656363616b207065726d75746174696f6e2e20546861742073686f756c6420646f2069742e"
                  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
         }),

   #endif
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("utils", "keccak_helpers", keccak_helpers);

}  // namespace Botan_Tests

#endif

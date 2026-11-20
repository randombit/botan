/*
* (C) 2015,2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <algorithm>
#include <optional>

#if defined(BOTAN_HAS_BASE64_CODEC)
   #include <botan/base64.h>
#endif

#if defined(BOTAN_HAS_BASE32_CODEC)
   #include <botan/base32.h>
#endif

#if defined(BOTAN_HAS_BASE58_CODEC)
   #include <botan/base58.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_BASE32_CODEC)

class Base32_Tests final : public Text_Based_Test {
   public:
      Base32_Tests() : Text_Based_Test("codec/base32.vec", "Base32", "Binary") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("Base32");

         const bool is_valid = (type == "valid");
         const std::string base32 = vars.get_req_str("Base32");

         try {
            if(is_valid) {
               const std::vector<uint8_t> binary = vars.get_req_bin("Binary");
               result.test_bin_eq("base32 decoding", Botan::base32_decode(base32), binary);
               result.test_str_eq("base32 encoding", Botan::base32_encode(binary), base32);
            } else {
               auto res = Botan::base32_decode(base32);
               result.test_failure("decoded invalid base32 to " + Botan::hex_encode(res));
            }
         } catch(std::exception& e) {
            if(is_valid) {
               result.test_failure("rejected valid base32", e.what());
            } else {
               result.test_note("rejected invalid base32");
            }
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         Test::Result result("Base32");
         const std::string valid_b32 = "MY======";

         for(const char ws_char : {' ', '\t', '\r', '\n'}) {
            for(size_t i = 0; i <= valid_b32.size(); ++i) {
               std::string b32_ws = valid_b32;
               b32_ws.insert(i, 1, ws_char);

               try {
                  result.test_failure("decoded whitespace base32", Botan::base32_decode(b32_ws, false));
               } catch(std::exception&) {}

               try {
                  result.test_bin_eq("base32 decoding with whitespace", Botan::base32_decode(b32_ws, true), "66");
               } catch(std::exception& e) {
                  result.test_failure(b32_ws, e.what());
               }
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("codec", "base32", Base32_Tests);

#endif

#if defined(BOTAN_HAS_BASE58_CODEC)

class Base58_Tests final : public Text_Based_Test {
   public:
      Base58_Tests() : Text_Based_Test("codec/base58.vec", "Base58", "Binary") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("Base58");

         const bool is_valid = (type == "valid");
         const std::string base58 = vars.get_req_str("Base58");

         try {
            if(is_valid) {
               const std::vector<uint8_t> binary = vars.get_req_bin("Binary");
               result.test_bin_eq("base58 decoding", Botan::base58_decode(base58), binary);
               result.test_str_eq("base58 encoding", Botan::base58_encode(binary), base58);
            } else {
               auto res = Botan::base58_decode(base58);
               result.test_failure("decoded invalid base58 to " + Botan::hex_encode(res));
            }
         } catch(std::exception& e) {
            if(is_valid) {
               result.test_failure("rejected valid base58", e.what());
            } else {
               result.test_note("rejected invalid base58");
            }
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         Test::Result result("Base58");

         // Whitespace is ignored wherever it appears, including inside a block of 8 characters
         const std::vector<uint8_t> expected =
            Botan::hex_decode("6162636465666768696a6b6c6d6e6f707172737475767778797a");

         const std::vector<std::string> with_ws = {
            "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f\n",
            " 3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f",
            "3yxU 3u1igY8WkgtjK92fbJQCd4BZiiT1v25f",
            "3yxU3u1i\ngY8Wkgtj\nK92fbJQC\nd4BZiiT1\nv25f",
            "3yxU3u1igY8Wkgtj K92fbJQCd4BZiiT1v25f",
            "3yxU3u1igY8WkgtjK92fbJ  QCd4BZiiT1v25f",
            "3 y x U 3 u 1 i g Y 8 W k g t j K 9 2 f b J Q C d 4 B Z i i T 1 v 2 5 f",
         };

         for(const auto& b58 : with_ws) {
            try {
               result.test_bin_eq("base58 decoding with whitespace", Botan::base58_decode(b58), expected);
            } catch(std::exception& e) {
               result.test_failure("rejected valid base58 with whitespace", e.what());
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("codec", "base58", Base58_Tests);

class Base58_Check_Tests final : public Text_Based_Test {
   public:
      Base58_Check_Tests() : Text_Based_Test("codec/base58c.vec", "Base58", "Binary") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("Base58 Check");

         const bool is_valid = (type == "valid");
         const std::string base58 = vars.get_req_str("Base58");

         try {
            if(is_valid) {
               const std::vector<uint8_t> binary = vars.get_req_bin("Binary");
               result.test_bin_eq("base58 decoding", Botan::base58_check_decode(base58), binary);
               result.test_str_eq("base58 encoding", Botan::base58_check_encode(binary), base58);
            } else {
               auto res = Botan::base58_check_decode(base58);
               result.test_failure("decoded invalid base58c to " + Botan::hex_encode(res));
            }
         } catch(std::exception& e) {
            if(is_valid) {
               result.test_failure("rejected valid base58c", e.what());
            } else {
               result.test_note("rejected invalid base58c");
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("codec", "base58c", Base58_Check_Tests);

#endif

#if defined(BOTAN_HAS_BASE64_CODEC)

class Base64_Tests final : public Text_Based_Test {
   public:
      Base64_Tests() : Text_Based_Test("codec/base64.vec", "Base64", "Binary") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("Base64");

         const bool is_valid = (type == "valid");
         const std::string base64 = vars.get_req_str("Base64");

         try {
            if(is_valid) {
               const std::vector<uint8_t> binary = vars.get_req_bin("Binary");
               result.test_bin_eq("base64 decoding", Botan::base64_decode(base64), binary);
               result.test_str_eq("base64 encoding", Botan::base64_encode(binary), base64);
            } else {
               auto res = Botan::base64_decode(base64);
               result.test_failure("decoded invalid base64 to " + Botan::hex_encode(res));
            }
         } catch(std::exception& e) {
            if(is_valid) {
               result.test_failure("rejected valid base64", e.what());
            } else {
               result.test_note("rejected invalid base64");
            }
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         Test::Result result("Base64");
         const std::string valid_b64 = "Zg==";

         for(const char ws_char : {' ', '\t', '\r', '\n'}) {
            for(size_t i = 0; i <= valid_b64.size(); ++i) {
               std::string b64_ws = valid_b64;
               b64_ws.insert(i, 1, ws_char);

               try {
                  result.test_failure("decoded whitespace base64", Botan::base64_decode(b64_ws, false));
               } catch(std::exception&) {}

               try {
                  result.test_bin_eq("base64 decoding with whitespace", Botan::base64_decode(b64_ws, true), "66");
               } catch(std::exception& e) {
                  result.test_failure(b64_ws, e.what());
               }
            }
         }

         // Long inputs exercise the SIMD bulk paths in some build configurations
         std::vector<uint8_t> long_bin(3000);
         for(size_t i = 0; i != long_bin.size(); ++i) {
            long_bin[i] = static_cast<uint8_t>(i * 7 + i / 251);
         }

         const std::string long_b64 = Botan::base64_encode(long_bin);

         // PEM style line wrapping
         std::string long_b64_ws;
         for(size_t i = 0; i != long_b64.size(); ++i) {
            if(i > 0 && i % 64 == 0) {
               long_b64_ws += '\n';
            }
            long_b64_ws += long_b64[i];
         }

         try {
            result.test_bin_eq("long base64 decoding", Botan::base64_decode(long_b64, false), long_bin);
            result.test_bin_eq("long base64 decoding with newlines", Botan::base64_decode(long_b64_ws, true), long_bin);
         } catch(std::exception& e) {
            result.test_failure("long base64 roundtrip", e.what());
         }

         try {
            std::string corrupted = long_b64;
            corrupted[corrupted.size() / 2] = '!';
            result.test_failure("decoded corrupted base64", Botan::base64_decode(corrupted));
         } catch(std::exception&) {
            result.test_note("rejected corrupted base64");
         }

         test_buffer_bounds(result);

         return {result};
      }

   private:
      static constexpr size_t CanaryLen = 64;
      static constexpr uint8_t Canary = 0xA5;

      static bool canaries_intact(std::span<const uint8_t> buf) {
         const auto is_canary = [](uint8_t b) { return b == Canary; };
         const auto head = buf.first(CanaryLen);
         const auto tail = buf.last(CanaryLen);
         return std::all_of(head.begin(), head.end(), is_canary) && std::all_of(tail.begin(), tail.end(), is_canary);
      }

      static void check_decode_bounds(Test::Result& result, std::string_view input, bool ignore_ws) {
         // An exact size allocation lets sanitizers see any read past the end
         const std::vector<char> in(input.begin(), input.end());
         const size_t max_output = Botan::base64_decode_max_output(in.size());

         // The streaming decoder never uses the SIMD bulk paths
         std::vector<uint8_t> ref(max_output);
         std::optional<size_t> ref_len;
         try {
            size_t consumed = 0;
            const size_t written = Botan::base64_decode(ref.data(), in.data(), in.size(), consumed, true, ignore_ws);
            if(consumed == in.size()) {
               ref_len = written;
            }
         } catch(Botan::Invalid_Argument&) {}

         std::vector<uint8_t> buf(CanaryLen + max_output + CanaryLen, Canary);
         const auto out = std::span{buf}.subspan(CanaryLen, max_output);
         std::optional<size_t> out_len;
         try {
            out_len = Botan::base64_decode(out.data(), in.data(), in.size(), ignore_ws);
         } catch(Botan::Invalid_Argument&) {}

         const std::string what = "base64 decoding " + std::to_string(in.size()) + " chars";

         if(!canaries_intact(buf)) {
            result.test_failure(what + " wrote outside of the output buffer");
         } else if(out_len.has_value() != ref_len.has_value()) {
            result.test_failure(what + " disagrees with the streaming decoder on validity");
         } else if(out_len.has_value()) {
            if(result.test_sz_eq(what + " length", *out_len, *ref_len)) {
               result.test_bin_eq(what, out.first(*out_len), std::span{ref}.first(*ref_len));
            }
         } else {
            result.test_success();
         }
      }

      static void check_encode_bounds(Test::Result& result, size_t len) {
         std::vector<uint8_t> bin(len);
         for(size_t i = 0; i != len; ++i) {
            bin[i] = static_cast<uint8_t>(i * 7 + len);
         }

         const size_t max_output = Botan::base64_encode_max_output(len);
         std::vector<uint8_t> buf(CanaryLen + max_output + CanaryLen, Canary);
         char* out = Botan::cast_uint8_ptr_to_char(&buf[CanaryLen]);

         size_t consumed = 0;
         const size_t produced = Botan::base64_encode(out, bin.data(), bin.size(), consumed, true);

         const std::string what = "base64 encoding " + std::to_string(len) + " bytes";

         if(!canaries_intact(buf)) {
            result.test_failure(what + " wrote outside of the output buffer");
         } else if(produced != max_output || consumed != len) {
            result.test_failure(what + " returned unexpected lengths");
         } else {
            std::vector<uint8_t> decoded(Botan::base64_decode_max_output(produced));
            size_t decode_consumed = 0;
            decoded.resize(Botan::base64_decode(decoded.data(), out, produced, decode_consumed, true, false));
            result.test_bin_eq(what, decoded, bin);
         }
      }

      // Every buffer is exactly the documented size, and the outputs are
      // surrounded by canaries, so any write outside of them is detected
      static void test_buffer_bounds(Test::Result& result) {
         constexpr size_t max_len = 320;
         const std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

         for(size_t len = 0; len <= max_len; ++len) {
            check_encode_bounds(result, len);

            for(const bool all_zero : {true, false}) {
               std::string body(len, 'A');
               if(!all_zero) {
                  for(size_t i = 0; i != len; ++i) {
                     body[i] = alphabet[(i * 7 + len) % alphabet.size()];
                  }
               }

               // Includes excess padding, and padding following complete groups
               for(size_t pads = 0; pads <= 3; ++pads) {
                  const std::string padded = body + std::string(pads, '=');

                  // PEM style line wrapping
                  std::string wrapped;
                  for(size_t i = 0; i < padded.size(); i += 64) {
                     wrapped += padded.substr(i, 64);
                     wrapped += '\n';
                  }

                  for(const auto& input : {padded, wrapped, " " + padded}) {
                     for(const bool ignore_ws : {true, false}) {
                        check_decode_bounds(result, input, ignore_ws);
                     }
                  }
               }
            }
         }
      }
};

BOTAN_REGISTER_TEST("codec", "base64", Base64_Tests);

#endif

class Codec_Error_Char_Display_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Codec error message character display");

         const std::vector<std::pair<char, std::string>> cases = {
            {'\x1b', "\\x1B"},
            {'\x00', "\\x00"},
            {'\n', "\\n"},
            {'\r', "\\r"},
            {'\t', "\\t"},
            {'\x7f', "\\x7F"},
            {static_cast<char>(0xFF), "\\xFF"},
         };

         for(const auto& [bad, expect] : cases) {
            try {
               Botan::hex_decode(std::string(1, bad), false);
               result.test_failure("hex_decode accepted invalid byte");
            } catch(const Botan::Invalid_Argument& e) {
               const std::string msg = e.what();
               result.test_is_true("message uses escaped string", msg.find(expect) != std::string::npos);
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("codec", "codec_error_char_display", Codec_Error_Char_Display_Tests);

}  // namespace

}  // namespace Botan_Tests

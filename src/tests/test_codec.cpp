/*
* (C) 2015,2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

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
               result.test_eq("base32 decoding", Botan::base32_decode(base32), binary);
               result.test_eq("base32 encoding", Botan::base32_encode(binary), base32);
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

         for(char ws_char : {' ', '\t', '\r', '\n'}) {
            for(size_t i = 0; i <= valid_b32.size(); ++i) {
               std::string b32_ws = valid_b32;
               b32_ws.insert(i, 1, ws_char);

               try {
                  result.test_failure("decoded whitespace base32", Botan::base32_decode(b32_ws, false));
               } catch(std::exception&) {}

               try {
                  result.test_eq("base32 decoding with whitespace", Botan::base32_decode(b32_ws, true), "66");
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
               result.test_eq("base58 decoding", Botan::base58_decode(base58), binary);
               result.test_eq("base58 encoding", Botan::base58_encode(binary), base58);
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
               result.test_eq("base58 decoding", Botan::base58_check_decode(base58), binary);
               result.test_eq("base58 encoding", Botan::base58_check_encode(binary), base58);
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
               result.test_eq("base64 decoding", Botan::base64_decode(base64), binary);
               result.test_eq("base64 encoding", Botan::base64_encode(binary), base64);
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

         for(char ws_char : {' ', '\t', '\r', '\n'}) {
            for(size_t i = 0; i <= valid_b64.size(); ++i) {
               std::string b64_ws = valid_b64;
               b64_ws.insert(i, 1, ws_char);

               try {
                  result.test_failure("decoded whitespace base64", Botan::base64_decode(b64_ws, false));
               } catch(std::exception&) {}

               try {
                  result.test_eq("base64 decoding with whitespace", Botan::base64_decode(b64_ws, true), "66");
               } catch(std::exception& e) {
                  result.test_failure(b64_ws, e.what());
               }
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("codec", "base64", Base64_Tests);

#endif

}  // namespace Botan_Tests

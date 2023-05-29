/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PEM_CODEC)

   #include <botan/pem.h>

namespace Botan_Tests {

class PEM_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PEM encoding");

         std::vector<uint8_t> vec = {0, 1, 2, 3, 4};

         const std::string pem1 = Botan::PEM_Code::encode(vec, "BUNNY", 3);

         result.test_eq("PEM encoding", pem1, "-----BEGIN BUNNY-----\nAAE\nCAw\nQ=\n-----END BUNNY-----\n");

         std::string label1 = "this is overwritten";
         const Botan::secure_vector<uint8_t> decoded1 = Botan::PEM_Code::decode(pem1, label1);

         result.test_eq("PEM decoding label", label1, "BUNNY");

         result.test_throws("PEM decoding unexpected label",
                            "PEM: Label mismatch, wanted 'FLOOFY' got 'BUNNY'",
                            [pem1]() { Botan::PEM_Code::decode_check_label(pem1, "FLOOFY"); });

         const std::string malformed_pem1 = "---BEGIN BUNNY-----\n-----END BUNNY-----";
         result.test_throws("PEM decoding bad init label", "PEM: No PEM header found", [malformed_pem1]() {
            Botan::PEM_Code::decode_check_label(malformed_pem1, "BUNNY");
         });

         const std::string malformed_pem2 = "-----BEGIN BUNNY-----\n-----END FLOOFY-----";
         result.test_throws("PEM decoding bad init label", "PEM: Malformed PEM trailer", [malformed_pem2]() {
            Botan::PEM_Code::decode_check_label(malformed_pem2, "BUNNY");
         });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pem", PEM_Tests);

}  // namespace Botan_Tests

#endif

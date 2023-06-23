/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PK_PADDING)
   #include <botan/internal/emsa.h>
#endif

#if defined(BOTAN_HAS_EME_PKCS1)
   #include <botan/internal/eme_pkcs.h>
#endif

#include <botan/internal/fmt.h>

namespace Botan_Tests {

#if defined(BOTAN_HAS_EME_PKCS1)

class EME_PKCS1v15_Decoding_Tests final : public Text_Based_Test {
   public:
      EME_PKCS1v15_Decoding_Tests() : Text_Based_Test("pk_pad_eme/pkcs1.vec", "RawCiphertext", "Plaintext") {}

      Test::Result run_one_test(const std::string& hdr, const VarMap& vars) override {
         const bool is_valid = (hdr == "valid");

         Test::Result result("PKCSv15 Decoding");

         Botan::EME_PKCS1v15 pkcs;

         const std::vector<uint8_t> ciphertext = vars.get_req_bin("RawCiphertext");
         const std::vector<uint8_t> plaintext = vars.get_opt_bin("Plaintext");

         if(is_valid == false) {
            result.test_eq("Plaintext value should be empty for invalid EME inputs", plaintext.size(), 0);
         }

         uint8_t valid_mask = 0;
         Botan::secure_vector<uint8_t> decoded = pkcs.unpad(valid_mask, ciphertext.data(), ciphertext.size());

         result.confirm("EME valid_mask has expected value", valid_mask == 0x00 || valid_mask == 0xFF);
         result.test_eq("EME decoding valid/invalid matches", valid_mask == 0xFF, is_valid);

         if(valid_mask == 0xFF) {
            result.test_eq("EME decoded plaintext correct", decoded, plaintext);
         } else {
            bool all_zeros = true;
            for(size_t i = 0; i != decoded.size(); ++i) {
               if(decoded[i] != 0) {
                  all_zeros = false;
               }
            }

            result.confirm("On invalid padding output is all zero", all_zeros);
         }

         // TODO: also test that encoding is accepted

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "eme_pkcs1v15", EME_PKCS1v15_Decoding_Tests);

class EMSA_unit_tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result name_tests("EMSA_name_tests");

         std::vector<std::string> pads_need_hash = {
   #if BOTAN_HAS_EMSA_X931
            "EMSA2",
   #endif
   #if BOTAN_HAS_EMSA_PKCS1
            "EMSA3",
   #endif
   #if BOTAN_HAS_EMSA_PSSR
            "EMSA4",
            "PSSR_Raw",
   #endif
   #if BOTAN_HAS_ISO_9796
            "ISO_9796_DS2",
            "ISO_9796_DS3",
   #endif
         };

         std::vector<std::string> pads_no_hash = {
   #if BOTAN_HAS_EMSA_RAW
            "Raw",
   #endif
   #if BOTAN_HAS_EMSA_PKCS1
            "EMSA3(Raw)",
            "EMSA3(Raw,SHA-512)",
   #endif
         };

         for(const auto& pad : pads_need_hash) {
            try {
               const std::string hash_to_use = "SHA-256";
               auto emsa_1 = Botan::EMSA::create(Botan::fmt("{}({})", pad, hash_to_use));
               auto emsa_2 = Botan::EMSA::create(emsa_1->name());
               name_tests.test_eq("EMSA_name_test for " + pad, emsa_1->name(), emsa_2->name());
            } catch(Botan::Lookup_Error&) {
               name_tests.test_note("Skipping test due to missing hash");
            } catch(const std::exception& e) {
               name_tests.test_failure("EMSA_name_test for " + pad + ": " + e.what());
            }
         }

         for(const auto& pad : pads_need_hash) {
            std::string algo_name = pad + "(YYZ)";
            try {
               auto emsa = Botan::EMSA::create_or_throw(algo_name);
               name_tests.test_failure("EMSA_name_test for " + pad + ": " + "Could create EMSA with fantasy hash YYZ");
            } catch(Botan::Lookup_Error&) {
               name_tests.test_note("Skipping test due to missing hash");
            } catch(const std::exception& e) {
               name_tests.test_eq(
                  "EMSA_name_test for " + pad, e.what(), "Could not find any algorithm named \"" + algo_name + "\"");
            }
         }

         for(const auto& pad : pads_no_hash) {
            try {
               auto emsa_1 = Botan::EMSA::create(pad);
               auto emsa_2 = Botan::EMSA::create(emsa_1->name());
               name_tests.test_eq("EMSA_name_test for " + pad, emsa_1->name(), emsa_2->name());
            } catch(Botan::Lookup_Error&) {
               name_tests.test_note("Skipping test due to missing hash");
            } catch(const std::exception& e) {
               name_tests.test_failure("EMSA_name_test for " + pad + ": " + e.what());
            }
         }

         return {name_tests};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_pad_emsa_unit", EMSA_unit_tests);

#endif

}  // namespace Botan_Tests

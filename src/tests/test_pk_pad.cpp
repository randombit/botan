/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PK_PADDING)
   #include <botan/internal/eme.h>
   #include <botan/internal/emsa.h>
   #include <botan/internal/fmt.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_EME_PKCS1)
class EME_PKCS1v15_Decoding_Tests final : public Text_Based_Test {
   public:
      EME_PKCS1v15_Decoding_Tests() : Text_Based_Test("pk_pad_eme/pkcs1.vec", "RawCiphertext", "Plaintext") {}

      Test::Result run_one_test(const std::string& hdr, const VarMap& vars) override {
         const bool is_valid = (hdr == "valid");

         Test::Result result("PKCSv15 Decoding");

         auto pkcs = Botan::EME::create("PKCS1v15");
         if(!pkcs) {
            return result;
         }

         const std::vector<uint8_t> ciphertext = vars.get_req_bin("RawCiphertext");
         const std::vector<uint8_t> plaintext = vars.get_opt_bin("Plaintext");

         if(is_valid == false) {
            result.test_eq("Plaintext value should be empty for invalid EME inputs", plaintext.size(), 0);
         }

         std::vector<uint8_t> decoded(ciphertext.size());
         auto len = pkcs->unpad(decoded, ciphertext);

         result.test_eq("EME decoding valid/invalid matches", len.has_value().as_bool(), is_valid);

         if(len.has_value().as_bool()) {
            decoded.resize(len.value_or(0));
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
#endif

}  // namespace Botan_Tests

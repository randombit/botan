/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/exceptn.h>

#if defined(BOTAN_HAS_RSA_ENCRYPTION_PADDING)
   #include <botan/internal/enc_padding.h>
#endif

#if defined(BOTAN_HAS_RSA_SIGNATURE_PADDING)
   #include <botan/pk_options.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/sig_padding.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_EME_PKCS1)
class EME_PKCS1v15_Decoding_Tests final : public Text_Based_Test {
   public:
      EME_PKCS1v15_Decoding_Tests() : Text_Based_Test("pk_pad_eme/pkcs1.vec", "RawCiphertext", "Plaintext") {}

      Test::Result run_one_test(const std::string& hdr, const VarMap& vars) override {
         const bool is_valid = (hdr == "valid");

         Test::Result result("PKCSv15 Decoding");

         auto pkcs = Botan::EncryptionPaddingScheme::create("PKCS1v15");
         if(!pkcs) {
            return result;
         }

         const std::vector<uint8_t> ciphertext = vars.get_req_bin("RawCiphertext");
         const std::vector<uint8_t> plaintext = vars.get_opt_bin("Plaintext");

         if(!is_valid) {
            result.test_sz_eq("Plaintext value should be empty for invalid EME inputs", plaintext.size(), 0);
         }

         std::vector<uint8_t> decoded(ciphertext.size());
         auto len = pkcs->unpad(decoded, ciphertext);

         result.test_bool_eq("EME decoding valid/invalid matches", len.has_value().as_bool(), is_valid);

         if(len.has_value().as_bool()) {
            decoded.resize(len.value_or(0));
            result.test_bin_eq("EME decoded plaintext correct", decoded, plaintext);
         } else {
            bool all_zeros = true;
            for(const uint8_t b : decoded) {
               if(b != 0) {
                  all_zeros = false;
               }
            }

            result.test_is_true("On invalid padding output is all zero", all_zeros);
         }

         // TODO: also test that encoding is accepted

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "eme_pkcs1v15", EME_PKCS1v15_Decoding_Tests);
#endif

}  // namespace

}  // namespace Botan_Tests

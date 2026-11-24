/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RSA_ENCRYPTION_PADDING)
   #include "test_rng.h"
   #include <botan/internal/ct_utils.h>
   #include <botan/internal/enc_padding.h>
   #include <botan/internal/pk_options_impl.h>
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

         auto pkcs = Botan::EncryptionPaddingScheme::create_or_throw(
            Botan::PK_Options_Reader_Access::read(Botan::PK_Encryption_Options().with_padding("PKCS1v15")));

         const std::vector<uint8_t> ciphertext = vars.get_req_bin("RawCiphertext");
         const std::vector<uint8_t> plaintext = vars.get_opt_bin("Plaintext");

         if(!is_valid) {
            result.test_sz_eq("Plaintext value should be empty for invalid EME inputs", plaintext.size(), 0);
         }

         std::vector<uint8_t> decoded(ciphertext.size());
         const auto len = pkcs->unpad(decoded, ciphertext);

         // Unpadding leaves the outputs marked as secret for the valgrind checks
         const size_t decoded_len = Botan::CT::driveby_unpoison(len.value_or(0));
         Botan::CT::unpoison(decoded);

         result.test_bool_eq("EME decoding valid/invalid matches", len.has_value().as_bool(), is_valid);

         if(len.has_value().as_bool()) {
            decoded.resize(decoded_len);
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

class EME_PKCS1v15_Encoding_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PKCSv15 Encoding");

         auto pkcs = Botan::EncryptionPaddingScheme::create_or_throw(
            Botan::PK_Options_Reader_Access::read(Botan::PK_Encryption_Options().with_padding("PKCS1v15")));

         // A 256 bit key and a 3 byte input leave 27 bytes of padding
         const std::vector<uint8_t> input = {'a', 'b', 'c'};
         std::vector<uint8_t> padding = {0x00, 0x01, 0x02, 0x03, 0x04, 0x00};
         for(uint8_t i = 6; i != 26; ++i) {
            padding.push_back(i);
         }
         padding.push_back(0x00);

         // Each zero byte of the padding is replaced by the next nonzero output
         std::vector<uint8_t> rng_output = padding;
         rng_output.insert(rng_output.end(), {0x00, 0xAA, 0xBB, 0xCC});
         Fixed_Output_RNG rng(rng_output);

         std::vector<uint8_t> expected = {0x02, 0xAA, 0x01, 0x02, 0x03, 0x04, 0xBB};
         expected.insert(expected.end(), padding.begin() + 6, padding.end() - 1);
         expected.insert(expected.end(), {0xCC, 0x00});
         expected.insert(expected.end(), input.begin(), input.end());

         std::vector<uint8_t> encoded(expected.size());
         const size_t written = pkcs->pad(encoded, input, 256, rng);

         result.test_sz_eq("encoding size", written, expected.size());
         result.test_bin_eq("zero padding bytes are replaced", encoded, expected);
         result.test_is_true("all RNG output was used", rng.empty());

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "eme_pkcs1v15_encode", EME_PKCS1v15_Encoding_Tests);
#endif

}  // namespace

}  // namespace Botan_Tests

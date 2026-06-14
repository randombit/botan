/*
* (C) 2017,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_AEAD_SIV)
   #include <botan/aead.h>
   #include <botan/hex.h>
   #include <botan/rng.h>
   #include <botan/internal/parsing.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_AEAD_SIV)

class SIV_Tests final : public Text_Based_Test {
   public:
      SIV_Tests() : Text_Based_Test("siv_ad.vec", "Key,In,ADs,Out", "Nonce") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const std::vector<uint8_t> nonce = vars.get_opt_bin("Nonce");
         const std::vector<uint8_t> input = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");
         const std::vector<std::string> ad_list = Botan::split_on(vars.get_req_str("ADs"), ',');

         const std::string siv_name = algo + "/SIV";

         Test::Result result(siv_name);

         auto siv = Botan::AEAD_Mode::create(siv_name, Botan::Cipher_Dir::Encryption);

         if(!siv) {
            result.test_note("Skipping test due to missing cipher");
            return result;
         }

         siv->set_key(key);

         for(size_t i = 0; i != ad_list.size(); ++i) {
            std::vector<uint8_t> ad = Botan::hex_decode(ad_list[i]);
            siv->set_associated_data_n(i, ad);
         }

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         siv->start(nonce);
         siv->finish(buf, 0);

         result.test_bin_eq("SIV ciphertext", buf, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("modes", "siv_ad", SIV_Tests);

class SIV_Noncontiguous_AD_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("SIV non-contiguous AD");

         auto gapped = Botan::AEAD_Mode::create("AES-128/SIV", Botan::Cipher_Dir::Encryption);
         if(!gapped) {
            result.test_note("Skipping test due to missing cipher");
            return {result};
         }
         auto enc = Botan::AEAD_Mode::create("AES-128/SIV", Botan::Cipher_Dir::Encryption);

         const auto key = rng().random_vec(16 * 2);
         const auto ad0 = rng().random_vec(32);
         const auto ad2 = rng().random_vec(48);
         const auto input = rng().random_vec(10);

         gapped->set_key(key);
         enc->set_key(key);

         // gapped: indices 0 and 2 set, index 1 skipped
         gapped->set_associated_data_n(0, ad0);
         gapped->set_associated_data_n(2, ad2);

         Botan::secure_vector<uint8_t> buf_gapped = input;
         gapped->start();
         gapped->finish(buf_gapped, 0);

         // enc: index 1 set to a zero-length AD
         enc->set_associated_data_n(0, ad0);
         enc->set_associated_data_n(1, {});
         enc->set_associated_data_n(2, ad2);

         Botan::secure_vector<uint8_t> buf_explicit = input;
         enc->start();
         enc->finish(buf_explicit, 0);

         result.test_bin_eq("SIV AD gap is equivalent to an explicit empty AD", buf_gapped, buf_explicit);

         // Decryption must similarly handle an AAD gap
         auto dec = Botan::AEAD_Mode::create("AES-128/SIV", Botan::Cipher_Dir::Decryption);
         dec->set_key(key);
         dec->set_associated_data_n(0, ad0);
         dec->set_associated_data_n(2, ad2);
         dec->start();
         dec->finish(buf_gapped, 0);
         result.test_bin_eq("gapped AD round-trips", buf_gapped, input);

         return {result};
      }
};

BOTAN_REGISTER_TEST("modes", "siv_noncontiguous_ad", SIV_Noncontiguous_AD_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests

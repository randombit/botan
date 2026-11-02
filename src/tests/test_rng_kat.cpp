/*
* (C) 2014,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
   #include <botan/mac.h>
#endif

#if defined(BOTAN_HAS_CHACHA_RNG)
   #include <botan/chacha_rng.h>
#endif

#if defined(BOTAN_HAS_CTR_DRBG)
   #include <botan/block_cipher.h>
   #include <botan/ctr_drbg.h>
   #include <botan/internal/ctr_drbg_nodf.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_HMAC_DRBG)

class HMAC_DRBG_Tests final : public Text_Based_Test {
   public:
      HMAC_DRBG_Tests() :
            Text_Based_Test(
               "rng/hmac_drbg.vec", "EntropyInput,EntropyInputReseed,Out", "AdditionalInput1,AdditionalInput2") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> seed_input = vars.get_req_bin("EntropyInput");
         const std::vector<uint8_t> reseed_input = vars.get_req_bin("EntropyInputReseed");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         const std::vector<uint8_t> ad1 = vars.get_opt_bin("AdditionalInput1");
         const std::vector<uint8_t> ad2 = vars.get_opt_bin("AdditionalInput2");

         Test::Result result("HMAC_DRBG(" + algo + ")");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(" + algo + ")");

         if(!mac) {
            result.note_missing("HMAC(" + algo + ")");
            return result;
         }

         auto rng = std::make_unique<Botan::HMAC_DRBG>(std::move(mac));
         rng->initialize_with(seed_input.data(), seed_input.size());

         // now reseed
         rng->add_entropy(reseed_input.data(), reseed_input.size());

         std::vector<uint8_t> out(expected.size());
         // first block is discarded
         rng->randomize_with_input(out.data(), out.size(), ad1.data(), ad1.size());
         rng->randomize_with_input(out.data(), out.size(), ad2.data(), ad2.size());

         result.test_bin_eq("rng", out, expected);
         return result;
      }
};

BOTAN_REGISTER_SMOKE_TEST("rng", "hmac_drbg", HMAC_DRBG_Tests);

#endif

#if defined(BOTAN_HAS_CTR_DRBG)

class CTR_DRBG_Tests : public Text_Based_Test {
   public:
      explicit CTR_DRBG_Tests(const std::string& data_file) :
            Text_Based_Test(data_file, "EntropyInput,EntropyInputReseed,Out", "AdditionalInput1,AdditionalInput2") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> seed_input = vars.get_req_bin("EntropyInput");
         const std::vector<uint8_t> reseed_input = vars.get_req_bin("EntropyInputReseed");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         const std::vector<uint8_t> ad1 = vars.get_opt_bin("AdditionalInput1");
         const std::vector<uint8_t> ad2 = vars.get_opt_bin("AdditionalInput2");

         auto cipher = Botan::BlockCipher::create(algo);

         if(!cipher) {
            Test::Result result("CTR_DRBG(" + algo + ")");
            result.note_missing(algo);
            return result;
         }

         auto rng = make_drbg(std::move(cipher));
         Test::Result result(rng->name());

         rng->initialize_with(seed_input);

         // now reseed
         rng->add_entropy(reseed_input);

         std::vector<uint8_t> out(expected.size());
         // first block is discarded
         rng->randomize_with_input(out, ad1);
         rng->randomize_with_input(out, ad2);

         result.test_bin_eq("rng", out, expected);
         return result;
      }

   protected:
      virtual std::unique_ptr<Botan::CTR_DRBG> make_drbg(std::unique_ptr<Botan::BlockCipher> cipher) const = 0;
};

class CTR_DRBG_DF_Tests final : public CTR_DRBG_Tests {
   public:
      CTR_DRBG_DF_Tests() : CTR_DRBG_Tests("rng/ctr_drbg.vec") {}

   private:
      std::unique_ptr<Botan::CTR_DRBG> make_drbg(std::unique_ptr<Botan::BlockCipher> cipher) const override {
         return std::make_unique<Botan::CTR_DRBG>(std::move(cipher));
      }
};

class CTR_DRBG_NoDF_Tests final : public CTR_DRBG_Tests {
   public:
      CTR_DRBG_NoDF_Tests() : CTR_DRBG_Tests("rng/ctr_drbg_nodf.vec") {}

   private:
      std::unique_ptr<Botan::CTR_DRBG> make_drbg(std::unique_ptr<Botan::BlockCipher> cipher) const override {
         return Botan::CTR_DRBG_Without_DF::create(std::move(cipher));
      }
};

BOTAN_REGISTER_TEST("rng", "ctr_drbg", CTR_DRBG_DF_Tests);
BOTAN_REGISTER_TEST("rng", "ctr_drbg_nodf", CTR_DRBG_NoDF_Tests);

#endif

#if defined(BOTAN_HAS_CHACHA_RNG)

class ChaCha_RNG_Tests final : public Text_Based_Test {
   public:
      ChaCha_RNG_Tests() :
            Text_Based_Test(
               "rng/chacha_rng.vec", "EntropyInput,EntropyInputReseed,Out", "AdditionalInput1,AdditionalInput2") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const std::vector<uint8_t> seed_input = vars.get_req_bin("EntropyInput");
         const std::vector<uint8_t> reseed_input = vars.get_req_bin("EntropyInputReseed");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         const std::vector<uint8_t> ad1 = vars.get_opt_bin("AdditionalInput1");
         const std::vector<uint8_t> ad2 = vars.get_opt_bin("AdditionalInput2");

         Test::Result result("ChaCha_RNG");

         Botan::ChaCha_RNG rng;
         rng.initialize_with(seed_input.data(), seed_input.size());

         // now reseed
         rng.add_entropy(reseed_input.data(), reseed_input.size());

         std::vector<uint8_t> out(expected.size());
         // first block is discarded
         rng.randomize_with_input(out.data(), out.size(), ad1.data(), ad1.size());
         rng.randomize_with_input(out.data(), out.size(), ad2.data(), ad2.size());

         result.test_bin_eq("rng", out, expected);
         return result;
      }
};

BOTAN_REGISTER_TEST("rng", "chacha_rng", ChaCha_RNG_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests

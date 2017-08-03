/*
* (C) 2014,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_CHACHA_RNG)
   #include <botan/chacha_rng.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_HMAC_DRBG)

class HMAC_DRBG_Tests : public Text_Based_Test
   {
   public:
      HMAC_DRBG_Tests()
         : Text_Based_Test("rng/hmac_drbg.vec",
                           "EntropyInput,EntropyInputReseed,Out",
                           "AdditionalInput1,AdditionalInput2") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> seed_input   = get_req_bin(vars, "EntropyInput");
         const std::vector<uint8_t> reseed_input = get_req_bin(vars, "EntropyInputReseed");
         const std::vector<uint8_t> expected     = get_req_bin(vars, "Out");

         const std::vector<uint8_t> ad1 = get_opt_bin(vars, "AdditionalInput1");
         const std::vector<uint8_t> ad2 = get_opt_bin(vars, "AdditionalInput2");

         Test::Result result("HMAC_DRBG(" + algo + ")");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(" + algo + ")");

         if(!mac)
            {
            result.note_missing("HMAC(" + algo + ")");
            return result;
            }

         std::unique_ptr<Botan::HMAC_DRBG> rng(new Botan::HMAC_DRBG(std::move(mac)));
         rng->initialize_with(seed_input.data(), seed_input.size());

         // now reseed
         rng->add_entropy(reseed_input.data(), reseed_input.size());

         std::vector<uint8_t> out(expected.size());
         // first block is discarded
         rng->randomize_with_input(out.data(), out.size(), ad1.data(), ad1.size());
         rng->randomize_with_input(out.data(), out.size(), ad2.data(), ad2.size());

         result.test_eq("rng", out, expected);
         return result;
         }

   };

BOTAN_REGISTER_TEST("hmac_drbg", HMAC_DRBG_Tests);

#endif

#if defined(BOTAN_HAS_CHACHA_RNG)

class ChaCha_RNG_Tests : public Text_Based_Test
   {
   public:
      ChaCha_RNG_Tests()
         : Text_Based_Test("rng/chacha_rng.vec",
                           "EntropyInput,EntropyInputReseed,Out",
                           "AdditionalInput1,AdditionalInput2") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const std::vector<uint8_t> seed_input   = get_req_bin(vars, "EntropyInput");
         const std::vector<uint8_t> reseed_input = get_req_bin(vars, "EntropyInputReseed");
         const std::vector<uint8_t> expected     = get_req_bin(vars, "Out");

         const std::vector<uint8_t> ad1 = get_opt_bin(vars, "AdditionalInput1");
         const std::vector<uint8_t> ad2 = get_opt_bin(vars, "AdditionalInput2");

         Test::Result result("ChaCha_RNG");

         Botan::ChaCha_RNG rng;
         rng.initialize_with(seed_input.data(), seed_input.size());

         // now reseed
         rng.add_entropy(reseed_input.data(), reseed_input.size());

         std::vector<uint8_t> out(expected.size());
         // first block is discarded
         rng.randomize_with_input(out.data(), out.size(), ad1.data(), ad1.size());
         rng.randomize_with_input(out.data(), out.size(), ad2.data(), ad2.size());

         result.test_eq("rng", out, expected);
         return result;
         }

   };

BOTAN_REGISTER_TEST("chacha_rng", ChaCha_RNG_Tests);

#endif

}

}

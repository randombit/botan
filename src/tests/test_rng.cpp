/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_rng.h"

#if defined(BOTAN_HAS_HMAC_DRBG)
  #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_X931_RNG)
  #include <botan/x931_rng.h>
#endif

namespace Botan_Tests {

namespace {

Botan::RandomNumberGenerator* get_rng(const std::string& algo_str, const std::vector<byte>& ikm)
   {
   const std::vector<std::string> algo_name = Botan::parse_algorithm_name(algo_str);

   const std::string rng_name = algo_name[0];


#if defined(BOTAN_HAS_X931_RNG)
   if(rng_name == "X9.31-RNG")
      {
      auto bc = Botan::BlockCipher::create(algo_name[1]);

      if(!bc)
         {
         return nullptr;
         }

      return new Botan::ANSI_X931_RNG(bc.release(), new Fixed_Output_RNG(ikm));
      }
#endif

   return nullptr;
   }

#if defined(BOTAN_HAS_X931_RNG)
class X931_RNG_Tests : public Text_Based_Test
   {
   public:
      X931_RNG_Tests() : Text_Based_Test("x931.vec", {"IKM", "L", "Out"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> ikm      = get_req_bin(vars, "IKM");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         const size_t L = get_req_sz(vars, "L");

         Test::Result result(algo);

         result.test_eq("length", L, expected.size());

         std::unique_ptr<Botan::RandomNumberGenerator> rng(get_rng(algo, ikm));
         if(!rng)
            {
            result.note_missing("RNG " + algo);
            return result;
            }

         result.test_eq("rng", rng->random_vec(L), expected);

         return result;
         }

   };

BOTAN_REGISTER_TEST("x931_rng", X931_RNG_Tests);
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)

class HMAC_DRBG_Tests : public Text_Based_Test
   {
   public:
      HMAC_DRBG_Tests() : Text_Based_Test("hmac_drbg.vec",
                                          {"EntropyInput", "EntropyInputReseed", "Out"},
                                          {"AdditionalInput1", "AdditionalInput2"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<byte> seed_input   = get_req_bin(vars, "EntropyInput");
         const std::vector<byte> reseed_input = get_req_bin(vars, "EntropyInputReseed");
         const std::vector<byte> expected     = get_req_bin(vars, "Out");

         const std::vector<byte> ad1 = get_opt_bin(vars, "AdditionalInput1");
         const std::vector<byte> ad2 = get_opt_bin(vars, "AdditionalInput2");

         Test::Result result("HMAC_DRBG(" + algo + ")");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(" + algo + ")");
         if(!mac)
            {
            result.note_missing("HMAC(" + algo + ")");
            return result;
            }

         std::unique_ptr<Botan::HMAC_DRBG> rng(new Botan::HMAC_DRBG(mac.release(), 0));
         rng->initialize_with(seed_input.data(), seed_input.size());

         // now reseed
         rng->add_entropy(reseed_input.data(), reseed_input.size());

         std::vector<byte> out(expected.size());
         // first block is discarded
         rng->randomize_with_input(out.data(), out.size(), ad1.data(), ad1.size());
         rng->randomize_with_input(out.data(), out.size(), ad2.data(), ad2.size());

         result.test_eq("rng", out, expected);
         return result;
         }

   };

BOTAN_REGISTER_TEST("hmac_drbg", HMAC_DRBG_Tests);

#endif

}

}

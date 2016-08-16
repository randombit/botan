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

#if defined(BOTAN_HAS_X931_RNG)
class X931_RNG_Tests : public Text_Based_Test
   {
   public:
      X931_RNG_Tests() : Text_Based_Test("x931.vec", {"IKM", "Out"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> ikm      = get_req_bin(vars, "IKM");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result("X9.31-RNG(" + algo + ")");

         std::unique_ptr<Botan::BlockCipher> bc = Botan::BlockCipher::create(algo);

         if(!bc)
            {
            result.note_missing("X9.31 cipher " + algo);
            return result;
            }

         Botan::ANSI_X931_RNG rng(bc.release(), new Fixed_Output_RNG(ikm));

         std::vector<uint8_t> output(expected.size());
         rng.randomize(output.data(), output.size());
         result.test_eq("rng", output, expected);

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

class HMAC_DRBG_Reseed_Tests : public Test
   {
   public:
      HMAC_DRBG_Reseed_Tests() : Test() {}

      std::vector<Test::Result> run() override
         {
         Test::Result result("HMAC_DRBG Reseed");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         if(!mac)
            {
            result.note_missing("HMAC(SHA-256)");
            return {result};
            }

         Botan::HMAC_DRBG rng(mac.release(), 17);
         Botan::secure_vector<Botan::byte> seed_input(
               {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF});
         Botan::secure_vector<Botan::byte> output_after_initialization(
               {0x26,0x06,0x95,0xF4,0xB8,0x96,0x0D,0x0B,0x27,0x4E,0xA2,0x9E,0x8D,0x2B,0x5A,0x35});
         Botan::secure_vector<Botan::byte> output_without_reseed(
               {0xC4,0x90,0x04,0x5B,0x35,0x4F,0x50,0x09,0x68,0x45,0xF0,0x4B,0x11,0x03,0x58,0xF0});
         result.test_eq("is_seeded",rng.is_seeded(),false);

         rng.initialize_with(seed_input.data(), seed_input.size());

         Botan::secure_vector<Botan::byte> out(16);

         rng.randomize(out.data(), out.size());
         result.test_eq("out before reseed", out, output_after_initialization);

         // reseed must happend here
         rng.randomize(out.data(), out.size());
         result.test_ne("out after reseed", out, output_without_reseed);
         return {result};
         }
   };

BOTAN_REGISTER_TEST("hmac_drbg_reseed", HMAC_DRBG_Reseed_Tests);

#endif

}

}

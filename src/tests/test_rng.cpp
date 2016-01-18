/*
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/entropy_src.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
  #include <botan/hmac_drbg.h>
#endif

namespace Botan_Tests {

namespace {

class Fixed_Output_Entropy_Source : public Botan::Entropy_Source
   {
   public:
      std::string name() const override { return "Fixed_Output"; }

      void poll(Botan::Entropy_Accumulator& accum) override
         {
         if(m_poll >= m_output.size())
            throw Test_Error("Fixed_Output_Entropy_Source out of bytes");

         accum.add(m_output[m_poll].data(),
                   m_output[m_poll].size(),
                   m_output[m_poll].size() * 8);
         m_poll++;
         };

      Fixed_Output_Entropy_Source(const std::vector<uint8_t>& seed,
                                  const std::vector<uint8_t>& reseed)
         {
         m_output.push_back(seed);
         m_output.push_back(reseed);
         }

   private:
      size_t m_poll = 0;
      std::vector<std::vector<uint8_t>> m_output;
   };

#if defined(BOTAN_HAS_SYSTEM_RNG)

class System_RNG_Tests : public Test
   {
   public:
      std::vector<Test::Result> run()
         {
         Test::Result result("System_RNG");

         try
            {
            Botan::System_RNG rng;

            std::vector<uint8_t> buf(4096);
            rng.randomize(buf.data(), buf.size());

            rng.add_entropy(buf.data(), buf.size());

            size_t bits = rng.reseed(256);
            result.test_gte("Reseed bits", bits, 1);
            }
         catch(Botan::Exception& e)
            {
            result.test_failure(e.what());
            }

         return { result };
         }
   };

BOTAN_REGISTER_TEST("system_rng", System_RNG_Tests);

#endif


#if defined(BOTAN_HAS_HMAC_DRBG)

class HMAC_DRBG_Tests : public Text_Based_Test
   {
   public:
      HMAC_DRBG_Tests() : Text_Based_Test("hmac_drbg.vec",
                                          {"EntropyInput",
                                           "EntropyInputReseed",
                                           "Out"},

                                          {"AdditionalInput1",
                                           "AdditionalInput2"}) {}

      Test::Result run_one_test(const std::string& hmac_hash, const VarMap& vars) override
         {
         const std::vector<byte> seed_input   = get_req_bin(vars, "EntropyInput");
         const std::vector<byte> reseed_input = get_req_bin(vars, "EntropyInputReseed");
         const std::vector<byte> expected     = get_req_bin(vars, "Out");

         const std::vector<byte> addl_data1 = get_opt_bin(vars, "AdditionalInput1");
         const std::vector<byte> addl_data2 = get_opt_bin(vars, "AdditionalInput2");

         Test::Result result("HMAC_DRBG(" + hmac_hash + ")");

         std::unique_ptr<Botan::HMAC_DRBG> drbg;
         try
            {
            drbg.reset(new Botan::HMAC_DRBG(hmac_hash, 0));
            }
         catch(Botan::Lookup_Error&)
            {
            return result;
            }

         Botan::Entropy_Sources srcs;
         std::unique_ptr<Botan::Entropy_Source> src(new Fixed_Output_Entropy_Source(seed_input, reseed_input));
         srcs.add_source(std::move(src));

         // seed
         drbg->reseed_with_sources(srcs, 8 * seed_input.size(), std::chrono::milliseconds(100));

         // reseed
         drbg->reseed_with_sources(srcs, 8 * reseed_input.size(), std::chrono::milliseconds(100));

         std::vector<byte> output(expected.size());

         // generate and discard first block
         drbg->randomize_with_input(output.data(), output.size(),
                                    addl_data1.data(), addl_data1.size());

         // test vector is second block of output
         drbg->randomize_with_input(output.data(), output.size(),
                                    addl_data2.data(), addl_data2.size());

         result.test_eq("rng", output, expected);
         return result;
         }

   };

BOTAN_REGISTER_TEST("hmac_drbg", HMAC_DRBG_Tests);

#endif

}

}

/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)
   #include <botan/tss.h>
   #include "test_rng.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)

class TSS_Recovery_Tests final : public Text_Based_Test
   {
   public:
      TSS_Recovery_Tests() : Text_Based_Test("tss/recovery.vec", "N,M,Shares,Recovered") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override
         {
         Test::Result result("TSS");

         const std::vector<uint8_t> input = vars.get_req_bin("Recovered");
         const size_t N = vars.get_req_sz("N");
         const size_t M = vars.get_req_sz("M");
         const std::vector<std::vector<uint8_t>> expected_shares = vars.get_req_bin_list("Shares");

         try
            {
            std::vector<Botan::RTSS_Share> shares;

            for(auto&& v : expected_shares)
               {
               shares.push_back(Botan::RTSS_Share(v.data(), v.size()));
               }

            auto reconstructed_secret_all = Botan::RTSS_Share::reconstruct(shares);
            result.test_eq("Reconstructed secret correctly from all shares", reconstructed_secret_all, input);

            if(header == "Invalid")
               result.test_failure("Invalid shares should not result in recovery");

            if(N != M)
               {
               while(shares.size() > M)
                  {
                  size_t to_remove = Test::rng().next_byte() % shares.size();
                  shares.erase(shares.begin() + to_remove);
                  try
                     {
                     auto reconstructed_secret = Botan::RTSS_Share::reconstruct(shares);
                     result.test_eq("Reconstructed secret correctly from reduced shares", reconstructed_secret, input);
                     }
                  catch(Botan::Decoding_Error&)
                     {
                     result.test_failure("Reconstruction failed with share count " + std::to_string(shares.size()));
                     }
                  }
               }

            }
         catch(std::exception& e)
            {

            if(header == "Valid")
               result.test_failure("Valid TSS failed to recover", e.what());
            else
               result.test_success("Invalid TSS rejected as expected");
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("utils", "tss_recovery", TSS_Recovery_Tests);

class TSS_Generation_Tests final : public Text_Based_Test
   {
   public:
      TSS_Generation_Tests() : Text_Based_Test("tss/generation.vec", "Input,RNG,Hash,Id,N,M,Shares") {}

      static size_t tss_hash_len(const std::string& hash)
         {
         if(hash == "None")
            return 0;
         else if(hash == "SHA-1")
            return 20;
         else if(hash == "SHA-256")
            return 32;
         else
            throw Test_Error("Unknown TSS hash algorithm " + hash);
         }

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("TSS");

         const std::vector<uint8_t> input = vars.get_req_bin("Input");
         const std::vector<uint8_t> id = vars.get_req_bin("Id");
         const std::vector<uint8_t> rng_data = vars.get_req_bin("RNG");
         const uint8_t N = vars.get_req_u8("N");
         const uint8_t M = vars.get_req_u8("M");
         const std::string hash = vars.get_req_str("Hash");
         const std::vector<std::vector<uint8_t>> expected_shares = vars.get_req_bin_list("Shares");

         if(expected_shares.size() != N)
            throw Test_Error("Invalid test data for TSS share count != N");

         if(rng_data.size() != (input.size() + tss_hash_len(hash)) * (M-1))
            throw Test_Error("Invalid test data for TSS share bad RNG input size");

         Fixed_Output_RNG fixed_rng(rng_data);

         std::vector<Botan::RTSS_Share> shares =
            Botan::RTSS_Share::split(M, N, input.data(), static_cast<uint16_t>(input.size()),
                                     id, hash, fixed_rng);

         result.test_eq("Expected number of shares", shares.size(), N);

         for(size_t i = 0; i != N; ++i)
            {
            result.test_eq("Expected share", shares[i].data(), expected_shares[i]);
            }

         auto reconstructed_secret_all = Botan::RTSS_Share::reconstruct(shares);
         result.test_eq("Reconstructed secret correctly from all shares", reconstructed_secret_all, input);

         if(N != M)
            {
            while(shares.size() > M)
               {
               size_t to_remove = Test::rng().next_byte() % shares.size();
               shares.erase(shares.begin() + to_remove);

               try
                  {
                  auto reconstructed_secret = Botan::RTSS_Share::reconstruct(shares);
                  result.test_eq("Reconstructed secret correctly from reduced shares", reconstructed_secret, input);
                  }
               catch(Botan::Decoding_Error&)
                  {
                  result.test_failure("Reconstruction failed with share count " + std::to_string(shares.size()));
                  }
               }
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("utils", "tss_generation", TSS_Generation_Tests);

#endif // BOTAN_HAS_THRESHOLD_SECRET_SHARING

}

}

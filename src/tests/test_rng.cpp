/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"
#include "tests.h"

#include <botan/hex.h>
#include <botan/lookup.h>
#include <iostream>
#include <fstream>

#if defined(BOTAN_HAS_HMAC_DRBG)
  #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_X931_RNG)
  #include <botan/x931_rng.h>
#endif

using namespace Botan;

namespace {

RandomNumberGenerator* get_rng(const std::string& algo_str, const std::string& ikm_hex)
   {
   class AllOnce_RNG : public Fixed_Output_RNG
      {
      public:
         AllOnce_RNG(const std::vector<byte>& in) : Fixed_Output_RNG(in) {}

         Botan::secure_vector<byte> random_vec(size_t)
            {
            Botan::secure_vector<byte> vec(this->remaining());
            this->randomize(&vec[0], vec.size());
            return vec;
            }
      };

   const auto ikm = hex_decode(ikm_hex);

   const auto algo_name = parse_algorithm_name(algo_str);

   const std::string rng_name = algo_name[0];

#if defined(BOTAN_HAS_HMAC_DRBG)
   if(rng_name == "HMAC_DRBG")
      return new HMAC_DRBG(get_mac("HMAC(" + algo_name[1] + ")"), new AllOnce_RNG(ikm));
#endif

#if defined(BOTAN_HAS_X931_RNG)
   if(rng_name == "X9.31-RNG")
      return new ANSI_X931_RNG(get_block_cipher(algo_name[1]),
                               new Fixed_Output_RNG(ikm));
#endif

   return nullptr;
   }

size_t x931_test(const std::string& algo,
                 const std::string& ikm,
                 const std::string& out,
                 size_t L)
   {
   std::unique_ptr<RandomNumberGenerator> rng(get_rng(algo, ikm));

   if(!rng)
      throw std::runtime_error("Unknown RNG " + algo);

   const std::string got = hex_encode(rng->random_vec(L));

   if(got != out)
      {
      std::cout << "X9.31 " << got << " != " << out << std::endl;
      return 1;
      }

   return 0;
   }

size_t hmac_drbg_test(std::map<std::string, std::string> m)
   {
   const std::string algo = m["RNG"];
   const std::string ikm = m["EntropyInput"];

   std::unique_ptr<RandomNumberGenerator> rng(get_rng(algo, ikm));
   if(!rng)
      throw std::runtime_error("Unknown RNG " + algo);

   rng->reseed(0); // force initialization

   // now reseed
   const auto reseed_input = hex_decode(m["EntropyInputReseed"]);
   rng->add_entropy(&reseed_input[0], reseed_input.size());

   const std::string out = m["Out"];

   const size_t out_len = out.size() / 2;

   rng->random_vec(out_len); // gen 1st block (discarded)

   const std::string got = hex_encode(rng->random_vec(out_len));

   if(got != out)
      {
      std::cout << algo << " " << got << " != " << out << std::endl;
      return 1;
      }

   return 0;
   }

}

size_t test_rngs()
   {
   std::ifstream hmac_drbg_vec(TEST_DATA_DIR "/hmac_drbg.vec");
   std::ifstream x931_vec(TEST_DATA_DIR "/x931.vec");

   size_t fails = 0;

   fails += run_tests_bb(hmac_drbg_vec, "RNG", "Out", true, hmac_drbg_test);

   fails += run_tests_bb(x931_vec, "RNG", "Out", true,
                         [](std::map<std::string, std::string> m) -> size_t
                         {
                         return x931_test(m["RNG"], m["IKM"], m["Out"], to_u32bit(m["L"]));
                         });

   return fails;
   }

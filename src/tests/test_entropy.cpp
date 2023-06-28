/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"
#include "tests.h"
#include <botan/entropy_src.h>

#if defined(BOTAN_HAS_COMPRESSION)
   #include <botan/compression.h>
#endif

namespace Botan_Tests {

namespace {

class Entropy_Source_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Botan::Entropy_Sources& srcs = Botan::Entropy_Sources::global_sources();

         std::vector<std::string> src_names = srcs.enabled_sources();

         std::vector<Test::Result> results;

         for(const auto& src_name : src_names) {
            Test::Result result("Entropy source " + src_name);

            result.start_timer();

            try {
               SeedCapturing_RNG rng;

               size_t bits = srcs.poll_just(rng, src_name);

               result.test_gte("Entropy estimate", rng.seed_material().size() * 8, bits);

               if(rng.samples() > 0) {
                  result.test_gte("Seed material bytes", rng.seed_material().size(), 1);
                  result.test_gte("Samples", rng.samples(), 1);
               }

               result.test_note("poll result", rng.seed_material());

#if defined(BOTAN_HAS_COMPRESSION)
               if(!rng.seed_material().empty()) {
                  /*
                  * Skip bzip2 both due to OS X problem (GH #394) and because bzip2's
                  * large blocks cause the entropy differential test to fail sometimes.
                  */
                  for(const std::string comp_algo : {"zlib", "lzma"}) {
                     auto comp = Botan::Compression_Algorithm::create(comp_algo);

                     if(comp) {
                        size_t comp1_size = 0;

                        try {
                           Botan::secure_vector<uint8_t> compressed;
                           compressed.assign(rng.seed_material().begin(), rng.seed_material().end());
                           comp->start(9);
                           comp->finish(compressed);

                           comp1_size = compressed.size();

                           result.test_gte(
                              comp_algo + " compressed entropy better than advertised", compressed.size() * 8, bits);
                        } catch(std::exception& e) {
                           result.test_failure(comp_algo + " exception while compressing", e.what());
                        }

                        SeedCapturing_RNG rng2;

                        size_t bits2 = srcs.poll_just(rng2, src_name);

                        result.test_note("poll 2 result", rng2.seed_material());

                        if(!rng.seed_material().empty() && !rng2.seed_material().empty()) {
                           try {
                              Botan::secure_vector<uint8_t> compressed;
                              compressed.insert(
                                 compressed.end(), rng.seed_material().begin(), rng.seed_material().end());
                              compressed.insert(
                                 compressed.end(), rng2.seed_material().begin(), rng2.seed_material().end());

                              comp->start();
                              comp->finish(compressed);

                              size_t comp2_size = compressed.size();

                              result.test_lt("Two blocks of entropy are larger than one", comp1_size, comp2_size);

                              size_t comp_diff = comp2_size - comp1_size;

                              result.test_gte(
                                 comp_algo + " diff compressed entropy better than advertised", comp_diff * 8, bits2);
                           } catch(std::exception& e) {
                              result.test_failure(comp_algo + " exception while compressing", e.what());
                           }
                        }
                     }
                  }
               }
#endif
            } catch(std::exception& e) {
               result.test_failure("during entropy collection test", e.what());
            }

            result.end_timer();
            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("rng", "entropy", Entropy_Source_Tests);

}  // namespace

}  // namespace Botan_Tests

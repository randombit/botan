/*
* (C) 2024 Planck Security S.A.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#ifdef BOTAN_HAS_JITTER_RNG

   #include <botan/auto_rng.h>
   #include <botan/entropy_src.h>
   #include <botan/exceptn.h>
   #include <botan/jitter_rng.h>
   #include <botan/system_rng.h>

namespace Botan_Tests {

namespace {

std::vector<Test::Result> test_jitter_rng() {
   return {
      CHECK("Jitter_RNG basic usage",
            [](Test::Result& result) {
               const std::vector<size_t> sample_counts{0, 1, 2, 4, 64, 128, 512};

               Botan::Jitter_RNG rng;
               for(auto sample_count : sample_counts) {
                  [[maybe_unused]] auto buf = rng.random_vec(sample_count);
               }
               result.test_success("Basic usage working.");
            }),

      CHECK("Jitter_RNG clear",
            [](Test::Result& result) {
               const std::vector<size_t> sample_counts{64, 128};

               Botan::Jitter_RNG rng;
               for(auto sample_count : sample_counts) {
                  [[maybe_unused]] auto buf = rng.random_vec(sample_count);
                  rng.clear();
               }
               result.test_success("Clearing works.");
            }),

      CHECK("Jitter_RNG modes and oversampling rate",
            [](Test::Result& result) {
               for(auto mode : {Botan::Jitter_RNG::Mode::Default, Botan::Jitter_RNG::Mode::FIPS}) {
                  Botan::Jitter_RNG rng(mode);
                  result.test_sz_eq("output produced", rng.random_vec(64).size(), size_t(64));

                  // an oversampling rate the library accepts in any mode
                  Botan::Jitter_RNG rng_osr(mode, 3);
                  result.test_sz_eq("output produced with explicit osr", rng_osr.random_vec(64).size(), size_t(64));
               }
            }),

      CHECK("Jitter_RNG NTG.1",
            [](Test::Result& result) {
               const auto ntg1 = Botan::Jitter_RNG::Mode::NTG1;

               if(Botan::Jitter_RNG::ntg1_supported()) {
                  try {
                     Botan::Jitter_RNG rng(ntg1);
                     result.test_sz_eq("output produced", rng.random_vec(64).size(), size_t(64));
                  } catch(const Botan::Internal_Error&) {
                     result.test_note("NTG.1 init error due to failing health tests.");
                  } catch(const Botan::Not_Implemented&) {
                     result.test_failure(
                        "NTG.1 check not working. Not_Implemented should only be thrown when jitterentropy is "
                        "older than 3.7.0 and does not support the NTG.1 mode.");
                  }
               } else {
                  result.test_throws<Botan::Not_Implemented>("NTG.1 is rejected if unsupported by jitterentropy",
                                                             [ntg1]() { Botan::Jitter_RNG rng(ntg1); });
               }
            }),

      CHECK("JitterRNG as entropy source",
            [](Test::Result& result) {
               for(std::string_view mode : {"jitter_rng", "jitter_rng_fips", "jitter_rng_ntg1"}) {
                  try {
                     Botan::Entropy_Sources entropy_sources;
                     entropy_sources.add_source(Botan::Entropy_Source::create(mode));
                     Botan::AutoSeeded_RNG rng{entropy_sources};

                     [[maybe_unused]] auto buf = rng.random_vec(512);
                  } catch(const Botan::Internal_Error&) {
                     if(mode == "jitter_rng") {
                        result.test_failure("Default mode without health tests should not throw an Internal_Error.");
                     }
                  } catch(const Botan::Not_Implemented&) {
                     if(mode != "jitter_rng_ntg1") {
                        result.test_failure("All modes other than NTG.1 should always be implemented.");
                     }
                  }
               }
               result.test_success("All modes supported modes working.");
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("rng", "jitter_rng", test_jitter_rng);

}  // namespace Botan_Tests

#endif

/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "tests.h"

#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_TPM2)
   #include <botan/tpm2_rng.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TPM2)
namespace {

bool not_zero_64(std::span<const uint8_t> in) {
   Botan::BufferSlicer bs(in);

   while(bs.remaining() > 8) {
      if(Botan::load_be(bs.take<8>()) == 0) {
         return false;
      }
   }
   // Ignore remaining bytes

   return true;
}

std::vector<Test::Result> test_tpm2_rng() {
   auto ctx = Botan::TPM2_Context::create();

   auto rng = Botan::TPM2_RNG(ctx);

   return {
      Botan_Tests::CHECK("Basic functionalities",
                         [&](Test::Result& result) {
                            result.confirm("Accepts input", rng.accepts_input());
                            result.confirm("Is seeded", rng.is_seeded());
                            result.test_eq("Right name", rng.name(), "TPM2_RNG");

                            result.test_no_throw("Clear", [&] { rng.clear(); });
                         }),
      Botan_Tests::CHECK("Random number generation",
                         [&](Test::Result& result) {
                            std::array<uint8_t, 8> buf1 = {};
                            rng.randomize(buf1);
                            result.confirm("Is at least not 0 (8)", not_zero_64(buf1));

                            std::array<uint8_t, 15> buf2 = {};
                            rng.randomize(buf2);
                            result.confirm("Is at least not 0 (15)", not_zero_64(buf2));

                            std::array<uint8_t, 256> buf3 = {};
                            rng.randomize(buf3);
                            result.confirm("Is at least not 0 (256)", not_zero_64(buf3));
                         }),

      Botan_Tests::CHECK("Randomize with inputs",
                         [&](Test::Result& result) {
                            std::array<uint8_t, 9> buf1 = {};
                            rng.randomize_with_input(buf1, std::array<uint8_t, 30>{});
                            result.confirm("Randomized with inputs is at least not 0 (9)", not_zero_64(buf1));

                            std::array<uint8_t, 66> buf2 = {};
                            rng.randomize_with_input(buf2, std::array<uint8_t, 64>{});
                            result.confirm("Randomized with inputs is at least not 0 (66)", not_zero_64(buf2));

                            std::array<uint8_t, 256> buf3 = {};
                            rng.randomize_with_input(buf3, std::array<uint8_t, 196>{});
                            result.confirm("Randomized with inputs is at least not 0 (256)", not_zero_64(buf3));
                         }),
   };
}
}  // namespace

BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_rng", test_tpm2_rng);
#endif

}  // namespace Botan_Tests

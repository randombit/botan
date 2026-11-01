/*
* (C) 2016,2019,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hwrng.h>

#include <botan/internal/isa_extn.h>

namespace Botan::HWRNG {

CPUID::Feature feature() {
   return CPUID::Feature::DARN;
}

BOTAN_FN_ISA_RNG std::optional<uint64_t> read_once() {
   /*
   DARN indicates error by returning 0xFF..FF, ie is biased. Which is crazy.
   Avoid the bias by invoking it twice and, assuming both succeed, returning the
   XOR of the two results, which should unbias the output.
   */
   uint64_t output = 0;   // NOLINT(*-const-correctness) clang-tidy doesn't understand inline asm
   uint64_t output2 = 0;  // NOLINT(*-const-correctness) clang-tidy doesn't understand inline asm
   // DARN codes are 0: 32-bit conditioned, 1: 64-bit conditioned, 2: 64-bit raw (ala RDSEED)
   asm volatile("darn %0, 1" : "=r"(output));   // NOLINT(*-no-assembler)
   asm volatile("darn %0, 1" : "=r"(output2));  // NOLINT(*-no-assembler)

   const bool success = (~output) != 0 && (~output2) != 0;

   if(success) {
      return output ^ output2;
   } else {
      return std::nullopt;
   }
}

}  // namespace Botan::HWRNG

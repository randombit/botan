/*
* (C) 2026 Mika Tammi
*     2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hwrng.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/target_info.h>

#if !defined(BOTAN_USE_GCC_INLINE_ASM)
   #include <arm_acle.h>
#endif

namespace Botan::HWRNG {

CPUID::Feature feature() {
   return CPUID::Feature::RNG;
}

BOTAN_FN_ISA_RNG std::optional<uint64_t> read_once() {
   uint64_t output = 0;  // NOLINT(*-const-correctness) clang-tidy doesn't understand inline asm

#if defined(BOTAN_USE_GCC_INLINE_ASM)
   uint64_t ok = 0;  // NOLINT(*-const-correctness) clang-tidy doesn't understand inline asm
   // RNDR sets the Z flag if it could not produce a random number
   // NOLINTNEXTLINE(*-no-assembler)
   asm volatile("mrs %0, rndr; cset %1, ne" : "=r"(output), "=r"(ok) : : "cc");
#else
   const bool ok = (__rndr(&output) == 0);
#endif

   if(ok) {
      return output;
   } else {
      return std::nullopt;
   }
}

}  // namespace Botan::HWRNG

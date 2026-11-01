/*
* (C) 2016,2019,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hwrng.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/target_info.h>

#if !defined(BOTAN_USE_GCC_INLINE_ASM)
   #include <immintrin.h>
#endif

namespace Botan::HWRNG {

namespace {

#if defined(BOTAN_TARGET_ARCH_IS_X86_32)
using rdrand_output = uint32_t;
#else
using rdrand_output = uint64_t;
#endif

BOTAN_FN_ISA_RNG std::optional<rdrand_output> rdrand() {
   rdrand_output output = 0;  // NOLINT(*-const-correctness) clang-tidy doesn't understand inline asm
   int cf = 0;                // NOLINT(*-const-correctness) clang-tidy doesn't understand inline asm

#if defined(BOTAN_USE_GCC_INLINE_ASM)
   // same asm seq works for 32 and 64 bit
   // NOLINTNEXTLINE(*-no-assembler)
   asm volatile("rdrand %0; adcl $0,%1" : "=r"(output), "=r"(cf) : "0"(output), "1"(cf) : "cc");
#elif defined(BOTAN_TARGET_ARCH_IS_X86_32)
   cf = _rdrand32_step(&output);
#else
   unsigned long long outputll = 0;
   cf = _rdrand64_step(&outputll);
   output = static_cast<uint64_t>(outputll);
#endif

   if(cf == 1) {
      return output;
   } else {
      return std::nullopt;
   }
}

}  // namespace

CPUID::Feature feature() {
   return CPUID::Feature::RDRAND;
}

std::optional<uint64_t> read_once() {
#if defined(BOTAN_TARGET_ARCH_IS_X86_32)
   // In 32-bit mode RDRAND can only produce 32 bits per invocation
   const auto lo = rdrand();
   const auto hi = rdrand();

   if(lo && hi) {
      return (static_cast<uint64_t>(*hi) << 32) | *lo;
   } else {
      return std::nullopt;
   }
#else
   return rdrand();
#endif
}

}  // namespace Botan::HWRNG

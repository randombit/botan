/*
* (C) 2016,2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/processor_rng.h>

#include <botan/internal/cpuid.h>
#include <botan/internal/loadstor.h>

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   #include <immintrin.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
/*
   * According to Intel, RDRAND is guaranteed to generate a random
   * number within 10 retries on a working CPU
   */
const size_t HWRNG_RETRIES = 10;

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
/**
    * PowerISA 3.0 p.78:
    *    When the error value is obtained, software is expected to repeat the
    *    operation. [...] The recommended number of attempts may be
    *    implementation specific. In the absence of other guidance, ten attempts
    *    should be adequate.
    */
const size_t HWRNG_RETRIES = 10;

#else
/*
   * Lacking specific guidance we give the CPU quite a bit of leeway
   */
const size_t HWRNG_RETRIES = 512;
#endif

#if defined(BOTAN_TARGET_ARCH_IS_X86_32)
typedef uint32_t hwrng_output;
#else
typedef uint64_t hwrng_output;
#endif

hwrng_output read_hwrng(bool& success) {
   hwrng_output output = 0;
   success = false;

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   int cf = 0;
   #if defined(BOTAN_USE_GCC_INLINE_ASM)
   // same asm seq works for 32 and 64 bit
   asm volatile("rdrand %0; adcl $0,%1" : "=r"(output), "=r"(cf) : "0"(output), "1"(cf) : "cc");
   #elif defined(BOTAN_TARGET_ARCH_IS_X86_32)
   cf = _rdrand32_step(&output);
   #else
   cf = _rdrand64_step(reinterpret_cast<unsigned long long*>(&output));
   #endif
   success = (1 == cf);

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

   /*
   DARN indicates error by returning 0xFF..FF, ie is biased. Which is crazy.
   Avoid the bias by invoking it twice and, assuming both succeed, returning the
   XOR of the two results, which should unbias the output.
   */
   uint64_t output2 = 0;
   // DARN codes are 0: 32-bit conditioned, 1: 64-bit conditioned, 2: 64-bit raw (ala RDSEED)
   asm volatile("darn %0, 1" : "=r"(output));
   asm volatile("darn %0, 1" : "=r"(output2));

   if((~output) != 0 && (~output2) != 0) {
      output ^= output2;
      success = true;
   }

#endif

   if(success) {
      return output;
   }

   return 0;
}

hwrng_output read_hwrng() {
   for(size_t i = 0; i < HWRNG_RETRIES; ++i) {
      bool success = false;
      hwrng_output output = read_hwrng(success);

      if(success) {
         return output;
      }
   }

   throw PRNG_Unseeded("Processor RNG instruction failed to produce output within expected iterations");
}

}  // namespace

//static
bool Processor_RNG::available() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   return CPUID::has_rdrand();
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   return CPUID::has_darn_rng();
#else
   return false;
#endif
}

std::string Processor_RNG::name() const {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   return "rdrand";
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   return "darn";
#else
   return "hwrng";
#endif
}

void Processor_RNG::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) {
   // No way to provide entropy to processor-specific generator, ignore...
   BOTAN_UNUSED(in);

   while(out.size() >= sizeof(hwrng_output)) {
      const hwrng_output r = read_hwrng();
      store_le(r, out.data());
      out = out.subspan(sizeof(hwrng_output));
   }

   if(!out.empty()) {
      // at most sizeof(hwrng_output)-1 bytes left
      const hwrng_output r = read_hwrng();
      uint8_t hwrng_bytes[sizeof(hwrng_output)];
      store_le(r, hwrng_bytes);

      for(size_t i = 0; i != out.size(); ++i) {
         out[i] = hwrng_bytes[i];
      }
   }
}

Processor_RNG::Processor_RNG() {
   if(!Processor_RNG::available()) {
      throw Invalid_State("Current CPU does not support RNG instruction");
   }
}

size_t Processor_RNG::reseed(Entropy_Sources& /*srcs*/,
                             size_t /*poll_bits*/,
                             std::chrono::milliseconds /*poll_timeout*/) {
   /* no way to add entropy */
   return 0;
}

}  // namespace Botan

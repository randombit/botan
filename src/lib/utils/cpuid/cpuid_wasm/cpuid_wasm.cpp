/*
* (C) 2025 Jack Lloyd
* (C) 2025 polarnis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

namespace Botan {

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   // There's no cpuid equivalent for Wasm, but we can detect some VM capabilities (like SIMD128 or Relaxed SIMD)
   // at compile time either way.
   enum class Wasm_vmcap_bit : uint64_t {
      SIMD128_bit = (1 << 0),
   };

   uint64_t flags = 0;
#ifdef __wasm_simd128__
   flags |= static_cast<std::underlying_type_t<Wasm_vmcap_bit>>(Wasm_vmcap_bit::SIMD128_bit);
#endif

   uint32_t feat = 0;
   feat |= if_set(flags, Wasm_vmcap_bit::SIMD128_bit, CPUFeature::Bit::SIMD128, allowed);

   return feat;
}

}  // namespace Botan

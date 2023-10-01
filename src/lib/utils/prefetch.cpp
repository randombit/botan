/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/prefetch.h>

#include <botan/internal/bit_ops.h>
#include <new>

namespace Botan {

uint64_t prefetch_array_raw(size_t bytes, const void* arrayv) noexcept {
#if defined(__cpp_lib_hardware_interference_size)
   const size_t cache_line_size = std::hardware_destructive_interference_size;
#else
   // We arbitrarily use a 64 byte cache line, which is by far the most
   // common size.
   //
   // Runtime detection adds too much overhead to this function.
   const size_t cache_line_size = 64;
#endif

   const uint8_t* array = static_cast<const uint8_t*>(arrayv);

   volatile uint64_t combiner = 1;

   for(size_t idx = 0; idx < bytes; idx += cache_line_size) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_prefetch)
      // we have no way of knowing if the compiler will emit anything here
      __builtin_prefetch(&array[idx]);
#endif

      combiner = combiner | array[idx];
   }

   /*
   * The combiner variable is initialized with 1, and we accumulate using OR, so
   * now combiner must be a value other than zero. This being the case we will
   * always return zero here. Hopefully the compiler will not figure this out.
   */
   return ct_is_zero(combiner);
}

}  // namespace Botan

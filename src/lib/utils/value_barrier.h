/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_VALUE_BARRIER_H_
#define BOTAN_VALUE_BARRIER_H_

#include <botan/internal/target_info.h>
#include <concepts>
#include <type_traits>

namespace Botan::CT {

/**
* This function returns its argument, but (if called in a non-constexpr context)
* attempts to prevent the compiler from reasoning about the value or the possible
* range of values. Such optimizations have a way of breaking constant time code.
*
* The method that is use is decided at configuration time based on the target
* compiler and architecture (see `ct_value_barrier` blocks in `src/build-data/cc`).
* The decision can be overridden by the user with the configure.py option
* `--ct-value-barrier-type=`
*
* There are three options currently possible in the data files and with the
* option:
*
*  * `asm`: Use an inline assembly expression which (currently) prevents Clang
*    and GCC from optimizing based on the possible value of the input expression.
*
*  * `volatile`: Launder the input through a volatile variable. This is likely
*    to cause significant performance regressions since the value must be
*    actually stored and loaded back from memory each time.
*
*  * `none`: disable constant time barriers entirely. This is used
*    with MSVC, which is not known to perform optimizations that break
*    constant time code and which does not support GCC-style inline asm.
*
*/
template <std::unsigned_integral T>
   requires(!std::same_as<bool, T>)
constexpr inline T value_barrier(T x) {
   if(std::is_constant_evaluated()) {
      return x;
   } else {
#if defined(BOTAN_CT_VALUE_BARRIER_USE_ASM)
      /*
      * We may want a "stronger" statement such as
      *     asm volatile("" : "+r,m"(x) : : "memory);
      * (see https://theunixzoo.co.uk/blog/2021-10-14-preventing-optimisations.html)
      * however the current approach seems sufficient with current compilers,
      * and is minimally damaging with regards to degrading code generation.
      */
      asm("" : "+r"(x) : /* no input */);  // NOLINT(*-no-assembler)
      return x;
#elif defined(BOTAN_CT_VALUE_BARRIER_USE_VOLATILE)
      volatile T vx = x;
      return vx;
#else
      return x;
#endif
   }
}

}  // namespace Botan::CT

#endif

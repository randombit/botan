/*
* Helpers for compiler-assisted stack scrubbing
* (C) 2025 Jack Lloyd
*     2025 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTIL_STACK_SCRUBBING_H_
#define BOTAN_UTIL_STACK_SCRUBBING_H_

#include <botan/compiler.h>
#include <botan/internal/target_info.h>

// TODO(Botan4): Move this to compiler.h (currently still a public header)

#if !defined(BOTAN_SCRUB_STACK_AFTER_RETURN)
   #if BOTAN_COMPILER_HAS_ATTRIBUTE(strub) && defined(BOTAN_USE_COMPILER_ASSISTED_STACK_SCRUBBING)
      /**
      * When a function definition is annotated with this macro, the compiler
      * generates a wrapper for the function's body to handle stack scrubbing
      * in the wrapper. In contrast to 'strub("at-calls")' this does not alter
      * the function's ABI.
      *
      * It is okay to use this annotation on C++ method definitions (in *.cpp),
      * even if the function is a public API.
      *
      * Currently this is supported on GCC 14+ only
      * See: https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Common-Type-Attributes.html#index-strub-type-attribute
      */
      #define BOTAN_SCRUB_STACK_AFTER_RETURN BOTAN_COMPILER_ATTRIBUTE(strub("internal"))
   #else
      #define BOTAN_SCRUB_STACK_AFTER_RETURN
   #endif
#endif

#endif

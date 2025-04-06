/*
* Define useful compiler-specific macros
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTIL_COMPILER_FLAGS_H_
#define BOTAN_UTIL_COMPILER_FLAGS_H_

#include <botan/api.h>
#include <botan/build.h>

BOTAN_FUTURE_INTERNAL_HEADER(compiler.h)

/*
* Define BOTAN_COMPILER_HAS_BUILTIN
*/
#if defined(__has_builtin)
   #define BOTAN_COMPILER_HAS_BUILTIN(x) __has_builtin(x)
#else
   #define BOTAN_COMPILER_HAS_BUILTIN(x) 0
#endif

/*
* Define BOTAN_COMPILER_HAS_ATTRIBUTE
*/
#if defined(__has_attribute)
   #define BOTAN_COMPILER_HAS_ATTRIBUTE(x) __has_attribute(x)
   #define BOTAN_COMPILER_ATTRIBUTE(x) __attribute__((x))
#else
   #define BOTAN_COMPILER_HAS_ATTRIBUTE(x) 0
   #define BOTAN_COMPILER_ATTRIBUTE(x) /**/
#endif

/*
* Hack for Loongarch64 GCC bug
*
* For some reason __has_attribute(target) is true, but it does not support the
* target attribute... this supposedly is fixed in GCC 15 but this is untested.
*/
#if defined(__GNUC__) && defined(__loongarch64) && (__GNUC__ <= 14)
   #define BOTAN_COMPILER_DOES_NOT_HAVE_TARGET_ATTRIBUTE
#endif

/*
* Define BOTAN_FUNC_ISA
*
* TODO(Botan4) Move this to isa_extn.h
*/
#if BOTAN_COMPILER_HAS_ATTRIBUTE(target) && !defined(BOTAN_COMPILER_DOES_NOT_HAVE_TARGET_ATTRIBUTE)
   #define BOTAN_FUNC_ISA(isa) BOTAN_COMPILER_ATTRIBUTE(target(isa))
#else
   #define BOTAN_FUNC_ISA(isa)
#endif

/*
* Define BOTAN_FUNC_ISA_INLINE
*
* TODO(Botan4) Remove this
*/
#define BOTAN_FUNC_ISA_INLINE(isa) BOTAN_FUNC_ISA(isa) BOTAN_FORCE_INLINE

/*
* Define BOTAN_EARLY_INIT
*/
#if BOTAN_COMPILER_HAS_ATTRIBUTE(init_priority)
   #define BOTAN_EARLY_INIT(prio) BOTAN_COMPILER_ATTRIBUTE(init_priority(prio))
#else
   #define BOTAN_EARLY_INIT(prio) /**/
#endif

/*
* Define BOTAN_FORCE_INLINE
*/
#if !defined(BOTAN_FORCE_INLINE)

   #if BOTAN_COMPILER_HAS_ATTRIBUTE(always_inline)
      #define BOTAN_FORCE_INLINE inline BOTAN_COMPILER_ATTRIBUTE(always_inline)

   #elif defined(_MSC_VER)
      #define BOTAN_FORCE_INLINE __forceinline

   #else
      #define BOTAN_FORCE_INLINE inline
   #endif

#endif

#endif

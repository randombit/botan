/*
* Define useful compiler-specific macros
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/* This header is included in both C++ and C (via ffi.h) and should only
   contain macro definitions. Avoid C++ style // comments in this file.
*/

#ifndef BOTAN_UTIL_COMPILER_FLAGS_H_
#define BOTAN_UTIL_COMPILER_FLAGS_H_

/* Should we use GCC-style inline assembler? */
#if defined(BOTAN_BUILD_COMPILER_IS_GCC) || \
   defined(BOTAN_BUILD_COMPILER_IS_CLANG) || \
   defined(BOTAN_BUILD_COMPILER_IS_XLC) || \
   defined(BOTAN_BUILD_COMPILER_IS_SUN_STUDIO)

  #define BOTAN_USE_GCC_INLINE_ASM
#endif

/**
* Used to annotate API exports which are public and supported.
* These APIs will not be broken/removed unless strictly required for
* functionality or security, and only in new major versions.
* @param maj The major version this public API was released in
* @param min The minor version this public API was released in
*/
#define BOTAN_PUBLIC_API(maj,min) BOTAN_DLL

/**
* Used to annotate API exports which are public, but are now deprecated
* and which will be removed in a future major release.
*/
#define BOTAN_DEPRECATED_API(msg) BOTAN_DLL BOTAN_DEPRECATED(msg)

/**
* Used to annotate API exports which are public and can be used by
* applications if needed, but which are intentionally not documented,
* and which may change incompatibly in a future major version.
*/
#define BOTAN_UNSTABLE_API BOTAN_DLL

/**
* Used to annotate API exports which are exported but only for the
* purposes of testing. They should not be used by applications and
* may be removed or changed without notice.
*/
#define BOTAN_TEST_API BOTAN_DLL

/**
* Used to annotate API exports which are exported but only for the
* purposes of fuzzing. They should not be used by applications and
* may be removed or changed without notice.
*
* They are only exported if the fuzzers are being built
*/
#if defined(BOTAN_FUZZERS_ARE_BEING_BUILT)
  #define BOTAN_FUZZER_API BOTAN_DLL
#else
  #define BOTAN_FUZZER_API
#endif

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
* Define BOTAN_FUNC_ISA
*/
#if BOTAN_COMPILER_HAS_ATTRIBUTE(target)
  #define BOTAN_FUNC_ISA(isa) BOTAN_COMPILER_ATTRIBUTE(target(isa))
#else
  #define BOTAN_FUNC_ISA(isa)
#endif

/*
* Define BOTAN_MALLOC_FN
*/
#if BOTAN_COMPILER_HAS_ATTRIBUTE(malloc)
  #define BOTAN_MALLOC_FN BOTAN_COMPILER_ATTRIBUTE(malloc)
#elif defined(_MSC_VER)
  #define BOTAN_MALLOC_FN __declspec(restrict)
#else
  #define BOTAN_MALLOC_FN
#endif

/*
* Define BOTAN_EARLY_INIT
*/
#if BOTAN_COMPILER_HAS_ATTRIBUTE(init_priority)
  #define BOTAN_EARLY_INIT(prio) BOTAN_COMPILER_ATTRIBUTE(init_priority(prio))
#else
  #define BOTAN_EARLY_INIT(prio) /**/
#endif

/*
* Define BOTAN_DEPRECATED
*/
#if !defined(BOTAN_NO_DEPRECATED_WARNINGS) && !defined(BOTAN_AMALGAMATION_H_)

  #if defined(__cplusplus)
    #define BOTAN_DEPRECATED(msg) [[deprecated(msg)]]
  #elif BOTAN_COMPILER_HAS_ATTRIBUTE(deprecated)
    #define BOTAN_DEPRECATED(msg) BOTAN_COMPILER_ATTRIBUTE(deprecated(msg))
  #elif defined(_MSC_VER)
    #define BOTAN_DEPRECATED(msg) __declspec(deprecated(msg))
  #endif

  #if !defined(BOTAN_IS_BEING_BUILT)
    #if defined(__clang__)
      #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("message \"this header is deprecated\"")
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) _Pragma("message \"this header will be made internal in the future\"")
    #elif defined(_MSC_VER)
      #define BOTAN_DEPRECATED_HEADER(hdr) __pragma(message("this header is deprecated"))
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) __pragma(message("this header will be made internal in the future"))
    #elif defined(__GNUC__)
      #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("GCC warning \"this header is deprecated\"")
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) _Pragma("GCC warning \"this header will be made internal in the future\"")
    #endif
  #endif

#endif

#if !defined(BOTAN_DEPRECATED)
  #define BOTAN_DEPRECATED(msg)
#endif

#if !defined(BOTAN_DEPRECATED_HEADER)
  #define BOTAN_DEPRECATED_HEADER(hdr)
#endif

#if !defined(BOTAN_FUTURE_INTERNAL_HEADER)
  #define BOTAN_FUTURE_INTERNAL_HEADER(hdr)
#endif

/*
* Define BOTAN_FORCE_INLINE
*/
#if !defined(BOTAN_FORCE_INLINE)

  #if BOTAN_COMPILER_HAS_ATTRIBUTE(always_inline)
    #define BOTAN_FORCE_INLINE inline BOTAN_COMPILER_ATTRIBUTE(always_inline)

  #elif defined (_MSC_VER)
    #define BOTAN_FORCE_INLINE __forceinline

  #else
    #define BOTAN_FORCE_INLINE inline
  #endif

#endif

/*
* Define BOTAN_PARALLEL_SIMD_FOR
*/
#if !defined(BOTAN_PARALLEL_SIMD_FOR)

#if defined(BOTAN_BUILD_COMPILER_IS_GCC)
  #define BOTAN_PARALLEL_SIMD_FOR _Pragma("GCC ivdep") for
#else
  #define BOTAN_PARALLEL_SIMD_FOR for
#endif

#endif

#if defined(BOTAN_BUILD_COMPILER_IS_GCC)
  #define BOTAN_DIAGNOSTIC_PUSH              _Pragma("GCC diagnostic push")
  #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
  #define BOTAN_DIAGNOSTIC_POP               _Pragma("GCC diagnostic pop")
#elif defined(BOTAN_BUILD_COMPILER_IS_CLANG)
  #define BOTAN_DIAGNOSTIC_PUSH              _Pragma("clang diagnostic push")
  #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
  #define BOTAN_DIAGNOSTIC_POP               _Pragma("clang diagnostic pop")
#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC)
  #define BOTAN_DIAGNOSTIC_PUSH              __pragma(warning(push))
  #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED __pragma(warning(disable : 4996))
  #define BOTAN_DIAGNOSTIC_POP               __pragma(warning(pop))
#else
  #define BOTAN_DIAGNOSTIC_PUSH
  #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED
  #define BOTAN_DIAGNOSTIC_POP
#endif

#endif

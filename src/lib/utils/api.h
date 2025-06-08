/*
* (C) 2016,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_API_ANNOTATIONS_H_
#define BOTAN_API_ANNOTATIONS_H_

#include <botan/build.h>

/**
* Used to annotate API exports which are public and supported.
* These APIs will not be broken/removed unless strictly required for
* functionality or security, and only in new major versions.
* @param maj The major version this public API was released in
* @param min The minor version this public API was released in
*/
#define BOTAN_PUBLIC_API(maj, min) BOTAN_DLL

/**
* Used to annotate API exports which are public, but are now deprecated
* and which will be removed in a future major release.
*/
#define BOTAN_DEPRECATED_API(msg) BOTAN_DEPRECATED(msg) BOTAN_DLL

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
* Define BOTAN_DEPRECATED
*/
#if !defined(BOTAN_NO_DEPRECATED_WARNINGS) && !defined(BOTAN_AMALGAMATION_H_) && !defined(BOTAN_IS_BEING_BUILT)

   #define BOTAN_DEPRECATED(msg) [[deprecated(msg)]]

   #if defined(__clang__)
      #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("message \"this header is deprecated\"")
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) _Pragma("message \"this header will be made internal in the future\"")
   #elif defined(_MSC_VER)
      #define BOTAN_DEPRECATED_HEADER(hdr) __pragma(message("this header is deprecated"))
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) __pragma(message("this header will be made internal in the future"))
   #elif defined(__GNUC__)
      #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("GCC warning \"this header is deprecated\"")
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) \
         _Pragma("GCC warning \"this header will be made internal in the future\"")
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

#if defined(__clang__)
   #define BOTAN_DIAGNOSTIC_PUSH _Pragma("clang diagnostic push")
   #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS \
      _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
   #define BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE
   #define BOTAN_DIAGNOSTIC_POP _Pragma("clang diagnostic pop")
#elif defined(__GNUG__)
   #define BOTAN_DIAGNOSTIC_PUSH _Pragma("GCC diagnostic push")
   #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS \
      _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
   #define BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE
   #define BOTAN_DIAGNOSTIC_POP _Pragma("GCC diagnostic pop")
#elif defined(_MSC_VER)
   #define BOTAN_DIAGNOSTIC_PUSH __pragma(warning(push))
   #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS __pragma(warning(disable : 4996))
   #define BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE __pragma(warning(disable : 4250))
   #define BOTAN_DIAGNOSTIC_POP __pragma(warning(pop))
#else
   #define BOTAN_DIAGNOSTIC_PUSH
   #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS
   #define BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE
   #define BOTAN_DIAGNOSTIC_POP
#endif

#endif

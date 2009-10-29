/**
* Lightweight wrappers for SIMD operations
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SIMD_32_H__
#define BOTAN_SIMD_32_H__

#include <botan/types.h>

//#define BOTAN_TARGET_CPU_HAS_SSE2

#if defined(BOTAN_TARGET_CPU_HAS_SSE2)

  #include <botan/simd_sse.h>
  namespace Botan { typedef SIMD_SSE2 SIMD_32; }

#elif defined(BOTAN_TARGET_CPU_HAS_ALTIVEC)

  #include <botan/simd_altivec.h>
  namespace Botan { typedef SIMD_Altivec SIMD_32; }

#else

  #include <botan/simd_scalar.h>
  namespace Botan { typedef SIMD_Scalar SIMD_32; }

#endif

#endif

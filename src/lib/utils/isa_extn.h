/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTIL_ISA_EXTN_H_
#define BOTAN_UTIL_ISA_EXTN_H_

#include <botan/compiler.h>
#include <botan/internal/target_info.h>

/*
* GCC and Clang use string identifiers to tag ISA extensions (eg using the
* `target` function attribute).
*
* This file consolidates the actual definition of such target attributes
*/

#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)

   #define BOTAN_FN_ISA_SIMD_4X32 BOTAN_FUNC_ISA("ssse3")
   #define BOTAN_FN_ISA_SIMD_2X64 BOTAN_FUNC_ISA("ssse3")
   #define BOTAN_FN_ISA_SIMD_4X64 BOTAN_FUNC_ISA("avx2")
   #define BOTAN_FN_ISA_SIMD_8X64 BOTAN_FN_ISA_AVX512
   #define BOTAN_FN_ISA_CLMUL BOTAN_FUNC_ISA("pclmul,ssse3")
   #define BOTAN_FN_ISA_AESNI BOTAN_FUNC_ISA("aes,ssse3")
   #define BOTAN_FN_ISA_SHANI BOTAN_FUNC_ISA("sha,ssse3,sse4.1")
   #define BOTAN_FN_ISA_SHA512 BOTAN_FUNC_ISA("sha512,avx2")
   #define BOTAN_FN_ISA_SSE2 BOTAN_FUNC_ISA("sse2")
   #define BOTAN_FN_ISA_AVX2 BOTAN_FUNC_ISA("avx2")
   #define BOTAN_FN_ISA_AVX2_BMI2 BOTAN_FUNC_ISA("avx2,bmi,bmi2")
   #define BOTAN_FN_ISA_AVX2_VAES BOTAN_FUNC_ISA("vaes,avx2")
   #define BOTAN_FN_ISA_AVX2_SM3 BOTAN_FUNC_ISA("sm3,avx2")
   #define BOTAN_FN_ISA_AVX2_SM4 BOTAN_FUNC_ISA("sm4,avx2")
   #define BOTAN_FN_ISA_AVX2_GFNI BOTAN_FUNC_ISA("gfni,avx2")
   #define BOTAN_FN_ISA_AVX512 BOTAN_FUNC_ISA("avx512f,avx512dq,avx512bw,avx512vl")
   #define BOTAN_FN_ISA_AVX512_BMI2 BOTAN_FUNC_ISA("avx512f,avx512dq,avx512bw,avx512vl,bmi,bmi2")
   #define BOTAN_FN_ISA_AVX512_GFNI BOTAN_FUNC_ISA("avx512f,avx512dq,avx512bw,avx512vl,gfni")

#endif

#if defined(BOTAN_TARGET_ARCH_IS_ARM64)

   #define BOTAN_FN_ISA_SIMD_4X32 BOTAN_FUNC_ISA("+simd")
   #define BOTAN_FN_ISA_CLMUL BOTAN_FUNC_ISA("+crypto+aes")
   #define BOTAN_FN_ISA_AES BOTAN_FUNC_ISA("+crypto+aes")
   #define BOTAN_FN_ISA_SHA2 BOTAN_FUNC_ISA("+crypto+sha2")
   #define BOTAN_FN_ISA_SM4 BOTAN_FUNC_ISA("arch=armv8.2-a+sm4")
   #define BOTAN_FN_ISA_SHA512 BOTAN_FUNC_ISA("arch=armv8.2-a+sha3")

#endif

#if defined(BOTAN_TARGET_ARCH_IS_ARM32)
   #define BOTAN_FN_ISA_SIMD_4X32 BOTAN_FUNC_ISA("fpu=neon")
#endif

#if defined(BOTAN_TARGET_ARCH_IS_PPC_FAMILY)

   #define BOTAN_FN_ISA_SIMD_4X32 BOTAN_FUNC_ISA("altivec")
   #define BOTAN_FN_ISA_CLMUL BOTAN_FUNC_ISA("vsx,crypto")
   #define BOTAN_FN_ISA_AES BOTAN_FUNC_ISA("vsx,crypto")

#endif

#if defined(BOTAN_TARGET_ARCH_IS_LOONGARCH64)

   #define BOTAN_FN_ISA_SIMD_4X32 BOTAN_FUNC_ISA("lsx")

#endif

#if defined(BOTAN_TARGET_ARCH_IS_WASM)

   #define BOTAN_FN_ISA_SIMD_4X32 BOTAN_FUNC_ISA("simd128")

#endif

#endif

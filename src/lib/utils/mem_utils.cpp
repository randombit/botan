/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mem_ops.h>

#include <botan/internal/target_info.h>
#include <cstring>

#if defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
   #include <string.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
#endif

namespace Botan {

void secure_scrub_memory(void* ptr, size_t n) {
#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
   ::RtlSecureZeroMemory(ptr, n);

#elif defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
   ::explicit_bzero(ptr, n);

#elif defined(BOTAN_TARGET_OS_HAS_EXPLICIT_MEMSET)
   (void)::explicit_memset(ptr, 0, n);

#else
   /*
   * Call memset through a static volatile pointer, which the compiler should
   * not elide. This construct should be safe in conforming compilers, but who
   * knows. This has been checked to generate the expected code, which saves the
   * memset address in the data segment and unconditionally loads and jumps to
   * that address, with the following targets:
   *
   * x86-64: Clang 19, GCC 6, 11, 13, 14
   * riscv64: GCC 14
   * aarch64: GCC 14
   * armv7: GCC 14
   *
   * Actually all of them generated the expected jump even without marking the
   * function pointer as volatile. However this seems worth including as an
   * additional precaution.
   */
   static void* (*const volatile memset_ptr)(void*, int, size_t) = std::memset;
   (memset_ptr)(ptr, 0, n);
#endif
}

}  // namespace Botan

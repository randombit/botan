/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/version.h>
#include <botan/mem_ops.h>
#include <botan/hex.h>
#include <cstdio>

namespace Botan_FFI {

int ffi_error_exception_thrown(const char* func_name, const char* exn)
   {
   fprintf(stderr, "in %s exception %s\n", func_name, exn);
   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

}

extern "C" {

using namespace Botan_FFI;

/*
* Versioning
*/
uint32_t botan_ffi_api_version()
   {
   return BOTAN_HAS_FFI;
   }

int botan_ffi_supports_api(uint32_t api_version)
   {
   /*
   * In the future if multiple versions are supported, this
   * function would accept any of them.
   */
   if(api_version == BOTAN_HAS_FFI)
      return BOTAN_FFI_SUCCESS;
   return -1;
   }

const char* botan_version_string()
   {
   return Botan::version_cstr();
   }

uint32_t botan_version_major() { return Botan::version_major(); }
uint32_t botan_version_minor() { return Botan::version_minor(); }
uint32_t botan_version_patch() { return Botan::version_patch(); }
uint32_t botan_version_datestamp()  { return Botan::version_datestamp(); }

int botan_same_mem(const uint8_t* x, const uint8_t* y, size_t len)
   {
   return Botan::same_mem(x, y, len) ? 0 : -1;
   }

int botan_scrub_mem(uint8_t* mem, size_t bytes)
   {
   Botan::secure_scrub_memory(mem, bytes);
   return BOTAN_FFI_SUCCESS;
   }

int botan_hex_encode(const uint8_t* in, size_t len, char* out, uint32_t flags)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      const bool uppercase = (flags & BOTAN_FFI_HEX_LOWER_CASE) == 0;
      Botan::hex_encode(out, in, len, uppercase);
      return BOTAN_FFI_SUCCESS;
      });
   }

}


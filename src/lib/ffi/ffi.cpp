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
#include <botan/base64.h>
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
   // Current API version
   if(api_version == BOTAN_HAS_FFI)
      return BOTAN_FFI_SUCCESS;

   // Older versions that are still supported

   // This is the 2.1/2.2 API
   if(api_version == 20170327)
      return BOTAN_FFI_SUCCESS;

   // This is the 2.0 API
   if(api_version == 20150515)
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

int botan_constant_time_compare(const uint8_t* x, const uint8_t* y, size_t len)
   {
   return Botan::constant_time_compare(x, y, len) ? 0 : -1;
   }

int botan_same_mem(const uint8_t* x, const uint8_t* y, size_t len)
   {
   return botan_constant_time_compare(x, y, len);
   }

int botan_scrub_mem(void* mem, size_t bytes)
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

int botan_hex_decode(const char* hex_str, size_t in_len, uint8_t* out, size_t* out_len)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      const std::vector<uint8_t> bin = Botan::hex_decode(hex_str, in_len);
      return Botan_FFI::write_vec_output(out, out_len, bin);
      });
   }

int botan_base64_encode(const uint8_t* in, size_t len, char* out, size_t* out_len)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      const std::string base64 = Botan::base64_encode(in, len);
      return Botan_FFI::write_str_output(out, out_len, base64);
      });
   }

int botan_base64_decode(const char* base64_str, size_t in_len,
                        uint8_t* out, size_t* out_len)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      if(*out_len < Botan::base64_decode_max_output(in_len))
         {
         *out_len = Botan::base64_decode_max_output(in_len);
         return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         }

      *out_len = Botan::base64_decode(out, std::string(base64_str, in_len));
      return BOTAN_FFI_SUCCESS;
      });
   }

}


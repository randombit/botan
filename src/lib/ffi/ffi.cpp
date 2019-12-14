/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/os_utils.h>
#include <botan/version.h>
#include <botan/mem_ops.h>
#include <botan/hex.h>
#include <botan/base64.h>
#include <cstdio>
#include <cstdlib>

namespace Botan_FFI {

int ffi_error_exception_thrown(const char* func_name, const char* exn, int rc)
   {
   std::string val;
   if(Botan::OS::read_env_variable(val, "BOTAN_FFI_PRINT_EXCEPTIONS") == true && val != "")
      {
      std::fprintf(stderr, "in %s exception '%s' returning %d\n", func_name, exn, rc);
      }
   return rc;
   }

namespace {

int ffi_map_error_type(Botan::ErrorType err)
   {
   switch(err)
      {
      case Botan::ErrorType::Unknown:
         return BOTAN_FFI_ERROR_UNKNOWN_ERROR;

      case Botan::ErrorType::SystemError:
      case Botan::ErrorType::IoError:
      case Botan::ErrorType::OpenSSLError:
      case Botan::ErrorType::Pkcs11Error:
      case Botan::ErrorType::CommonCryptoError:
      case Botan::ErrorType::TPMError:
      case Botan::ErrorType::ZlibError:
      case Botan::ErrorType::Bzip2Error:
      case Botan::ErrorType::LzmaError:
      case Botan::ErrorType::DatabaseError:
         return BOTAN_FFI_ERROR_SYSTEM_ERROR;

      case Botan::ErrorType::NotImplemented:
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
      case Botan::ErrorType::OutOfMemory:
         return BOTAN_FFI_ERROR_OUT_OF_MEMORY;
      case Botan::ErrorType::InternalError:
         return BOTAN_FFI_ERROR_INTERNAL_ERROR;
      case Botan::ErrorType::InvalidObjectState:
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      case Botan::ErrorType::KeyNotSet:
         return BOTAN_FFI_ERROR_KEY_NOT_SET;
      case Botan::ErrorType::InvalidArgument:
      case Botan::ErrorType::InvalidNonceLength:
         return BOTAN_FFI_ERROR_BAD_PARAMETER;

      case Botan::ErrorType::EncodingFailure:
      case Botan::ErrorType::DecodingFailure:
         return BOTAN_FFI_ERROR_INVALID_INPUT;

      case Botan::ErrorType::InvalidTag:
         return BOTAN_FFI_ERROR_BAD_MAC;

      case Botan::ErrorType::InvalidKeyLength:
         return BOTAN_FFI_ERROR_INVALID_KEY_LENGTH;
      case Botan::ErrorType::LookupError:
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;

      case Botan::ErrorType::HttpError:
         return BOTAN_FFI_ERROR_HTTP_ERROR;
      case Botan::ErrorType::TLSError:
         return BOTAN_FFI_ERROR_TLS_ERROR;
      case Botan::ErrorType::RoughtimeError:
         return BOTAN_FFI_ERROR_ROUGHTIME_ERROR;
      }

   return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
   }

}

int ffi_guard_thunk(const char* func_name, std::function<int ()> thunk)
   {
   try
      {
      return thunk();
      }
   catch(std::bad_alloc&)
      {
      return ffi_error_exception_thrown(func_name, "bad_alloc", BOTAN_FFI_ERROR_OUT_OF_MEMORY);
      }
   catch(Botan_FFI::FFI_Error& e)
      {
      return ffi_error_exception_thrown(func_name, e.what(), e.error_code());
      }
   catch(Botan::Exception& e)
      {
      return ffi_error_exception_thrown(func_name, e.what(), ffi_map_error_type(e.error_type()));
      }
   catch(std::exception& e)
      {
      return ffi_error_exception_thrown(func_name, e.what());
      }
   catch(...)
      {
      return ffi_error_exception_thrown(func_name, "unknown exception");
      }

   return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
   }

}

extern "C" {

using namespace Botan_FFI;

const char* botan_error_description(int err)
   {
   switch(err)
      {
      case BOTAN_FFI_SUCCESS:
         return "OK";

      case BOTAN_FFI_INVALID_VERIFIER:
         return "Invalid verifier";

      case BOTAN_FFI_ERROR_INVALID_INPUT:
         return "Invalid input";

      case BOTAN_FFI_ERROR_BAD_MAC:
         return "Invalid authentication code";

      case BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE:
         return "Insufficient buffer space";

      case BOTAN_FFI_ERROR_EXCEPTION_THROWN:
         return "Exception thrown";

      case BOTAN_FFI_ERROR_OUT_OF_MEMORY:
         return "Out of memory";

      case BOTAN_FFI_ERROR_SYSTEM_ERROR:
         return "Error while calling system API";

      case BOTAN_FFI_ERROR_INTERNAL_ERROR:
         return "Internal error";

      case BOTAN_FFI_ERROR_BAD_FLAG:
         return "Bad flag";

      case BOTAN_FFI_ERROR_NULL_POINTER:
         return "Null pointer argument";

      case BOTAN_FFI_ERROR_BAD_PARAMETER:
         return "Bad parameter";

      case BOTAN_FFI_ERROR_KEY_NOT_SET:
         return "Key not set on object";

      case BOTAN_FFI_ERROR_INVALID_KEY_LENGTH:
         return "Invalid key length";

      case BOTAN_FFI_ERROR_INVALID_OBJECT_STATE:
         return "Invalid object state";

      case BOTAN_FFI_ERROR_NOT_IMPLEMENTED:
         return "Not implemented";

      case BOTAN_FFI_ERROR_INVALID_OBJECT:
         return "Invalid object handle";

      case BOTAN_FFI_ERROR_TLS_ERROR:
         return "TLS error";

      case BOTAN_FFI_ERROR_HTTP_ERROR:
         return "HTTP error";

      case BOTAN_FFI_ERROR_UNKNOWN_ERROR:
         return "Unknown error";
      }

   return "Unknown error";
   }

/*
* Versioning
*/
uint32_t botan_ffi_api_version()
   {
   return BOTAN_HAS_FFI;
   }

int botan_ffi_supports_api(uint32_t api_version)
   {
   // This is the API introduced in 2.13
   if(api_version == 20191214)
      return BOTAN_FFI_SUCCESS;

   // This is the API introduced in 2.8
   if(api_version == 20180713)
      return BOTAN_FFI_SUCCESS;

   // This is the API introduced in 2.3
   if(api_version == 20170815)
      return BOTAN_FFI_SUCCESS;

   // This is the API introduced in 2.1
   if(api_version == 20170327)
      return BOTAN_FFI_SUCCESS;

   // This is the API introduced in 2.0
   if(api_version == 20150515)
      return BOTAN_FFI_SUCCESS;

   // Something else:
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
   return ffi_guard_thunk(__func__, [=]() -> int {
      const bool uppercase = (flags & BOTAN_FFI_HEX_LOWER_CASE) == 0;
      Botan::hex_encode(out, in, len, uppercase);
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_hex_decode(const char* hex_str, size_t in_len, uint8_t* out, size_t* out_len)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::vector<uint8_t> bin = Botan::hex_decode(hex_str, in_len);
      return Botan_FFI::write_vec_output(out, out_len, bin);
      });
   }

int botan_base64_encode(const uint8_t* in, size_t len, char* out, size_t* out_len)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string base64 = Botan::base64_encode(in, len);
      return Botan_FFI::write_str_output(out, out_len, base64);
      });
   }

int botan_base64_decode(const char* base64_str, size_t in_len,
                        uint8_t* out, size_t* out_len)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
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

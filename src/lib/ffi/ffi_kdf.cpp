/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_rng.h>
#include <botan/pbkdf.h>
#include <botan/kdf.h>

#if defined(BOTAN_HAS_BCRYPT)
  #include <botan/bcrypt.h>
#endif

extern "C" {

using namespace Botan_FFI;

int botan_pbkdf(const char* pbkdf_algo, uint8_t out[], size_t out_len,
                const char* pass, const uint8_t salt[], size_t salt_len,
                size_t iterations)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      std::unique_ptr<Botan::PBKDF> pbkdf(Botan::get_pbkdf(pbkdf_algo));
      pbkdf->pbkdf_iterations(out, out_len, pass, salt, salt_len, iterations);
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_pbkdf_timed(const char* pbkdf_algo,
                      uint8_t out[], size_t out_len,
                      const char* password,
                      const uint8_t salt[], size_t salt_len,
                      size_t ms_to_run,
                      size_t* iterations_used)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      std::unique_ptr<Botan::PBKDF> pbkdf(Botan::get_pbkdf(pbkdf_algo));
      pbkdf->pbkdf_timed(out, out_len, password, salt, salt_len,
                         std::chrono::milliseconds(ms_to_run),
                         *iterations_used);
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_kdf(const char* kdf_algo,
              uint8_t out[], size_t out_len,
              const uint8_t secret[], size_t secret_len,
              const uint8_t salt[], size_t salt_len,
              const uint8_t label[], size_t label_len)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      std::unique_ptr<Botan::KDF> kdf(Botan::get_kdf(kdf_algo));
      kdf->kdf(out, out_len, secret, secret_len, salt, salt_len, label, label_len);
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_bcrypt_generate(uint8_t* out, size_t* out_len,
                          const char* pass,
                          botan_rng_t rng_obj, size_t wf,
                          uint32_t flags)
   {
#if defined(BOTAN_HAS_BCRYPT)
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      BOTAN_ASSERT_ARG_NON_NULL(out);
      BOTAN_ASSERT_ARG_NON_NULL(out_len);
      BOTAN_ASSERT_ARG_NON_NULL(pass);

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      if(wf < 4 || wf > 18)
         throw FFI_Error("Bad bcrypt work factor " + std::to_string(wf));

      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      const std::string bcrypt = Botan::generate_bcrypt(pass, rng, static_cast<uint16_t>(wf));
      return write_str_output(out, out_len, bcrypt);
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_bcrypt_is_valid(const char* pass, const char* hash)
   {
#if defined(BOTAN_HAS_BCRYPT)
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      return Botan::check_bcrypt(pass, hash) ? BOTAN_FFI_SUCCESS : BOTAN_FFI_INVALID_VERIFIER;
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

}

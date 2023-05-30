/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_TOTP)
   #include <botan/otp.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_TOTP)

BOTAN_FFI_DECLARE_STRUCT(botan_totp_struct, Botan::TOTP, 0x3D9D2CD1);

#endif

int botan_totp_init(
   botan_totp_t* totp, const uint8_t key[], size_t key_len, const char* hash_algo, size_t digits, size_t time_step) {
   if(totp == nullptr || key == nullptr || hash_algo == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *totp = nullptr;

#if defined(BOTAN_HAS_TOTP)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto otp = std::make_unique<Botan::TOTP>(key, key_len, hash_algo, digits, time_step);
      *totp = new botan_totp_struct(std::move(otp));

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(totp, key, key_len, hash_algo, digits, time_step);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_totp_destroy(botan_totp_t totp) {
#if defined(BOTAN_HAS_TOTP)
   return BOTAN_FFI_CHECKED_DELETE(totp);
#else
   BOTAN_UNUSED(totp);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_totp_generate(botan_totp_t totp, uint32_t* totp_code, uint64_t timestamp) {
#if defined(BOTAN_HAS_TOTP)
   if(totp == nullptr || totp_code == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(totp, [=](auto& t) { *totp_code = t.generate_totp(timestamp); });

#else
   BOTAN_UNUSED(totp, totp_code, timestamp);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_totp_check(botan_totp_t totp, uint32_t totp_code, uint64_t timestamp, size_t acceptable_clock_drift) {
#if defined(BOTAN_HAS_TOTP)
   return BOTAN_FFI_VISIT(totp, [=](auto& t) {
      const bool ok = t.verify_totp(totp_code, timestamp, acceptable_clock_drift);
      return (ok ? BOTAN_FFI_SUCCESS : BOTAN_FFI_INVALID_VERIFIER);
   });

#else
   BOTAN_UNUSED(totp, totp_code, timestamp, acceptable_clock_drift);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_HOTP)
   #include <botan/otp.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_HOTP)

BOTAN_FFI_DECLARE_STRUCT(botan_hotp_struct, Botan::HOTP, 0x89CBF191);

#endif

int botan_hotp_init(botan_hotp_t* hotp, const uint8_t key[], size_t key_len, const char* hash_algo, size_t digits) {
   if(hotp == nullptr || key == nullptr || hash_algo == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *hotp = nullptr;

#if defined(BOTAN_HAS_HOTP)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto otp = std::make_unique<Botan::HOTP>(key, key_len, hash_algo, digits);
      *hotp = new botan_hotp_struct(std::move(otp));

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(hotp, key, key_len, hash_algo, digits);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_hotp_destroy(botan_hotp_t hotp) {
#if defined(BOTAN_HAS_HOTP)
   return BOTAN_FFI_CHECKED_DELETE(hotp);
#else
   BOTAN_UNUSED(hotp);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_hotp_generate(botan_hotp_t hotp, uint32_t* hotp_code, uint64_t hotp_counter) {
#if defined(BOTAN_HAS_HOTP)
   if(hotp == nullptr || hotp_code == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(hotp, [=](auto& h) { *hotp_code = h.generate_hotp(hotp_counter); });

#else
   BOTAN_UNUSED(hotp, hotp_code, hotp_counter);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_hotp_check(
   botan_hotp_t hotp, uint64_t* next_hotp_counter, uint32_t hotp_code, uint64_t hotp_counter, size_t resync_range) {
#if defined(BOTAN_HAS_HOTP)
   return BOTAN_FFI_VISIT(hotp, [=](auto& h) {
      auto resp = h.verify_hotp(hotp_code, hotp_counter, resync_range);

      if(next_hotp_counter) {
         *next_hotp_counter = resp.second;
      }

      return (resp.first == true) ? BOTAN_FFI_SUCCESS : BOTAN_FFI_INVALID_VERIFIER;
   });

#else
   BOTAN_UNUSED(hotp, next_hotp_counter, hotp_code, hotp_counter, resync_range);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

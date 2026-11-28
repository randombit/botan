/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/assert.h>
#include <botan/internal/ffi_mp.h>
#include <botan/internal/ffi_util.h>
#include <memory>

#if defined(BOTAN_HAS_FPE_FE1)
   #include <botan/fpe_fe1.h>
#endif

#if defined(BOTAN_HAS_FPE_FF1)
   #include <botan/fpe_ff1.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_FPE_FE1)

BOTAN_FFI_DECLARE_UNIQUE_STRUCT(botan_fpe_struct, Botan::FPE_FE1, 0xD49FB820);

#endif

#if defined(BOTAN_HAS_FPE_FF1)

BOTAN_FFI_DECLARE_UNIQUE_STRUCT(botan_fpe_ff1_struct, Botan::FPE_FF1, 0x3A6F1FF1);

#endif

int botan_fpe_fe1_init(
   botan_fpe_t* fpe, botan_mp_t n, const uint8_t key[], size_t key_len, size_t rounds, uint32_t flags) {
#if defined(BOTAN_HAS_FPE_FE1)
   return ffi_guard_thunk(__func__, [=]() {
      if(any_null_pointers(fpe, key)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *fpe = nullptr;

      if(flags != 0 && flags != BOTAN_FPE_FLAG_FE1_COMPAT_MODE) {
         return BOTAN_FFI_ERROR_BAD_FLAG;
      }

      const bool compat_mode = (flags & BOTAN_FPE_FLAG_FE1_COMPAT_MODE) != 0;

      auto fpe_obj = std::make_unique<Botan::FPE_FE1>(safe_get(n), rounds, compat_mode);

      fpe_obj->set_key(key, key_len);

      return ffi_new_object(fpe, std::move(fpe_obj));
   });
#else
   BOTAN_UNUSED(fpe, n, key, key_len, rounds, flags);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_destroy(botan_fpe_t fpe) {
#if defined(BOTAN_HAS_FPE_FE1)
   return BOTAN_FFI_CHECKED_DELETE(fpe);
#else
   BOTAN_UNUSED(fpe);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_encrypt(botan_fpe_t fpe, botan_mp_t x, const uint8_t tweak[], size_t tweak_len) {
   if(tweak_len > 0 && tweak == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_FPE_FE1)
   return ffi_guard_thunk(__func__, [=]() {
      const Botan::BigInt r = safe_get(fpe).encrypt(safe_get(x), tweak, tweak_len);
      safe_get(x) = r;
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(fpe, x, tweak, tweak_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_decrypt(botan_fpe_t fpe, botan_mp_t x, const uint8_t tweak[], size_t tweak_len) {
   if(tweak_len > 0 && tweak == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_FPE_FE1)
   return ffi_guard_thunk(__func__, [=]() {
      const Botan::BigInt r = safe_get(fpe).decrypt(safe_get(x), tweak, tweak_len);
      safe_get(x) = r;
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(fpe, x, tweak, tweak_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_ff1_init(botan_fpe_ff1_t* fpe, size_t radix, const uint8_t key[], size_t key_len) {
#if defined(BOTAN_HAS_FPE_FF1)
   return ffi_guard_thunk(__func__, [=]() {
      if(any_null_pointers(fpe, key)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *fpe = nullptr;

      auto fpe_obj = std::make_unique<Botan::FPE_FF1>(radix);
      fpe_obj->set_key(key, key_len);

      return ffi_new_object(fpe, std::move(fpe_obj));
   });
#else
   BOTAN_UNUSED(fpe, radix, key, key_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_ff1_destroy(botan_fpe_ff1_t fpe) {
#if defined(BOTAN_HAS_FPE_FF1)
   return BOTAN_FFI_CHECKED_DELETE(fpe);
#else
   BOTAN_UNUSED(fpe);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_ff1_minimum_length(botan_fpe_ff1_t fpe, size_t* min_len) {
#if defined(BOTAN_HAS_FPE_FF1)
   if(min_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(fpe, [=](const auto& ff1) { *min_len = ff1.minimum_length(); });
#else
   BOTAN_UNUSED(fpe, min_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_ff1_encrypt(botan_fpe_ff1_t fpe, uint16_t x[], size_t x_len, const uint8_t tweak[], size_t tweak_len) {
   if((x_len > 0 && x == nullptr) || (tweak_len > 0 && tweak == nullptr)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_FPE_FF1)
   return BOTAN_FFI_VISIT(fpe, [=](const auto& ff1) { ff1.encrypt(std::span{x, x_len}, std::span{tweak, tweak_len}); });
#else
   BOTAN_UNUSED(fpe, x, x_len, tweak, tweak_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_ff1_decrypt(botan_fpe_ff1_t fpe, uint16_t x[], size_t x_len, const uint8_t tweak[], size_t tweak_len) {
   if((x_len > 0 && x == nullptr) || (tweak_len > 0 && tweak == nullptr)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_FPE_FF1)
   return BOTAN_FFI_VISIT(fpe, [=](const auto& ff1) { ff1.decrypt(std::span{x, x_len}, std::span{tweak, tweak_len}); });
#else
   BOTAN_UNUSED(fpe, x, x_len, tweak, tweak_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

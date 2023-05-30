/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_mp.h>
#include <botan/internal/ffi_util.h>
#include <memory>

#if defined(BOTAN_HAS_FPE_FE1)
   #include <botan/fpe_fe1.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_FPE_FE1)

BOTAN_FFI_DECLARE_STRUCT(botan_fpe_struct, Botan::FPE_FE1, 0xD49FB820);

#endif

int botan_fpe_fe1_init(
   botan_fpe_t* fpe, botan_mp_t n, const uint8_t key[], size_t key_len, size_t rounds, uint32_t flags) {
#if defined(BOTAN_HAS_FPE_FE1)
   return ffi_guard_thunk(__func__, [=]() {
      if(fpe == nullptr || key == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *fpe = nullptr;

      if(flags != 0 && flags != BOTAN_FPE_FLAG_FE1_COMPAT_MODE) {
         return BOTAN_FFI_ERROR_BAD_FLAG;
      }

      const bool compat_mode = (flags & BOTAN_FPE_FLAG_FE1_COMPAT_MODE);

      std::unique_ptr<Botan::FPE_FE1> fpe_obj(new Botan::FPE_FE1(safe_get(n), rounds, compat_mode));

      fpe_obj->set_key(key, key_len);

      *fpe = new botan_fpe_struct(std::move(fpe_obj));
      return BOTAN_FFI_SUCCESS;
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
#if defined(BOTAN_HAS_FPE_FE1)
   return ffi_guard_thunk(__func__, [=]() {
      Botan::BigInt r = safe_get(fpe).encrypt(safe_get(x), tweak, tweak_len);
      safe_get(x) = r;
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(fpe, x, tweak, tweak_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_fpe_decrypt(botan_fpe_t fpe, botan_mp_t x, const uint8_t tweak[], size_t tweak_len) {
#if defined(BOTAN_HAS_FPE_FE1)
   return ffi_guard_thunk(__func__, [=]() {
      Botan::BigInt r = safe_get(fpe).decrypt(safe_get(x), tweak, tweak_len);
      safe_get(x) = r;
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(fpe, x, tweak, tweak_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/assert.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_TPM2)
   #include <botan/tpm2_context.h>
   #include <botan/tpm2_rng.h>
   #include <botan/tpm2_session.h>

   #if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
      #include <botan/tpm2_crypto_backend.h>
   #endif
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_TPM2)

BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tpm2_ctx_struct, Botan::TPM2::Context, 0xD2B95E15);
BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tpm2_session_struct, Botan::TPM2::Session, 0x9ACCAB52);

   #if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
BOTAN_FFI_DECLARE_UNIQUE_STRUCT(botan_tpm2_crypto_backend_state_struct, Botan::TPM2::CryptoCallbackState, 0x1AC84DE5);
   #endif

}  // extern "C"

namespace {

Botan::TPM2::SessionBundle sessions(botan_tpm2_session_t s1, botan_tpm2_session_t s2, botan_tpm2_session_t s3) {
   return Botan::TPM2::SessionBundle((s1 != nullptr) ? safe_get(s1) : nullptr,
                                     (s2 != nullptr) ? safe_get(s2) : nullptr,
                                     (s3 != nullptr) ? safe_get(s3) : nullptr);
}

}  // namespace

extern "C" {

#endif

int botan_tpm2_supports_crypto_backend() {
#if defined(BOTAN_HAS_TPM2)
   return Botan::TPM2::Context::supports_botan_crypto_backend() ? 1 : 0;
#else
   return 0;
#endif
}

int botan_tpm2_ctx_init(botan_tpm2_ctx_t* ctx_out, const char* tcti_nameconf) {
#if defined(BOTAN_HAS_TPM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ctx_out == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto tcti = [=]() -> std::optional<std::string> {
         if(tcti_nameconf == nullptr) {
            return {};
         } else {
            return std::string(tcti_nameconf);
         }
      }();

      auto ctx = Botan::TPM2::Context::create(std::move(tcti));
      return ffi_new_object(ctx_out, std::move(ctx));
   });
#else
   BOTAN_UNUSED(ctx_out, tcti_nameconf);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tpm2_ctx_init_ex(botan_tpm2_ctx_t* ctx_out, const char* tcti_name, const char* tcti_conf) {
#if defined(BOTAN_HAS_TPM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ctx_out == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto tcti_name_str = [=]() -> std::optional<std::string> {
         if(tcti_name == nullptr) {
            return {};
         } else {
            return std::string(tcti_name);
         }
      }();

      auto tcti_conf_str = [=]() -> std::optional<std::string> {
         if(tcti_conf == nullptr) {
            return {};
         } else {
            return std::string(tcti_conf);
         }
      }();

      auto ctx = Botan::TPM2::Context::create(std::move(tcti_name_str), std::move(tcti_conf_str));
      return ffi_new_object(ctx_out, std::move(ctx));
   });
#else
   BOTAN_UNUSED(ctx_out, tcti_name, tcti_conf);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tpm2_ctx_from_esys(botan_tpm2_ctx_t* ctx_out, ESYS_CONTEXT* esys_ctx) {
#if defined(BOTAN_HAS_TPM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(any_null_pointers(ctx_out, esys_ctx)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto ctx = Botan::TPM2::Context::create(esys_ctx);
      return ffi_new_object(ctx_out, std::move(ctx));
   });
#else
   BOTAN_UNUSED(ctx_out, esys_ctx);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tpm2_ctx_enable_crypto_backend(botan_tpm2_ctx_t ctx, botan_rng_t rng) {
#if defined(BOTAN_HAS_TPM2)
   return BOTAN_FFI_VISIT(ctx, [=](const std::shared_ptr<Botan::TPM2::Context>& tpm2_ctx) -> int {
      Botan::RandomNumberGenerator& rng_ref = safe_get(rng);

      // The lifetime of the RNG used for the crypto backend should be managed
      // by the TPM2::Context. Here, we just need to trust the user that they
      // keep the passed-in RNG instance intact for the lifetime of the context.
      tpm2_ctx->use_botan_crypto_backend(std::shared_ptr<Botan::RandomNumberGenerator>(&rng_ref, [](auto*) {}));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ctx, rng);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Frees all resources of a TPM2 context
 * @param ctx TPM2 context
 * @return 0 on success
 */
int botan_tpm2_ctx_destroy(botan_tpm2_ctx_t ctx) {
#if defined(BOTAN_HAS_TPM2)
   return BOTAN_FFI_CHECKED_DELETE(ctx);
#else
   BOTAN_UNUSED(ctx);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tpm2_enable_crypto_backend(botan_tpm2_crypto_backend_state_t* cbs_out,
                                     ESYS_CONTEXT* esys_ctx,
                                     botan_rng_t rng) {
#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(any_null_pointers(cbs_out, esys_ctx)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::RandomNumberGenerator& rng_ref = safe_get(rng);

      // Here, we just need to trust the user that they keep the passed-in RNG
      // instance intact for the lifetime of the context.
      const std::shared_ptr<Botan::RandomNumberGenerator> rng_ptr(&rng_ref, [](auto*) {});
      return ffi_new_object(cbs_out, Botan::TPM2::use_botan_crypto_backend(esys_ctx, rng_ptr));
   });
#else
   BOTAN_UNUSED(cbs_out, esys_ctx, rng);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tpm2_crypto_backend_state_destroy(botan_tpm2_crypto_backend_state_t cbs) {
#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   return BOTAN_FFI_CHECKED_DELETE(cbs);
#else
   BOTAN_UNUSED(cbs);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tpm2_rng_init(botan_rng_t* rng_out,
                        botan_tpm2_ctx_t ctx,
                        botan_tpm2_session_t s1,
                        botan_tpm2_session_t s2,
                        botan_tpm2_session_t s3) {
#if defined(BOTAN_HAS_TPM2)
   return BOTAN_FFI_VISIT(ctx, [=](const std::shared_ptr<Botan::TPM2::Context>& tpm2_ctx) -> int {
      if(rng_out == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      return ffi_new_object(rng_out,
                            std::make_unique<Botan::TPM2::RandomNumberGenerator>(tpm2_ctx, sessions(s1, s2, s3)));
   });
#else
   BOTAN_UNUSED(rng_out, ctx, s1, s2, s3);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tpm2_unauthenticated_session_init(botan_tpm2_session_t* session_out, botan_tpm2_ctx_t ctx) {
#if defined(BOTAN_HAS_TPM2)
   return BOTAN_FFI_VISIT(ctx, [=](const std::shared_ptr<Botan::TPM2::Context>& tpm2_ctx) -> int {
      if(session_out == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      return ffi_new_object(session_out, Botan::TPM2::Session::unauthenticated_session(tpm2_ctx));
   });
#else
   BOTAN_UNUSED(session_out, ctx);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tpm2_session_destroy(botan_tpm2_session_t session) {
#if defined(BOTAN_HAS_TPM2)
   return BOTAN_FFI_CHECKED_DELETE(session);
#else
   BOTAN_UNUSED(session);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_TPM2)
   #include <botan/tpm2.h>
   #include <botan/tpm2_rng.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_TPM2)
/**
 * This wrapper is required since BOTAN_FFI_DECLARE_STRUCT internally produces a unique pointer,
 * but the TPM2_Context is meant to be used as a shared pointer.
 */
struct botan_tpm2_ctx_wrapper {
      std::shared_ptr<Botan::TPM2_Context> ctx;
};

BOTAN_FFI_DECLARE_STRUCT(botan_tpm2_ctx_struct, botan_tpm2_ctx_wrapper, 0xD2B95E15);
#endif

int botan_tpm2_ctx_init(botan_tpm2_ctx_t* ctx_out, const char* tcti_nameconf) {
#if defined(BOTAN_HAS_TPM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ctx_out == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      auto ctx = std::make_unique<botan_tpm2_ctx_wrapper>();

      auto tcti = [=]() -> std::optional<std::string> {
         if(tcti_nameconf == nullptr) {
            return {};
         } else {
            return std::string(tcti_nameconf);
         }
      }();

      ctx->ctx = Botan::TPM2_Context::create(std::move(tcti));
      *ctx_out = new botan_tpm2_ctx_struct(std::move(ctx));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ctx_out);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Frees all resouces of a TPM2 context
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

int botan_tpm2_rng_init(botan_rng_t* rng_out, botan_tpm2_ctx_t ctx) {
#if defined(BOTAN_HAS_TPM2)
   return BOTAN_FFI_VISIT(ctx, [=](botan_tpm2_ctx_wrapper& ctx_wrapper) -> int {
      if(rng_out == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *rng_out = new botan_rng_struct(std::make_unique<Botan::TPM2_RNG>(ctx_wrapper.ctx));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(rng_out, ctx);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

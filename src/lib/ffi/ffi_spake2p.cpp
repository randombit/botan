/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/assert.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   #include <botan/rng.h>
   #include <botan/spake2p.h>
   #include <botan/internal/ffi_ec.h>
#endif

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)

namespace {

Botan::SPAKE2p::SystemParameters spake2p_params_from_name(const char* ciphersuite) {
   using Botan::SPAKE2p::SystemParameters;

   const std::string_view name(ciphersuite);

   if(name == "P256-SHA256") {
      return SystemParameters::rfc9383_p256_sha256();
   } else if(name == "P256-SHA512") {
      return SystemParameters::rfc9383_p256_sha512();
   } else if(name == "P384-SHA256") {
      return SystemParameters::rfc9383_p384_sha256();
   } else if(name == "P384-SHA512") {
      return SystemParameters::rfc9383_p384_sha512();
   } else if(name == "P521-SHA512") {
      return SystemParameters::rfc9383_p521_sha512();
   } else {
      throw Botan::Invalid_Argument("Unknown SPAKE2+ ciphersuite");
   }
}

std::span<const uint8_t> spake2p_opt_span(const uint8_t* ptr, size_t len) {
   if(ptr == nullptr && len > 0) {
      throw Botan::Invalid_Argument("Null pointer with non-zero length");
   }
   return {ptr, len};
}

}  // namespace

#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
BOTAN_FFI_DECLARE_STRUCT(botan_spake2p_params_struct, Botan::SPAKE2p::SystemParameters, 0x2E1B4A96);
BOTAN_FFI_DECLARE_STRUCT(botan_spake2p_prover_struct, Botan::SPAKE2p::ProverContext, 0x9F337C29);
BOTAN_FFI_DECLARE_STRUCT(botan_spake2p_verifier_struct, Botan::SPAKE2p::VerifierContext, 0xD70A9E13);
#else
BOTAN_FFI_DECLARE_DUMMY_STRUCT(botan_spake2p_params_struct, 0x2E1B4A96);
BOTAN_FFI_DECLARE_DUMMY_STRUCT(botan_spake2p_prover_struct, 0x9F337C29);
BOTAN_FFI_DECLARE_DUMMY_STRUCT(botan_spake2p_verifier_struct, 0xD70A9E13);
#endif

int botan_spake2p_params_init(botan_spake2p_params_t* params, const char* ciphersuite) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   if(any_null_pointers(params, ciphersuite)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto p = std::make_unique<Botan::SPAKE2p::SystemParameters>(spake2p_params_from_name(ciphersuite));
      return ffi_new_object(params, std::move(p));
   });
#else
   BOTAN_UNUSED(params, ciphersuite);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_params_init_custom(
   botan_spake2p_params_t* params, botan_ec_group_t group, const uint8_t seed[], size_t seed_len, const char* hash_fn) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   if(any_null_pointers(params, group, hash_fn)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto p = std::make_unique<Botan::SPAKE2p::SystemParameters>(
         Botan::SPAKE2p::SystemParameters::custom(safe_get(group), spake2p_opt_span(seed, seed_len), hash_fn));
      return ffi_new_object(params, std::move(p));
   });
#else
   BOTAN_UNUSED(params, group, seed, seed_len, hash_fn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_params_destroy(botan_spake2p_params_t params) {
   return BOTAN_FFI_CHECKED_DELETE(params);
}

int botan_spake2p_params_share_size(botan_spake2p_params_t params, size_t* share_size) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(params, [=](const auto& p) -> int {
      if(share_size == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      *share_size = p.share_size();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(params, share_size);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_params_confirmation_size(botan_spake2p_params_t params, size_t* confirmation_size) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(params, [=](const auto& p) -> int {
      if(confirmation_size == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      *confirmation_size = p.confirmation_size();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(params, confirmation_size);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_derive_secret(botan_spake2p_params_t params,
                                const char* password,
                                const uint8_t prover_id[],
                                size_t prover_id_len,
                                const uint8_t verifier_id[],
                                size_t verifier_id_len,
                                const uint8_t salt[],
                                size_t salt_len,
                                botan_view_ctx ctx,
                                botan_view_bin_fn view) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   if(any_null_pointers(params, password)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto sec = Botan::SPAKE2p::ProverSecret::from_password(safe_get(params),
                                                                   password,
                                                                   spake2p_opt_span(prover_id, prover_id_len),
                                                                   spake2p_opt_span(verifier_id, verifier_id_len),
                                                                   spake2p_opt_span(salt, salt_len));
      return invoke_view_callback(view, ctx, sec.serialize());
   });
#else
   BOTAN_UNUSED(params, password, prover_id, prover_id_len, verifier_id, verifier_id_len);
   BOTAN_UNUSED(salt, salt_len, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_registration_record(botan_spake2p_params_t params,
                                      botan_rng_t rng,
                                      const uint8_t secret[],
                                      size_t secret_len,
                                      botan_view_ctx ctx,
                                      botan_view_bin_fn view) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   if(any_null_pointers(params, rng, secret)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto sec = Botan::SPAKE2p::ProverSecret::deserialize(safe_get(params), {secret, secret_len});
      return invoke_view_callback(view, ctx, sec.registration_record(safe_get(rng)).serialize());
   });
#else
   BOTAN_UNUSED(params, rng, secret, secret_len, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_prover_init(botan_spake2p_prover_t* prover,
                              botan_spake2p_params_t params,
                              const uint8_t secret[],
                              size_t secret_len,
                              const uint8_t prover_id[],
                              size_t prover_id_len,
                              const uint8_t verifier_id[],
                              size_t verifier_id_len,
                              const uint8_t context[],
                              size_t context_len) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   if(any_null_pointers(prover, params, secret)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto& p = safe_get(params);
      const auto sec = Botan::SPAKE2p::ProverSecret::deserialize(p, {secret, secret_len});
      auto ctx = std::make_unique<Botan::SPAKE2p::ProverContext>(p,
                                                                 sec,
                                                                 spake2p_opt_span(prover_id, prover_id_len),
                                                                 spake2p_opt_span(verifier_id, verifier_id_len),
                                                                 spake2p_opt_span(context, context_len));
      return ffi_new_object(prover, std::move(ctx));
   });
#else
   BOTAN_UNUSED(prover, params, secret, secret_len, prover_id, prover_id_len);
   BOTAN_UNUSED(verifier_id, verifier_id_len, context, context_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_prover_destroy(botan_spake2p_prover_t prover) {
   return BOTAN_FFI_CHECKED_DELETE(prover);
}

int botan_spake2p_prover_generate_message(botan_spake2p_prover_t prover,
                                          botan_rng_t rng,
                                          botan_view_ctx ctx,
                                          botan_view_bin_fn view) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(prover, [=](auto& p) -> int {
      if(rng == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      return invoke_view_callback(view, ctx, p.generate_message(safe_get(rng)));
   });
#else
   BOTAN_UNUSED(prover, rng, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_prover_process_message(botan_spake2p_prover_t prover,
                                         botan_rng_t rng,
                                         const uint8_t peer_message[],
                                         size_t peer_message_len,
                                         botan_view_ctx ctx,
                                         botan_view_bin_fn view) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(prover, [=](auto& p) -> int {
      if(any_null_pointers(rng, peer_message)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      return invoke_view_callback(view, ctx, p.process_message({peer_message, peer_message_len}, safe_get(rng)));
   });
#else
   BOTAN_UNUSED(prover, rng, peer_message, peer_message_len, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_prover_shared_secret(botan_spake2p_prover_t prover, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(prover, [=](auto& p) -> int { return invoke_view_callback(view, ctx, p.shared_secret()); });
#else
   BOTAN_UNUSED(prover, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_verifier_init(botan_spake2p_verifier_t* verifier,
                                botan_spake2p_params_t params,
                                const uint8_t record[],
                                size_t record_len,
                                const uint8_t prover_id[],
                                size_t prover_id_len,
                                const uint8_t verifier_id[],
                                size_t verifier_id_len,
                                const uint8_t context[],
                                size_t context_len) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   if(any_null_pointers(verifier, params, record)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto& p = safe_get(params);
      const auto rec = Botan::SPAKE2p::RegistrationRecord::deserialize(p, {record, record_len});
      auto ctx = std::make_unique<Botan::SPAKE2p::VerifierContext>(p,
                                                                   rec,
                                                                   spake2p_opt_span(prover_id, prover_id_len),
                                                                   spake2p_opt_span(verifier_id, verifier_id_len),
                                                                   spake2p_opt_span(context, context_len));
      return ffi_new_object(verifier, std::move(ctx));
   });
#else
   BOTAN_UNUSED(verifier, params, record, record_len, prover_id, prover_id_len);
   BOTAN_UNUSED(verifier_id, verifier_id_len, context, context_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_verifier_destroy(botan_spake2p_verifier_t verifier) {
   return BOTAN_FFI_CHECKED_DELETE(verifier);
}

int botan_spake2p_verifier_process_message(botan_spake2p_verifier_t verifier,
                                           botan_rng_t rng,
                                           const uint8_t peer_message[],
                                           size_t peer_message_len,
                                           botan_view_ctx ctx,
                                           botan_view_bin_fn view) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(verifier, [=](auto& v) -> int {
      if(any_null_pointers(rng, peer_message)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      return invoke_view_callback(view, ctx, v.process_message({peer_message, peer_message_len}, safe_get(rng)));
   });
#else
   BOTAN_UNUSED(verifier, rng, peer_message, peer_message_len, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_verifier_verify_confirmation(botan_spake2p_verifier_t verifier,
                                               const uint8_t confirmation[],
                                               size_t confirmation_len) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(verifier, [=](auto& v) -> int {
      if(confirmation == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      v.verify_confirmation({confirmation, confirmation_len});
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(verifier, confirmation, confirmation_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_verifier_skip_confirmation(botan_spake2p_verifier_t verifier) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(verifier, [](auto& v) -> int {
      v.skip_confirmation();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(verifier);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_spake2p_verifier_shared_secret(botan_spake2p_verifier_t verifier,
                                         botan_view_ctx ctx,
                                         botan_view_bin_fn view) {
#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   return BOTAN_FFI_VISIT(verifier, [=](auto& v) -> int { return invoke_view_callback(view, ctx, v.shared_secret()); });
#else
   BOTAN_UNUSED(verifier, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

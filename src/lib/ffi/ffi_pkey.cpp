/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/data_src.h>
#include <botan/hash.h>
#include <botan/pk_algs.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_HASH_ID)
   #include <botan/internal/hash_id.h>
#endif

extern "C" {

using namespace Botan_FFI;

int botan_privkey_create(botan_privkey_t* key_obj,
                         const char* algo_name,
                         const char* algo_params,
                         botan_rng_t rng_obj) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(key_obj == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *key_obj = nullptr;
      if(rng_obj == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      std::unique_ptr<Botan::Private_Key> key(
         Botan::create_private_key(algo_name ? algo_name : "RSA", rng, algo_params ? algo_params : ""));

      if(key) {
         *key_obj = new botan_privkey_struct(std::move(key));
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
      }
   });
}

int botan_privkey_load(
   botan_privkey_t* key, botan_rng_t rng_obj, const uint8_t bits[], size_t len, const char* password) {
   BOTAN_UNUSED(rng_obj);

   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory src(bits, len);

      std::unique_ptr<Botan::Private_Key> pkcs8;

      if(password == nullptr) {
         pkcs8 = Botan::PKCS8::load_key(src);
      } else {
         pkcs8 = Botan::PKCS8::load_key(src, std::string(password));
      }

      if(pkcs8) {
         *key = new botan_privkey_struct(std::move(pkcs8));
         return BOTAN_FFI_SUCCESS;
      }
      return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
   });
}

int botan_privkey_destroy(botan_privkey_t key) {
   return BOTAN_FFI_CHECKED_DELETE(key);
}

int botan_pubkey_load(botan_pubkey_t* key, const uint8_t bits[], size_t bits_len) {
   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory src(bits, bits_len);
      std::unique_ptr<Botan::Public_Key> pubkey(Botan::X509::load_key(src));

      if(pubkey == nullptr) {
         return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
      }

      *key = new botan_pubkey_struct(std::move(pubkey));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pubkey_destroy(botan_pubkey_t key) {
   return BOTAN_FFI_CHECKED_DELETE(key);
}

int botan_privkey_export_pubkey(botan_pubkey_t* pubout, botan_privkey_t key_obj) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto public_key = safe_get(key_obj).public_key();
      *pubout = new botan_pubkey_struct(std::move(public_key));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_privkey_algo_name(botan_privkey_t key, char out[], size_t* out_len) {
   return BOTAN_FFI_VISIT(key, [=](const auto& k) { return write_str_output(out, out_len, k.algo_name()); });
}

int botan_pubkey_algo_name(botan_pubkey_t key, char out[], size_t* out_len) {
   return BOTAN_FFI_VISIT(key, [=](const auto& k) { return write_str_output(out, out_len, k.algo_name()); });
}

int botan_pubkey_check_key(botan_pubkey_t key, botan_rng_t rng, uint32_t flags) {
   const bool strong = (flags & BOTAN_CHECK_KEY_EXPENSIVE_TESTS);

   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      return (k.check_key(safe_get(rng), strong) == true) ? 0 : BOTAN_FFI_ERROR_INVALID_INPUT;
   });
}

int botan_privkey_check_key(botan_privkey_t key, botan_rng_t rng, uint32_t flags) {
   const bool strong = (flags & BOTAN_CHECK_KEY_EXPENSIVE_TESTS);
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      return (k.check_key(safe_get(rng), strong) == true) ? 0 : BOTAN_FFI_ERROR_INVALID_INPUT;
   });
}

int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags) {
   if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER) {
      return copy_view_bin(out, out_len, botan_pubkey_view_der, key);
   } else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM) {
      return copy_view_str(out, out_len, botan_pubkey_view_pem, key);
   } else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_RAW) {
      return copy_view_bin(out, out_len, botan_pubkey_view_raw, key);
   } else {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }
}

int botan_pubkey_view_der(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(
      key, [=](const auto& k) -> int { return invoke_view_callback(view, ctx, Botan::X509::BER_encode(k)); });
}

int botan_pubkey_view_pem(botan_pubkey_t key, botan_view_ctx ctx, botan_view_str_fn view) {
   return BOTAN_FFI_VISIT(
      key, [=](const auto& k) -> int { return invoke_view_callback(view, ctx, Botan::X509::PEM_encode(k)); });
}

int botan_pubkey_view_raw(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(
      key, [=](const auto& k) -> int { return invoke_view_callback(view, ctx, k.raw_public_key_bits()); });
}

int botan_privkey_export(botan_privkey_t key, uint8_t out[], size_t* out_len, uint32_t flags) {
   if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER) {
      return copy_view_bin(out, out_len, botan_privkey_view_der, key);
   } else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM) {
      return copy_view_str(out, out_len, botan_privkey_view_pem, key);
   } else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_RAW) {
      return copy_view_bin(out, out_len, botan_privkey_view_raw, key);
   } else {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }
}

int botan_privkey_view_der(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(
      key, [=](const auto& k) -> int { return invoke_view_callback(view, ctx, Botan::PKCS8::BER_encode(k)); });
}

int botan_privkey_view_pem(botan_privkey_t key, botan_view_ctx ctx, botan_view_str_fn view) {
   return BOTAN_FFI_VISIT(
      key, [=](const auto& k) -> int { return invoke_view_callback(view, ctx, Botan::PKCS8::PEM_encode(k)); });
}

int botan_privkey_view_raw(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(
      key, [=](const auto& k) -> int { return invoke_view_callback(view, ctx, k.raw_private_key_bits()); });
}

int botan_privkey_export_encrypted(botan_privkey_t key,
                                   uint8_t out[],
                                   size_t* out_len,
                                   botan_rng_t rng_obj,
                                   const char* pass,
                                   const char* /*ignored - pbe*/,
                                   uint32_t flags) {
   return botan_privkey_export_encrypted_pbkdf_iter(key, out, out_len, rng_obj, pass, 100000, nullptr, nullptr, flags);
}

int botan_privkey_export_encrypted_pbkdf_msec(botan_privkey_t key,
                                              uint8_t out[],
                                              size_t* out_len,
                                              botan_rng_t rng,
                                              const char* passphrase,
                                              uint32_t pbkdf_msec,
                                              size_t* pbkdf_iters_out,
                                              const char* cipher,
                                              const char* pbkdf_hash,
                                              uint32_t flags) {
   if(pbkdf_iters_out) {
      *pbkdf_iters_out = 0;
   }

   if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER) {
      return copy_view_bin(
         out, out_len, botan_privkey_view_encrypted_der_timed, key, rng, passphrase, cipher, pbkdf_hash, pbkdf_msec);
   } else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM) {
      return copy_view_str(
         out, out_len, botan_privkey_view_encrypted_pem_timed, key, rng, passphrase, cipher, pbkdf_hash, pbkdf_msec);
   } else {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }
}

int botan_privkey_view_encrypted_der_timed(botan_privkey_t key,
                                           botan_rng_t rng_obj,
                                           const char* passphrase,
                                           const char* maybe_cipher,
                                           const char* maybe_pbkdf_algo,
                                           size_t pbkdf_runtime_msec,
                                           botan_view_ctx ctx,
                                           botan_view_bin_fn view) {
   if(passphrase == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      const std::chrono::milliseconds pbkdf_time(pbkdf_runtime_msec);
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      const std::string cipher = (maybe_cipher ? maybe_cipher : "");
      const std::string pbkdf_algo = (maybe_pbkdf_algo ? maybe_pbkdf_algo : "");

      auto pkcs8 =
         Botan::PKCS8::BER_encode_encrypted_pbkdf_msec(k, rng, passphrase, pbkdf_time, nullptr, cipher, pbkdf_algo);

      return invoke_view_callback(view, ctx, pkcs8);
   });
}

int botan_privkey_view_encrypted_pem_timed(botan_privkey_t key,
                                           botan_rng_t rng_obj,
                                           const char* passphrase,
                                           const char* maybe_cipher,
                                           const char* maybe_pbkdf_algo,
                                           size_t pbkdf_runtime_msec,
                                           botan_view_ctx ctx,
                                           botan_view_str_fn view) {
   if(passphrase == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      const std::chrono::milliseconds pbkdf_time(pbkdf_runtime_msec);
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      const std::string cipher = (maybe_cipher ? maybe_cipher : "");
      const std::string pbkdf_algo = (maybe_pbkdf_algo ? maybe_pbkdf_algo : "");

      auto pkcs8 =
         Botan::PKCS8::PEM_encode_encrypted_pbkdf_msec(k, rng, passphrase, pbkdf_time, nullptr, cipher, pbkdf_algo);

      return invoke_view_callback(view, ctx, pkcs8);
   });
}

int botan_privkey_export_encrypted_pbkdf_iter(botan_privkey_t key,
                                              uint8_t out[],
                                              size_t* out_len,
                                              botan_rng_t rng,
                                              const char* passphrase,
                                              size_t pbkdf_iter,
                                              const char* cipher,
                                              const char* pbkdf_algo,
                                              uint32_t flags) {
   if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER) {
      return copy_view_bin(
         out, out_len, botan_privkey_view_encrypted_der, key, rng, passphrase, cipher, pbkdf_algo, pbkdf_iter);
   } else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM) {
      return copy_view_str(
         out, out_len, botan_privkey_view_encrypted_pem, key, rng, passphrase, cipher, pbkdf_algo, pbkdf_iter);
   } else {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }
}

int botan_privkey_view_encrypted_der(botan_privkey_t key,
                                     botan_rng_t rng_obj,
                                     const char* passphrase,
                                     const char* maybe_cipher,
                                     const char* maybe_pbkdf_algo,
                                     size_t maybe_pbkdf_iterations,
                                     botan_view_ctx ctx,
                                     botan_view_bin_fn view) {
   if(passphrase == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      const std::string cipher = (maybe_cipher ? maybe_cipher : "");
      const std::string pbkdf_algo = (maybe_pbkdf_algo ? maybe_pbkdf_algo : "");
      const size_t pbkdf_iter = (maybe_pbkdf_iterations ? maybe_pbkdf_iterations : 100000);

      auto pkcs8 = Botan::PKCS8::BER_encode_encrypted_pbkdf_iter(k, rng, passphrase, pbkdf_iter, cipher, pbkdf_algo);

      return invoke_view_callback(view, ctx, pkcs8);
   });
}

int botan_privkey_view_encrypted_pem(botan_privkey_t key,
                                     botan_rng_t rng_obj,
                                     const char* passphrase,
                                     const char* maybe_cipher,
                                     const char* maybe_pbkdf_algo,
                                     size_t maybe_pbkdf_iterations,
                                     botan_view_ctx ctx,
                                     botan_view_str_fn view) {
   if(passphrase == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      const std::string cipher = (maybe_cipher ? maybe_cipher : "");
      const std::string pbkdf_algo = (maybe_pbkdf_algo ? maybe_pbkdf_algo : "");
      const size_t pbkdf_iter = (maybe_pbkdf_iterations ? maybe_pbkdf_iterations : 100000);

      auto pkcs8 = Botan::PKCS8::PEM_encode_encrypted_pbkdf_iter(k, rng, passphrase, pbkdf_iter, cipher, pbkdf_algo);

      return invoke_view_callback(view, ctx, pkcs8);
   });
}

int botan_pubkey_estimated_strength(botan_pubkey_t key, size_t* estimate) {
   return BOTAN_FFI_VISIT(key, [=](const auto& k) { *estimate = k.estimated_strength(); });
}

int botan_pubkey_fingerprint(botan_pubkey_t key, const char* hash_fn, uint8_t out[], size_t* out_len) {
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      auto h = Botan::HashFunction::create_or_throw(hash_fn);
      return write_vec_output(out, out_len, h->process(k.public_key_bits()));
   });
}

int botan_pkcs_hash_id(const char* hash_name, uint8_t pkcs_id[], size_t* pkcs_id_len) {
#if defined(BOTAN_HAS_HASH_ID)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::vector<uint8_t> hash_id = Botan::pkcs_hash_id(hash_name);
      return write_output(pkcs_id, pkcs_id_len, hash_id.data(), hash_id.size());
   });
#else
   BOTAN_UNUSED(hash_name, pkcs_id, pkcs_id_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

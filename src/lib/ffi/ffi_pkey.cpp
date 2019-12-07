/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/data_src.h>
#include <botan/hash.h>
#include <botan/pkcs8.h>
#include <botan/pk_keys.h>
#include <botan/x509_key.h>
#include <botan/pk_algs.h>

#if defined(BOTAN_HAS_HASH_ID)
  #include <botan/hash_id.h>
#endif

extern "C" {

using namespace Botan_FFI;

int botan_privkey_create(botan_privkey_t* key_obj,
                         const char* algo_name,
                         const char* algo_params,
                         botan_rng_t rng_obj)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(key_obj == nullptr)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      *key_obj = nullptr;
      if(rng_obj == nullptr)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      std::unique_ptr<Botan::Private_Key> key(
         Botan::create_private_key(algo_name ? algo_name : "RSA",
                                   rng,
                                   algo_params ? algo_params : ""));

      if(key)
         {
         *key_obj = new botan_privkey_struct(key.release());
         return BOTAN_FFI_SUCCESS;
         }
      else
         {
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
         }
      });
   }

int botan_privkey_load(botan_privkey_t* key, botan_rng_t rng_obj,
                       const uint8_t bits[], size_t len,
                       const char* password)
   {
   BOTAN_UNUSED(rng_obj);

   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory src(bits, len);

      std::unique_ptr<Botan::Private_Key> pkcs8;

      if(password == nullptr)
         {
         pkcs8 = Botan::PKCS8::load_key(src);
         }
      else
         {
         pkcs8 = Botan::PKCS8::load_key(src, std::string(password));
         }

      if(pkcs8)
         {
         *key = new botan_privkey_struct(pkcs8.release());
         return BOTAN_FFI_SUCCESS;
         }
      return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
      });
   }

int botan_privkey_destroy(botan_privkey_t key)
   {
   return BOTAN_FFI_CHECKED_DELETE(key);
   }

int botan_pubkey_load(botan_pubkey_t* key,
                      const uint8_t bits[], size_t bits_len)
   {
   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory src(bits, bits_len);
      std::unique_ptr<Botan::Public_Key> pubkey(Botan::X509::load_key(src));

      if(pubkey == nullptr)
         return BOTAN_FFI_ERROR_UNKNOWN_ERROR;

      *key = new botan_pubkey_struct(pubkey.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_pubkey_destroy(botan_pubkey_t key)
   {
   return BOTAN_FFI_CHECKED_DELETE(key);
   }

int botan_privkey_export_pubkey(botan_pubkey_t* pubout, botan_privkey_t key_obj)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::Public_Key>
         pubkey(Botan::X509::load_key(Botan::X509::BER_encode(safe_get(key_obj))));

      *pubout = new botan_pubkey_struct(pubkey.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_privkey_algo_name(botan_privkey_t key, char out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, { return write_str_output(out, out_len, k.algo_name()); });
   }

int botan_pubkey_algo_name(botan_pubkey_t key, char out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, { return write_str_output(out, out_len, k.algo_name()); });
   }

int botan_pubkey_check_key(botan_pubkey_t key, botan_rng_t rng, uint32_t flags)
   {
   const bool strong = (flags & BOTAN_CHECK_KEY_EXPENSIVE_TESTS);

   return BOTAN_FFI_RETURNING(Botan::Public_Key, key, k, {
      return (k.check_key(safe_get(rng), strong) == true) ? 0 : BOTAN_FFI_ERROR_INVALID_INPUT;
      });
   }

int botan_privkey_check_key(botan_privkey_t key, botan_rng_t rng, uint32_t flags)
   {
   const bool strong = (flags & BOTAN_CHECK_KEY_EXPENSIVE_TESTS);
   return BOTAN_FFI_RETURNING(Botan::Private_Key, key, k, {
      return (k.check_key(safe_get(rng), strong) == true) ? 0 : BOTAN_FFI_ERROR_INVALID_INPUT;
      });
   }

int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, {
      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         return write_vec_output(out, out_len, Botan::X509::BER_encode(k));
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         return write_str_output(out, out_len, Botan::X509::PEM_encode(k));
      else
         return BOTAN_FFI_ERROR_BAD_FLAG;
      });
   }

int botan_privkey_export(botan_privkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         return write_vec_output(out, out_len, Botan::PKCS8::BER_encode(k));
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         return write_str_output(out, out_len, Botan::PKCS8::PEM_encode(k));
      else
         return BOTAN_FFI_ERROR_BAD_FLAG;
      });
   }

int botan_privkey_export_encrypted(botan_privkey_t key,
                                   uint8_t out[], size_t* out_len,
                                   botan_rng_t rng_obj,
                                   const char* pass,
                                   const char* /*ignored - pbe*/,
                                   uint32_t flags)
   {
   return botan_privkey_export_encrypted_pbkdf_iter(key, out, out_len, rng_obj, pass, 100000, nullptr, nullptr, flags);
   }

int botan_privkey_export_encrypted_pbkdf_msec(botan_privkey_t key,
                                              uint8_t out[], size_t* out_len,
                                              botan_rng_t rng_obj,
                                              const char* pass,
                                              uint32_t pbkdf_msec,
                                              size_t* pbkdf_iters_out,
                                              const char* maybe_cipher,
                                              const char* maybe_pbkdf_hash,
                                              uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      const std::chrono::milliseconds pbkdf_time(pbkdf_msec);
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      const std::string cipher = (maybe_cipher ? maybe_cipher : "");
      const std::string pbkdf_hash = (maybe_pbkdf_hash ? maybe_pbkdf_hash : "");

      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         {
         return write_vec_output(out, out_len,
                                 Botan::PKCS8::BER_encode_encrypted_pbkdf_msec(k, rng, pass, pbkdf_time, pbkdf_iters_out, cipher, pbkdf_hash));
         }
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         {
         return write_str_output(out, out_len,
                                 Botan::PKCS8::PEM_encode_encrypted_pbkdf_msec(k, rng, pass, pbkdf_time, pbkdf_iters_out, cipher, pbkdf_hash));
         }
      else
         {
         return -2;
         }
      });
   }

int botan_privkey_export_encrypted_pbkdf_iter(botan_privkey_t key,
                                              uint8_t out[], size_t* out_len,
                                              botan_rng_t rng_obj,
                                              const char* pass,
                                              size_t pbkdf_iter,
                                              const char* maybe_cipher,
                                              const char* maybe_pbkdf_hash,
                                              uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      const std::string cipher = (maybe_cipher ? maybe_cipher : "");
      const std::string pbkdf_hash = (maybe_pbkdf_hash ? maybe_pbkdf_hash : "");

      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         {
         return write_vec_output(out, out_len,
                                 Botan::PKCS8::BER_encode_encrypted_pbkdf_iter(k, rng, pass, pbkdf_iter, cipher, pbkdf_hash));
         }
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         {
         return write_str_output(out, out_len,
                                 Botan::PKCS8::PEM_encode_encrypted_pbkdf_iter(k, rng, pass, pbkdf_iter, cipher, pbkdf_hash));
         }
      else
         {
         return -2;
         }
      });
   }

int botan_pubkey_estimated_strength(botan_pubkey_t key, size_t* estimate)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, { *estimate = k.estimated_strength(); });
   }

int botan_pubkey_fingerprint(botan_pubkey_t key, const char* hash_fn,
                             uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, {
      std::unique_ptr<Botan::HashFunction> h(Botan::HashFunction::create(hash_fn));
      return write_vec_output(out, out_len, h->process(k.public_key_bits()));
      });
   }

int botan_pkcs_hash_id(const char* hash_name, uint8_t pkcs_id[], size_t* pkcs_id_len)
   {
#if defined(BOTAN_HAS_HASH_ID)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::vector<uint8_t> hash_id = Botan::pkcs_hash_id(hash_name);
      return write_output(pkcs_id, pkcs_id_len, hash_id.data(), hash_id.size());
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

}

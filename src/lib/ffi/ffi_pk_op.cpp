/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/pubkey.h>
#include <botan/system_rng.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

extern "C" {

using namespace Botan_FFI;

BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_encrypt_struct, Botan::PK_Encryptor, 0x891F3FC3);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_decrypt_struct, Botan::PK_Decryptor, 0x912F3C37);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_sign_struct, Botan::PK_Signer, 0x1AF0C39F);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_verify_struct, Botan::PK_Verifier, 0x2B91F936);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_ka_struct, Botan::PK_Key_Agreement, 0x2939CAB1);

BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_kem_encrypt_struct, Botan::PK_KEM_Encryptor, 0x1D13A446);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_kem_decrypt_struct, Botan::PK_KEM_Decryptor, 0x1743D8E6);

int botan_pk_op_encrypt_create(botan_pk_op_encrypt_t* op, botan_pubkey_t key_obj, const char* padding, uint32_t flags) {
   if(op == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(flags != 0 && flags != BOTAN_PUBKEY_DER_FORMAT_SIGNATURE) {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;

      auto pk = std::make_unique<Botan::PK_Encryptor_EME>(safe_get(key_obj), Botan::system_rng(), padding);
      *op = new botan_pk_op_encrypt_struct(std::move(pk));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_encrypt_destroy(botan_pk_op_encrypt_t op) {
   return BOTAN_FFI_CHECKED_DELETE(op);
}

int botan_pk_op_encrypt_output_length(botan_pk_op_encrypt_t op, size_t ptext_len, size_t* ctext_len) {
   if(ctext_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(op, [=](const auto& o) { *ctext_len = o.ciphertext_length(ptext_len); });
}

int botan_pk_op_encrypt(botan_pk_op_encrypt_t op,
                        botan_rng_t rng_obj,
                        uint8_t out[],
                        size_t* out_len,
                        const uint8_t plaintext[],
                        size_t plaintext_len) {
   return BOTAN_FFI_VISIT(op, [=](const auto& o) {
      return write_vec_output(out, out_len, o.encrypt(plaintext, plaintext_len, safe_get(rng_obj)));
   });
}

/*
* Public Key Decryption
*/
int botan_pk_op_decrypt_create(botan_pk_op_decrypt_t* op,
                               botan_privkey_t key_obj,
                               const char* padding,
                               uint32_t flags) {
   if(op == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(flags != 0) {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;

      auto pk = std::make_unique<Botan::PK_Decryptor_EME>(safe_get(key_obj), Botan::system_rng(), padding);
      *op = new botan_pk_op_decrypt_struct(std::move(pk));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_decrypt_destroy(botan_pk_op_decrypt_t op) {
   return BOTAN_FFI_CHECKED_DELETE(op);
}

int botan_pk_op_decrypt_output_length(botan_pk_op_decrypt_t op, size_t ctext_len, size_t* ptext_len) {
   if(ptext_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(op, [=](const auto& o) { *ptext_len = o.plaintext_length(ctext_len); });
}

int botan_pk_op_decrypt(
   botan_pk_op_decrypt_t op, uint8_t out[], size_t* out_len, const uint8_t ciphertext[], size_t ciphertext_len) {
   return BOTAN_FFI_VISIT(
      op, [=](const auto& o) { return write_vec_output(out, out_len, o.decrypt(ciphertext, ciphertext_len)); });
}

/*
* Signature Generation
*/
int botan_pk_op_sign_create(botan_pk_op_sign_t* op, botan_privkey_t key_obj, const char* hash, uint32_t flags) {
   if(op == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(flags != 0 && flags != BOTAN_PUBKEY_DER_FORMAT_SIGNATURE) {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;

      auto format = (flags & BOTAN_PUBKEY_DER_FORMAT_SIGNATURE) ? Botan::Signature_Format::DerSequence
                                                                : Botan::Signature_Format::Standard;

      auto pk = std::make_unique<Botan::PK_Signer>(safe_get(key_obj), Botan::system_rng(), hash, format);
      *op = new botan_pk_op_sign_struct(std::move(pk));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_sign_destroy(botan_pk_op_sign_t op) {
   return BOTAN_FFI_CHECKED_DELETE(op);
}

int botan_pk_op_sign_output_length(botan_pk_op_sign_t op, size_t* sig_len) {
   if(sig_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(op, [=](const auto& o) { *sig_len = o.signature_length(); });
}

int botan_pk_op_sign_update(botan_pk_op_sign_t op, const uint8_t in[], size_t in_len) {
   return BOTAN_FFI_VISIT(op, [=](auto& o) { o.update(in, in_len); });
}

int botan_pk_op_sign_finish(botan_pk_op_sign_t op, botan_rng_t rng_obj, uint8_t out[], size_t* out_len) {
   return BOTAN_FFI_VISIT(op, [=](auto& o) { return write_vec_output(out, out_len, o.signature(safe_get(rng_obj))); });
}

int botan_pk_op_verify_create(botan_pk_op_verify_t* op, botan_pubkey_t key_obj, const char* hash, uint32_t flags) {
   if(op == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(flags != 0 && flags != BOTAN_PUBKEY_DER_FORMAT_SIGNATURE) {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;
      auto format = (flags & BOTAN_PUBKEY_DER_FORMAT_SIGNATURE) ? Botan::Signature_Format::DerSequence
                                                                : Botan::Signature_Format::Standard;
      auto pk = std::make_unique<Botan::PK_Verifier>(safe_get(key_obj), hash, format);
      *op = new botan_pk_op_verify_struct(std::move(pk));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_verify_destroy(botan_pk_op_verify_t op) {
   return BOTAN_FFI_CHECKED_DELETE(op);
}

int botan_pk_op_verify_update(botan_pk_op_verify_t op, const uint8_t in[], size_t in_len) {
   return BOTAN_FFI_VISIT(op, [=](auto& o) { o.update(in, in_len); });
}

int botan_pk_op_verify_finish(botan_pk_op_verify_t op, const uint8_t sig[], size_t sig_len) {
   return BOTAN_FFI_VISIT(op, [=](auto& o) {
      const bool legit = o.check_signature(sig, sig_len);

      if(legit)
         return BOTAN_FFI_SUCCESS;
      else
         return BOTAN_FFI_INVALID_VERIFIER;
   });
}

int botan_pk_op_key_agreement_create(botan_pk_op_ka_t* op, botan_privkey_t key_obj, const char* kdf, uint32_t flags) {
   if(op == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(flags != 0) {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;
      auto pk = std::make_unique<Botan::PK_Key_Agreement>(safe_get(key_obj), Botan::system_rng(), kdf);
      *op = new botan_pk_op_ka_struct(std::move(pk));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_key_agreement_destroy(botan_pk_op_ka_t op) {
   return BOTAN_FFI_CHECKED_DELETE(op);
}

int botan_pk_op_key_agreement_export_public(botan_privkey_t key, uint8_t out[], size_t* out_len) {
   return copy_view_bin(out, out_len, botan_pk_op_key_agreement_view_public, key);
}

int botan_pk_op_key_agreement_view_public(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(key, [=](const auto& k) -> int {
      if(auto kak = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(&k))
         return invoke_view_callback(view, ctx, kak->public_value());
      else
         return BOTAN_FFI_ERROR_INVALID_INPUT;
   });
}

int botan_pk_op_key_agreement_size(botan_pk_op_ka_t op, size_t* out_len) {
   return BOTAN_FFI_VISIT(op, [=](const auto& o) {
      if(out_len == nullptr)
         return BOTAN_FFI_ERROR_NULL_POINTER;
      *out_len = o.agreed_value_size();
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_key_agreement(botan_pk_op_ka_t op,
                              uint8_t out[],
                              size_t* out_len,
                              const uint8_t other_key[],
                              size_t other_key_len,
                              const uint8_t salt[],
                              size_t salt_len) {
   return BOTAN_FFI_VISIT(op, [=](const auto& o) {
      auto k = o.derive_key(*out_len, other_key, other_key_len, salt, salt_len).bits_of();
      return write_vec_output(out, out_len, k);
   });
}

int botan_pk_op_kem_encrypt_create(botan_pk_op_kem_encrypt_t* op, botan_pubkey_t key_obj, const char* padding) {
   if(op == nullptr || padding == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto pk = std::make_unique<Botan::PK_KEM_Encryptor>(safe_get(key_obj), padding);
      *op = new botan_pk_op_kem_encrypt_struct(std::move(pk));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_kem_encrypt_destroy(botan_pk_op_kem_encrypt_t op) {
   return BOTAN_FFI_CHECKED_DELETE(op);
}

int botan_pk_op_kem_encrypt_shared_key_length(botan_pk_op_kem_encrypt_t op,
                                              size_t desired_shared_key_length,
                                              size_t* output_shared_key_length) {
   if(output_shared_key_length == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(op, [=](auto& kem) {
      *output_shared_key_length = kem.shared_key_length(desired_shared_key_length);
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_kem_encrypt_encapsulated_key_length(botan_pk_op_kem_encrypt_t op,
                                                    size_t* output_encapsulated_key_length) {
   if(output_encapsulated_key_length == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(op, [=](auto& kem) {
      *output_encapsulated_key_length = kem.encapsulated_key_length();
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_kem_encrypt_create_shared_key(botan_pk_op_kem_encrypt_t op,
                                              botan_rng_t rng,
                                              const uint8_t salt[],
                                              size_t salt_len,
                                              size_t desired_shared_key_len,
                                              uint8_t shared_key_out[],
                                              size_t* shared_key_len,
                                              uint8_t encapsulated_key_out[],
                                              size_t* encapsulated_key_len) {
   return BOTAN_FFI_VISIT(op, [=](auto& kem) {
      const auto result = kem.encrypt(safe_get(rng), desired_shared_key_len, {salt, salt_len});

      int rc = write_vec_output(encapsulated_key_out, encapsulated_key_len, result.encapsulated_shared_key());

      if(rc != 0)
         return rc;

      return write_vec_output(shared_key_out, shared_key_len, result.shared_key());
   });
}

int botan_pk_op_kem_decrypt_create(botan_pk_op_kem_decrypt_t* op, botan_privkey_t key_obj, const char* padding) {
   if(op == nullptr || padding == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto pk = std::make_unique<Botan::PK_KEM_Decryptor>(safe_get(key_obj), Botan::system_rng(), padding);
      *op = new botan_pk_op_kem_decrypt_struct(std::move(pk));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_kem_decrypt_shared_key_length(botan_pk_op_kem_decrypt_t op,
                                              size_t desired_shared_key_length,
                                              size_t* output_shared_key_length) {
   if(output_shared_key_length == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(op, [=](auto& kem) {
      *output_shared_key_length = kem.shared_key_length(desired_shared_key_length);
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_pk_op_kem_decrypt_shared_key(botan_pk_op_kem_decrypt_t op,
                                       const uint8_t salt[],
                                       size_t salt_len,
                                       const uint8_t encapsulated_key[],
                                       size_t encapsulated_key_len,
                                       size_t desired_shared_key_len,
                                       uint8_t shared_key_out[],
                                       size_t* shared_key_len) {
   return BOTAN_FFI_VISIT(op, [=](auto& kem) {
      const auto shared_key =
         kem.decrypt(encapsulated_key, encapsulated_key_len, desired_shared_key_len, salt, salt_len);

      write_vec_output(shared_key_out, shared_key_len, shared_key);
   });
}

int botan_pk_op_kem_decrypt_destroy(botan_pk_op_kem_decrypt_t op) {
   return BOTAN_FFI_CHECKED_DELETE(op);
}
}

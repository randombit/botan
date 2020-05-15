/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/pubkey.h>

extern "C" {

using namespace Botan_FFI;

BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_encrypt_struct, Botan::PK_Encryptor, 0x891F3FC3);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_decrypt_struct, Botan::PK_Decryptor, 0x912F3C37);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_sign_struct, Botan::PK_Signer, 0x1AF0C39F);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_verify_struct, Botan::PK_Verifier, 0x2B91F936);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_ka_struct, Botan::PK_Key_Agreement, 0x2939CAB1);

int botan_pk_op_encrypt_create(botan_pk_op_encrypt_t* op,
                               botan_pubkey_t key_obj,
                               const char* padding,
                               uint32_t flags)
   {
   if(op == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   if(flags != 0 && flags != BOTAN_PUBKEY_DER_FORMAT_SIGNATURE)
      return BOTAN_FFI_ERROR_BAD_FLAG;

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;

      std::unique_ptr<Botan::PK_Encryptor> pk(new Botan::PK_Encryptor_EME(safe_get(key_obj), Botan::system_rng(), padding));
      *op = new botan_pk_op_encrypt_struct(pk.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_pk_op_encrypt_destroy(botan_pk_op_encrypt_t op)
   {
   return BOTAN_FFI_CHECKED_DELETE(op);
   }

int botan_pk_op_encrypt_output_length(botan_pk_op_encrypt_t op, size_t ptext_len, size_t* ctext_len)
   {
   if(ctext_len == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;
   return BOTAN_FFI_DO(Botan::PK_Encryptor, op, o, { *ctext_len = o.ciphertext_length(ptext_len); });
   }

int botan_pk_op_encrypt(botan_pk_op_encrypt_t op,
                        botan_rng_t rng_obj,
                        uint8_t out[], size_t* out_len,
                        const uint8_t plaintext[], size_t plaintext_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Encryptor, op, o, {
      return write_vec_output(out, out_len, o.encrypt(plaintext, plaintext_len, safe_get(rng_obj)));
      });
   }

/*
* Public Key Decryption
*/
int botan_pk_op_decrypt_create(botan_pk_op_decrypt_t* op,
                               botan_privkey_t key_obj,
                               const char* padding,
                               uint32_t flags)
   {
   if(op == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   if(flags != 0)
      return BOTAN_FFI_ERROR_BAD_FLAG;

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;

      std::unique_ptr<Botan::PK_Decryptor> pk(new Botan::PK_Decryptor_EME(safe_get(key_obj), Botan::system_rng(), padding));
      *op = new botan_pk_op_decrypt_struct(pk.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_pk_op_decrypt_destroy(botan_pk_op_decrypt_t op)
   {
   return BOTAN_FFI_CHECKED_DELETE(op);
   }

int botan_pk_op_decrypt_output_length(botan_pk_op_decrypt_t op, size_t ctext_len, size_t* ptext_len)
   {
   if(ptext_len == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;
   return BOTAN_FFI_DO(Botan::PK_Decryptor, op, o, { *ptext_len = o.plaintext_length(ctext_len); });
   }

int botan_pk_op_decrypt(botan_pk_op_decrypt_t op,
                        uint8_t out[], size_t* out_len,
                        const uint8_t ciphertext[], size_t ciphertext_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Decryptor, op, o, {
      return write_vec_output(out, out_len, o.decrypt(ciphertext, ciphertext_len));
      });
   }

/*
* Signature Generation
*/
int botan_pk_op_sign_create(botan_pk_op_sign_t* op,
                            botan_privkey_t key_obj,
                            const char* hash,
                            uint32_t flags)
   {
   if(op == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   if(flags != 0 && flags != BOTAN_PUBKEY_DER_FORMAT_SIGNATURE)
      return BOTAN_FFI_ERROR_BAD_FLAG;

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;

      auto format = (flags & BOTAN_PUBKEY_DER_FORMAT_SIGNATURE) ? Botan::DER_SEQUENCE : Botan::IEEE_1363;

      std::unique_ptr<Botan::PK_Signer> pk(new Botan::PK_Signer(safe_get(key_obj), Botan::system_rng(), hash, format));
      *op = new botan_pk_op_sign_struct(pk.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_pk_op_sign_destroy(botan_pk_op_sign_t op)
   {
   return BOTAN_FFI_CHECKED_DELETE(op);
   }

int botan_pk_op_sign_output_length(botan_pk_op_sign_t op, size_t* sig_len)
   {
   if(sig_len == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   return BOTAN_FFI_DO(Botan::PK_Signer, op, o, { *sig_len = o.signature_length(); });
   }

int botan_pk_op_sign_update(botan_pk_op_sign_t op, const uint8_t in[], size_t in_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Signer, op, o, { o.update(in, in_len); });
   }

int botan_pk_op_sign_finish(botan_pk_op_sign_t op, botan_rng_t rng_obj, uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Signer, op, o, {
      return write_vec_output(out, out_len, o.signature(safe_get(rng_obj)));
      });
   }

int botan_pk_op_verify_create(botan_pk_op_verify_t* op,
                              botan_pubkey_t key_obj,
                              const char* hash,
                              uint32_t flags)
   {
   if(op == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   if(flags != 0 && flags != BOTAN_PUBKEY_DER_FORMAT_SIGNATURE)
      return BOTAN_FFI_ERROR_BAD_FLAG;

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;
      auto format = (flags & BOTAN_PUBKEY_DER_FORMAT_SIGNATURE) ? Botan::DER_SEQUENCE : Botan::IEEE_1363;
      std::unique_ptr<Botan::PK_Verifier> pk(new Botan::PK_Verifier(safe_get(key_obj), hash, format));
      *op = new botan_pk_op_verify_struct(pk.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_pk_op_verify_destroy(botan_pk_op_verify_t op)
   {
   return BOTAN_FFI_CHECKED_DELETE(op);
   }

int botan_pk_op_verify_update(botan_pk_op_verify_t op, const uint8_t in[], size_t in_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Verifier, op, o, { o.update(in, in_len); });
   }

int botan_pk_op_verify_finish(botan_pk_op_verify_t op, const uint8_t sig[], size_t sig_len)
   {
   return BOTAN_FFI_RETURNING(Botan::PK_Verifier, op, o, {
      const bool legit = o.check_signature(sig, sig_len);

      if(legit)
         return BOTAN_FFI_SUCCESS;
      else
         return BOTAN_FFI_INVALID_VERIFIER;
      });
   }

int botan_pk_op_key_agreement_create(botan_pk_op_ka_t* op,
                                     botan_privkey_t key_obj,
                                     const char* kdf,
                                     uint32_t flags)
   {
   if(op == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   if(flags != 0)
      return BOTAN_FFI_ERROR_BAD_FLAG;

   return ffi_guard_thunk(__func__, [=]() -> int {
      *op = nullptr;
      std::unique_ptr<Botan::PK_Key_Agreement> pk(new Botan::PK_Key_Agreement(safe_get(key_obj), Botan::system_rng(), kdf));
      *op = new botan_pk_op_ka_struct(pk.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_pk_op_key_agreement_destroy(botan_pk_op_ka_t op)
   {
   return BOTAN_FFI_CHECKED_DELETE(op);
   }

int botan_pk_op_key_agreement_export_public(botan_privkey_t key,
                                            uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      if(auto kak = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(&k))
         return write_vec_output(out, out_len, kak->public_value());
      return BOTAN_FFI_ERROR_BAD_FLAG;
      });
   }

int botan_pk_op_key_agreement_size(botan_pk_op_ka_t op, size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Key_Agreement, op, o, {
      if(out_len == nullptr)
         return BOTAN_FFI_ERROR_NULL_POINTER;
      *out_len = o.agreed_value_size();
      });
   }

int botan_pk_op_key_agreement(botan_pk_op_ka_t op,
                              uint8_t out[], size_t* out_len,
                              const uint8_t other_key[], size_t other_key_len,
                              const uint8_t salt[], size_t salt_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Key_Agreement, op, o, {
      auto k = o.derive_key(*out_len, other_key, other_key_len, salt, salt_len).bits_of();
      return write_vec_output(out, out_len, k);
      });
   }

}

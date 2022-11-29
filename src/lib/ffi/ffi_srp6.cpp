/*
* (C) 2022 Rostyslav Khudolii
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/bigint.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>
#include <botan/rng.h>
#include <botan/srp6.h>
#include <botan/symkey.h>

extern "C" {

   using namespace Botan_FFI;

   BOTAN_FFI_DECLARE_STRUCT(botan_srp6_server_session_struct,
                            Botan::SRP6_Server_Session, 0x44F7425F);

   int botan_srp6_server_session_init(botan_srp6_server_session_t* srp6)
      {
      return ffi_guard_thunk(__func__, [=]() -> int
         {
         *srp6 = new botan_srp6_server_session_struct(
            std::make_unique<Botan::SRP6_Server_Session>());
         return BOTAN_FFI_SUCCESS;
         });
      }

   int botan_srp6_server_session_destroy(botan_srp6_server_session_t srp6)
      {
      return BOTAN_FFI_CHECKED_DELETE(srp6);
      }

   int botan_srp6_server_session_step1(botan_srp6_server_session_t srp6,
                                       const uint8_t* verifier,
                                       size_t verifier_len, const char* group_id,
                                       const char* hash_id, botan_rng_t rng_obj,
                                       uint8_t b_pub[], size_t* b_pub_len)
      {
      return BOTAN_FFI_VISIT(srp6, [=](auto& s) -> int
         {
         if(!verifier || !group_id || !hash_id || !rng_obj)
            {
            return BOTAN_FFI_ERROR_NULL_POINTER;
            }
         try
            {
            Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
            auto v_bn = Botan::BigInt::decode(verifier, verifier_len);
            auto b_pub_bn = s.step1(v_bn, group_id, hash_id, rng);
            return write_vec_output(b_pub, b_pub_len,
                                    Botan::BigInt::encode(b_pub_bn));
            }
         catch(Botan::Decoding_Error&)
            {
            return BOTAN_FFI_ERROR_BAD_PARAMETER;
            }
         catch(Botan::Lookup_Error&)
            {
            return BOTAN_FFI_ERROR_BAD_PARAMETER;
            }
         });
      }

   int botan_srp6_server_session_step2(botan_srp6_server_session_t srp6,
                                       const uint8_t a[], size_t a_len,
                                       uint8_t key[], size_t* key_len)
      {
      return BOTAN_FFI_VISIT(srp6, [=](auto& s) -> int
         {
         if(!a)
            {
            return BOTAN_FFI_ERROR_NULL_POINTER;
            }
         try
            {
            Botan::BigInt a_bn = Botan::BigInt::decode(a, a_len);
            auto key_sk = s.step2(a_bn);
            return write_vec_output(key, key_len, key_sk.bits_of());
            }
         catch(Botan::Decoding_Error&)
            {
            return BOTAN_FFI_ERROR_BAD_PARAMETER;
            }
         });
      }

   int botan_generate_srp6_verifier(const char* username, const char* password,
                                    const uint8_t salt[], size_t salt_len,
                                    const char* group_id, const char* hash_id,
                                    uint8_t verifier[], size_t* verifier_len)
      {
      return ffi_guard_thunk(__func__, [=]() -> int
         {
         if(!username || !password || !salt || !group_id || !hash_id)
            {
            return BOTAN_FFI_ERROR_NULL_POINTER;
            }
         try
            {
            std::vector<uint8_t> salt_vec(salt, salt + salt_len);
            auto verifier_bn = Botan::generate_srp6_verifier(
               username, password, salt_vec, group_id, hash_id);
            return write_vec_output(verifier, verifier_len,
                                    Botan::BigInt::encode(verifier_bn));
            }
         catch(Botan::Lookup_Error&)
            {
            return BOTAN_FFI_ERROR_BAD_PARAMETER;
            }
         });
      }

   int botan_srp6_client_agree(const char* identity, const char* password,
                               const char* group_id, const char* hash_id,
                               const uint8_t salt[], size_t salt_len,
                               const uint8_t b[], size_t b_len, botan_rng_t rng_obj,
                               uint8_t A[], size_t* A_len, uint8_t K[],
                               size_t* K_len)
      {
      return ffi_guard_thunk(__func__, [=]() -> int
         {
         if(!identity || !password || !salt || !group_id || !hash_id || !b || !rng_obj)
            {
            return BOTAN_FFI_ERROR_NULL_POINTER;
            }
         try
            {
            std::vector<uint8_t> saltv(salt, salt + salt_len);
            Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
            auto b_bn = Botan::BigInt::decode(b, b_len);
            auto [A_bn, K_sk] = Botan::srp6_client_agree(
               identity, password, group_id, hash_id, saltv, b_bn, rng);
            auto ret_a = write_vec_output(A, A_len, Botan::BigInt::encode(A_bn));
            auto ret_k = write_vec_output(K, K_len, K_sk.bits_of());
            if(ret_a != BOTAN_FFI_SUCCESS)
               {
               return ret_a;
               }
            if(ret_k != BOTAN_FFI_SUCCESS)
               {
               return ret_k;
               }
            return BOTAN_FFI_SUCCESS;
            }
         catch(Botan::Lookup_Error&)
            {
            return BOTAN_FFI_ERROR_BAD_PARAMETER;
            }
         });
      }

   }

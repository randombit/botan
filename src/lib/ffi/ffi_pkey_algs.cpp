/*
* (C) 2015,2017 Jack Lloyd
* (C) 2017 Ribose Inc
* (C) 2018 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/hash.h>
#include <botan/pem.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_mp.h>

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
  #include <botan/ecc_key.h>
#endif

#if defined(BOTAN_HAS_DL_PUBLIC_KEY_FAMILY)
  #include <botan/dl_algo.h>
#endif

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_SM2)
  #include <botan/sm2.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

#if defined(BOTAN_HAS_ED25519)
  #include <botan/ed25519.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
  #include <botan/mceliece.h>
#endif

#if defined(BOTAN_HAS_MCEIES)
  #include <botan/mceies.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif


namespace {

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

// These are always called within an existing try/catch block

template<class ECPrivateKey_t>
int privkey_load_ec(std::unique_ptr<ECPrivateKey_t>& key,
                    const Botan::BigInt& scalar,
                    const char* curve_name)
   {
   if(curve_name == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   Botan::Null_RNG null_rng;
   Botan::EC_Group grp(curve_name);
   key.reset(new ECPrivateKey_t(null_rng, grp, scalar));
   return BOTAN_FFI_SUCCESS;
   }

template<class ECPublicKey_t>
int pubkey_load_ec(std::unique_ptr<ECPublicKey_t>& key,
                   const Botan::BigInt& public_x,
                   const Botan::BigInt& public_y,
                   const char* curve_name)
   {
   if(curve_name == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   Botan::EC_Group grp(curve_name);
   Botan::PointGFp uncompressed_point = grp.point(public_x, public_y);
   key.reset(new ECPublicKey_t(grp, uncompressed_point));
   return BOTAN_FFI_SUCCESS;
   }

#endif

Botan::BigInt pubkey_get_field(const Botan::Public_Key& key,
                               const std::string& field)
   {
   // Maybe this should be `return key.get_integer_field(field_name)`?

#if defined(BOTAN_HAS_RSA)
   if(const Botan::RSA_PublicKey* rsa = dynamic_cast<const Botan::RSA_PublicKey*>(&key))
      {
      if(field == "n")
         return rsa->get_n();
      else if(field == "e")
         return rsa->get_e();
      else
         throw Botan_FFI::FFI_Error("Bad field", BOTAN_FFI_ERROR_BAD_PARAMETER);
      }
#endif

#if defined(BOTAN_HAS_DL_PUBLIC_KEY_FAMILY)
   // Handles DSA, ElGamal, etc
   if(const Botan::DL_Scheme_PublicKey* dl = dynamic_cast<const Botan::DL_Scheme_PublicKey*>(&key))
      {
      if(field == "p")
         return dl->group_p();
      else if(field == "q")
         return dl->group_q();
      else if(field == "g")
         return dl->group_g();
      else if(field == "y")
         return dl->get_y();
      else
         throw Botan_FFI::FFI_Error("Bad field", BOTAN_FFI_ERROR_BAD_PARAMETER);
      }
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   if(const Botan::EC_PublicKey* ecc = dynamic_cast<const Botan::EC_PublicKey*>(&key))
      {
      if(field == "public_x")
         return ecc->public_point().get_affine_x();
      else if(field == "public_y")
         return ecc->public_point().get_affine_y();
      else if(field == "base_x")
         return ecc->domain().get_g_x();
      else if(field == "base_y")
         return ecc->domain().get_g_y();
      else if(field == "p")
         return ecc->domain().get_p();
      else if(field == "a")
         return ecc->domain().get_a();
      else if(field == "b")
         return ecc->domain().get_b();
      else if(field == "cofactor")
         return ecc->domain().get_cofactor();
      else if(field == "order")
         return ecc->domain().get_order();
      else
         throw Botan_FFI::FFI_Error("Bad field", BOTAN_FFI_ERROR_BAD_PARAMETER);
      }
#endif

   // Some other algorithm type not supported by this function
   throw Botan_FFI::FFI_Error("Field getter not implemented for this algorithm type",
                              BOTAN_FFI_ERROR_NOT_IMPLEMENTED);
   }

Botan::BigInt privkey_get_field(const Botan::Private_Key& key,
                                const std::string& field)
   {
   //return key.get_integer_field(field);

#if defined(BOTAN_HAS_RSA)

   if(const Botan::RSA_PrivateKey* rsa = dynamic_cast<const Botan::RSA_PrivateKey*>(&key))
      {
      if(field == "p")
         return rsa->get_p();
      else if(field == "q")
         return rsa->get_q();
      else if(field == "d")
         return rsa->get_d();
      else if(field == "c")
         return rsa->get_c();
      else if(field == "d1")
         return rsa->get_d1();
      else if(field == "d2")
         return rsa->get_d2();
      else
         return pubkey_get_field(key, field);
      }
#endif

#if defined(BOTAN_HAS_DL_PUBLIC_KEY_FAMILY)
   // Handles DSA, ElGamal, etc
   if(const Botan::DL_Scheme_PrivateKey* dl = dynamic_cast<const Botan::DL_Scheme_PrivateKey*>(&key))
      {
      if(field == "x")
         return dl->get_x();
      else
         return pubkey_get_field(key, field);
      }
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   if(const Botan::EC_PrivateKey* ecc = dynamic_cast<const Botan::EC_PrivateKey*>(&key))
      {
      if(field == "x")
         return ecc->private_value();
      else
         return pubkey_get_field(key, field);
      }
#endif

   return pubkey_get_field(key, field);
   }

}

extern "C" {

using namespace Botan_FFI;

int botan_pubkey_get_field(botan_mp_t output,
                           botan_pubkey_t key,
                           const char* field_name_cstr)
   {
   if(field_name_cstr == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   const std::string field_name(field_name_cstr);

   return BOTAN_FFI_DO(Botan::Public_Key, key, k, {
      safe_get(output) = pubkey_get_field(k, field_name);
      });
   }

int botan_privkey_get_field(botan_mp_t output,
                            botan_privkey_t key,
                            const char* field_name_cstr)
   {
   if(field_name_cstr == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   const std::string field_name(field_name_cstr);

   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      safe_get(output) = privkey_get_field(k, field_name);
      });
   }

/* RSA specific operations */

int botan_privkey_create_rsa(botan_privkey_t* key_obj, botan_rng_t rng_obj, size_t n_bits)
   {
   if(n_bits < 1024 || n_bits > 16*1024)
      return BOTAN_FFI_ERROR_BAD_PARAMETER;

   std::string n_str = std::to_string(n_bits);

   return botan_privkey_create(key_obj, "RSA", n_str.c_str(), rng_obj);
   }

int botan_privkey_load_rsa(botan_privkey_t* key,
                           botan_mp_t rsa_p, botan_mp_t rsa_q, botan_mp_t rsa_e)
   {
#if defined(BOTAN_HAS_RSA)
   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      *key = new botan_privkey_struct(new Botan::RSA_PrivateKey(safe_get(rsa_p),
                                                                safe_get(rsa_q),
                                                                safe_get(rsa_e)));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, rsa_p, rsa_q, rsa_e);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_load_rsa_pkcs1(botan_privkey_t* key,
                                 const uint8_t bits[],
                                 size_t len)
   {
#if defined(BOTAN_HAS_RSA)
   *key = nullptr;

   Botan::secure_vector<uint8_t> src(bits, bits + len);
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::AlgorithmIdentifier alg_id("RSA", Botan::AlgorithmIdentifier::USE_NULL_PARAM);
      *key = new botan_privkey_struct(new Botan::RSA_PrivateKey(alg_id, src));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, bits, len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_rsa(botan_pubkey_t* key,
                          botan_mp_t n, botan_mp_t e)
   {
#if defined(BOTAN_HAS_RSA)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      *key = new botan_pubkey_struct(new Botan::RSA_PublicKey(safe_get(n), safe_get(e)));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, n, e);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_rsa_get_p(botan_mp_t p, botan_privkey_t key)
   {
   return botan_privkey_get_field(p, key, "p");
   }

int botan_privkey_rsa_get_q(botan_mp_t q, botan_privkey_t key)
   {
   return botan_privkey_get_field(q, key, "q");
   }

int botan_privkey_rsa_get_n(botan_mp_t n, botan_privkey_t key)
   {
   return botan_privkey_get_field(n, key, "n");
   }

int botan_privkey_rsa_get_e(botan_mp_t e, botan_privkey_t key)
   {
   return botan_privkey_get_field(e, key, "e");
   }

int botan_privkey_rsa_get_d(botan_mp_t d, botan_privkey_t key)
   {
   return botan_privkey_get_field(d, key, "d");
   }

int botan_pubkey_rsa_get_e(botan_mp_t e, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(e, key, "e");
   }

int botan_pubkey_rsa_get_n(botan_mp_t n, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(n, key, "n");
   }

int botan_privkey_rsa_get_privkey(botan_privkey_t rsa_key,
                                  uint8_t out[], size_t* out_len,
                                  uint32_t flags)
   {
#if defined(BOTAN_HAS_RSA)
   return BOTAN_FFI_DO(Botan::Private_Key, rsa_key, k, {
      if(const Botan::RSA_PrivateKey* rsa = dynamic_cast<const Botan::RSA_PrivateKey*>(&k))
         {
         if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
            return write_vec_output(out, out_len, rsa->private_key_bits());
         else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
            return write_str_output(out, out_len, Botan::PEM_Code::encode(rsa->private_key_bits(),
                  "RSA PRIVATE KEY"));
         else
            return BOTAN_FFI_ERROR_BAD_FLAG;
         }
      else
         {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
         }
      });
#else
   BOTAN_UNUSED(rsa_key, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

/* DSA specific operations */
int botan_privkey_create_dsa(botan_privkey_t* key, botan_rng_t rng_obj, size_t pbits, size_t qbits)
   {
#if defined(BOTAN_HAS_DSA)

    if ((rng_obj == nullptr) || (key == nullptr))
      return BOTAN_FFI_ERROR_NULL_POINTER;

    if ((pbits % 64) || (qbits % 8) ||
        (pbits < 1024) || (pbits > 3072) ||
        (qbits < 160) || (qbits > 256)) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
    }

    return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      Botan::DL_Group group(rng, Botan::DL_Group::Prime_Subgroup, pbits, qbits);
      *key = new botan_privkey_struct(new Botan::DSA_PrivateKey(rng, group));
      return BOTAN_FFI_SUCCESS;
    });
#else
    BOTAN_UNUSED(key, rng_obj, pbits, qbits);
    return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_load_dsa(botan_privkey_t* key,
                           botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t x)
   {
#if defined(BOTAN_HAS_DSA)
   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::Null_RNG null_rng;
      Botan::DL_Group group(safe_get(p), safe_get(q), safe_get(g));
      *key = new botan_privkey_struct(new Botan::DSA_PrivateKey(null_rng, group, safe_get(x)));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, p, q, g, x);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_dsa(botan_pubkey_t* key,
                          botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t y)
   {
#if defined(BOTAN_HAS_DSA)
   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(q), safe_get(g));
      *key = new botan_pubkey_struct(new Botan::DSA_PublicKey(group, safe_get(y)));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, p, q, g, y);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_dsa_get_x(botan_mp_t x, botan_privkey_t key)
   {
   return botan_privkey_get_field(x, key, "x");
   }

int botan_pubkey_dsa_get_p(botan_mp_t p, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(p, key, "p");
   }

int botan_pubkey_dsa_get_q(botan_mp_t q, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(q, key, "q");
   }

int botan_pubkey_dsa_get_g(botan_mp_t g, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(g, key, "g");
   }

int botan_pubkey_dsa_get_y(botan_mp_t y, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(y, key, "y");
   }

int botan_privkey_create_ecdsa(botan_privkey_t* key_obj, botan_rng_t rng_obj, const char* param_str)
   {
   return botan_privkey_create(key_obj, "ECDSA", param_str, rng_obj);
   }

/* ECDSA specific operations */

int botan_pubkey_load_ecdsa(botan_pubkey_t* key,
                            const botan_mp_t public_x,
                            const botan_mp_t public_y,
                            const char* curve_name)
   {
#if defined(BOTAN_HAS_ECDSA)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::ECDSA_PublicKey> p_key;

      int rc = pubkey_load_ec(p_key, safe_get(public_x), safe_get(public_y), curve_name);
      if(rc == BOTAN_FFI_SUCCESS)
         *key = new botan_pubkey_struct(p_key.release());

      return rc;
      });
#else
   BOTAN_UNUSED(key, public_x, public_y, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_load_ecdsa(botan_privkey_t* key,
                             const botan_mp_t scalar,
                             const char* curve_name)
   {
#if defined(BOTAN_HAS_ECDSA)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::ECDSA_PrivateKey> p_key;
      int rc = privkey_load_ec(p_key, safe_get(scalar), curve_name);
      if(rc == BOTAN_FFI_SUCCESS)
         *key = new botan_privkey_struct(p_key.release());
      return rc;
      });
#else
   BOTAN_UNUSED(key, scalar, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

/* ElGamal specific operations */
int botan_privkey_create_elgamal(botan_privkey_t* key,
                                 botan_rng_t rng_obj,
                                 size_t pbits,
                                 size_t qbits)
   {
#if defined(BOTAN_HAS_ELGAMAL)

    if ((rng_obj == nullptr) || (key == nullptr))
      return BOTAN_FFI_ERROR_NULL_POINTER;

    if ((pbits < 1024) || (qbits<160)) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
    }

    Botan::DL_Group::PrimeType prime_type = ((pbits-1) == qbits)
      ? Botan::DL_Group::Strong
      : Botan::DL_Group::Prime_Subgroup;

    return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      Botan::DL_Group group(rng, prime_type, pbits, qbits);
      *key = new botan_privkey_struct(new Botan::ElGamal_PrivateKey(rng, group));
      return BOTAN_FFI_SUCCESS;
    });
#else
    BOTAN_UNUSED(key, rng_obj, pbits);
    return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_elgamal(botan_pubkey_t* key,
                              botan_mp_t p, botan_mp_t g, botan_mp_t y)
   {
#if defined(BOTAN_HAS_ELGAMAL)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(g));
      *key = new botan_pubkey_struct(new Botan::ElGamal_PublicKey(group, safe_get(y)));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, p, g, y);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_load_elgamal(botan_privkey_t* key,
                               botan_mp_t p, botan_mp_t g, botan_mp_t x)
   {
#if defined(BOTAN_HAS_ELGAMAL)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::Null_RNG null_rng;
      Botan::DL_Group group(safe_get(p), safe_get(g));
      *key = new botan_privkey_struct(new Botan::ElGamal_PrivateKey(null_rng, group, safe_get(x)));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, p, g, x);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

/* Diffie Hellman specific operations */

int botan_privkey_create_dh(botan_privkey_t* key_obj, botan_rng_t rng_obj, const char* param_str)
   {
   return botan_privkey_create(key_obj, "DH", param_str, rng_obj);
   }

int botan_privkey_load_dh(botan_privkey_t* key,
                          botan_mp_t p, botan_mp_t g, botan_mp_t x)
   {
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::Null_RNG null_rng;
      Botan::DL_Group group(safe_get(p), safe_get(g));
      *key = new botan_privkey_struct(new Botan::DH_PrivateKey(null_rng, group, safe_get(x)));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, p, g, x);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_dh(botan_pubkey_t* key,
                         botan_mp_t p, botan_mp_t g, botan_mp_t y)
   {
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(g));
      *key = new botan_pubkey_struct(new Botan::DH_PublicKey(group, safe_get(y)));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, p, g, y);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

/* ECDH + x25519 specific operations */

int botan_privkey_create_ecdh(botan_privkey_t* key_obj, botan_rng_t rng_obj, const char* param_str)
   {
   if(param_str == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   const std::string params(param_str);

   if(params == "curve25519")
      return botan_privkey_create(key_obj, "Curve25519", "", rng_obj);

   return botan_privkey_create(key_obj, "ECDH", param_str, rng_obj);
   }

int botan_pubkey_load_ecdh(botan_pubkey_t* key,
                           const botan_mp_t public_x,
                           const botan_mp_t public_y,
                           const char* curve_name)
   {
#if defined(BOTAN_HAS_ECDH)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::ECDH_PublicKey> p_key;
      int rc = pubkey_load_ec(p_key, safe_get(public_x), safe_get(public_y), curve_name);

      if(rc == BOTAN_FFI_SUCCESS)
         *key = new botan_pubkey_struct(p_key.release());
      return rc;
      });
#else
   BOTAN_UNUSED(key, public_x, public_y, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_load_ecdh(botan_privkey_t* key,
                            const botan_mp_t scalar,
                            const char* curve_name)
   {
#if defined(BOTAN_HAS_ECDH)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::ECDH_PrivateKey> p_key;
      int rc = privkey_load_ec(p_key, safe_get(scalar), curve_name);
      if(rc == BOTAN_FFI_SUCCESS)
         *key = new botan_privkey_struct(p_key.release());
      return rc;
      });
#else
   BOTAN_UNUSED(key, scalar, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

/* SM2 specific operations */

int botan_pubkey_sm2_compute_za(uint8_t out[],
                                size_t* out_len,
                                const char* ident,
                                const char* hash_algo,
                                const botan_pubkey_t key)
   {
   if(out == nullptr || out_len == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;
   if(ident == nullptr || hash_algo == nullptr || key == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

#if defined(BOTAN_HAS_SM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::Public_Key& pub_key = safe_get(key);
      const Botan::EC_PublicKey* ec_key = dynamic_cast<const Botan::EC_PublicKey*>(&pub_key);

      if(ec_key == nullptr)
         return BOTAN_FFI_ERROR_BAD_PARAMETER;

      if(ec_key->algo_name() != "SM2")
         return BOTAN_FFI_ERROR_BAD_PARAMETER;

      const std::string ident_str(ident);
      std::unique_ptr<Botan::HashFunction> hash =
         Botan::HashFunction::create_or_throw(hash_algo);

      const std::vector<uint8_t> za =
         Botan::sm2_compute_za(*hash, ident_str, ec_key->domain(), ec_key->public_point());

      return write_vec_output(out, out_len, za);
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_sm2(botan_pubkey_t* key,
                          const botan_mp_t public_x,
                          const botan_mp_t public_y,
                          const char* curve_name)
   {
#if defined(BOTAN_HAS_SM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::SM2_PublicKey> p_key;
      if(!pubkey_load_ec(p_key, safe_get(public_x), safe_get(public_y), curve_name))
         {
         *key = new botan_pubkey_struct(p_key.release());
         return BOTAN_FFI_SUCCESS;
         }
      return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
      });
#else
   BOTAN_UNUSED(key, public_x, public_y, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_load_sm2(botan_privkey_t* key,
                           const botan_mp_t scalar,
                           const char* curve_name)
   {
#if defined(BOTAN_HAS_SM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::SM2_PrivateKey> p_key;
      int rc = privkey_load_ec(p_key, safe_get(scalar), curve_name);

      if(rc == BOTAN_FFI_SUCCESS)
         *key = new botan_privkey_struct(p_key.release());
      return rc;
      });
#else
   BOTAN_UNUSED(key, scalar, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_sm2_enc(botan_pubkey_t* key,
                              const botan_mp_t public_x,
                              const botan_mp_t public_y,
                              const char* curve_name)
   {
   return botan_pubkey_load_sm2(key, public_x, public_y, curve_name);
   }

int botan_privkey_load_sm2_enc(botan_privkey_t* key,
                               const botan_mp_t scalar,
                               const char* curve_name)
   {
   return botan_privkey_load_sm2(key, scalar, curve_name);
   }

/* Ed25519 specific operations */

int botan_privkey_load_ed25519(botan_privkey_t* key,
                               const uint8_t privkey[32])
   {
#if defined(BOTAN_HAS_ED25519)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::secure_vector<uint8_t> privkey_vec(privkey, privkey + 32);
      *key = new botan_privkey_struct(new Botan::Ed25519_PrivateKey(privkey_vec));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, privkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_ed25519(botan_pubkey_t* key,
                              const uint8_t pubkey[32])
   {
#if defined(BOTAN_HAS_ED25519)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::vector<uint8_t> pubkey_vec(pubkey, pubkey + 32);
      *key = new botan_pubkey_struct(new Botan::Ed25519_PublicKey(pubkey_vec));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, pubkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_ed25519_get_privkey(botan_privkey_t key,
                                      uint8_t output[64])
   {
#if defined(BOTAN_HAS_ED25519)
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      if(Botan::Ed25519_PrivateKey* ed = dynamic_cast<Botan::Ed25519_PrivateKey*>(&k))
         {
         const Botan::secure_vector<uint8_t>& ed_key = ed->get_private_key();
         if(ed_key.size() != 64)
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         Botan::copy_mem(output, ed_key.data(), ed_key.size());
         return BOTAN_FFI_SUCCESS;
         }
      else
         {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
         }
      });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_ed25519_get_pubkey(botan_pubkey_t key,
                                    uint8_t output[32])
   {
#if defined(BOTAN_HAS_ED25519)
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, {
      if(Botan::Ed25519_PublicKey* ed = dynamic_cast<Botan::Ed25519_PublicKey*>(&k))
         {
         const std::vector<uint8_t>& ed_key = ed->get_public_key();
         if(ed_key.size() != 32)
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         Botan::copy_mem(output, ed_key.data(), ed_key.size());
         return BOTAN_FFI_SUCCESS;
         }
      else
         {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
         }
      });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

/* X25519 specific operations */

int botan_privkey_load_x25519(botan_privkey_t* key,
                              const uint8_t privkey[32])
   {
#if defined(BOTAN_HAS_X25519)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::secure_vector<uint8_t> privkey_vec(privkey, privkey + 32);
      *key = new botan_privkey_struct(new Botan::X25519_PrivateKey(privkey_vec));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, privkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_x25519(botan_pubkey_t* key,
                             const uint8_t pubkey[32])
   {
#if defined(BOTAN_HAS_X25519)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::vector<uint8_t> pubkey_vec(pubkey, pubkey + 32);
      *key = new botan_pubkey_struct(new Botan::X25519_PublicKey(pubkey_vec));
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(key, pubkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_x25519_get_privkey(botan_privkey_t key,
                                     uint8_t output[32])
   {
#if defined(BOTAN_HAS_X25519)
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      if(Botan::X25519_PrivateKey* x25519 = dynamic_cast<Botan::X25519_PrivateKey*>(&k))
         {
         const Botan::secure_vector<uint8_t>& x25519_key = x25519->get_x();
         if(x25519_key.size() != 32)
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         Botan::copy_mem(output, x25519_key.data(), x25519_key.size());
         return BOTAN_FFI_SUCCESS;
         }
      else
         {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
         }
      });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_x25519_get_pubkey(botan_pubkey_t key,
                                   uint8_t output[32])
   {
#if defined(BOTAN_HAS_X25519)
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, {
      if(Botan::X25519_PublicKey* x25519 = dynamic_cast<Botan::X25519_PublicKey*>(&k))
         {
         const std::vector<uint8_t>& x25519_key = x25519->public_value();
         if(x25519_key.size() != 32)
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         Botan::copy_mem(output, x25519_key.data(), x25519_key.size());
         return BOTAN_FFI_SUCCESS;
         }
      else
         {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
         }
      });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_create_mceliece(botan_privkey_t* key_obj, botan_rng_t rng_obj, size_t n, size_t t)
   {
   const std::string mce_params = std::to_string(n) + "," + std::to_string(t);
   return botan_privkey_create(key_obj, "McEliece", mce_params.c_str(), rng_obj);
   }

int botan_mceies_decrypt(botan_privkey_t mce_key_obj,
                         const char* aead,
                         const uint8_t ct[], size_t ct_len,
                         const uint8_t ad[], size_t ad_len,
                         uint8_t out[], size_t* out_len)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::Private_Key& key = safe_get(mce_key_obj);

#if defined(BOTAN_HAS_MCELIECE) && defined(BOTAN_HAS_MCEIES)
      Botan::McEliece_PrivateKey* mce = dynamic_cast<Botan::McEliece_PrivateKey*>(&key);
      if(!mce)
         return BOTAN_FFI_ERROR_BAD_PARAMETER;

      const Botan::secure_vector<uint8_t> pt = mceies_decrypt(*mce, ct, ct_len, ad, ad_len, aead);
      return write_vec_output(out, out_len, pt);
#else
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
      });
   }

int botan_mceies_encrypt(botan_pubkey_t mce_key_obj,
                         botan_rng_t rng_obj,
                         const char* aead,
                         const uint8_t pt[], size_t pt_len,
                         const uint8_t ad[], size_t ad_len,
                         uint8_t out[], size_t* out_len)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::Public_Key& key = safe_get(mce_key_obj);
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

#if defined(BOTAN_HAS_MCELIECE) && defined(BOTAN_HAS_MCEIES)
      Botan::McEliece_PublicKey* mce = dynamic_cast<Botan::McEliece_PublicKey*>(&key);
      if(!mce)
         return BOTAN_FFI_ERROR_BAD_PARAMETER;

      Botan::secure_vector<uint8_t> ct = mceies_encrypt(*mce, pt, pt_len, ad, ad_len, rng, aead);
      return write_vec_output(out, out_len, ct);
#else
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
      });
   }

}

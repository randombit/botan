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
#include <botan/internal/ffi_mp.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   #include <botan/ecc_key.h>
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

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif

#if defined(BOTAN_HAS_X448)
   #include <botan/x448.h>
#endif

#if defined(BOTAN_HAS_ED25519)
   #include <botan/ed25519.h>
#endif

#if defined(BOTAN_HAS_ED448)
   #include <botan/ed448.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
   #include <botan/mceliece.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_KYBER)
   #include <botan/kyber.h>
#endif

namespace {

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

// These are always called within an existing try/catch block

template <class ECPrivateKey_t>
int privkey_load_ec(std::unique_ptr<ECPrivateKey_t>& key, const Botan::BigInt& scalar, const char* curve_name) {
   if(curve_name == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   Botan::Null_RNG null_rng;
   const auto grp = Botan::EC_Group::from_name(curve_name);
   key.reset(new ECPrivateKey_t(null_rng, grp, scalar));
   return BOTAN_FFI_SUCCESS;
}

template <class ECPublicKey_t>
int pubkey_load_ec(std::unique_ptr<ECPublicKey_t>& key,
                   const Botan::BigInt& public_x,
                   const Botan::BigInt& public_y,
                   const char* curve_name) {
   if(curve_name == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   const auto grp = Botan::EC_Group::from_name(curve_name);
   Botan::EC_Point uncompressed_point = grp.point(public_x, public_y);
   key.reset(new ECPublicKey_t(grp, uncompressed_point));
   return BOTAN_FFI_SUCCESS;
}

#endif

Botan::BigInt pubkey_get_field(const Botan::Public_Key& key, std::string_view field) {
#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   // Not currently handled by get_int_field
   if(const Botan::EC_PublicKey* ecc = dynamic_cast<const Botan::EC_PublicKey*>(&key)) {
      if(field == "public_x") {
         return ecc->public_point().get_affine_x();
      } else if(field == "public_y") {
         return ecc->public_point().get_affine_y();
      }
   }
#endif

   try {
      return key.get_int_field(field);
   } catch(Botan::Unknown_PK_Field_Name&) {
      throw Botan_FFI::FFI_Error("Unknown key field", BOTAN_FFI_ERROR_BAD_PARAMETER);
   }
}

Botan::BigInt privkey_get_field(const Botan::Private_Key& key, std::string_view field) {
#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   // Not currently handled by get_int_field
   if(const Botan::EC_PublicKey* ecc = dynamic_cast<const Botan::EC_PublicKey*>(&key)) {
      if(field == "public_x") {
         return ecc->public_point().get_affine_x();
      } else if(field == "public_y") {
         return ecc->public_point().get_affine_y();
      }
   }
#endif

   try {
      return key.get_int_field(field);
   } catch(Botan::Unknown_PK_Field_Name&) {
      throw Botan_FFI::FFI_Error("Unknown key field", BOTAN_FFI_ERROR_BAD_PARAMETER);
   }
}

}  // namespace

extern "C" {

using namespace Botan_FFI;

int botan_pubkey_get_field(botan_mp_t output, botan_pubkey_t key, const char* field_name_cstr) {
   if(field_name_cstr == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   const std::string field_name(field_name_cstr);

   return BOTAN_FFI_VISIT(key, [=](const auto& k) { safe_get(output) = pubkey_get_field(k, field_name); });
}

int botan_privkey_get_field(botan_mp_t output, botan_privkey_t key, const char* field_name_cstr) {
   if(field_name_cstr == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   const std::string field_name(field_name_cstr);

   return BOTAN_FFI_VISIT(key, [=](const auto& k) { safe_get(output) = privkey_get_field(k, field_name); });
}

/* RSA specific operations */

int botan_privkey_create_rsa(botan_privkey_t* key_obj, botan_rng_t rng_obj, size_t n_bits) {
   if(n_bits < 1024 || n_bits > 16 * 1024) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }

   std::string n_str = std::to_string(n_bits);

   return botan_privkey_create(key_obj, "RSA", n_str.c_str(), rng_obj);
}

int botan_privkey_load_rsa(botan_privkey_t* key, botan_mp_t rsa_p, botan_mp_t rsa_q, botan_mp_t rsa_e) {
#if defined(BOTAN_HAS_RSA)
   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto rsa = std::make_unique<Botan::RSA_PrivateKey>(safe_get(rsa_p), safe_get(rsa_q), safe_get(rsa_e));
      *key = new botan_privkey_struct(std::move(rsa));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, rsa_p, rsa_q, rsa_e);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_load_rsa_pkcs1(botan_privkey_t* key, const uint8_t bits[], size_t len) {
#if defined(BOTAN_HAS_RSA)
   *key = nullptr;

   Botan::secure_vector<uint8_t> src(bits, bits + len);
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::AlgorithmIdentifier alg_id("RSA", Botan::AlgorithmIdentifier::USE_NULL_PARAM);
      auto rsa = std::make_unique<Botan::RSA_PrivateKey>(alg_id, src);
      *key = new botan_privkey_struct(std::move(rsa));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, bits, len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_rsa(botan_pubkey_t* key, botan_mp_t n, botan_mp_t e) {
#if defined(BOTAN_HAS_RSA)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto rsa = std::make_unique<Botan::RSA_PublicKey>(safe_get(n), safe_get(e));
      *key = new botan_pubkey_struct(std::move(rsa));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, n, e);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_rsa_get_p(botan_mp_t p, botan_privkey_t key) {
   return botan_privkey_get_field(p, key, "p");
}

int botan_privkey_rsa_get_q(botan_mp_t q, botan_privkey_t key) {
   return botan_privkey_get_field(q, key, "q");
}

int botan_privkey_rsa_get_n(botan_mp_t n, botan_privkey_t key) {
   return botan_privkey_get_field(n, key, "n");
}

int botan_privkey_rsa_get_e(botan_mp_t e, botan_privkey_t key) {
   return botan_privkey_get_field(e, key, "e");
}

int botan_privkey_rsa_get_d(botan_mp_t d, botan_privkey_t key) {
   return botan_privkey_get_field(d, key, "d");
}

int botan_pubkey_rsa_get_e(botan_mp_t e, botan_pubkey_t key) {
   return botan_pubkey_get_field(e, key, "e");
}

int botan_pubkey_rsa_get_n(botan_mp_t n, botan_pubkey_t key) {
   return botan_pubkey_get_field(n, key, "n");
}

int botan_privkey_rsa_get_privkey(botan_privkey_t rsa_key, uint8_t out[], size_t* out_len, uint32_t flags) {
#if defined(BOTAN_HAS_RSA)
   return BOTAN_FFI_VISIT(rsa_key, [=](const auto& k) -> int {
      if(const Botan::RSA_PrivateKey* rsa = dynamic_cast<const Botan::RSA_PrivateKey*>(&k)) {
         if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
            return write_vec_output(out, out_len, rsa->private_key_bits());
         else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
            return write_str_output(out, out_len, Botan::PEM_Code::encode(rsa->private_key_bits(), "RSA PRIVATE KEY"));
         else
            return BOTAN_FFI_ERROR_BAD_FLAG;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(rsa_key, out, out_len, flags);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/* DSA specific operations */
int botan_privkey_create_dsa(botan_privkey_t* key, botan_rng_t rng_obj, size_t pbits, size_t qbits) {
#if defined(BOTAN_HAS_DSA)

   if((rng_obj == nullptr) || (key == nullptr)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if((pbits % 64) || (qbits % 8) || (pbits < 1024) || (pbits > 3072) || (qbits < 160) || (qbits > 256)) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      Botan::DL_Group group(rng, Botan::DL_Group::Prime_Subgroup, pbits, qbits);
      auto dsa = std::make_unique<Botan::DSA_PrivateKey>(rng, group);
      *key = new botan_privkey_struct(std::move(dsa));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, rng_obj, pbits, qbits);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_load_dsa(botan_privkey_t* key, botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t x) {
#if defined(BOTAN_HAS_DSA)
   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(q), safe_get(g));
      auto dsa = std::make_unique<Botan::DSA_PrivateKey>(group, safe_get(x));
      *key = new botan_privkey_struct(std::move(dsa));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, p, q, g, x);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_dsa(botan_pubkey_t* key, botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t y) {
#if defined(BOTAN_HAS_DSA)
   *key = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(q), safe_get(g));
      auto dsa = std::make_unique<Botan::DSA_PublicKey>(group, safe_get(y));
      *key = new botan_pubkey_struct(std::move(dsa));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, p, q, g, y);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_dsa_get_x(botan_mp_t x, botan_privkey_t key) {
   return botan_privkey_get_field(x, key, "x");
}

int botan_pubkey_dsa_get_p(botan_mp_t p, botan_pubkey_t key) {
   return botan_pubkey_get_field(p, key, "p");
}

int botan_pubkey_dsa_get_q(botan_mp_t q, botan_pubkey_t key) {
   return botan_pubkey_get_field(q, key, "q");
}

int botan_pubkey_dsa_get_g(botan_mp_t g, botan_pubkey_t key) {
   return botan_pubkey_get_field(g, key, "g");
}

int botan_pubkey_dsa_get_y(botan_mp_t y, botan_pubkey_t key) {
   return botan_pubkey_get_field(y, key, "y");
}

int botan_privkey_create_ecdsa(botan_privkey_t* key_obj, botan_rng_t rng_obj, const char* param_str) {
   return botan_privkey_create(key_obj, "ECDSA", param_str, rng_obj);
}

/* ECDSA specific operations */

int botan_pubkey_ecc_key_used_explicit_encoding(botan_pubkey_t key) {
#if defined(BOTAN_HAS_ECC_KEY)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::Public_Key& pub_key = safe_get(key);
      const Botan::EC_PublicKey* ec_key = dynamic_cast<const Botan::EC_PublicKey*>(&pub_key);

      if(ec_key == nullptr) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      return ec_key->domain().used_explicit_encoding() ? 1 : 0;
   });
#else
   BOTAN_UNUSED(key);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_ecdsa(botan_pubkey_t* key,
                            const botan_mp_t public_x,
                            const botan_mp_t public_y,
                            const char* curve_name) {
#if defined(BOTAN_HAS_ECDSA)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::ECDSA_PublicKey> p_key;

      int rc = pubkey_load_ec(p_key, safe_get(public_x), safe_get(public_y), curve_name);
      if(rc == BOTAN_FFI_SUCCESS) {
         *key = new botan_pubkey_struct(std::move(p_key));
      }

      return rc;
   });
#else
   BOTAN_UNUSED(key, public_x, public_y, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_load_ecdsa(botan_privkey_t* key, const botan_mp_t scalar, const char* curve_name) {
#if defined(BOTAN_HAS_ECDSA)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::ECDSA_PrivateKey> p_key;
      int rc = privkey_load_ec(p_key, safe_get(scalar), curve_name);
      if(rc == BOTAN_FFI_SUCCESS) {
         *key = new botan_privkey_struct(std::move(p_key));
      }
      return rc;
   });
#else
   BOTAN_UNUSED(key, scalar, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/* ElGamal specific operations */
int botan_privkey_create_elgamal(botan_privkey_t* key, botan_rng_t rng_obj, size_t pbits, size_t qbits) {
#if defined(BOTAN_HAS_ELGAMAL)

   if((rng_obj == nullptr) || (key == nullptr)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if((pbits < 1024) || (qbits < 160)) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }

   Botan::DL_Group::PrimeType prime_type =
      ((pbits - 1) == qbits) ? Botan::DL_Group::Strong : Botan::DL_Group::Prime_Subgroup;

   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      Botan::DL_Group group(rng, prime_type, pbits, qbits);
      auto elg = std::make_unique<Botan::ElGamal_PrivateKey>(rng, group);
      *key = new botan_privkey_struct(std::move(elg));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, rng_obj, pbits, qbits);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_elgamal(botan_pubkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t y) {
#if defined(BOTAN_HAS_ELGAMAL)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(g));
      auto elg = std::make_unique<Botan::ElGamal_PublicKey>(group, safe_get(y));
      *key = new botan_pubkey_struct(std::move(elg));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, p, g, y);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_load_elgamal(botan_privkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t x) {
#if defined(BOTAN_HAS_ELGAMAL)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(g));
      auto elg = std::make_unique<Botan::ElGamal_PrivateKey>(group, safe_get(x));
      *key = new botan_privkey_struct(std::move(elg));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, p, g, x);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/* Diffie Hellman specific operations */

int botan_privkey_create_dh(botan_privkey_t* key_obj, botan_rng_t rng_obj, const char* param_str) {
   return botan_privkey_create(key_obj, "DH", param_str, rng_obj);
}

int botan_privkey_load_dh(botan_privkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t x) {
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(g));
      auto dh = std::make_unique<Botan::DH_PrivateKey>(group, safe_get(x));
      *key = new botan_privkey_struct(std::move(dh));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, p, g, x);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_dh(botan_pubkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t y) {
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DL_Group group(safe_get(p), safe_get(g));
      auto dh = std::make_unique<Botan::DH_PublicKey>(group, safe_get(y));
      *key = new botan_pubkey_struct(std::move(dh));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, p, g, y);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/* ECDH + x25519/x448 specific operations */

int botan_privkey_create_ecdh(botan_privkey_t* key_obj, botan_rng_t rng_obj, const char* param_str) {
   if(param_str == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   const std::string params(param_str);

   if(params == "x25519" || params == "curve25519") {
      return botan_privkey_create(key_obj, "X25519", "", rng_obj);
   }

   if(params == "x448") {
      return botan_privkey_create(key_obj, "X448", "", rng_obj);
   }

   return botan_privkey_create(key_obj, "ECDH", param_str, rng_obj);
}

int botan_pubkey_load_ecdh(botan_pubkey_t* key,
                           const botan_mp_t public_x,
                           const botan_mp_t public_y,
                           const char* curve_name) {
#if defined(BOTAN_HAS_ECDH)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::ECDH_PublicKey> p_key;
      int rc = pubkey_load_ec(p_key, safe_get(public_x), safe_get(public_y), curve_name);

      if(rc == BOTAN_FFI_SUCCESS) {
         *key = new botan_pubkey_struct(std::move(p_key));
      }
      return rc;
   });
#else
   BOTAN_UNUSED(key, public_x, public_y, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_load_ecdh(botan_privkey_t* key, const botan_mp_t scalar, const char* curve_name) {
#if defined(BOTAN_HAS_ECDH)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::ECDH_PrivateKey> p_key;
      int rc = privkey_load_ec(p_key, safe_get(scalar), curve_name);
      if(rc == BOTAN_FFI_SUCCESS) {
         *key = new botan_privkey_struct(std::move(p_key));
      }
      return rc;
   });
#else
   BOTAN_UNUSED(key, scalar, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/* SM2 specific operations */

int botan_pubkey_sm2_compute_za(
   uint8_t out[], size_t* out_len, const char* ident, const char* hash_algo, const botan_pubkey_t key) {
   if(out == nullptr || out_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   if(ident == nullptr || hash_algo == nullptr || key == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_SM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::Public_Key& pub_key = safe_get(key);
      const Botan::EC_PublicKey* ec_key = dynamic_cast<const Botan::EC_PublicKey*>(&pub_key);

      if(ec_key == nullptr) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      if(ec_key->algo_name() != "SM2") {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      const std::string ident_str(ident);
      std::unique_ptr<Botan::HashFunction> hash = Botan::HashFunction::create_or_throw(hash_algo);

      const std::vector<uint8_t> za = Botan::sm2_compute_za(*hash, ident_str, ec_key->domain(), ec_key->public_point());

      return write_vec_output(out, out_len, za);
   });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_sm2(botan_pubkey_t* key,
                          const botan_mp_t public_x,
                          const botan_mp_t public_y,
                          const char* curve_name) {
#if defined(BOTAN_HAS_SM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::SM2_PublicKey> p_key;
      if(!pubkey_load_ec(p_key, safe_get(public_x), safe_get(public_y), curve_name)) {
         *key = new botan_pubkey_struct(std::move(p_key));
         return BOTAN_FFI_SUCCESS;
      }
      return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
   });
#else
   BOTAN_UNUSED(key, public_x, public_y, curve_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_load_sm2(botan_privkey_t* key, const botan_mp_t scalar, const char* curve_name) {
#if defined(BOTAN_HAS_SM2)
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::unique_ptr<Botan::SM2_PrivateKey> p_key;
      int rc = privkey_load_ec(p_key, safe_get(scalar), curve_name);

      if(rc == BOTAN_FFI_SUCCESS) {
         *key = new botan_privkey_struct(std::move(p_key));
      }
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
                              const char* curve_name) {
   return botan_pubkey_load_sm2(key, public_x, public_y, curve_name);
}

int botan_privkey_load_sm2_enc(botan_privkey_t* key, const botan_mp_t scalar, const char* curve_name) {
   return botan_privkey_load_sm2(key, scalar, curve_name);
}

/* Ed25519 specific operations */

int botan_privkey_load_ed25519(botan_privkey_t* key, const uint8_t privkey[32]) {
#if defined(BOTAN_HAS_ED25519)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::secure_vector<uint8_t> privkey_vec(privkey, privkey + 32);
      auto ed25519 = std::make_unique<Botan::Ed25519_PrivateKey>(privkey_vec);
      *key = new botan_privkey_struct(std::move(ed25519));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, privkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_ed25519(botan_pubkey_t* key, const uint8_t pubkey[32]) {
#if defined(BOTAN_HAS_ED25519)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::vector<uint8_t> pubkey_vec(pubkey, pubkey + 32);
      auto ed25519 = std::make_unique<Botan::Ed25519_PublicKey>(pubkey_vec);
      *key = new botan_pubkey_struct(std::move(ed25519));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, pubkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_ed25519_get_privkey(botan_privkey_t key, uint8_t output[64]) {
#if defined(BOTAN_HAS_ED25519)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      if(auto ed = dynamic_cast<const Botan::Ed25519_PrivateKey*>(&k)) {
         const auto ed_key = ed->raw_private_key_bits();
         if(ed_key.size() != 64)
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         Botan::copy_mem(output, ed_key.data(), ed_key.size());
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_ed25519_get_pubkey(botan_pubkey_t key, uint8_t output[32]) {
#if defined(BOTAN_HAS_ED25519)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      if(auto ed = dynamic_cast<const Botan::Ed25519_PublicKey*>(&k)) {
         const std::vector<uint8_t>& ed_key = ed->get_public_key();
         if(ed_key.size() != 32)
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         Botan::copy_mem(output, ed_key.data(), ed_key.size());
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/* Ed448 specific operations */

int botan_privkey_load_ed448(botan_privkey_t* key, const uint8_t privkey[57]) {
#if defined(BOTAN_HAS_ED448)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto ed448 = std::make_unique<Botan::Ed448_PrivateKey>(std::span(privkey, 57));
      *key = new botan_privkey_struct(std::move(ed448));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, privkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_ed448(botan_pubkey_t* key, const uint8_t pubkey[57]) {
#if defined(BOTAN_HAS_ED448)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto ed448 = std::make_unique<Botan::Ed448_PublicKey>(std::span(pubkey, 57));
      *key = new botan_pubkey_struct(std::move(ed448));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, pubkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_ed448_get_privkey(botan_privkey_t key, uint8_t output[57]) {
#if defined(BOTAN_HAS_ED448)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      if(auto ed = dynamic_cast<const Botan::Ed448_PrivateKey*>(&k)) {
         const auto ed_key = ed->raw_private_key_bits();
         Botan::copy_mem(std::span(output, 57), ed_key);
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_ed448_get_pubkey(botan_pubkey_t key, uint8_t output[57]) {
#if defined(BOTAN_HAS_ED448)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      if(auto ed = dynamic_cast<const Botan::Ed448_PublicKey*>(&k)) {
         const auto ed_key = ed->public_key_bits();
         Botan::copy_mem(std::span(output, 57), ed_key);
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/* X25519 specific operations */

int botan_privkey_load_x25519(botan_privkey_t* key, const uint8_t privkey[32]) {
#if defined(BOTAN_HAS_X25519)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::secure_vector<uint8_t> privkey_vec(privkey, privkey + 32);
      auto x25519 = std::make_unique<Botan::X25519_PrivateKey>(privkey_vec);
      *key = new botan_privkey_struct(std::move(x25519));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, privkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_x25519(botan_pubkey_t* key, const uint8_t pubkey[32]) {
#if defined(BOTAN_HAS_X25519)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::vector<uint8_t> pubkey_vec(pubkey, pubkey + 32);
      auto x25519 = std::make_unique<Botan::X25519_PublicKey>(pubkey_vec);
      *key = new botan_pubkey_struct(std::move(x25519));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, pubkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_x25519_get_privkey(botan_privkey_t key, uint8_t output[32]) {
#if defined(BOTAN_HAS_X25519)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      if(auto x25519 = dynamic_cast<const Botan::X25519_PrivateKey*>(&k)) {
         const auto x25519_key = x25519->raw_private_key_bits();
         if(x25519_key.size() != 32)
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         Botan::copy_mem(output, x25519_key.data(), x25519_key.size());
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_x25519_get_pubkey(botan_pubkey_t key, uint8_t output[32]) {
#if defined(BOTAN_HAS_X25519)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      if(auto x25519 = dynamic_cast<const Botan::X25519_PublicKey*>(&k)) {
         const std::vector<uint8_t>& x25519_key = x25519->public_value();
         if(x25519_key.size() != 32)
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         Botan::copy_mem(output, x25519_key.data(), x25519_key.size());
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/* X448 specific operations */

int botan_privkey_load_x448(botan_privkey_t* key, const uint8_t privkey[56]) {
#if defined(BOTAN_HAS_X448)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto x448 = std::make_unique<Botan::X448_PrivateKey>(std::span(privkey, 56));
      *key = new botan_privkey_struct(std::move(x448));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, privkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_x448(botan_pubkey_t* key, const uint8_t pubkey[56]) {
#if defined(BOTAN_HAS_X448)
   *key = nullptr;
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto x448 = std::make_unique<Botan::X448_PublicKey>(std::span(pubkey, 56));
      *key = new botan_pubkey_struct(std::move(x448));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(key, pubkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_x448_get_privkey(botan_privkey_t key, uint8_t output[56]) {
#if defined(BOTAN_HAS_X448)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      if(auto x448 = dynamic_cast<const Botan::X448_PrivateKey*>(&k)) {
         const auto x448_key = x448->raw_private_key_bits();
         Botan::copy_mem(std::span(output, 56), x448_key);
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_x448_get_pubkey(botan_pubkey_t key, uint8_t output[56]) {
#if defined(BOTAN_HAS_X448)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) {
      if(auto x448 = dynamic_cast<const Botan::X448_PublicKey*>(&k)) {
         const std::vector<uint8_t>& x448_key = x448->public_value();
         Botan::copy_mem(std::span(output, 56), x448_key);
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, output);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/*
* Algorithm specific key operations: Kyber
*/

int botan_privkey_load_kyber(botan_privkey_t* key, const uint8_t privkey[], size_t key_len) {
#if defined(BOTAN_HAS_KYBER)
   *key = nullptr;
   switch(key_len) {
      case 1632:
         return ffi_guard_thunk(__func__, [=]() -> int {
            const Botan::secure_vector<uint8_t> privkey_vec(privkey, privkey + 1632);
            auto kyber512 = std::make_unique<Botan::Kyber_PrivateKey>(privkey_vec, Botan::KyberMode::Kyber512_R3);
            *key = new botan_privkey_struct(std::move(kyber512));
            return BOTAN_FFI_SUCCESS;
         });
      case 2400:
         return ffi_guard_thunk(__func__, [=]() -> int {
            const Botan::secure_vector<uint8_t> privkey_vec(privkey, privkey + 2400);
            auto kyber768 = std::make_unique<Botan::Kyber_PrivateKey>(privkey_vec, Botan::KyberMode::Kyber768_R3);
            *key = new botan_privkey_struct(std::move(kyber768));
            return BOTAN_FFI_SUCCESS;
         });
      case 3168:
         return ffi_guard_thunk(__func__, [=]() -> int {
            const Botan::secure_vector<uint8_t> privkey_vec(privkey, privkey + 3168);
            auto kyber1024 = std::make_unique<Botan::Kyber_PrivateKey>(privkey_vec, Botan::KyberMode::Kyber1024_R3);
            *key = new botan_privkey_struct(std::move(kyber1024));
            return BOTAN_FFI_SUCCESS;
         });
      default:
         BOTAN_UNUSED(key, privkey, key_len);
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }
#else
   BOTAN_UNUSED(key, privkey);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_load_kyber(botan_pubkey_t* key, const uint8_t pubkey[], size_t key_len) {
#if defined(BOTAN_HAS_KYBER)
   *key = nullptr;
   switch(key_len) {
      case 800:
         return ffi_guard_thunk(__func__, [=]() -> int {
            const std::vector<uint8_t> pubkey_vec(pubkey, pubkey + 800);
            auto kyber512 = std::make_unique<Botan::Kyber_PublicKey>(pubkey_vec, Botan::KyberMode::Kyber512_R3);
            *key = new botan_pubkey_struct(std::move(kyber512));
            return BOTAN_FFI_SUCCESS;
         });
      case 1184:
         return ffi_guard_thunk(__func__, [=]() -> int {
            const std::vector<uint8_t> pubkey_vec(pubkey, pubkey + 1184);
            auto kyber768 = std::make_unique<Botan::Kyber_PublicKey>(pubkey_vec, Botan::KyberMode::Kyber768_R3);
            *key = new botan_pubkey_struct(std::move(kyber768));
            return BOTAN_FFI_SUCCESS;
         });
      case 1568:
         return ffi_guard_thunk(__func__, [=]() -> int {
            const std::vector<uint8_t> pubkey_vec(pubkey, pubkey + 1568);
            auto kyber1024 = std::make_unique<Botan::Kyber_PublicKey>(pubkey_vec, Botan::KyberMode::Kyber1024_R3);
            *key = new botan_pubkey_struct(std::move(kyber1024));
            return BOTAN_FFI_SUCCESS;
         });
      default:
         BOTAN_UNUSED(key, pubkey, key_len);
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }
#else
   BOTAN_UNUSED(key, pubkey, key_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_view_kyber_raw_key(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_KYBER)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) -> int {
      if(auto kyber = dynamic_cast<const Botan::Kyber_PrivateKey*>(&k)) {
         return invoke_view_callback(view, ctx, kyber->raw_private_key_bits());
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_view_kyber_raw_key(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_KYBER)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) -> int {
      if(auto kyber = dynamic_cast<const Botan::Kyber_PublicKey*>(&k)) {
         return invoke_view_callback(view, ctx, kyber->public_key_bits());
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_pubkey_view_ec_public_point(const botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   return BOTAN_FFI_VISIT(key, [=](const auto& k) -> int {
      if(auto ecc = dynamic_cast<const Botan::EC_PublicKey*>(&k)) {
         auto pt = ecc->public_point().encode(Botan::EC_Point_Format::Uncompressed);
         return invoke_view_callback(view, ctx, pt);
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(key, view, ctx);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_privkey_create_mceliece(botan_privkey_t* key_obj, botan_rng_t rng_obj, size_t n, size_t t) {
   const std::string mce_params = std::to_string(n) + "," + std::to_string(t);
   return botan_privkey_create(key_obj, "McEliece", mce_params.c_str(), rng_obj);
}

int botan_mceies_decrypt(botan_privkey_t mce_key_obj,
                         const char* aead,
                         const uint8_t ct[],
                         size_t ct_len,
                         const uint8_t ad[],
                         size_t ad_len,
                         uint8_t out[],
                         size_t* out_len) {
   BOTAN_UNUSED(mce_key_obj, aead, ct, ct_len, ad, ad_len, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
}

int botan_mceies_encrypt(botan_pubkey_t mce_key_obj,
                         botan_rng_t rng_obj,
                         const char* aead,
                         const uint8_t pt[],
                         size_t pt_len,
                         const uint8_t ad[],
                         size_t ad_len,
                         uint8_t out[],
                         size_t* out_len) {
   BOTAN_UNUSED(mce_key_obj, rng_obj, aead, pt, pt_len, ad, ad_len, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
}
}

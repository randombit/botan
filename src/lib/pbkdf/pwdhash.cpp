/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pwdhash.h>

#include <botan/exceptn.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_PBKDF2)
   #include <botan/pbkdf2.h>
#endif

#if defined(BOTAN_HAS_PGP_S2K)
   #include <botan/pgp_s2k.h>
#endif

#if defined(BOTAN_HAS_SCRYPT)
   #include <botan/scrypt.h>
#endif

#if defined(BOTAN_HAS_ARGON2)
   #include <botan/argon2.h>
#endif

#if defined(BOTAN_HAS_PBKDF_BCRYPT)
   #include <botan/bcrypt_pbkdf.h>
#endif

namespace Botan {

void PasswordHash::derive_key(uint8_t out[],
                              size_t out_len,
                              const char* password,
                              size_t password_len,
                              const uint8_t salt[],
                              size_t salt_len,
                              const uint8_t ad[],
                              size_t ad_len,
                              const uint8_t key[],
                              size_t key_len) const {
   BOTAN_UNUSED(ad, key);

   if(ad_len == 0 && key_len == 0) {
      return this->derive_key(out, out_len, password, password_len, salt, salt_len);
   } else {
      throw Not_Implemented("PasswordHash " + this->to_string() + " does not support AD or key");
   }
}

std::unique_ptr<PasswordHashFamily> PasswordHashFamily::create(std::string_view algo_spec, std::string_view provider) {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_PBKDF2)
   if(req.algo_name() == "PBKDF2") {
      if(provider.empty() || provider == "base") {
         if(auto mac = MessageAuthenticationCode::create("HMAC(" + req.arg(0) + ")")) {
            return std::make_unique<PBKDF2_Family>(std::move(mac));
         }

         if(auto mac = MessageAuthenticationCode::create(req.arg(0))) {
            return std::make_unique<PBKDF2_Family>(std::move(mac));
         }
      }

      return nullptr;
   }
#endif

#if defined(BOTAN_HAS_SCRYPT)
   if(req.algo_name() == "Scrypt") {
      return std::make_unique<Scrypt_Family>();
   }
#endif

#if defined(BOTAN_HAS_ARGON2)
   if(req.algo_name() == "Argon2d") {
      return std::make_unique<Argon2_Family>(static_cast<uint8_t>(0));
   } else if(req.algo_name() == "Argon2i") {
      return std::make_unique<Argon2_Family>(static_cast<uint8_t>(1));
   } else if(req.algo_name() == "Argon2id") {
      return std::make_unique<Argon2_Family>(static_cast<uint8_t>(2));
   }
#endif

#if defined(BOTAN_HAS_PBKDF_BCRYPT)
   if(req.algo_name() == "Bcrypt-PBKDF") {
      return std::make_unique<Bcrypt_PBKDF_Family>();
   }
#endif

#if defined(BOTAN_HAS_PGP_S2K)
   if(req.algo_name() == "OpenPGP-S2K" && req.arg_count() == 1) {
      if(auto hash = HashFunction::create(req.arg(0))) {
         return std::make_unique<RFC4880_S2K_Family>(std::move(hash));
      }
   }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
}

//static
std::unique_ptr<PasswordHashFamily> PasswordHashFamily::create_or_throw(std::string_view algo,
                                                                        std::string_view provider) {
   if(auto pbkdf = PasswordHashFamily::create(algo, provider)) {
      return pbkdf;
   }
   throw Lookup_Error("PasswordHashFamily", algo, provider);
}

std::vector<std::string> PasswordHashFamily::providers(std::string_view algo_spec) {
   return probe_providers_of<PasswordHashFamily>(algo_spec);
}

}  // namespace Botan

/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pwdhash.h>
#include <botan/exceptn.h>
#include <botan/scan_name.h>

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

std::unique_ptr<PasswordHashFamily> PasswordHashFamily::create(const std::string& algo_spec,
                                     const std::string& provider)
   {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_PBKDF2)
   if(req.algo_name() == "PBKDF2")
      {
      // TODO OpenSSL

      if(provider.empty() || provider == "base")
         {
         if(auto mac = MessageAuthenticationCode::create(req.arg(0)))
            return std::unique_ptr<PasswordHashFamily>(new PBKDF2_Family(mac.release()));

         if(auto mac = MessageAuthenticationCode::create("HMAC(" + req.arg(0) + ")"))
            return std::unique_ptr<PasswordHashFamily>(new PBKDF2_Family(mac.release()));
         }

      return nullptr;
      }
#endif

#if defined(BOTAN_HAS_SCRYPT)
   if(req.algo_name() == "Scrypt")
      {
      return std::unique_ptr<PasswordHashFamily>(new Scrypt_Family);
      }
#endif

#if defined(BOTAN_HAS_ARGON2)
   if(req.algo_name() == "Argon2d")
      {
      return std::unique_ptr<PasswordHashFamily>(new Argon2_Family(0));
      }
   else if(req.algo_name() == "Argon2i")
      {
      return std::unique_ptr<PasswordHashFamily>(new Argon2_Family(1));
      }
   else if(req.algo_name() == "Argon2id")
      {
      return std::unique_ptr<PasswordHashFamily>(new Argon2_Family(2));
      }
#endif

#if defined(BOTAN_HAS_PBKDF_BCRYPT)
   if(req.algo_name() == "Bcrypt-PBKDF")
      {
      return std::unique_ptr<PasswordHashFamily>(new Bcrypt_PBKDF_Family);
      }
#endif

#if defined(BOTAN_HAS_PGP_S2K)
   if(req.algo_name() == "OpenPGP-S2K" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         {
         return std::unique_ptr<PasswordHashFamily>(new RFC4880_S2K_Family(hash.release()));
         }
      }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<PasswordHashFamily>
PasswordHashFamily::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto pbkdf = PasswordHashFamily::create(algo, provider))
      {
      return pbkdf;
      }
   throw Lookup_Error("PasswordHashFamily", algo, provider);
   }

std::vector<std::string> PasswordHashFamily::providers(const std::string& algo_spec)
   {
   return probe_providers_of<PasswordHashFamily>(algo_spec, { "base", "openssl" });
   }

}

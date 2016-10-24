/*
* PBKDF
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbkdf.h>
#include <botan/scan_name.h>

#if defined(BOTAN_HAS_PBKDF1)
#include <botan/pbkdf1.h>
#endif

#if defined(BOTAN_HAS_PBKDF2)
#include <botan/pbkdf2.h>
#endif

namespace Botan {

PBKDF::~PBKDF() {}

std::unique_ptr<PBKDF> PBKDF::create(const std::string& algo_spec,
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
            return std::unique_ptr<PBKDF>(new PKCS5_PBKDF2(mac.release()));

         if(auto mac = MessageAuthenticationCode::create("HMAC(" + req.arg(0) + ")"))
            return std::unique_ptr<PBKDF>(new PKCS5_PBKDF2(mac.release()));
         }

      return nullptr;
      }
#endif

#if defined(BOTAN_HAS_PBKDF1)
   if(req.algo_name() == "PBKDF1" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         return std::unique_ptr<PBKDF>(new PKCS5_PBKDF1(hash.release()));

      }
#endif

   return nullptr;
   }

std::vector<std::string> PBKDF::providers(const std::string& algo_spec)
   {
   return probe_providers_of<PBKDF>(algo_spec, { "base", "openssl" });
   }

void PBKDF::pbkdf_timed(byte out[], size_t out_len,
                        const std::string& passphrase,
                        const byte salt[], size_t salt_len,
                        std::chrono::milliseconds msec,
                        size_t& iterations) const
   {
   iterations = pbkdf(out, out_len, passphrase, salt, salt_len, 0, msec);
   }

void PBKDF::pbkdf_iterations(byte out[], size_t out_len,
                             const std::string& passphrase,
                             const byte salt[], size_t salt_len,
                             size_t iterations) const
   {
   if(iterations == 0)
      throw Invalid_Argument(name() + ": Invalid iteration count");

   const size_t iterations_run = pbkdf(out, out_len, passphrase,
                                       salt, salt_len, iterations,
                                       std::chrono::milliseconds(0));
   BOTAN_ASSERT_EQUAL(iterations, iterations_run, "Expected PBKDF iterations");
   }

secure_vector<byte> PBKDF::pbkdf_iterations(size_t out_len,
                                            const std::string& passphrase,
                                            const byte salt[], size_t salt_len,
                                            size_t iterations) const
   {
   secure_vector<byte> out(out_len);
   pbkdf_iterations(out.data(), out_len, passphrase, salt, salt_len, iterations);
   return out;
   }

secure_vector<byte> PBKDF::pbkdf_timed(size_t out_len,
                                       const std::string& passphrase,
                                       const byte salt[], size_t salt_len,
                                       std::chrono::milliseconds msec,
                                       size_t& iterations) const
   {
   secure_vector<byte> out(out_len);
   pbkdf_timed(out.data(), out_len, passphrase, salt, salt_len, msec, iterations);
   return out;
   }

}

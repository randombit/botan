/*
* PBKDF
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbkdf.h>

#include <botan/exceptn.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_PBKDF2)
   #include <botan/pbkdf2.h>
#endif

#if defined(BOTAN_HAS_PGP_S2K)
   #include <botan/pgp_s2k.h>
#endif

namespace Botan {

std::unique_ptr<PBKDF> PBKDF::create(std::string_view algo_spec, std::string_view provider) {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_PBKDF2)
   if(req.algo_name() == "PBKDF2") {
      // TODO OpenSSL

      if(provider.empty() || provider == "base") {
         if(auto mac = MessageAuthenticationCode::create("HMAC(" + req.arg(0) + ")")) {
            return std::make_unique<PKCS5_PBKDF2>(std::move(mac));
         }

         if(auto mac = MessageAuthenticationCode::create(req.arg(0))) {
            return std::make_unique<PKCS5_PBKDF2>(std::move(mac));
         }
      }

      return nullptr;
   }
#endif

#if defined(BOTAN_HAS_PGP_S2K)
   if(req.algo_name() == "OpenPGP-S2K" && req.arg_count() == 1) {
      if(auto hash = HashFunction::create(req.arg(0))) {
         return std::make_unique<OpenPGP_S2K>(std::move(hash));
      }
   }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
}

//static
std::unique_ptr<PBKDF> PBKDF::create_or_throw(std::string_view algo, std::string_view provider) {
   if(auto pbkdf = PBKDF::create(algo, provider)) {
      return pbkdf;
   }
   throw Lookup_Error("PBKDF", algo, provider);
}

std::vector<std::string> PBKDF::providers(std::string_view algo_spec) {
   return probe_providers_of<PBKDF>(algo_spec);
}

void PBKDF::pbkdf_timed(uint8_t out[],
                        size_t out_len,
                        std::string_view passphrase,
                        const uint8_t salt[],
                        size_t salt_len,
                        std::chrono::milliseconds msec,
                        size_t& iterations) const {
   iterations = pbkdf(out, out_len, passphrase, salt, salt_len, 0, msec);
}

void PBKDF::pbkdf_iterations(uint8_t out[],
                             size_t out_len,
                             std::string_view passphrase,
                             const uint8_t salt[],
                             size_t salt_len,
                             size_t iterations) const {
   if(iterations == 0) {
      throw Invalid_Argument(name() + ": Invalid iteration count");
   }

   const size_t iterations_run =
      pbkdf(out, out_len, passphrase, salt, salt_len, iterations, std::chrono::milliseconds(0));
   BOTAN_ASSERT_EQUAL(iterations, iterations_run, "Expected PBKDF iterations");
}

secure_vector<uint8_t> PBKDF::pbkdf_iterations(
   size_t out_len, std::string_view passphrase, const uint8_t salt[], size_t salt_len, size_t iterations) const {
   secure_vector<uint8_t> out(out_len);
   pbkdf_iterations(out.data(), out_len, passphrase, salt, salt_len, iterations);
   return out;
}

secure_vector<uint8_t> PBKDF::pbkdf_timed(size_t out_len,
                                          std::string_view passphrase,
                                          const uint8_t salt[],
                                          size_t salt_len,
                                          std::chrono::milliseconds msec,
                                          size_t& iterations) const {
   secure_vector<uint8_t> out(out_len);
   pbkdf_timed(out.data(), out_len, passphrase, salt, salt_len, msec, iterations);
   return out;
}

}  // namespace Botan

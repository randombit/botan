/*
* PBKDF
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbkdf.h>
#include <botan/internal/algo_registry.h>

#if defined(BOTAN_HAS_PBKDF1)
#include <botan/pbkdf1.h>
#endif

#if defined(BOTAN_HAS_PBKDF2)
#include <botan/pbkdf2.h>
#endif

namespace Botan {

#define BOTAN_REGISTER_PBKDF_1HASH(type, name)                          \
   BOTAN_REGISTER_NAMED_T(PBKDF, name, type, (make_new_T_1X<type, HashFunction>))

#if defined(BOTAN_HAS_PBKDF1)
BOTAN_REGISTER_PBKDF_1HASH(PKCS5_PBKDF1, "PBKDF1");
#endif

#if defined(BOTAN_HAS_PBKDF2)
BOTAN_REGISTER_NAMED_T(PBKDF, "PBKDF2", PKCS5_PBKDF2, PKCS5_PBKDF2::make);
#endif

PBKDF::~PBKDF() {}

std::unique_ptr<PBKDF> PBKDF::create(const std::string& algo_spec,
                                     const std::string& provider)
   {
   return std::unique_ptr<PBKDF>(make_a<PBKDF>(Botan::PBKDF::Spec(algo_spec), provider));
   }

std::vector<std::string> PBKDF::providers(const std::string& algo_spec)
   {
   return providers_of<PBKDF>(PBKDF::Spec(algo_spec));
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

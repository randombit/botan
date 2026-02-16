/*
* (C) 2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PBKDF_BCRYPT_H_
#define BOTAN_PBKDF_BCRYPT_H_

#include <botan/pwdhash.h>

// Use pwdhash.h
BOTAN_FUTURE_INTERNAL_HEADER(bcrypt_pbkdf.h)

namespace Botan {

/**
* Bcrypt-PBKDF key derivation function
*/
class BOTAN_PUBLIC_API(2, 11) Bcrypt_PBKDF final : public PasswordHash {
   public:
      BOTAN_FUTURE_EXPLICIT Bcrypt_PBKDF(size_t iterations);

      /**
      * Derive a new key under the current Bcrypt-PBKDF parameter set
      */
      void derive_key(uint8_t out[],
                      size_t out_len,
                      const char* password,
                      size_t password_len,
                      const uint8_t salt[],
                      size_t salt_len) const override;

      std::string to_string() const override;

      size_t iterations() const override { return m_iterations; }

      size_t parallelism() const override { return 0; }

      size_t memory_param() const override { return 0; }

      size_t total_memory_usage() const override { return 4096; }

   private:
      size_t m_iterations;
};

class BOTAN_PUBLIC_API(2, 11) Bcrypt_PBKDF_Family final : public PasswordHashFamily {
   public:
      Bcrypt_PBKDF_Family() = default;

      std::string name() const override;

      std::unique_ptr<PasswordHash> tune_params(size_t output_len,
                                                uint64_t desired_runtime_msec,
                                                std::optional<size_t> max_memory,
                                                uint64_t tune_msec) const override;

      std::unique_ptr<PasswordHash> default_params() const override;

      std::unique_ptr<PasswordHash> from_iterations(size_t iterations) const override;

      std::unique_ptr<PasswordHash> from_params(size_t iterations, size_t /*unused*/, size_t /*unused*/) const override;
};

/**
* Bcrypt PBKDF compatible with OpenBSD bcrypt_pbkdf
*/
BOTAN_DEPRECATED("Use PasswordHashFamily+PasswordHash")

inline void bcrypt_pbkdf(uint8_t output[],
                         size_t output_len,
                         const char* password,
                         size_t password_len,
                         const uint8_t salt[],
                         size_t salt_len,
                         size_t rounds) {
   auto pwdhash_fam = PasswordHashFamily::create_or_throw("Bcrypt-PBKDF");
   auto pwdhash = pwdhash_fam->from_params(rounds);
   pwdhash->derive_key(output, output_len, password, password_len, salt, salt_len);
}

}  // namespace Botan

#endif

/*
* PKCS#12 KDF (RFC 7292 Appendix B)
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PKCS12_KDF_H_
#define BOTAN_PKCS12_KDF_H_

#include <botan/hash.h>
#include <botan/pwdhash.h>
#include <botan/types.h>

#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace Botan {

/**
* PKCS#12 KDF (RFC 7292 Appendix B)
*
* The id parameter (purpose byte) is fixed at family construction time:
*   1 = encryption key, 2 = IV, 3 = MAC key
*
* The family spec used with PasswordHashFamily::create() is
* "PKCS12-KDF(hash,id)", e.g. "PKCS12-KDF(SHA-1,1)" with two arguments.
* PKCS12_KDF::to_string() additionally embeds the iteration count for
* round-tripping a fully-parameterized instance, producing
* "PKCS12-KDF(hash,id,iterations)"; that 3-argument form is not accepted
* by PasswordHashFamily::create() and should not be used as an algo spec.
*/
class PKCS12_KDF final : public PasswordHash {
   public:
      PKCS12_KDF(std::unique_ptr<HashFunction> hash, uint8_t id, size_t iterations);

      std::string to_string() const override;

      size_t iterations() const override { return m_iterations; }

      void derive_key(uint8_t out[],
                      size_t out_len,
                      const char* password,
                      size_t password_len,
                      const uint8_t salt[],
                      size_t salt_len) const override;

   private:
      std::unique_ptr<HashFunction> m_hash;
      uint8_t m_id;
      size_t m_iterations;
};

/**
* Low-level PKCS#12 KDF (RFC 7292 Appendix B).
*
* Runs the KDF on a caller-supplied @p pwd_bytes buffer without applying
* @c pkcs12_encode_password. Intended for the very rare case (e.g. OpenSSL
* empty-password interop) where the RFC 7292 UCS-2 BE encoding + null
* terminator is not the desired input. Normal callers should use the
* PKCS12_KDF class.
*/
BOTAN_TEST_API void pkcs12_kdf(std::span<uint8_t> out,
                               std::span<const uint8_t> pwd_bytes,
                               std::span<const uint8_t> salt,
                               size_t iterations,
                               uint8_t id,
                               HashFunction& hash);

class PKCS12_KDF_Family final : public PasswordHashFamily {
   public:
      PKCS12_KDF_Family(std::unique_ptr<HashFunction> hash, size_t id);

      std::string name() const override;

      std::unique_ptr<PasswordHash> tune_params(size_t output_length,
                                                uint64_t desired_runtime_msec,
                                                std::optional<size_t> max_memory_usage_mb = {},
                                                uint64_t tuning_msec = 10) const override;

      std::unique_ptr<PasswordHash> default_params() const override;

      std::unique_ptr<PasswordHash> from_iterations(size_t iterations) const override;

      std::unique_ptr<PasswordHash> from_params(size_t i1, size_t i2 = 0, size_t i3 = 0) const override;

   private:
      std::unique_ptr<HashFunction> m_hash;
      uint8_t m_id;
};

}  // namespace Botan

#endif

/*
* PKCS#12 KDF
* (C) 2026
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PKCS12_KDF_H_
#define BOTAN_PKCS12_KDF_H_

#include <botan/pwdhash.h>
#include <botan/secmem.h>

namespace Botan {

/**
 * PKCS#12 Key Derivation Function
 *
 * This implements the key derivation function defined in RFC 7292 Appendix B.
 * It derives key material from a password and salt using an iterative hash
 * construction with SHA-1.
 *
 * The ID parameter specifies the type of output:
 *   1 = key material for encryption
 *   2 = initialization vector
 *   3 = MAC key
 */
class BOTAN_PUBLIC_API(3, 7) PKCS12_KDF final : public PasswordHash {
   public:
      /**
       * @param iterations the number of iterations
       * @param id the purpose ID (1=key, 2=IV, 3=MAC)
       */
      PKCS12_KDF(size_t iterations, uint8_t id = 1);

      size_t iterations() const override { return m_iterations; }

      std::string to_string() const override;

      void derive_key(uint8_t out[],
                      size_t out_len,
                      const char* password,
                      size_t password_len,
                      const uint8_t salt[],
                      size_t salt_len) const override;

      /**
       * Convenience function for deriving key material
       */
      secure_vector<uint8_t> derive_key(size_t out_len,
                                        std::string_view password,
                                        std::span<const uint8_t> salt) const;

   private:
      size_t m_iterations;
      uint8_t m_id;
};

/**
 * PKCS#12 Key Derivation Family
 */
class BOTAN_PUBLIC_API(3, 7) PKCS12_KDF_Family final : public PasswordHashFamily {
   public:
      /**
       * @param id the purpose ID (1=key, 2=IV, 3=MAC)
       */
      explicit PKCS12_KDF_Family(uint8_t id = 1);

      std::string name() const override;

      std::unique_ptr<PasswordHash> tune_params(size_t output_len,
                                                uint64_t desired_runtime_msec,
                                                std::optional<size_t> max_memory,
                                                uint64_t tune_msec) const override;

      std::unique_ptr<PasswordHash> default_params() const override;

      std::unique_ptr<PasswordHash> from_iterations(size_t iter) const override;

      std::unique_ptr<PasswordHash> from_params(size_t iter, size_t /*unused*/, size_t /*unused*/) const override;

   private:
      uint8_t m_id;
};

/**
 * Derive a key using PKCS#12 KDF (RFC 7292 Appendix B)
 *
 * @param out output buffer
 * @param out_len length of output in bytes
 * @param password the password (will be converted to UTF-16BE)
 * @param salt the salt value
 * @param salt_len length of salt in bytes
 * @param iterations number of iterations
 * @param id purpose ID (1=key, 2=IV, 3=MAC)
 * @param hash_algo hash algorithm to use (default: SHA-1, also supports SHA-256)
 */
BOTAN_PUBLIC_API(3, 7)
void pkcs12_kdf(uint8_t out[],
                size_t out_len,
                std::string_view password,
                const uint8_t salt[],
                size_t salt_len,
                size_t iterations,
                uint8_t id,
                std::string_view hash_algo = "SHA-1");

}  // namespace Botan

#endif

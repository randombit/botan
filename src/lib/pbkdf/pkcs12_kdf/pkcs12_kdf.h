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
#include <botan/secmem.h>
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
* "PKCS12-KDF(hash,id)", e.g. "PKCS12-KDF(SHA-1,1)" — two arguments.
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

class PKCS12_KDF_Family final : public PasswordHashFamily {
   public:
      PKCS12_KDF_Family(std::unique_ptr<HashFunction> hash, uint8_t id);

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

/**
 * Encode a UTF-8 password for use with the PKCS#12 KDF (RFC 7292 Appendix B).
 * Converts to PKCS#12 BMPString encoding (UCS-2BE / BMP-only, not full UTF-16)
 * and appends a 2-byte null terminator ({0x00, 0x00}).
 * An empty password produces {0x00, 0x00}, matching the RFC 7292 convention.
 * 
 * Non-BMP characters are not representable in UCS-2/BMPString and are rejected
 * by the underlying UTF-8-to-UCS-2 conversion.
 *
 * Use this before calling the low-level pkcs12_kdf() free function when the
 * password comes from a string. The PKCS12_KDF PasswordHash class always
 * applies this encoding internally, so empty passwords passed through the
 * PasswordHash interface use the RFC 7292 form ({0x00, 0x00}); the
 * OpenSSL-style empty-password encoding (passlen=0, no P contribution) is
 * only reachable via the pkcs12_kdf() free function by passing an empty span.
 */
secure_vector<uint8_t> pkcs12_encode_password(std::string_view password);

/**
 * Derive a key using the PKCS#12 KDF (RFC 7292 Appendix B).
 * The password_bytes are used verbatim — call pkcs12_encode_password first
 * for string passwords, or pass an empty span for the OpenSSL-style
 * empty-password encoding (passlen=0, no P contribution). Note: the
 * PKCS12_KDF PasswordHash class does not expose this OpenSSL-style mode;
 * it always uses pkcs12_encode_password() and therefore the RFC 7292
 * empty-password form ({0x00, 0x00}).
 *
 * @param out output buffer
 * @param out_len length of output in bytes
 * @param password_bytes pre-encoded password bytes (no implicit conversion)
 * @param salt the salt value
 * @param salt_len length of salt in bytes
 * @param iterations number of hash iterations
 * @param id purpose ID: 1 = key, 2 = IV, 3 = MAC key
 * @param hash_algo hash algorithm to use (default: SHA-1). Any registered hash
 *                  with a defined block size is accepted (RFC 7292 needs 'v',
 *                  the hash's block size); hashes that report block size 0
 *                  are rejected at derivation time.
 */
void pkcs12_kdf(uint8_t out[],
                size_t out_len,
                std::span<const uint8_t> password_bytes,
                const uint8_t salt[],
                size_t salt_len,
                size_t iterations,
                uint8_t id,
                std::string_view hash_algo = "SHA-1");

}  // namespace Botan

#endif

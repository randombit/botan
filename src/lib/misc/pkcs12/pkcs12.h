/*
* PKCS#12
* (C) 2026
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PKCS12_H_
#define BOTAN_PKCS12_H_

#include <botan/pk_keys.h>
#include <botan/secmem.h>
#include <botan/x509cert.h>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

/**
 * Options for PKCS#12 generation
 */
struct BOTAN_PUBLIC_API(3, 7) PKCS12_Options {
      /**
       * Password for encrypting the private key and optionally certificates.
       * If empty, no encryption is applied (not recommended).
       */
      std::string password;

      /**
       * Friendly name attribute for the key/certificate
       */
      std::string friendly_name;

      /**
       * Number of iterations for the PKCS#12 KDF (default: 2048)
       */
      size_t iterations = 2048;

      /**
       * Encryption algorithm for the private key.
       * Supported: "PBE-SHA1-3DES" (default, most compatible),
       *            "PBE-SHA1-2DES",
       *            "PBES2-SHA256-AES256" or "PBES2(AES-256/CBC,SHA-256)",
       *            "PBES2-SHA256-AES128" or "PBES2(AES-128/CBC,SHA-256)"
       */
      std::string key_encryption_algo = "PBE-SHA1-3DES";

      /**
       * Encryption algorithm for certificates.
       * If empty, certificates are stored unencrypted (shrouded in Data).
       * Supported: "PBE-SHA1-3DES", "PBE-SHA1-2DES",
       *            "PBES2-SHA256-AES256", "PBES2-SHA256-AES128", empty
       */
      std::string cert_encryption_algo;

      /**
       * Whether to include MAC for integrity protection (recommended, default: true)
       */
      bool include_mac = true;
};

/**
 * Result of parsing a PKCS#12 file
 */
class BOTAN_PUBLIC_API(3, 7) PKCS12_Data {
   public:
      PKCS12_Data() = default;

      /**
       * @return the private key, or nullptr if not present
       */
      const std::shared_ptr<Private_Key>& private_key() const { return m_private_key; }

      /**
       * @return the end-entity certificate, or nullptr if not present
       */
      const std::shared_ptr<X509_Certificate>& certificate() const { return m_certificate; }

      /**
       * @return intermediate/CA certificates in the chain
       */
      const std::vector<std::shared_ptr<X509_Certificate>>& ca_certificates() const { return m_ca_certs; }

      /**
       * @return all certificates (end-entity + chain)
       */
      std::vector<std::shared_ptr<X509_Certificate>> all_certificates() const;

      /**
       * @return the friendly name attribute, if present
       */
      const std::string& friendly_name() const { return m_friendly_name; }

      /**
       * @return true if this contains a private key
       */
      bool has_private_key() const { return m_private_key != nullptr; }

      /**
       * @return true if this contains a certificate
       */
      bool has_certificate() const { return m_certificate != nullptr; }

   private:
      friend class PKCS12;

      std::shared_ptr<Private_Key> m_private_key;
      std::shared_ptr<X509_Certificate> m_certificate;
      std::vector<std::shared_ptr<X509_Certificate>> m_ca_certs;
      std::string m_friendly_name;
      std::vector<uint8_t> m_local_key_id;
};

/**
 * PKCS#12/PFX file parser and generator
 *
 * PKCS#12 is a file format for storing cryptographic objects like
 * private keys and X.509 certificates together, typically protected
 * by a password.
 *
 * Example usage - parsing:
 * @code
 * auto data = PKCS12::parse(pfx_bytes, "password");
 * auto key = data.private_key();
 * auto cert = data.certificate();
 * @endcode
 *
 * Example usage - generating:
 * @code
 * PKCS12_Options opts;
 * opts.password = "mypassword";
 * opts.friendly_name = "My Certificate";
 * auto pfx = PKCS12::create(private_key, cert, ca_certs, opts, rng);
 * @endcode
 */
class BOTAN_PUBLIC_API(3, 7) PKCS12 final {
   public:
      /**
       * Parse a PKCS#12/PFX file
       *
       * @param data the PFX file contents
       * @param password the password to decrypt the file
       * @return parsed contents
       * @throws Decoding_Error if parsing fails
       * @throws Invalid_Authentication_Tag if MAC verification fails
       */
      static PKCS12_Data parse(std::span<const uint8_t> data, std::string_view password);

      /**
       * Parse a PKCS#12/PFX file from a DataSource
       *
       * @param source data source containing the PFX file
       * @param password the password to decrypt the file
       * @return parsed contents
       */
      static PKCS12_Data parse(DataSource& source, std::string_view password);

      /**
       * Create a PKCS#12/PFX file
       *
       * @param key the private key to include (may be nullptr)
       * @param cert the end-entity certificate (may be nullptr)
       * @param ca_certs additional CA/intermediate certificates
       * @param options generation options
       * @param rng random number generator
       * @return DER-encoded PFX file
       */
      static std::vector<uint8_t> create(const Private_Key* key,
                                         const X509_Certificate* cert,
                                         const std::vector<X509_Certificate>& ca_certs,
                                         const PKCS12_Options& options,
                                         RandomNumberGenerator& rng);

      /**
       * Create a PKCS#12/PFX file with just a key and certificate
       */
      static std::vector<uint8_t> create(const Private_Key& key,
                                         const X509_Certificate& cert,
                                         const PKCS12_Options& options,
                                         RandomNumberGenerator& rng) {
         return create(&key, &cert, {}, options, rng);
      }

      /**
       * Create a PKCS#12/PFX file with key, certificate, and CA chain
       */
      static std::vector<uint8_t> create(const Private_Key& key,
                                         const X509_Certificate& cert,
                                         const std::vector<X509_Certificate>& ca_certs,
                                         const PKCS12_Options& options,
                                         RandomNumberGenerator& rng) {
         return create(&key, &cert, ca_certs, options, rng);
      }

   private:
      PKCS12() = delete;
};

}  // namespace Botan

#endif

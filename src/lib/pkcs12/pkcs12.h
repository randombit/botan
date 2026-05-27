/*
* PKCS#12
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PKCS12_H_
#define BOTAN_PKCS12_H_

#include <botan/asn1_obj.h>
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
* Options controlling PKCS#12/PFX export.
*
* Use one of the static pseudo-constructors for the common cases:
*
*  - @ref modern        - PBES2-SHA256-AES256, SHA-256 MAC, 100 000 iterations
*  - @ref legacy_compat - PBE-SHA1-3DES, SHA-1 MAC, 2 048 iterations
*
* For custom configurations construct directly and use the @c with_*()
* mutators (chainable). Any field not set explicitly defaults to the
* "modern" value.
*/
class BOTAN_PUBLIC_API(3, 13) PKCS12_Export_Options final {
   public:
      /**
      * @param password password protecting the file. Empty is allowed
      *                 (PKCS#12 defines an encoding for it), but must not
      *                 be empty when @ref include_mac is true.
      * @param friendly_name optional friendly name attribute stored on the
      *                      private key bag and on the matching end-entity
      *                      certificate bag.
      */
      explicit PKCS12_Export_Options(std::string_view password, std::optional<std::string> friendly_name = {});

      /**
      * Modern defaults: PBES2-SHA256-AES256, SHA-256 MAC, 100 000 iterations.
      */
      static PKCS12_Export_Options modern(std::string_view password, std::optional<std::string> friendly_name = {});

      /**
      * Legacy-compatible defaults: PBE-SHA1-3DES, SHA-1 MAC, 2 048 iterations.
      * Use when interoperability with old software (Java keytool pre-2019,
      * older OpenSSL releases, Windows pre-Windows-10) is required.
      */
      static PKCS12_Export_Options legacy_compat(std::string_view password,
                                                 std::optional<std::string> friendly_name = {});

      /// Override the friendly-name attribute (otherwise taken from the bundle).
      PKCS12_Export_Options& with_friendly_name(std::string name);

      /// Set number of KDF iterations.
      PKCS12_Export_Options& with_iterations(size_t n);

      /// Set the private key encryption algorithm (PKCS#12 PBE or PBES2 name).
      PKCS12_Export_Options& with_key_encryption_algo(std::string algo);

      /**
      * Set the certificate encryption algorithm. Empty string (the default)
      * means certificates are stored unencrypted (inside an unencrypted
      * SafeContents); pass a non-empty algorithm to wrap them.
      */
      PKCS12_Export_Options& with_cert_encryption_algo(std::string algo);

      /// Set the digest used for the integrity MAC.
      PKCS12_Export_Options& with_mac_digest(std::string algo);

      /// Disable the integrity MAC. Generally not recommended.
      PKCS12_Export_Options& without_mac();

      const std::string& password() const { return m_password; }

      const std::optional<std::string>& friendly_name() const { return m_friendly_name; }

      size_t iterations() const { return m_iterations; }

      const std::string& key_encryption_algo() const { return m_key_encryption_algo; }

      /// Empty means: store certificates unencrypted.
      const std::string& cert_encryption_algo() const { return m_cert_encryption_algo; }

      const std::string& mac_digest() const { return m_mac_digest; }

      bool include_mac() const { return m_include_mac; }

   private:
      std::string m_password;
      std::optional<std::string> m_friendly_name;
      size_t m_iterations = 100000;
      std::string m_key_encryption_algo = "PBES2-SHA256-AES256";
      std::string m_cert_encryption_algo;
      std::string m_mac_digest = "SHA-256";
      bool m_include_mac = true;
};

/**
* PKCS#12/PFX bundle: parsed contents, mutable container, and exporter.
*
* PKCS#12 is a file format for storing cryptographic objects (private keys
* and X.509 certificates) together, typically protected by a password.
*
* The class can be used both to inspect an existing PFX and to build a new
* one. Construction from bytes parses an existing file; the default
* constructor produces an empty bundle that the caller populates with
* mutators (@ref add_key, @ref add_certificate, ...) before calling
* @ref export_to to serialize.
*
* @code
* // Parse
* Botan::PKCS12 p12(pfx_bytes, "password");
* if(!p12.private_keys().empty()) {
*    const auto& key = p12.private_keys().front();
*    // ...
* }
* if(auto ee = p12.end_entity_certificate()) {
*    // ...
* }
*
* // Build
* Botan::PKCS12 out;
* out.set_friendly_name("My Bundle");
* out.add_key(my_key);
* out.add_certificate(my_cert);
* for(const auto& ca : ca_chain) {
*    out.add_certificate(ca);
* }
* const auto blob = out.export_to(
*    Botan::PKCS12_Export_Options::modern("password"), rng);
* @endcode
*/
class BOTAN_PUBLIC_API(3, 13) PKCS12 final {
   public:
      /// Construct an empty bundle.
      PKCS12() = default;

      /**
      * Parse a PKCS#12/PFX file.
      *
      * @param data the PFX file contents
      * @param password the password to decrypt the file
      * @throws Decoding_Error if parsing fails
      * @throws Invalid_Authentication_Tag if MAC verification fails
      */
      PKCS12(std::span<const uint8_t> data, std::string_view password);

      /**
      * Private keys stored in the bundle, in the order they appear in the
      * PFX (for a parsed file) or in insertion order (for a built one).
      * PKCS#12 allows multiple keys per file; parsing currently surfaces all
      * KeyBag / PKCS8ShroudedKeyBag entries.
      */
      const std::vector<std::shared_ptr<Private_Key>>& private_keys() const { return m_private_keys; }

      /**
      * Certificates stored in the bundle, in the order they appear in the
      * PFX or in insertion order. The end-entity certificate (if any) is
      * not separated from CA/intermediate certificates at storage level;
      * use @ref end_entity_certificate to obtain it.
      */
      const std::vector<X509_Certificate>& certificates() const { return m_certificates; }

      /**
      * @return the first certificate whose subjectPublicKeyInfo matches one
      *         of the stored private keys, or @c nullopt if none match
      *         (e.g. a certificate-only or key-only bundle).
      */
      std::optional<X509_Certificate> end_entity_certificate() const;

      /**
      * Convenience helper: every certificate except the one returned by
      * @ref end_entity_certificate. Returned in storage order.
      */
      std::vector<X509_Certificate> ca_certificates() const;

      /**
      * Friendly-name attribute attached to the private key / end-entity
      * certificate bag, if present.
      */
      const std::optional<std::string>& friendly_name() const { return m_friendly_name; }

      /**
      * localKeyId attribute attached to the private key / end-entity
      * certificate bag, if present.
      */
      const std::optional<std::vector<uint8_t>>& local_key_id() const { return m_local_key_id; }

      /**
      * OIDs of bag types encountered during parsing but not handled by this
      * implementation (e.g. SecretBag). Empty for normal files and for
      * bundles constructed in-memory.
      */
      const std::vector<OID>& unknown_bag_types() const { return m_unknown_bag_types; }

      /// Add a private key. PKCS#12 supports multiple keys per file.
      void add_key(std::shared_ptr<Private_Key> key);

      /// Add a certificate. End-entity vs CA is determined at export time
      /// by matching against stored keys.
      void add_certificate(X509_Certificate cert);

      /// Set (or replace) the friendly-name attribute.
      void set_friendly_name(std::string name);

      /// Clear the friendly-name attribute.
      void clear_friendly_name();

      /// Set (or replace) the localKeyId attribute.
      void set_local_key_id(std::vector<uint8_t> id);

      /// Clear the localKeyId attribute.
      void clear_local_key_id();

      /**
      * Serialize the bundle as a PKCS#12/PFX file.
      *
      * @param options export options (password, algorithms, ...).
      * @param rng RNG used to generate salts, IVs and (if requested) the
      *            localKeyId when none is set explicitly.
      * @throws Invalid_Argument if @p options is internally inconsistent
      *         (e.g. unsupported algorithm or empty password with MAC).
      * @throws Invalid_Argument if a stored private key does not match any
      *         stored certificate (this implementation requires the
      *         end-entity cert to be present when a key is exported).
      */
      std::vector<uint8_t> export_to(const PKCS12_Export_Options& options, RandomNumberGenerator& rng) const;

   private:
      std::vector<std::shared_ptr<Private_Key>> m_private_keys;
      std::vector<X509_Certificate> m_certificates;
      std::optional<std::string> m_friendly_name;
      std::optional<std::vector<uint8_t>> m_local_key_id;
      std::vector<OID> m_unknown_bag_types;
};

}  // namespace Botan

#endif

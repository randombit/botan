/*
* X.509 Certificates
* (C) 1999-2007,2015,2017,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_CERTS_H_
#define BOTAN_X509_CERTS_H_

#include <botan/x509_obj.h>
#include <array>
#include <cstring>
#include <memory>
#include <span>

namespace Botan {

class AlternativeName;
class Extensions;
class NameConstraints;
class Public_Key;
class X509_DN;

class DNSName;
class EmailAddress;
class IPv4Address;
class IPv6Address;
class URI;

class X509_Certificate_Data;

/**
* This class represents an X.509 Certificate
*
* TODO(Botan4) mark this final once PKCS11_X509_Certificate is fixed
*/
class BOTAN_PUBLIC_API(2, 0) X509_Certificate : public X509_Object {
   public:
      /**
      * Create a public key object associated with the public key bits in this
      * certificate. If the public key bits was valid for X.509 encoding
      * purposes but invalid algorithmically (for example, RSA with an even
      * modulus) that will be detected at this point, and an exception will be
      * thrown.
      *
      * @return subject public key of this certificate
      */
      std::unique_ptr<Public_Key> subject_public_key() const;

      /**
      * Create a public key object associated with the public key bits in this
      * certificate. If the public key bits was valid for X.509 encoding
      * purposes but invalid algorithmically (for example, RSA with an even
      * modulus) that will be detected at this point, and an exception will be
      * thrown.
      *
      * @return subject public key of this certificate
      */
      BOTAN_DEPRECATED("Use subject_public_key") std::unique_ptr<Public_Key> load_subject_public_key() const;

      /**
      * Get the public key associated with this certificate. This includes the
      * outer AlgorithmIdentifier
      * @return subject public key of this certificate
      */
      const std::vector<uint8_t>& subject_public_key_bits() const;

      /**
      * Get the SubjectPublicKeyInfo associated with this certificate.
      * @return subject public key info of this certificate
      */
      const std::vector<uint8_t>& subject_public_key_info() const;

      /**
      * Return the algorithm identifier of the public key
      */
      const AlgorithmIdentifier& subject_public_key_algo() const;

      /**
      * Get the bit string of the public key associated with this certificate
      * @return public key bits
      */
      const std::vector<uint8_t>& subject_public_key_bitstring() const;

      /**
      * Get the SHA-1 bit string of the public key associated with this certificate.
      * This is used for OCSP among other protocols.
      * This function will throw if SHA-1 is not available.
      * @return hash of subject public key of this certificate
      */
      const std::vector<uint8_t>& subject_public_key_bitstring_sha1() const;

      /**
      * Get the certificate's issuer distinguished name (DN).
      * @return issuer DN of this certificate
      */
      const X509_DN& issuer_dn() const;

      /**
      * Get the certificate's subject distinguished name (DN).
      * @return subject DN of this certificate
      */
      const X509_DN& subject_dn() const;

      /**
      * Get a value for a specific subject_info parameter name.
      * @param name the name of the parameter to look up.
      * @return value(s) of the specified parameter or empty if not found
      */
      BOTAN_DEPRECATED("Use subject_dn and subject_alt_name to access subject names")
      std::vector<std::string> subject_info(std::string_view name) const;

      /**
      * Get a value for a specific subject_info parameter name.
      * @param name the name of the parameter to look up.
      * @return value(s) of the specified parameter or empty if not found
      */
      BOTAN_DEPRECATED("Use issuer_dn and issuer_alt_name to access issuer names")
      std::vector<std::string> issuer_info(std::string_view name) const;

      /**
      * Raw issuer DN bits
      */
      const std::vector<uint8_t>& raw_issuer_dn() const;

      /**
      * SHA-256 of Raw issuer DN
      */
      const std::vector<uint8_t>& raw_issuer_dn_sha256() const;

      /**
      * Raw subject DN
      */
      const std::vector<uint8_t>& raw_subject_dn() const;

      /**
      * SHA-256 of Raw subject DN
      */
      const std::vector<uint8_t>& raw_subject_dn_sha256() const;

      /**
      * SHA-1 of the entire certificate DER encoding
      */
      std::span<const uint8_t, 20> certificate_data_sha1() const;

      /**
      * SHA-256 of the entire certificate DER encoding
      */
      std::span<const uint8_t, 32> certificate_data_sha256() const;

      /**
      * Get the notBefore of the certificate as X509_Time
      * @return notBefore of the certificate
      */
      const X509_Time& not_before() const;

      /**
      * Get the notAfter of the certificate as X509_Time
      * @return notAfter of the certificate
      */
      const X509_Time& not_after() const;

      /**
      * Get the X509 version of this certificate object.
      * @return X509 version
      */
      uint32_t x509_version() const;

      /**
      * Get the serial number of this certificate.
      * @return certificates serial number
      */
      const std::vector<uint8_t>& serial_number() const;

      /**
      * Get the serial number's sign
      * @return 1 iff the serial is negative.
      */
      bool is_serial_negative() const;

      /**
      * Get the DER encoded AuthorityKeyIdentifier of this certificate.
      * @return DER encoded AuthorityKeyIdentifier
      */
      const std::vector<uint8_t>& authority_key_id() const;

      /**
      * Get the DER encoded SubjectKeyIdentifier of this certificate.
      * @return DER encoded SubjectKeyIdentifier
      */
      const std::vector<uint8_t>& subject_key_id() const;

      /**
      * Check whether this certificate is self signed.
      * If the DN issuer and subject agree,
      * @return true if this certificate is self signed
      */
      bool is_self_signed() const;

      /**
      * Check whether this certificate is a CA certificate.
      * @return true if this certificate is a CA certificate
      */
      bool is_CA_cert() const;

      /**
      * Returns true if the specified @param usage is set in the key usage extension
      * or if no key usage constraints are set at all.
      * To check if a certain key constraint is set in the certificate
      * use @see X509_Certificate#has_constraints.
      */
      bool allowed_usage(Key_Constraints usage) const;

      /**
      * Returns true if the specified @param usage is set in the extended key usage extension
      * or if no extended key usage constraints are set at all.
      * To check if a certain extended key constraint is set in the certificate
      * use @see X509_Certificate#has_ex_constraint.
      */
      bool allowed_extended_usage(std::string_view usage) const;

      /**
      * Returns true if the specified usage is set in the extended key usage extension,
      * or if no extended key usage constraints are set at all.
      * To check if a certain extended key constraint is set in the certificate
      * use @see X509_Certificate#has_ex_constraint.
      */
      bool allowed_extended_usage(const OID& usage) const;

      /**
      * Returns true if the required key and extended key constraints are set in the certificate
      * for the specified @param usage or if no key constraints are set in both the key usage
      * and extended key usage extension.
      */
      bool allowed_usage(Usage_Type usage) const;

      /**
      * Returns true if and only if the specified @param constraints are
      * included in the key usage extension.
      *
      * Typically for applications you want allowed_usage instead.
      */
      bool has_constraints(Key_Constraints constraints) const;

      /**
      * Returns true if and only if OID @param ex_constraint is
      * included in the extended key extension.
      */
      bool has_ex_constraint(std::string_view ex_constraint) const;

      /**
      * Returns true if and only if OID @param ex_constraint is
      * included in the extended key extension.
      */
      bool has_ex_constraint(const OID& ex_constraint) const;

      /**
      * Get the path length constraint as defined in the BasicConstraints extension.
      *
      * This returns an arbitrary value if the extension is not set (either 32 for v1
      * self-signed certificates, or else Cert_Extension::NO_CERT_PATH_LIMIT for v3
      * certificates without the extension)
      *
      * Prefer path_length_constraint
      *
      * @return path limit
      */
      BOTAN_DEPRECATED("Use X509_Certificate::path_length_constraint") uint32_t path_limit() const;

      /**
      * Get the path length constraint as defined in the BasicConstraints extension.
      *
      * Returns nullopt if either the extension is not set in the certificate,
      * or if the pathLenConstraint field was absent from the extension.
      *
      * @return path limit
      */
      std::optional<size_t> path_length_constraint() const;

      /**
      * Check whenever a given X509 Extension is marked critical in this
      * certificate.
      */
      bool is_critical(std::string_view ex_name) const;

      /**
      * Get the key constraints as defined in the KeyUsage extension of this
      * certificate.
      * @return key constraints
      */
      Key_Constraints constraints() const;

      /**
      * Get the key usage as defined in the ExtendedKeyUsage extension
      * of this certificate, or else an empty vector.
      * @return key usage
      */
      const std::vector<OID>& extended_key_usage() const;

      /**
      * Get the name constraints as defined in the NameConstraints
      * extension of this certificate.
      * @return name constraints
      */
      const NameConstraints& name_constraints() const;

      /**
      * Get the policies as defined in the CertificatePolicies extension
      * of this certificate.
      * @return certificate policies
      */
      const std::vector<OID>& certificate_policy_oids() const;

      /**
      * Get all extensions of this certificate.
      * @return certificate extensions
      */
      const Extensions& v3_extensions() const;

      /**
      * Return the v2 issuer key ID. v2 key IDs are almost never used,
      * instead see v3_subject_key_id.
      */
      const std::vector<uint8_t>& v2_issuer_key_id() const;

      /**
      * Return the v2 subject key ID. v2 key IDs are almost never used,
      * instead see v3_subject_key_id.
      */
      const std::vector<uint8_t>& v2_subject_key_id() const;

      /**
      * Return the subject alternative names (DNS, IP, ...)
      */
      const AlternativeName& subject_alt_name() const;

      /**
      * Return the issuer alternative names (DNS, IP, ...)
      */
      const AlternativeName& issuer_alt_name() const;

      /**
      * Return the listed address of an OCSP responder, or empty if not set
      */
      BOTAN_DEPRECATED("Use ocsp_responder_uris") std::string ocsp_responder() const;

      /**
      * Return the listed addresses of OCSP responders, or empty if not set
      */
      BOTAN_DEPRECATED("Use ocsp_responder_uris") std::vector<std::string> ocsp_responders() const;

      /**
      * Return the listed addresses of OCSP responders, or empty if not set
      */
      const std::vector<URI>& ocsp_responder_uris() const;

      /**
      * Return the listed addresses of ca issuers, or empty if not set
      */
      BOTAN_DEPRECATED("Use ca_issuer_uris") std::vector<std::string> ca_issuers() const;

      /**
      * Return the listed addresses of ca issuers, or empty if not set
      */
      const std::vector<URI>& ca_issuer_uris() const;

      /**
      * Return the CRL distribution point, or empty if not set
      */
      BOTAN_DEPRECATED("Use crl_distribution_point_uris") std::string crl_distribution_point() const;

      /**
      * Return the CRL distribution points, or empty if not set
      */
      BOTAN_DEPRECATED("Use crl_distribution_point_uris") std::vector<std::string> crl_distribution_points() const;

      /**
      * Return the CRL distribution points, or empty if not set
      */
      const std::vector<URI>& crl_distribution_point_uris() const;

      /**
      * Return all email addresses associated with the subject of this
      * certificate, in parsed form.
      *
      * This combines RFC 822 names from the subjectAltName extension with
      * email addresses carried in the subject DN's emailAddress attribute
      * (the latter is the legacy location for subject email, see RFC 5280
      * 4.2.1.10). DN attribute values that fail to parse as a mailbox are
      * silently skipped.
      */
      std::vector<EmailAddress> subject_email_addresses() const;

      /**
      * @return a free-form string describing the certificate
      */
      std::string to_string() const;

      /**
      * @return a fingerprint of the certificate
      * @param hash_name hash function used to calculate the fingerprint
      */
      std::string fingerprint(std::string_view hash_name = "SHA-1") const;

      /**
      * A collision resistant binary "tag" of a certificate
      *
      * The actual value is deliberately not exposed; a Tag can only be hashed
      * to a size_t, or compared with another Tag. This type is intended for use
      * as a key in std::map and std::unordered_map, or to be saved in a
      * std::set or std::unordered_set.
      */
      class Tag final {
         public:
            static constexpr size_t TagLen = 32;

            auto operator<=>(const Tag&) const = default;

            size_t hash() const noexcept {
               size_t h = 0;
               std::memcpy(&h, m_tag.data(), sizeof(h));
               return h;
            }

         private:
            friend X509_Certificate;

            explicit Tag(std::array<uint8_t, TagLen> tag) : m_tag(tag) {}

            std::array<std::uint8_t, TagLen> m_tag;
      };

      class TagHash final {
         public:
            size_t operator()(const X509_Certificate::Tag& tag) const noexcept { return tag.hash(); }
      };

      /**
      * Return a collision resistant binary "tag" of this certificate
      */
      Tag tag() const;

      /**
      * Check if a certain DNS name matches up with the information in
      * the cert
      *
      * The string variant additionally accepts a dotted-quad IPv4 input,
      * in which case the SAN for IPv4 addresses will be checked. Prefer
      * the typed overloads for IP and DNS matching.
      *
      * @param name DNS name to match
      */
      BOTAN_DEPRECATED("Use the DNSName / IPv4Address / IPv6Address overload")
      bool matches_dns_name(std::string_view name) const;

      /**
      * Check whether @p name matches the subject DNS names in this certificate.
      *
      * Compares against the dnsName entries in the subjectAltName, with the
      * RFC 6125 wildcard rules. If the certificate has no SAN at all, falls
      * back to a wildcard comparison against the subject CN.
      */
      bool matches_dns_name(const DNSName& name) const;

      /**
      * Check whether @p address appears as an iPAddress entry in the subjectAltName.
      */
      bool matches_ip(const IPv4Address& address) const;

      /**
      * Check whether @p address appears as an iPAddress entry in the subjectAltName.
      */
      bool matches_ip(const IPv6Address& address) const;

      /**
      * Check to certificates for equality.
      * @return true both certificates are (binary) equal
      */
      bool operator==(const X509_Certificate& other) const;

      /**
      * Impose an arbitrary (but consistent) ordering, eg to allow sorting
      * a container of certificate objects.
      * @return true if this is less than other by some unspecified criteria
      */
      bool operator<(const X509_Certificate& other) const;

      /**
      * Create a certificate from a data source providing the DER or
      * PEM encoded certificate.
      * @param source the data source
      */
      explicit X509_Certificate(DataSource& source);

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Create a certificate from a file containing the DER or PEM
      * encoded certificate.
      * @param filename the name of the certificate file
      */
      explicit X509_Certificate(std::string_view filename);
#endif

      /**
      * Create a certificate from a buffer
      * @param in the buffer containing the DER-encoded certificate
      */
      explicit X509_Certificate(std::span<const uint8_t> in);

      /**
      * Create a certificate from a buffer
      * @param data the buffer containing the DER-encoded certificate
      * @param length length of data in bytes
      */
      X509_Certificate(const uint8_t data[], size_t length) : X509_Certificate(std::span{data, length}) {}

      /**
      * Create an uninitialized certificate object. Any attempts to
      * access this object will throw an exception.
      */
      X509_Certificate() = default;

      X509_Certificate(const X509_Certificate& other) = default;
      X509_Certificate(X509_Certificate&& other) = default;
      X509_Certificate& operator=(const X509_Certificate& other) = default;
      X509_Certificate& operator=(X509_Certificate&& other) = default;
      ~X509_Certificate() override;

   private:
      std::string PEM_label() const override;

      std::vector<std::string> alternate_PEM_labels() const override;

      void force_decode() override;

      const X509_Certificate_Data& data() const;

      std::shared_ptr<const X509_Certificate_Data> m_data;
};

/**
* Check two certificates for inequality
* @param cert1 The first certificate
* @param cert2 The second certificate
* @return true if the arguments represent different certificates,
* false if they are binary identical
*/
BOTAN_PUBLIC_API(2, 0) bool operator!=(const X509_Certificate& cert1, const X509_Certificate& cert2);

}  // namespace Botan

#endif

/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_CERT_PARAM_BUILDER_H_
#define BOTAN_X509_CERT_PARAM_BUILDER_H_

#include <botan/api.h>
#include <botan/pkcs10.h>
#include <botan/x509cert.h>
#include <chrono>
#include <memory>
#include <optional>
#include <string_view>

namespace Botan {

class Certificate_Extension;
class Private_Key;
class RandomNumberGenerator;
class OID;

/**
* Certificate Metadata Builder
*
* Allows incrementally forming metadata included in a certificate or PKCS10 request.
*
* The various add_ methods each return a reference to this, allowing for convenient method chaining.
*/
class BOTAN_PUBLIC_API(3, 9) CertificateParametersBuilder final {
   public:
      CertificateParametersBuilder();

      CertificateParametersBuilder(const CertificateParametersBuilder& other) = delete;
      CertificateParametersBuilder& operator=(const CertificateParametersBuilder& other) = delete;

      CertificateParametersBuilder(CertificateParametersBuilder&& other) noexcept;
      CertificateParametersBuilder& operator=(CertificateParametersBuilder&& other) = delete;
      ~CertificateParametersBuilder();

      /**
      * Create a self-signed X.509 certificate from these parameters.
      *
      * @param not_before the initial validity time of the generated certificate
      * @param not_after the final validity time of the generated certificate
      * @param key the private key
      * @param rng the rng to use
      * @param hash_fn the hash function to use; if unset a reasonable default is used
      * @param padding optional padding scheme (for specifying RSA-PSS vs RSA-PKCS1,
      *        otherwise not necessary)
      *
      * @return newly created self-signed certificate
      */
      X509_Certificate into_self_signed_cert(std::chrono::system_clock::time_point not_before,
                                             std::chrono::system_clock::time_point not_after,
                                             const Private_Key& key,
                                             RandomNumberGenerator& rng,
                                             std::optional<std::string_view> hash_fn = {},
                                             std::optional<std::string_view> padding = {}) const;

      /**
      * Create a PKCS10 request
      *
      * @param key the private key
      * @param rng the rng to use
      * @param hash_fn the hash function to use; if unset a reasonable default is used
      * @param padding optional padding scheme (for specifying RSA-PSS vs RSA-PKCS1,
      *        otherwise not necessary)
      * @param challenge_password an optional challenge password included in the PKCS10 request
      *        (originally intended as a preshared key to allow authenticating a
      *        later revocation request, but now obsolete in most contexts)
      *
      * @return newly created self-signed certificate
      */
      PKCS10_Request into_pkcs10_request(const Private_Key& key,
                                         RandomNumberGenerator& rng,
                                         std::optional<std::string_view> hash_fn = {},
                                         std::optional<std::string_view> padding = {},
                                         std::optional<std::string_view> challenge_password = {}) const;

      /**
      * Add an additional common name to the certificate metadata
      */
      CertificateParametersBuilder& add_common_name(std::string_view cn);

      /**
      * Add an additional country name to the certificate metadata
      */
      CertificateParametersBuilder& add_country(std::string_view country);

      /**
      * Add an additional organization name to the certificate metadata
      */
      CertificateParametersBuilder& add_organization(std::string_view org);

      /**
      * Add an additional organization unit name to the certificate metadata
      */
      CertificateParametersBuilder& add_organizational_unit(std::string_view org_unit);

      /**
      * Add an additional locality name to the certificate metadata
      */
      CertificateParametersBuilder& add_locality(std::string_view locality);

      /**
      * Add an additional state name to the certificate metadata
      */
      CertificateParametersBuilder& add_state(std::string_view state);

      /**
      * Add an additional serial number to the certificate metadata
      *
      * Note this is the X.520 serial number included in the DN, and has nothing
      * to do with the serial number of the issued certificate.
      */
      CertificateParametersBuilder& add_serial_number(std::string_view serial);

      /**
      * Add an additional email address to the certificate metadata
      */
      CertificateParametersBuilder& add_email(std::string_view email);

      /**
      * Add an additional URI to the certificate metadata
      */
      CertificateParametersBuilder& add_uri(std::string_view uri);

      /**
      * Add an additional DNS name to the certificate metadata
      */
      CertificateParametersBuilder& add_dns(std::string_view dns);

      /**
      * Add an additional IPv4 address to the certificate metadata
      */
      CertificateParametersBuilder& add_ipv4(uint32_t ipv4);

      /**
      * Add a XMPP name to the certificate metadata
      */
      CertificateParametersBuilder& add_xmpp(std::string_view xmpp);

      /**
      * Add another allowed usage to the KeyUsage extension
      *
      * This is cummulative; all usages indicated are ORed together
      */
      CertificateParametersBuilder& add_allowed_usage(Key_Constraints kc);

      /**
      * Add another allowed usage to the ExtendedKeyUsage extension
      */
      CertificateParametersBuilder& add_allowed_extended_usage(const OID& usage);

      /**
      * Add an arbitrary certificate extension
      *
      * The extension
      */
      CertificateParametersBuilder& add_extension(std::unique_ptr<Certificate_Extension> extn,
                                                  bool is_critical = false);

      /**
      * Set the parameters as being for a CA certificate
      *
      * If the path limit is specified then the BasicConstraints extension will include
      * that value as the maximum chain length issuable by the resulting cert.
      *
      * It is not allowed to call set_as_ca_certificate more than once; further calls will
      * result in an Invalid_State exception.
      */
      CertificateParametersBuilder& set_as_ca_certificate(std::optional<size_t> path_limit = {});

   private:
      class State;
      std::unique_ptr<State> m_state;
};

}  // namespace Botan

#endif

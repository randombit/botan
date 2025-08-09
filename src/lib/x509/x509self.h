/*
* X.509 Self-Signed Certificate
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_SELF_H_
#define BOTAN_X509_SELF_H_

#include <botan/pkcs10.h>
#include <botan/pkix_types.h>
#include <botan/x509_builder.h>
#include <botan/x509cert.h>
#include <string>
#include <string_view>

namespace Botan {

class RandomNumberGenerator;
class Private_Key;

// Older interface for creating PKCS10 requests and self-signed certificates follows

/**
* Options for X.509 certificates.
*/
class BOTAN_PUBLIC_API(2, 0) X509_Cert_Options final {
   public:
      /**
      * the subject common name
      */
      std::string common_name;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject counry
      */
      std::string country;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject organization
      */
      std::string organization;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject organizational unit
      */
      std::string org_unit;  // NOLINT(*non-private-member-variable*)

      /**
       * additional subject organizational units.
       */
      std::vector<std::string> more_org_units;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject locality
      */
      std::string locality;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject state
      */
      std::string state;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject serial number
      */
      std::string serial_number;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject email adress
      */
      std::string email;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject URI
      */
      std::string uri;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject IPv4 address
      */
      std::string ip;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject DNS
      */
      std::string dns;  // NOLINT(*non-private-member-variable*)

      /**
       * additional subject DNS entries.
       */
      std::vector<std::string> more_dns;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject XMPP
      */
      std::string xmpp;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject challenge password
      */
      std::string challenge;  // NOLINT(*non-private-member-variable*)

      /**
      * the subject notBefore
      */
      X509_Time start;  // NOLINT(*non-private-member-variable*)
      /**
      * the subject notAfter
      */
      X509_Time end;  // NOLINT(*non-private-member-variable*)

      /**
      * Indicates whether the certificate request
      */
      bool is_CA = false;  // NOLINT(*non-private-member-variable*)

      /**
      * Indicates the BasicConstraints path limit
      */
      size_t path_limit = 0;  // NOLINT(*non-private-member-variable*)

      /**
      * Padding scheme to use. If empty uses a default
      */
      std::string padding_scheme;  // NOLINT(*non-private-member-variable*)

      /**
      * The key constraints for the subject public key
      */
      Key_Constraints constraints;  // NOLINT(*non-private-member-variable*)

      /**
      * The key extended constraints for the subject public key
      */
      std::vector<OID> ex_constraints;  // NOLINT(*non-private-member-variable*)

      /**
      * Additional X.509 extensions
      */
      Extensions extensions;  // NOLINT(*non-private-member-variable*)

      /**
      * Mark the certificate as a CA certificate and set the path limit.
      * @param limit the path limit to be set in the BasicConstraints extension.
      */
      void CA_key(size_t limit = 1);

      /**
      * Choose a padding scheme different from the default for the key used.
      */
      void set_padding_scheme(std::string_view scheme);

      /**
      * Set the notBefore of the certificate.
      * @param time the notBefore value of the certificate
      */
      void not_before(std::string_view time);

      /**
      * Set the notAfter of the certificate.
      * @param time the notAfter value of the certificate
      */
      void not_after(std::string_view time);

      /**
      * Add the key constraints of the KeyUsage extension.
      * @param constr the constraints to set
      */
      void add_constraints(Key_Constraints constr);

      /**
      * Add constraints to the ExtendedKeyUsage extension.
      * @param oid the oid to add
      */
      void add_ex_constraint(const OID& oid);

      /**
      * Add constraints to the ExtendedKeyUsage extension.
      * @param name the name to look up the oid to add
      */
      void add_ex_constraint(std::string_view name);

      CertificateParametersBuilder into_builder() const;

      /**
      * Construct a new options object
      * @param opts define the common name of this object. An example for this
      * parameter would be "common_name/country/organization/organizational_unit".
      * @param expire_time the expiration time (from the current clock in seconds)
      */
      BOTAN_FUTURE_EXPLICIT X509_Cert_Options(std::string_view opts = "", uint32_t expire_time = 365 * 24 * 60 * 60);
};

namespace X509 {

/**
* Create a self-signed X.509 certificate.
* @param opts the options defining the certificate to create
* @param key the private key used for signing, i.e. the key
* associated with this self-signed certificate
* @param hash_fn the hash function to use
* @param rng the rng to use
* @return newly created self-signed certificate
*/
BOTAN_PUBLIC_API(2, 0)
X509_Certificate create_self_signed_cert(const X509_Cert_Options& opts,
                                         const Private_Key& key,
                                         std::string_view hash_fn,
                                         RandomNumberGenerator& rng);

/**
* Create a PKCS#10 certificate request.
* @param opts the options defining the request to create
* @param key the key used to sign this request
* @param rng the rng to use
* @param hash_fn the hash function to use
* @return newly created PKCS#10 request
*/
BOTAN_PUBLIC_API(2, 0)
PKCS10_Request create_cert_req(const X509_Cert_Options& opts,
                               const Private_Key& key,
                               std::string_view hash_fn,
                               RandomNumberGenerator& rng);

}  // namespace X509

}  // namespace Botan

#endif

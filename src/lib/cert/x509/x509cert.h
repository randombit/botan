/*
* X.509 Certificates
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_CERTS_H__
#define BOTAN_X509_CERTS_H__

#include <botan/x509_obj.h>
#include <botan/x509_dn.h>
#include <botan/x509_key.h>
#include <botan/x509_ext.h>
#include <botan/asn1_alt_name.h>
#include <botan/datastor.h>
#include <botan/key_constraint.h>
#include <botan/name_constraint.h>
#include <map>
#include <memory>

namespace Botan {

enum class Usage_Type
   {
   UNSPECIFIED, // no restrictions
   TLS_SERVER_AUTH,
   TLS_CLIENT_AUTH,
   CERTIFICATE_AUTHORITY,
   OCSP_RESPONDER
   };

/**
* This class represents X.509 Certificate
*/
class BOTAN_DLL X509_Certificate final : public X509_Object
   {
   public:
      /**
      * Get the public key associated with this certificate.
      * @return subject public key of this certificate
      */
      Public_Key* subject_public_key() const;

      /**
      * Get the public key associated with this certificate.
      * @return subject public key of this certificate
      */
      std::vector<byte> subject_public_key_bits() const;

      /**
      * Get the certificate's issuer distinguished name (DN).
      * @return issuer DN of this certificate
      */
      X509_DN issuer_dn() const;

      /**
      * Get the certificate's subject distinguished name (DN).
      * @return subject DN of this certificate
      */
      X509_DN subject_dn() const;

      /**
      * Get a value for a specific subject_info parameter name.
      * @param name the name of the parameter to look up. Possible names are
      * "X509.Certificate.version", "X509.Certificate.serial",
      * "X509.Certificate.start", "X509.Certificate.end",
      * "X509.Certificate.v2.key_id", "X509.Certificate.public_key",
      * "X509v3.BasicConstraints.path_constraint",
      * "X509v3.BasicConstraints.is_ca", "X509v3.NameConstraints",
      * "X509v3.ExtendedKeyUsage", "X509v3.CertificatePolicies",
      * "X509v3.SubjectKeyIdentifier" or "X509.Certificate.serial".
      * @return value(s) of the specified parameter
      */
      std::vector<std::string> subject_info(const std::string& name) const;

      /**
      * Get a value for a specific subject_info parameter name.
      * @param name the name of the parameter to look up. Possible names are
      * "X509.Certificate.v2.key_id" or "X509v3.AuthorityKeyIdentifier".
      * @return value(s) of the specified parameter
      */
      std::vector<std::string> issuer_info(const std::string& name) const;

      /**
      * Raw subject DN
      */
      std::vector<byte> raw_issuer_dn() const;

      /**
      * Raw issuer DN
      */
      std::vector<byte> raw_subject_dn() const;

      /**
      * Get the notBefore of the certificate.
      * @return notBefore of the certificate
      */
      std::string start_time() const;

      /**
      * Get the notAfter of the certificate.
      * @return notAfter of the certificate
      */
      std::string end_time() const;

      /**
      * Get the X509 version of this certificate object.
      * @return X509 version
      */
      u32bit x509_version() const;

      /**
      * Get the serial number of this certificate.
      * @return certificates serial number
      */
      std::vector<byte> serial_number() const;

      /**
      * Get the DER encoded AuthorityKeyIdentifier of this certificate.
      * @return DER encoded AuthorityKeyIdentifier
      */
      std::vector<byte> authority_key_id() const;

      /**
      * Get the DER encoded SubjectKeyIdentifier of this certificate.
      * @return DER encoded SubjectKeyIdentifier
      */
      std::vector<byte> subject_key_id() const;

      /**
      * Check whether this certificate is self signed.
      * @return true if this certificate is self signed
      */
      bool is_self_signed() const { return m_self_signed; }

      /**
      * Check whether this certificate is a CA certificate.
      * @return true if this certificate is a CA certificate
      */
      bool is_CA_cert() const;

      bool allowed_usage(Key_Constraints usage) const;

      /**
      * Returns true if and only if name (referring to an extended key
      * constraint, eg "PKIX.ServerAuth") is included in the extended
      * key extension.
      */
      bool allowed_usage(const std::string& usage) const;

      bool allowed_usage(Usage_Type usage) const;

      /**
      * Get the path limit as defined in the BasicConstraints extension of
      * this certificate.
      * @return path limit
      */
      u32bit path_limit() const;

      /**
      * Check whenever a given X509 Extension is marked critical in this
      * certificate.
      */
      bool is_critical(const std::string& ex_name) const;

      /**
      * Get the key constraints as defined in the KeyUsage extension of this
      * certificate.
      * @return key constraints
      */
      Key_Constraints constraints() const;

      /**
      * Get the key constraints as defined in the ExtendedKeyUsage
      * extension of this certificate.
      * @return key constraints
      */
      std::vector<std::string> ex_constraints() const;

      /**
      * Get the name constraints as defined in the NameConstraints
      * extension of this certificate.
      * @return name constraints
      */
      NameConstraints name_constraints() const;

      /**
      * Get the policies as defined in the CertificatePolicies extension
      * of this certificate.
      * @return certificate policies
      */
      std::vector<std::string> policies() const;

      /**
      * Get all extensions of this certificate.
      * @return certificate extensions
      */
      Extensions v3_extensions() const;

      /**
      * Return the listed address of an OCSP responder, or empty if not set
      */
      std::string ocsp_responder() const;

      /**
      * Return the CRL distribution point, or empty if not set
      */
      std::string crl_distribution_point() const;

      /**
      * @return a string describing the certificate
      */
      std::string to_string() const;

      /**
      * Return a fingerprint of the certificate
      */
      std::string fingerprint(const std::string& = "SHA-1") const;

      /**
      * Check if a certain DNS name matches up with the information in
      * the cert
      */
      bool matches_dns_name(const std::string& name) const;

      /**
      * Check to certificates for equality.
      * @return true both certificates are (binary) equal
      */
      bool operator==(const X509_Certificate& other) const;

      /**
      * Impose an arbitrary (but consistent) ordering
      * @return true if this is less than other by some unspecified criteria
      */
      bool operator<(const X509_Certificate& other) const;

      /**
      * Create a certificate from a data source providing the DER or
      * PEM encoded certificate.
      * @param source the data source
      */
      explicit X509_Certificate(DataSource& source);

      /**
      * Create a certificate from a file containing the DER or PEM
      * encoded certificate.
      * @param filename the name of the certificate file
      */
      explicit X509_Certificate(const std::string& filename);

      explicit X509_Certificate(const std::vector<byte>& in);

      X509_Certificate(const X509_Certificate& other);

      X509_Certificate& operator=(const X509_Certificate& other);

   private:
      void force_decode() override;
      friend class X509_CA;
      friend class BER_Decoder;

      X509_Certificate() {}

      Data_Store m_subject, m_issuer;
      bool m_self_signed;
      Extensions m_v3_extensions;
   };

/**
* Check two certificates for inequality
* @return true if the arguments represent different certificates,
* false if they are binary identical
*/
BOTAN_DLL bool operator!=(const X509_Certificate&, const X509_Certificate&);

/*
* Data Store Extraction Operations
*/
BOTAN_DLL X509_DN create_dn(const Data_Store&);
BOTAN_DLL AlternativeName create_alt_name(const Data_Store&);

}

#endif

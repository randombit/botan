/*
* X.509 Certificate Extensions
* (C) 1999-2007,2012 Jack Lloyd
* (C) 2024 Anton Einax, Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_EXTENSIONS_H_
#define BOTAN_X509_EXTENSIONS_H_

#include <botan/bigint.h>
#include <botan/ipv4_address.h>
#include <botan/ipv6_address.h>
#include <botan/pkix_types.h>
#include <botan/telephone_number.h>

#include <array>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace Botan {

class X509_Certificate;

namespace Cert_Extension {

static const size_t NO_CERT_PATH_LIMIT = 0xFFFFFFF0;

/**
* Basic Constraints Extension
*/
class BOTAN_PUBLIC_API(2, 0) Basic_Constraints final : public Certificate_Extension {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Basic_Constraints>(m_is_ca, m_path_length_constraint);
      }

      BOTAN_FUTURE_EXPLICIT Basic_Constraints(bool is_ca = false, size_t path_length_constraint = 0);

      Basic_Constraints(bool is_ca, std::optional<size_t> path_length_constraint);

      BOTAN_DEPRECATED("Use is_ca") bool get_is_ca() const { return m_is_ca; }

      /**
      * Note that this function returns NO_CERT_PATH_LIMIT if the value was not set
      * in the extension.
      */
      BOTAN_DEPRECATED("Use path_length_constraint") size_t get_path_limit() const;

      bool is_ca() const { return m_is_ca; }

      std::optional<size_t> path_length_constraint() const { return m_path_length_constraint; }

      static OID static_oid() { return OID({2, 5, 29, 19}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.BasicConstraints"; }

      bool is_appropriate_context(Extension_Context context) const override;

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      bool m_is_ca;
      std::optional<size_t> m_path_length_constraint;
};

/**
* Key Usage Constraints Extension
*/
class BOTAN_PUBLIC_API(2, 0) Key_Usage final : public Certificate_Extension {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Key_Usage>(m_constraints);
      }

      explicit Key_Usage(Key_Constraints c) : m_constraints(c) {}

      explicit Key_Usage() : m_constraints(Key_Constraints::None) {}

      Key_Constraints get_constraints() const { return m_constraints; }

      static OID static_oid() { return OID({2, 5, 29, 15}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.KeyUsage"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return !m_constraints.empty(); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      Key_Constraints m_constraints;
};

/**
* Subject Key Identifier Extension
*/
class BOTAN_PUBLIC_API(2, 0) Subject_Key_ID final : public Certificate_Extension {
   public:
      Subject_Key_ID() = default;

      explicit Subject_Key_ID(const std::vector<uint8_t>& k) : m_key_id(k) {}

      /**
      * Derive the key identifier from the public key, using the first
      * method given in RFC 5280 4.2.1.2:
      *
      *    (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of
      *    the value of the BIT STRING subjectPublicKey (excluding the tag,
      *    length, and number of unused bits).
      */
      explicit Subject_Key_ID(const Public_Key& pub_key);

      BOTAN_DEPRECATED("Use Subject_Key_ID(const Public_Key&)")
      Subject_Key_ID(const std::vector<uint8_t>& public_key, std::string_view hash_fn);

      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Subject_Key_ID>(m_key_id);
      }

      const std::vector<uint8_t>& get_key_id() const { return m_key_id; }

      static OID static_oid() { return OID({2, 5, 29, 14}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.SubjectKeyIdentifier"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return (!m_key_id.empty()); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::vector<uint8_t> m_key_id;
};

/**
* Authority Key Identifier Extension
*/
class BOTAN_PUBLIC_API(2, 0) Authority_Key_ID final : public Certificate_Extension {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override { return std::make_unique<Authority_Key_ID>(*this); }

      Authority_Key_ID() = default;

      explicit Authority_Key_ID(const std::vector<uint8_t>& k) : m_key_id(k) {}

      /**
      * The authorityCertIssuer and authorityCertSerialNumber fields, which
      * identify the certificate holding the authority's signing key.
      */
      struct Authority_Cert_Identifier final {
            AlternativeName issuer;
            X509_Serial_Number serial_number;
      };

      Authority_Key_ID(const std::vector<uint8_t>& k, Authority_Cert_Identifier authority_cert) :
            m_key_id(k), m_authority_cert(std::move(authority_cert)) {}

      const std::vector<uint8_t>& get_key_id() const { return m_key_id; }

      /**
      * The authorityCertIssuer/authorityCertSerialNumber fields, if present
      */
      const std::optional<Authority_Cert_Identifier>& authority_cert_identifier() const { return m_authority_cert; }

      static OID static_oid() { return OID({2, 5, 29, 35}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.AuthorityKeyIdentifier"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return !m_key_id.empty() || m_authority_cert.has_value(); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::vector<uint8_t> m_key_id;
      std::optional<Authority_Cert_Identifier> m_authority_cert;
};

/**
* Subject Alternative Name Extension
*/
class BOTAN_PUBLIC_API(2, 4) Subject_Alternative_Name final : public Certificate_Extension {
   public:
      const AlternativeName& get_alt_name() const { return m_alt_name; }

      static OID static_oid() { return OID({2, 5, 29, 17}); }

      OID oid_of() const override { return static_oid(); }

      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Subject_Alternative_Name>(get_alt_name());
      }

      explicit Subject_Alternative_Name(const AlternativeName& name = AlternativeName()) : m_alt_name(name) {}

   private:
      std::string oid_name() const override { return "X509v3.SubjectAlternativeName"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return m_alt_name.has_items(); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      AlternativeName m_alt_name;
};

/**
* Issuer Alternative Name Extension
*/
class BOTAN_PUBLIC_API(2, 0) Issuer_Alternative_Name final : public Certificate_Extension {
   public:
      const AlternativeName& get_alt_name() const { return m_alt_name; }

      static OID static_oid() { return OID({2, 5, 29, 18}); }

      OID oid_of() const override { return static_oid(); }

      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Issuer_Alternative_Name>(get_alt_name());
      }

      explicit Issuer_Alternative_Name(const AlternativeName& name = AlternativeName()) : m_alt_name(name) {}

   private:
      std::string oid_name() const override { return "X509v3.IssuerAlternativeName"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return m_alt_name.has_items(); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      AlternativeName m_alt_name;
};

/**
* Extended Key Usage Extension
*/
class BOTAN_PUBLIC_API(2, 0) Extended_Key_Usage final : public Certificate_Extension {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Extended_Key_Usage>(m_oids);
      }

      Extended_Key_Usage() = default;

      explicit Extended_Key_Usage(const std::vector<OID>& o) : m_oids(o) {}

      const std::vector<OID>& object_identifiers() const { return m_oids; }

      static OID static_oid() { return OID({2, 5, 29, 37}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.ExtendedKeyUsage"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return (!m_oids.empty()); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::vector<OID> m_oids;
};

/**
* Name Constraints
*/
class BOTAN_PUBLIC_API(2, 0) Name_Constraints final : public Certificate_Extension {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Name_Constraints>(m_name_constraints);
      }

      Name_Constraints() = default;

      BOTAN_FUTURE_EXPLICIT Name_Constraints(const NameConstraints& nc) : m_name_constraints(nc) {}

      void validate(const X509_Certificate& subject,
                    const std::optional<X509_Certificate>& issuer,
                    const std::vector<X509_Certificate>& cert_path,
                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                    size_t pos) const override;

      const NameConstraints& get_name_constraints() const { return m_name_constraints; }

      static OID static_oid() { return OID({2, 5, 29, 30}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.NameConstraints"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return true; }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      NameConstraints m_name_constraints;
};

/**
* Certificate Policies Extension
*/
class BOTAN_PUBLIC_API(2, 0) Certificate_Policies final : public Certificate_Extension {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Certificate_Policies>(*this);
      }

      Certificate_Policies() = default;

      explicit Certificate_Policies(const std::vector<OID>& oids);

      const std::vector<OID>& get_policy_oids() const { return m_oids; }

      static OID static_oid() { return OID({2, 5, 29, 32}); }

      OID oid_of() const override { return static_oid(); }

      void validate(const X509_Certificate& subject,
                    const std::optional<X509_Certificate>& issuer,
                    const std::vector<X509_Certificate>& cert_path,
                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                    size_t pos) const override;

   private:
      std::string oid_name() const override { return "X509v3.CertificatePolicies"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return (!m_oids.empty()); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::vector<OID> m_oids;
      bool m_has_duplicate = false;
};

/**
* Authority Information Access Extension
*/
class BOTAN_PUBLIC_API(2, 0) Authority_Information_Access final : public Certificate_Extension {
   public:
      /**
      * An AccessDescription preserving accessMethod plus a raw view of the
      * accessLocation GeneralName.
      *
      *     AccessDescription  ::=  SEQUENCE {
      *          accessMethod          OBJECT IDENTIFIER,
      *          accessLocation        GeneralName }
      */
      class BOTAN_PUBLIC_API(3, 13) AccessDescription final {
         public:
            AccessDescription(OID method,
                              ASN1_Type location_tag,
                              ASN1_Class location_class,
                              std::vector<uint8_t> location_value) :
                  m_method(std::move(method)),
                  m_location_tag(location_tag),
                  m_location_class(location_class),
                  m_location_value(std::move(location_value)) {}

            const OID& access_method() const { return m_method; }

            /**
            * The GeneralName CHOICE tag (the [n] of the access location).
            */
            ASN1_Type location_tag() const { return m_location_tag; }

            ASN1_Class location_class() const { return m_location_class; }

            /**
            * The raw value bytes of the accessLocation, without the leading
            * tag/length. For a URI accessLocation this is the IA5String value;
            * for directoryName it is the DER of the Name.
            */
            const std::vector<uint8_t>& location_value() const { return m_location_value; }

            /**
            * If location is a URI (tag 6 IMPLICIT IA5String), return the string;
            * nullopt otherwise.
            */
            std::optional<std::string> location_as_uri_string() const;

         private:
            OID m_method;
            ASN1_Type m_location_tag;
            ASN1_Class m_location_class;
            std::vector<uint8_t> m_location_value;
      };

      std::unique_ptr<Certificate_Extension> copy() const override;

      Authority_Information_Access() = default;

      BOTAN_DEPRECATED("Use constructor with list of OCSP responder URIs")
      explicit Authority_Information_Access(std::string_view ocsp,
                                            const std::vector<std::string>& ca_issuers = std::vector<std::string>());

      BOTAN_DEPRECATED("Use constructor that accepts URI types")
      explicit Authority_Information_Access(const std::vector<std::string>& ocsp_responders,
                                            const std::vector<std::string>& ca_issuers = std::vector<std::string>());

      explicit Authority_Information_Access(std::vector<URI> ocsp_responders,
                                            std::vector<URI> ca_issuers = std::vector<URI>());

      /**
      * Construct an AIA from raw AccessDescriptions, allowing the caller to
      * emit access methods beyond id-ad-ocsp / id-ad-caIssuers and access
      * locations beyond URIs. The typed URI accessors (ocsp_responder_uris,
      * ca_issuer_uris) are also populated from any URI-form entries whose
      * accessMethod is id-ad-ocsp or id-ad-caIssuers so the two views stay
      * consistent.
      */
      explicit Authority_Information_Access(std::vector<AccessDescription> access_descriptions);

      /**
      * Append a single AccessDescription. URI-form id-ad-ocsp / id-ad-caIssuers
      * entries also populate the corresponding typed URI accessor list.
      */
      void add_access_description(AccessDescription ad);

      BOTAN_DEPRECATED("Use ocsp_responder_uris") std::string ocsp_responder() const {
         if(m_ocsp_responders.empty()) {
            return {};
         }
         return m_ocsp_responders[0].original_input();
      }

      BOTAN_DEPRECATED("Use ocsp_responder_uris") std::vector<std::string> ocsp_responders() const;

      const std::vector<URI>& ocsp_responder_uris() const { return m_ocsp_responders; }

      /**
      * The full set of AccessDescriptions, including access methods that are
      * not id-ad-ocsp or id-ad-caIssuers and access locations that are not URIs
      */
      const std::vector<AccessDescription>& access_descriptions() const { return m_access_descriptions; }

      static OID static_oid() { return OID({1, 3, 6, 1, 5, 5, 7, 1, 1}); }

      OID oid_of() const override { return static_oid(); }

      BOTAN_DEPRECATED("Use ca_issuer_uris") std::vector<std::string> ca_issuers() const;

      const std::vector<URI>& ca_issuer_uris() const { return m_ca_issuers; }

   private:
      std::string oid_name() const override { return "PKIX.AuthorityInformationAccess"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override {
         // The URI lists are views into the general AccessDescription list
         return !m_access_descriptions.empty();
      }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::vector<URI> m_ocsp_responders;
      std::vector<URI> m_ca_issuers;
      std::vector<AccessDescription> m_access_descriptions;
};

/**
* CRL Number Extension
*/
class BOTAN_PUBLIC_API(2, 0) CRL_Number final : public Certificate_Extension {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override;

      CRL_Number() : m_has_value(false), m_crl_number(BigInt::zero()) {}

      BOTAN_FUTURE_EXPLICIT CRL_Number(size_t n) : CRL_Number(BigInt::from_u64(n)) {}

      explicit CRL_Number(BigInt n);

      const BigInt& crl_number() const;

      BOTAN_DEPRECATED("Use crl_number") size_t get_crl_number() const;

      static OID static_oid() { return OID({2, 5, 29, 20}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.CRLNumber"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return m_has_value; }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      bool m_has_value;
      BigInt m_crl_number;
};

/**
* CRL Entry Reason Code Extension
*/
class BOTAN_PUBLIC_API(2, 0) CRL_ReasonCode final : public Certificate_Extension {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<CRL_ReasonCode>(m_reason);
      }

      explicit CRL_ReasonCode(CRL_Code r = CRL_Code::Unspecified) : m_reason(r) {}

      CRL_Code get_reason() const { return m_reason; }

      static OID static_oid() { return OID({2, 5, 29, 21}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.ReasonCode"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return (m_reason != CRL_Code::Unspecified); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      CRL_Code m_reason;
};

/**
* DistributionPointName used by CRLDistributionPoints and
* IssuingDistributionPoint (RFC 5280 4.2.1.13 / 5.2.5).
*
*     DistributionPointName ::= CHOICE {
*          fullName                [0]     GeneralNames,
*          nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
*
* Currently only the fullName CHOICE arm is supported; nameRelativeToCRLIssuer
* is rejected at decode time.
*/
class BOTAN_PUBLIC_API(3, 13) DistributionPointName final : public ASN1_Object {
   public:
      DistributionPointName() = default;

      explicit DistributionPointName(AlternativeName full_name) : m_full_name(std::move(full_name)) {}

      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      /**
      * The fullName GeneralNames
      *
      * In the current implementation this will always be set, it returns an
      * optional to help any future addition of nameRelativeToCRLIssuer, in
      * which case full_name would return nullopt and another getter would
      * return the relative name.
      */
      const std::optional<AlternativeName>& full_name() const { return m_full_name; }

   private:
      std::optional<AlternativeName> m_full_name;
};

/**
* CRL Distribution Points Extension (RFC 5280 4.2.1.13)
*/
class BOTAN_PUBLIC_API(2, 0) CRL_Distribution_Points final : public Certificate_Extension {
   public:
      /*
      * DistributionPoint ::= SEQUENCE {
      *      distributionPoint       [0]     DistributionPointName OPTIONAL,
      *      reasons                 [1]     ReasonFlags OPTIONAL,
      *      cRLIssuer               [2]     GeneralNames OPTIONAL }
      */
      class BOTAN_PUBLIC_API(2, 0) Distribution_Point final : public ASN1_Object {
         public:
            void encode_into(DER_Encoder& to) const override;
            void decode_from(BER_Decoder& from) override;

            Distribution_Point() = default;

            explicit Distribution_Point(const AlternativeName& name) : m_dp_name(DistributionPointName(name)) {}

            Distribution_Point(std::optional<DistributionPointName> dp_name,
                               std::optional<ReasonFlags> reasons,
                               std::optional<AlternativeName> crl_issuer) :
                  m_dp_name(std::move(dp_name)), m_reasons(reasons), m_crl_issuer(std::move(crl_issuer)) {}

            /**
            * Return the optional distribution point name
            */
            const std::optional<DistributionPointName>& distribution_point_name() const { return m_dp_name; }

            /**
            * Return the optional reason flags
            */
            const std::optional<ReasonFlags>& reasons() const { return m_reasons; }

            /**
            * Return the optional CRL issuer name
            */
            const std::optional<AlternativeName>& crl_issuer() const { return m_crl_issuer; }

            /**
            * Deprecated compatibility shim. Raises Invalid_State if the distributionPoint
            * field is absent or the name is a relative name.
            *
            * Prefer distribution_point_name(), which surfaces both the OPTIONAL field and
            * the CHOICE arm explicitly.
            */
            BOTAN_DEPRECATED("Use distribution_point_name()") const AlternativeName& point() const;

         private:
            std::optional<DistributionPointName> m_dp_name;
            std::optional<ReasonFlags> m_reasons;
            std::optional<AlternativeName> m_crl_issuer;
      };

      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<CRL_Distribution_Points>(*this);
      }

      CRL_Distribution_Points() = default;

      explicit CRL_Distribution_Points(const std::vector<Distribution_Point>& points);

      const std::vector<Distribution_Point>& distribution_points() const { return m_distribution_points; }

      BOTAN_DEPRECATED("Use crl_distribution_point_uris") std::vector<std::string> crl_distribution_urls() const;

      const std::vector<URI>& crl_distribution_point_uris() const { return m_crl_distribution_urls; }

      static OID static_oid() { return OID({2, 5, 29, 31}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.CRLDistributionPoints"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return !m_distribution_points.empty(); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::vector<Distribution_Point> m_distribution_points;
      std::vector<URI> m_crl_distribution_urls;
};

/**
* CRL Issuing Distribution Point Extension (RFC 5280 5.2.5)
*
*     IssuingDistributionPoint ::= SEQUENCE {
*          distributionPoint          [0] DistributionPointName OPTIONAL,
*          onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
*          onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
*          onlySomeReasons            [3] ReasonFlags OPTIONAL,
*          indirectCRL                [4] BOOLEAN DEFAULT FALSE,
*          onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
*/
class BOTAN_PUBLIC_API(2, 4) CRL_Issuing_Distribution_Point final : public Certificate_Extension {
   public:
      CRL_Issuing_Distribution_Point() = default;

      explicit CRL_Issuing_Distribution_Point(DistributionPointName dp_name) : m_dp_name(std::move(dp_name)) {}

      CRL_Issuing_Distribution_Point(std::optional<DistributionPointName> dp_name,
                                     bool only_contains_user_certs,
                                     bool only_contains_ca_certs,
                                     std::optional<ReasonFlags> only_some_reasons,
                                     bool indirect_crl,
                                     bool only_contains_attribute_certs) :
            m_dp_name(std::move(dp_name)),
            m_only_contains_user_certs(only_contains_user_certs),
            m_only_contains_ca_certs(only_contains_ca_certs),
            m_only_some_reasons(only_some_reasons),
            m_indirect_crl(indirect_crl),
            m_only_contains_attribute_certs(only_contains_attribute_certs) {}

      /**
      * Deprecated compatibility shim for the pre-3.13 API. Extracts the
      * DistributionPointName from a cert-side Distribution_Point.
      */
      BOTAN_DEPRECATED("Use the DistributionPointName constructor")
      explicit CRL_Issuing_Distribution_Point(const CRL_Distribution_Points::Distribution_Point& distribution_point) :
            m_dp_name(distribution_point.distribution_point_name()) {}

      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<CRL_Issuing_Distribution_Point>(*this);
      }

      /**
      * distributionPoint [0] DistributionPointName OPTIONAL.
      */
      const std::optional<DistributionPointName>& distribution_point_name() const { return m_dp_name; }

      bool only_contains_user_certs() const { return m_only_contains_user_certs; }

      bool only_contains_ca_certs() const { return m_only_contains_ca_certs; }

      const std::optional<ReasonFlags>& only_some_reasons() const { return m_only_some_reasons; }

      bool indirect_crl() const { return m_indirect_crl; }

      bool only_contains_attribute_certs() const { return m_only_contains_attribute_certs; }

      /**
      * Deprecated compatibility shim for the pre-3.13 API. Returns the
      * fullName GeneralNames; raises Invalid_State if the distributionPoint
      * field is absent or its CHOICE arm is nameRelativeToCRLIssuer.
      */
      BOTAN_DEPRECATED("Use distribution_point_name()") const AlternativeName& get_point() const;

      static OID static_oid() { return OID({2, 5, 29, 28}); }

      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.CRLIssuingDistributionPoint"; }

      bool is_appropriate_context(Extension_Context context) const override;

      /**
      * RFC 5280 5.2.5: "Conforming CRL issuers MUST NOT issue CRLs where
      * the DER encoding of the issuing distribution point extension is
      * an empty sequence." Suppress emission when no field is set.
      */
      bool should_encode() const override {
         return m_dp_name.has_value() || m_only_contains_user_certs || m_only_contains_ca_certs ||
                m_only_some_reasons.has_value() || m_indirect_crl || m_only_contains_attribute_certs;
      }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::optional<DistributionPointName> m_dp_name;
      bool m_only_contains_user_certs = false;
      bool m_only_contains_ca_certs = false;
      std::optional<ReasonFlags> m_only_some_reasons;
      bool m_indirect_crl = false;
      bool m_only_contains_attribute_certs = false;
};

/**
* OCSP NoCheck Extension
*
* RFC6960 4.2.2.2.1
*    A CA may specify that an OCSP client can trust a responder for the
*    lifetime of the responder's certificate.  The CA does so by
*    including the extension id-pkix-ocsp-nocheck.
*
* In other words: OCSP responder certificates with this extension do not need
*                 to be validated against some revocation info.
*/
class OCSP_NoCheck final : public Certificate_Extension {
   public:
      OCSP_NoCheck() = default;

      std::unique_ptr<Certificate_Extension> copy() const override { return std::make_unique<OCSP_NoCheck>(); }

      static OID static_oid() { return OID({1, 3, 6, 1, 5, 5, 7, 48, 1, 5}); }

      OID oid_of() const override { return static_oid(); }

      void validate(const X509_Certificate& subject,
                    const std::optional<X509_Certificate>& issuer,
                    const std::vector<X509_Certificate>& cert_path,
                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                    size_t pos) const override;

   private:
      std::string oid_name() const override { return "PKIX.OCSP.NoCheck"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return true; }

      std::vector<uint8_t> encode_inner() const override;

      void decode_inner(const std::vector<uint8_t>& in) override;
};

/**
* No Revocation Available Extension
*
* RFC 9608 Section 2
*
*    The noRevAvail extension, defined in [X.509-2019-TC2], allows a CA to
*    indicate that no revocation information will be made available for
*    this certificate.
*
*    This extension MUST NOT be present in CA public key certificates.
*
*    Conforming CAs MUST include this extension in certificates for which
*    no revocation information will be published.  When present,
*    conforming CAs MUST mark this extension as non-critical.
*/
class BOTAN_PUBLIC_API(3, 13) NoRevocationAvailable final : public Certificate_Extension {
   public:
      NoRevocationAvailable() = default;

      std::unique_ptr<Certificate_Extension> copy() const override { return std::make_unique<NoRevocationAvailable>(); }

      static OID static_oid() { return OID({2, 5, 29, 56}); }

      OID oid_of() const override { return static_oid(); }

      void validate(const X509_Certificate& subject,
                    const std::optional<X509_Certificate>& issuer,
                    const std::vector<X509_Certificate>& cert_path,
                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                    size_t pos) const override;

   private:
      std::string oid_name() const override { return "X509v3.NoRevocationAvailable"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return true; }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;
};

/**
* TNAuthList extension
*
* RFC 8226 Secure Telephone Identity Credentials: Certificates, Section 9
*
* The extension is a list of entries, each of which is a service provider
* code, a contiguous range of telephone numbers, or a single telephone number.
*/
class BOTAN_PUBLIC_API(3, 5) TNAuthList final : public Certificate_Extension {
   public:
      class BOTAN_PUBLIC_API(3, 5) Entry final : public ASN1_Object {
         public:
            /**
            * The TNEntry CHOICE alternative; the values are the context specific tags
            */
            enum Type : uint8_t /* NOLINT(*-use-enum-class) */ {
               ServiceProviderCode = 0,
               TelephoneNumberRange = 1,
               TelephoneNumber = 2
            };

            /**
            * Retained for the deprecated telephone_number_range accessor
            */
            struct TelephoneNumberRangeData {
                  ASN1_String start;
                  size_t count{};
            };

            using RangeContainer = std::vector<TelephoneNumberRangeData>;
            using DataContainer = std::variant<ASN1_String, RangeContainer>;

            /**
            * Create a service provider code entry, for instance an OCN or SPID
            *
            * Throws Invalid_Argument if @p spc is empty or not IA5
            */
            static Entry from_service_provider_code(std::string_view spc);

            /**
            * Create a telephone number range entry
            *
            * Throws Invalid_Argument if @p range holds fewer than two numbers
            */
            static Entry from_telephone_number_range(const Botan::TelephoneNumberRange& range);

            /**
            * Create a single telephone number entry
            */
            static Entry from_telephone_number(const Botan::TelephoneNumber& tn);

            /**
            * Default constructor; the entry is only meaningful once decoded
            */
            Entry() = default;

            void encode_into(DER_Encoder& to) const override;
            void decode_from(BER_Decoder& from) override;

            Type type() const { return m_type; }

            /**
            * Return the service provider code; throws unless type() is ServiceProviderCode
            */
            const std::string& service_provider_code() const;

            /**
            * Return the range; throws unless type() is TelephoneNumberRange
            */
            const Botan::TelephoneNumberRange& range() const;

            /**
            * Return the telephone number; throws unless type() is TelephoneNumber
            */
            const Botan::TelephoneNumber& number() const;

            /**
            * Return the range as a single element list; throws unless type() is TelephoneNumberRange
            */
            BOTAN_DEPRECATED("Use range()") const RangeContainer& telephone_number_range() const;

            /**
            * Return the telephone number as a string; throws unless type() is TelephoneNumber
            */
            BOTAN_DEPRECATED("Use number()") const std::string& telephone_number() const;

         private:
            void set_range(Botan::TelephoneNumberRange range);

            Type m_type = ServiceProviderCode;
            std::variant<std::string, Botan::TelephoneNumber, Botan::TelephoneNumberRange> m_data;
            // TODO(Botan4) remove along with telephone_number_range()
            RangeContainer m_legacy_range;
      };

      /**
      * Create an empty extension; only useful as a decoding target
      */
      TNAuthList() = default;

      /**
      * Create an extension from a list of entries; throws if @p entries is empty
      */
      explicit TNAuthList(std::vector<Entry> entries);

      /**
      * Decode a bare DER encoded TNAuthorizationList, such as one retrieved
      * via an id-ad-stirTNList access description (RFC 8226 Section 10.1)
      */
      static TNAuthList from_der(std::span<const uint8_t> der);

      std::unique_ptr<Certificate_Extension> copy() const override { return std::make_unique<TNAuthList>(*this); }

      static OID static_oid() { return OID({1, 3, 6, 1, 5, 5, 7, 1, 26}); }

      OID oid_of() const override { return static_oid(); }

      const std::vector<Entry>& entries() const { return m_tn_entries; }

      /**
      * Return true if every entry of @p delegate lies within the authority of
      * this list, following RFC 9060 Section 4. Service provider codes must
      * appear in this list verbatim. If this list contains a service provider
      * code, all numbers and ranges are accepted, including numbers containing
      * '*' or '#': the numbers behind a code are not known locally, so the
      * issuer's assignment checks are trusted. Otherwise, numbers containing
      * '*' or '#' must appear in this list verbatim, and numeric numbers and
      * ranges must fall within this list's numbers and ranges.
      */
      bool encompasses(const TNAuthList& delegate) const;

      /**
      * Checks this list against the list of every CA above it in the path,
      * adding TN_AUTH_LIST_ERROR to this certificate's status if any of
      * them does not encompass it.
      */
      void validate(const X509_Certificate& subject,
                    const std::optional<X509_Certificate>& issuer,
                    const std::vector<X509_Certificate>& cert_path,
                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                    size_t pos) const override;

   private:
      std::string oid_name() const override { return "PKIX.TNAuthList"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return !m_tn_entries.empty(); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::vector<Entry> m_tn_entries;
};

/**
 * IP Address Blocks Extension
 *
 * RFC 3779 X.509 Extensions for IP Addr
 *
*/
class BOTAN_PUBLIC_API(3, 9) IPAddressBlocks final : public Certificate_Extension {
   public:
      enum class Version : uint8_t {
         IPv4 = 4,
         IPv6 = 16,
      };

      /**
      * An IP address of the given version
      *
      * In a future major release this will become an alias of IPv4Address or
      * IPv6Address. Use to_bytes and the conversions to/from IPv4Address and
      * IPv6Address to write code that works with both.
      *
      * TODO(Botan4) remove this type
      */
      template <Version V>
      class BOTAN_PUBLIC_API(3, 9) IPAddress final {
            static constexpr size_t Length = static_cast<size_t>(V);

            using Address = std::conditional_t<V == Version::IPv4, IPv4Address, IPv6Address>;

         public:
            BOTAN_DEPRECATED("Construct from an IPv4Address or IPv6Address")
            explicit IPAddress(std::span<const uint8_t> v);

            /**
            * Create from an IPv4Address (for IPv4) or IPv6Address (for IPv6)
            */
            explicit IPAddress(const Address& addr) : m_value(addr.to_bytes()) {}

            /**
            * Return the address as bytes, network-byte-order
            */
            BOTAN_DEPRECATED("Use to_bytes") std::array<uint8_t, Length> value() const { return m_value; }

            /**
            * Return the address as bytes, network-byte-order
            */
            std::array<uint8_t, Length> to_bytes() const { return m_value; }

            /**
            * Convert to IPv4Address or IPv6Address
            */
            // NOLINTNEXTLINE(*-explicit-conversions,*-explicit-constructor)
            operator Address() const { return Address(m_value); }

         private:
            friend class IPAddressBlocks;
            IPAddress() = default;

            static IPAddress<V> from_bytes(std::span<const uint8_t> v);

            // The next address, wrapping to zero after the maximum value
            IPAddress<V> successor() const;

            BOTAN_DEPRECATED("Will be removed in a future major release")
            friend IPAddress<V> operator+(IPAddress<V> lhs, size_t rhs) {
               // we only really need to be able to compute +1, so this is fine
               for(size_t i = 0; i < rhs; i++) {
                  lhs = lhs.successor();
               }
               return lhs;
            }

            friend std::strong_ordering operator<=>(const IPAddress<V> lhs, const IPAddress<V>& rhs) {
               for(size_t i = 0; i < Length; i++) {
                  if(lhs.m_value[i] < rhs.m_value[i]) {
                     return std::strong_ordering::less;
                  } else if(lhs.m_value[i] > rhs.m_value[i]) {
                     return std::strong_ordering::greater;
                  }
               }
               return std::strong_ordering::equal;
            }

            friend bool operator==(const IPAddress<V>& lhs, const IPAddress<V>& rhs) {
               return lhs.m_value == rhs.m_value;
            }

            std::array<uint8_t, Length> m_value;
      };

      /*
      * TODO(Botan4) remove this type
      */
      template <Version V>
      class BOTAN_PUBLIC_API(3, 9) IPAddressOrRange final : public ASN1_Object {
            using Address = std::conditional_t<V == Version::IPv4, IPv4Address, IPv6Address>;
            using Subnet = std::conditional_t<V == Version::IPv4, IPv4Subnet, IPv6Subnet>;

         public:
            void encode_into(DER_Encoder& to) const override;
            void decode_from(BER_Decoder& from) override;

            IPAddressOrRange() = default;

            explicit IPAddressOrRange(const IPAddress<V>& addr) : m_min(addr), m_max(addr) {}

            IPAddressOrRange(const IPAddress<V>& min, const IPAddress<V>& max) : m_min(min), m_max(max) {
               if(max < min) {
                  throw Decoding_Error("IP address ranges must be sorted");
               }
            }

            /**
            * Create a range containing a single address (IPv4Address or IPv6Address)
            */
            explicit IPAddressOrRange(const Address& addr) : IPAddressOrRange(addr, addr) {}

            /**
            * Create a range of addresses (IPv4Address or IPv6Address) from min to max (inclusive)
            */
            IPAddressOrRange(const Address& min, const Address& max) :
                  IPAddressOrRange(IPAddress<V>(min), IPAddress<V>(max)) {}

            /**
            * Create a range covering exactly the addresses of a subnet (IPv4Subnet or IPv6Subnet)
            */
            explicit IPAddressOrRange(const Subnet& subnet) :
                  IPAddressOrRange(subnet.address(), subnet.last_address()) {}

            IPAddress<V> min() const { return m_min; }

            IPAddress<V> max() const { return m_max; }

            /**
            * If this range covers exactly the addresses of some subnet, return it.
            * Otherwise return nullopt.
            */
            std::optional<Subnet> as_subnet() const;

         private:
            IPAddress<V> m_min{};
            IPAddress<V> m_max{};

            IPAddress<V> decode_single_address(const ASN1_BitString& decoded, bool min);
      };

      template <Version V>
      class BOTAN_PUBLIC_API(3, 9) IPAddressChoice final : public ASN1_Object {
         public:
            void encode_into(DER_Encoder& to) const override;
            void decode_from(BER_Decoder& from) override;

            const std::optional<std::vector<IPAddressOrRange<V>>>& ranges() const { return m_ip_addr_ranges; }

            IPAddressChoice() = default;

            explicit IPAddressChoice(std::optional<std::span<const IPAddressOrRange<V>>> ranges);

         private:
            std::optional<std::vector<IPAddressOrRange<V>>> m_ip_addr_ranges;
      };

      class BOTAN_PUBLIC_API(3, 9) IPAddressFamily final : public ASN1_Object {
         public:
            typedef std::variant<IPAddressChoice<Version::IPv4>, IPAddressChoice<Version::IPv6>> AddrChoice;

            void encode_into(DER_Encoder& to) const override;
            void decode_from(BER_Decoder& from) override;

            IPAddressFamily() = default;

            explicit IPAddressFamily(const AddrChoice& choice, std::optional<uint8_t> safi = std::nullopt) :
                  m_safi(safi), m_ip_addr_choice(choice) {
               if(std::holds_alternative<IPAddressChoice<Version::IPv4>>(choice)) {
                  m_afi = 1;
               } else {
                  m_afi = 2;
               }
            }

            uint16_t afi() const { return m_afi; }

            std::optional<uint8_t> safi() const { return m_safi; }

            const AddrChoice& addr_choice() const { return m_ip_addr_choice; }

         private:
            uint16_t m_afi = 1;
            std::optional<uint8_t> m_safi;
            AddrChoice m_ip_addr_choice;
      };

      IPAddressBlocks() = default;

      explicit IPAddressBlocks(const std::vector<IPAddressFamily>& blocks) : m_ip_addr_blocks(blocks) {
         this->sort_and_merge();
      }

      std::unique_ptr<Certificate_Extension> copy() const override { return std::make_unique<IPAddressBlocks>(*this); }

      static OID static_oid() { return OID({1, 3, 6, 1, 5, 5, 7, 1, 7}); }

      OID oid_of() const override { return static_oid(); }

      void validate(const X509_Certificate& subject,
                    const std::optional<X509_Certificate>& issuer,
                    const std::vector<X509_Certificate>& cert_path,
                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                    size_t pos) const override;

      /// Add a single IPv4 address to this extension (for the specified SAFI, if any)
      void add_address(const IPv4Address& address, std::optional<uint8_t> safi = std::nullopt) {
         add_address(address, address, safi);
      }

      /// Add a single IPv6 address to this extension (for the specified SAFI, if any)
      void add_address(const IPv6Address& address, std::optional<uint8_t> safi = std::nullopt) {
         add_address(address, address, safi);
      }

      /// Add an IPv4 address range to this extension (for the specified SAFI, if any)
      void add_address(const IPv4Address& min, const IPv4Address& max, std::optional<uint8_t> safi = std::nullopt) {
         add_range(IPAddressOrRange<Version::IPv4>(min, max), safi);
      }

      /// Add an IPv6 address range to this extension (for the specified SAFI, if any)
      void add_address(const IPv6Address& min, const IPv6Address& max, std::optional<uint8_t> safi = std::nullopt) {
         add_range(IPAddressOrRange<Version::IPv6>(min, max), safi);
      }

      /// Add an IPv4 subnet to this extension (for the specified SAFI, if any)
      void add_address(const IPv4Subnet& subnet, std::optional<uint8_t> safi = std::nullopt) {
         add_range(IPAddressOrRange<Version::IPv4>(subnet), safi);
      }

      /// Add an IPv6 subnet to this extension (for the specified SAFI, if any)
      void add_address(const IPv6Subnet& subnet, std::optional<uint8_t> safi = std::nullopt) {
         add_range(IPAddressOrRange<Version::IPv6>(subnet), safi);
      }

      /// Add a single IP address to this extension (for the specified SAFI, if any)
      template <Version V>
      BOTAN_DEPRECATED("Use add_address taking an IPv4Address or IPv6Address")
      void add_address(const std::array<uint8_t, static_cast<size_t>(V)>& address,
                       std::optional<uint8_t> safi = std::nullopt) {
         add_range(IPAddressOrRange<V>(IPAddress<V>::from_bytes(address)), safi);
      }

      /// Add an IP address range to this extension (for the specified SAFI, if any)
      template <Version V>
      BOTAN_DEPRECATED("Use add_address taking an IPv4Address or IPv6Address")
      void add_address(const std::array<uint8_t, static_cast<std::size_t>(V)>& min,
                       const std::array<uint8_t, static_cast<std::size_t>(V)>& max,
                       std::optional<uint8_t> safi = std::nullopt) {
         add_range(IPAddressOrRange<V>(IPAddress<V>::from_bytes(min), IPAddress<V>::from_bytes(max)), safi);
      }

      /// Make the extension contain no allowed IP addresses for the specified IP version (and SAFI, if any)
      template <Version V>
      void restrict(std::optional<uint8_t> safi = std::nullopt) {
         std::vector<IPAddressOrRange<V>> addresses = {};
         m_ip_addr_blocks.push_back(IPAddressFamily(IPAddressChoice<V>(addresses), safi));
         sort_and_merge();
      }

      /// Mark the specified IP version as 'inherit' (for the specified SAFI, if any)
      template <Version V>
      void inherit(std::optional<uint8_t> safi = std::nullopt) {
         m_ip_addr_blocks.push_back(IPAddressFamily(IPAddressChoice<V>(), safi));
         sort_and_merge();
      }

      const std::vector<IPAddressFamily>& addr_blocks() const { return m_ip_addr_blocks; }

      /// The number of IPv4 families contained in the extension
      size_t v4_count() const { return m_v4_count; }

      /// The number of IPv6 families contained in the extension
      size_t v6_count() const { return m_v6_count; }

   private:
      std::string oid_name() const override { return "PKIX.IpAddrBlocks"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return true; }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      std::vector<IPAddressFamily> m_ip_addr_blocks;
      size_t m_v4_count = 0;
      size_t m_v6_count = 0;

      template <Version V>
      void add_range(const IPAddressOrRange<V>& range, std::optional<uint8_t> safi) {
         std::vector<IPAddressOrRange<V>> addresses = {range};
         m_ip_addr_blocks.push_back(IPAddressFamily(IPAddressChoice<V>(addresses), safi));
         sort_and_merge();
      }

      void sort_and_merge();
};

/**
 * AS Blocks Extension
 *
 * RFC 3779 X.509 Extensions for AS ID
 *
*/
class BOTAN_PUBLIC_API(3, 9) ASBlocks final : public Certificate_Extension {
   public:
      typedef uint32_t asnum_t;

      class BOTAN_PUBLIC_API(3, 9) ASIdOrRange final : public ASN1_Object {
         public:
            void encode_into(DER_Encoder& to) const override;
            void decode_from(BER_Decoder& from) override;

            asnum_t min() const { return m_min; }

            asnum_t max() const { return m_max; }

            ASIdOrRange() = default;

            explicit ASIdOrRange(asnum_t id) : m_min(id), m_max(id) {}

            ASIdOrRange(asnum_t min, asnum_t max) : m_min(min), m_max(max) {
               if(max < min) {
                  throw Decoding_Error("AS range numbers must be sorted");
               }
            }

         private:
            asnum_t m_min = 0;
            asnum_t m_max = 0;
      };

      class BOTAN_PUBLIC_API(3, 9) ASIdentifierChoice final : public ASN1_Object {
         public:
            void encode_into(DER_Encoder& to) const override;
            void decode_from(BER_Decoder& from) override;

            ASIdentifierChoice() = default;

            explicit ASIdentifierChoice(const std::optional<std::vector<ASIdOrRange>>& ranges);

            const std::optional<std::vector<ASIdOrRange>>& ranges() const { return m_as_ranges; }

         private:
            std::optional<std::vector<ASIdOrRange>> m_as_ranges;
      };

      class BOTAN_PUBLIC_API(3, 9) ASIdentifiers final : public ASN1_Object {
         public:
            void encode_into(DER_Encoder& to) const override;
            void decode_from(BER_Decoder& from) override;

            explicit ASIdentifiers(const std::optional<ASIdentifierChoice>& asnum,
                                   const std::optional<ASIdentifierChoice>& rdi) :
                  m_asnum(asnum), m_rdi(rdi) {
               if(!m_asnum.has_value() && !m_rdi.has_value()) {
                  throw Decoding_Error("One of asnum, rdi must be present");
               }
            }

            const std::optional<ASIdentifierChoice>& asnum() const { return m_asnum; }

            const std::optional<ASIdentifierChoice>& rdi() const { return m_rdi; }

         private:
            friend class ASBlocks;
            ASIdentifiers() = default;

            std::optional<ASIdentifierChoice> m_asnum;
            std::optional<ASIdentifierChoice> m_rdi;
      };

      ASBlocks() = default;

      explicit ASBlocks(const ASIdentifiers& as_idents) : m_as_identifiers(as_idents) {}

      std::unique_ptr<Certificate_Extension> copy() const override { return std::make_unique<ASBlocks>(*this); }

      static OID static_oid() { return OID({1, 3, 6, 1, 5, 5, 7, 1, 8}); }

      OID oid_of() const override { return static_oid(); }

      void validate(const X509_Certificate& subject,
                    const std::optional<X509_Certificate>& issuer,
                    const std::vector<X509_Certificate>& cert_path,
                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                    size_t pos) const override;

      /// Add a single asnum to this extension
      void add_asnum(asnum_t asnum) { add_asnum(asnum, asnum); }

      /// Add an asnum range to this extension
      void add_asnum(asnum_t min, asnum_t max) {
         m_as_identifiers = ASIdentifiers(add_new(m_as_identifiers.asnum(), min, max), m_as_identifiers.rdi());
      }

      /// Make the extension contain no allowed asnum's
      void restrict_asnum() {
         std::vector<ASIdOrRange> empty;
         m_as_identifiers = ASIdentifiers(ASIdentifierChoice(empty), m_as_identifiers.rdi());
      }

      /// Mark the asnum entry as 'inherit'
      void inherit_asnum() { m_as_identifiers = ASIdentifiers(ASIdentifierChoice(), m_as_identifiers.rdi()); }

      /// Add a single rdi to this extension
      void add_rdi(asnum_t rdi) { add_rdi(rdi, rdi); }

      /// Add an rdi range to this extension
      void add_rdi(asnum_t min, asnum_t max) {
         m_as_identifiers = ASIdentifiers(m_as_identifiers.asnum(), add_new(m_as_identifiers.rdi(), min, max));
      }

      /// Make the extension contain no allowed rdi's
      void restrict_rdi() {
         std::vector<ASIdOrRange> empty;
         m_as_identifiers = ASIdentifiers(m_as_identifiers.asnum(), ASIdentifierChoice(empty));
      }

      /// Mark the rdi entry as 'inherit'
      void inherit_rdi() { m_as_identifiers = ASIdentifiers(m_as_identifiers.asnum(), ASIdentifierChoice()); }

      const ASIdentifiers& as_identifiers() const { return m_as_identifiers; }

   private:
      ASIdentifiers m_as_identifiers;

      std::string oid_name() const override { return "PKIX.AutonomousSysIds"; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return true; }

      static ASIdentifierChoice add_new(const std::optional<ASIdentifierChoice>& old, asnum_t min, asnum_t max);

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;
};

/**
* An unknown X.509 extension
* Will add a failure to the path validation result, if critical
*/
class BOTAN_PUBLIC_API(2, 4) Unknown_Extension final : public Certificate_Extension {
   public:
      Unknown_Extension(const OID& oid, bool critical, bool failed_to_decode = false) :
            m_oid(oid), m_critical(critical), m_failed_to_decode(failed_to_decode) {}

      std::unique_ptr<Certificate_Extension> copy() const override {
         return std::make_unique<Unknown_Extension>(*this);
      }

      /**
      * Return the OID of this unknown extension
      */
      OID oid_of() const override { return m_oid; }

      //static_oid not defined for Unknown_Extension

      /**
      * Return the extension contents
      */
      const std::vector<uint8_t>& extension_contents() const { return m_bytes; }

      /**
      * Return if this extension was marked critical
      */
      bool is_critical_extension() const { return m_critical; }

      /**
      * Return true if this extension's OID was recognized but the contents
      * failed to decode.
      */
      bool failed_to_decode() const { return m_failed_to_decode; }

      void validate(const X509_Certificate& /*subject*/,
                    const std::optional<X509_Certificate>& /*issuer*/,
                    const std::vector<X509_Certificate>& /*cert_path*/,
                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                    size_t pos) const override {
         if(m_failed_to_decode) {
            cert_status.at(pos).insert(Certificate_Status_Code::EXTENSION_ENCODING_ERROR);
         } else if(m_critical) {
            cert_status.at(pos).insert(Certificate_Status_Code::UNKNOWN_CRITICAL_EXTENSION);
         }
      }

   private:
      std::string oid_name() const override { return ""; }

      bool is_appropriate_context(Extension_Context context) const override;

      bool should_encode() const override { return true; }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>& in) override;

      OID m_oid;
      bool m_critical;
      bool m_failed_to_decode;
      std::vector<uint8_t> m_bytes;
};

}  // namespace Cert_Extension

}  // namespace Botan

#endif

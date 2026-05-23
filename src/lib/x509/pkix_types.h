/*
* (C) 1999-2010,2012,2018,2020 Jack Lloyd
* (C) 2007 Yves Jerschow
* (C) 2015 Kai Michaelis
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PKIX_TYPES_H_
#define BOTAN_PKIX_TYPES_H_

#include <botan/asn1_obj.h>

#include <botan/dns_name.h>
#include <botan/email.h>
#include <botan/ipv4_address.h>
#include <botan/ipv6_address.h>
#include <botan/pkix_enums.h>
#include <botan/uri.h>
#include <initializer_list>
#include <iosfwd>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace Botan {

class X509_Certificate;
class Public_Key;

BOTAN_DEPRECATED("Use Key_Constraints::to_string")

inline std::string key_constraints_to_string(Key_Constraints c) {
   return c.to_string();
}

/**
* Distinguished Name
*/
class BOTAN_PUBLIC_API(2, 0) X509_DN final : public ASN1_Object {
   public:
      X509_DN() = default;

      X509_DN(std::initializer_list<std::pair<std::string_view, std::string_view>> args) {
         for(const auto& i : args) {
            add_attribute(i.first, i.second);
         }
      }

      /**
      * Since DN matching for Name Constraints requires preserving order and
      * multimaps have sorted keys, this constructor is deprecated.
      */
      BOTAN_DEPRECATED("Deprecated use initializer list constructor")
      explicit X509_DN(const std::multimap<OID, std::string>& args) {
         for(const auto& i : args) {
            add_attribute(i.first, i.second);
         }
      }

      /**
      * Since DN matching for Name Constraints requires preserving order and
      * multimaps have sorted keys, this constructor is deprecated.
      */
      BOTAN_DEPRECATED("Deprecated use initializer list constructor")
      explicit X509_DN(const std::multimap<std::string, std::string>& args) {
         for(const auto& i : args) {
            add_attribute(i.first, i.second);
         }
      }

      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      bool has_field(const OID& oid) const;
      ASN1_String get_first_attribute(const OID& oid) const;

      /*
      * Return the BER encoded data, if any
      */
      const std::vector<uint8_t>& get_bits() const { return m_dn_bits; }

      std::vector<uint8_t> DER_encode() const;

      bool empty() const { return m_rdn.empty(); }

      /**
      * Number of relative distinguished names (RDNs) in the DN. Note: prior
      * to multi-AVA RDN support this returned the total number of AVAs; the
      * two differ only when the DN contains a multi-valued RDN.
      */
      size_t count() const { return m_rdn.size(); }

      std::string to_string() const;

      /**
      * Return the DN as a sequence of RDNs. Each RDN is an X.501
      * SET OF AttributeTypeAndValue; the inner vector preserves the
      * decoded order but RDN equality is set-based per RFC 5280 7.1.
      */
      const std::vector<std::vector<std::pair<OID, ASN1_String>>>& rdns() const { return m_rdn; }

      /**
      * Return the DN attributes as a flat sequence of AVAs in decoded order.
      * RDN structure is not preserved in this view; prefer rdns() to retain it.
      */
      BOTAN_DEPRECATED("Use rdns() which preserves RDN structure")
      std::vector<std::pair<OID, ASN1_String>> dn_info() const;

      std::multimap<OID, std::string> get_attributes() const;
      std::multimap<std::string, std::string> contents() const;

      bool has_field(std::string_view attr) const;
      std::vector<std::string> get_attribute(std::string_view attr) const;
      std::string get_first_attribute(std::string_view attr) const;

      void add_attribute(std::string_view key, std::string_view val);

      void add_attribute(const OID& oid, std::string_view val) { add_attribute(oid, ASN1_String(val)); }

      void add_attribute(const OID& oid, const ASN1_String& val);

      /**
      * Append a complete RDN. The provided AVAs become one
      * RelativeDistinguishedName (X.501 SET OF AttributeTypeAndValue).
      * An empty input is ignored.
      */
      void add_rdn(std::vector<std::pair<OID, ASN1_String>> rdn);

      static std::string deref_info_field(std::string_view key);

      /**
      * Lookup upper bounds in characters for the length of distinguished name fields
      * as given in RFC 5280, Appendix A.
      *
      * @param oid the oid of the DN to lookup
      * @return the upper bound, or zero if no ub is known to Botan
      */
      static size_t lookup_ub(const OID& oid);

   private:
      // Outer vector: sequence of RDNs. Inner vector: AVAs within
      // one RDN (X.501 SET OF AttributeTypeAndValue).
      std::vector<std::vector<std::pair<OID, ASN1_String>>> m_rdn;
      std::vector<uint8_t> m_dn_bits;
};

BOTAN_PUBLIC_API(2, 0) bool operator==(const X509_DN& dn1, const X509_DN& dn2);
BOTAN_PUBLIC_API(2, 0) bool operator!=(const X509_DN& dn1, const X509_DN& dn2);

/*
The ordering here is arbitrary and may change from release to release.
It is intended for allowing DNs as keys in std::map and similar containers
*/
BOTAN_PUBLIC_API(2, 0) bool operator<(const X509_DN& dn1, const X509_DN& dn2);

BOTAN_PUBLIC_API(2, 0) std::ostream& operator<<(std::ostream& out, const X509_DN& dn);
BOTAN_PUBLIC_API(2, 0) std::istream& operator>>(std::istream& in, X509_DN& dn);

/**
* Alternative Name
*/
class BOTAN_PUBLIC_API(2, 0) AlternativeName final : public ASN1_Object {
   public:
      /// An "OtherName" GeneralName entry: type-id OID and the inner ANY value as raw BER
      class OtherNameValue final {
         public:
            const OID& oid() const { return m_oid; }

            std::span<const uint8_t> value() const { return m_value; }

            bool operator<(const OtherNameValue& other) const {
               if(oid() != other.oid()) {
                  return oid() < other.oid();
               }
               return m_value < other.m_value;
            }

         private:
            friend class AlternativeName;

            OtherNameValue(const OID& oid, std::vector<uint8_t> value) : m_oid(oid), m_value(std::move(value)) {}

            OtherNameValue(const OID& oid, std::span<const uint8_t> value) :
                  m_oid(oid), m_value(value.begin(), value.end()) {}

            OID m_oid;
            std::vector<uint8_t> m_value;
      };

      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      /// Create an empty name
      AlternativeName() = default;

      /// Add a URI to this AlternativeName, parsing and validating the input
      void add_uri(std::string_view uri);

      /// Add a previously parsed URI to this AlternativeName
      void add_uri(URI uri);

      /// Add an email address to this AlternativeName, parsing and validating the input
      void add_email(std::string_view addr);

      /// Add a previously parsed email address to this AlternativeName
      void add_email(EmailAddress addr);

      /// Add a DNS name to this AlternativeName, parsing and validating the input
      void add_dns(std::string_view dns);

      /// Add a previously parsed DNS name to this AlternativeName
      void add_dns(DNSName dns);

      /// Add an "OtherName" identified by object identifier to this AlternativeName
      void add_other_name(const OID& oid, const ASN1_String& value);

      /// Add an "OtherName" with arbitrary inner value, given as raw BER bytes
      ///
      /// `value` must be a complete BER-encoded object (tag + length + content)
      /// representing the inner ANY value of the OtherName.
      void add_other_name_value(const OID& oid, std::span<const uint8_t> value);

      /// Add a registeredID (RFC 5280 [8])
      void add_registered_id(const OID& oid);

      /// Add a directory name to this AlternativeName
      void add_dn(const X509_DN& dn);

      /// Add an IP address to this alternative name
      BOTAN_DEPRECATED("Use variant taking IPv4Address") void add_ipv4_address(uint32_t ipv4) {
         this->add_ipv4_address(IPv4Address(ipv4));
      }

      /// Add an IP address to this alternative name
      void add_ipv4_address(const IPv4Address& ipv4);

      /// Add an IPv6 address to this alternative name
      void add_ipv6_address(const IPv6Address& ipv6);

      /// Return the set of URIs included in this alternative name
      ///
      /// Deprecated: use uri_names() instead, which exposes the parsed
      /// URI values. This accessor constructs a copy.
      BOTAN_DEPRECATED("Use AlternativeName::uri_names") std::set<std::string> uris() const;

      /// Return the set of URIs included in this alternative name
      const std::set<URI>& uri_names() const { return m_uri; }

      /// Return the set of email addresses included in this alternative name
      ///
      /// Deprecated: use email_addresses() instead, which exposes the
      /// parsed EmailAddress values. This accessor constructs a copy.
      BOTAN_DEPRECATED("Use AlternativeName::email_addresses") std::set<std::string> email() const;

      /// Return the set of email addresses included in this alternative name
      const std::set<EmailAddress>& email_addresses() const { return m_email; }

      /// Return the set of DNS names included in this alternative name
      ///
      /// Deprecated: use dns_names() instead, which exposes the parsed
      /// DNSName values. This accessor constructs a copy.
      BOTAN_DEPRECATED("Use AlternativeName::dns_names") std::set<std::string> dns() const;

      /// Return the set of DNS names included in this alternative name
      const std::set<DNSName>& dns_names() const { return m_dns; }

      /// Return the set of IPv4 addresses included in this alternative name
      BOTAN_DEPRECATED("Use ipv4_addresses") std::set<uint32_t> ipv4_address() const;

      /// Return the set of IPv6 addresses included in this alternative name
      BOTAN_DEPRECATED("Use ipv6_addresses") const std::set<IPv6Address>& ipv6_address() const {
         return ipv6_addresses();
      }

      /// Return the set of IPv4 addresses included in this alternative name
      const std::set<IPv4Address>& ipv4_addresses() const { return m_ipv4_addrs; }

      /// Return the set of IPv6 addresses included in this alternative name
      const std::set<IPv6Address>& ipv6_addresses() const { return m_ipv6_addrs; }

      /// Return the set of "other names" whose value was a recognized ASN1_String type
      BOTAN_DEPRECATED("Use AlternativeName::other_name_values")
      const std::set<std::pair<OID, ASN1_String>>& other_names() const {
         return m_othernames;
      }

      /// Return all "OtherName" entries with their inner ANY value as raw BER
      const std::set<OtherNameValue>& other_name_values() const { return m_other_name_values; }

      /// Return the set of `SmtpUTF8Mailbox` SAN entries (RFC 9598).
      ///
      /// Any such values are also included with their raw encoding in other_name_values
      const std::set<SmtpUtf8Mailbox>& smtp_utf8_mailboxes() const { return m_smtp_utf8_mailboxes; }

      /// Return the set of registeredID OIDs
      const std::set<OID>& registered_ids() const { return m_registered_ids; }

      /// Return the set of directory names included in this alternative name
      const std::set<X509_DN>& directory_names() const { return m_dn_names; }

      /// Return the total number of names in this AlternativeName
      ///
      /// This only counts names which were parsed, ignoring names which
      /// were of some unknown type
      size_t count() const;

      /// Return true if this has any names set
      bool has_items() const;

      /// Return true if this alternative name is empty (zero names)
      bool is_empty() const;

      // Old, now deprecated interface follows:
      BOTAN_DEPRECATED("Use AlternativeName::{uris, email, dns, othernames, directory_names}")
      std::multimap<std::string, std::string> contents() const;

      BOTAN_DEPRECATED("Use AlternativeName::{uris, email, dns, othernames, directory_names}.empty()")
      bool has_field(std::string_view attr) const;

      BOTAN_DEPRECATED("Use AlternativeName::{uris, email, dns, othernames, directory_names}")
      std::vector<std::string> get_attribute(std::string_view attr) const;

      BOTAN_DEPRECATED("Use AlternativeName::{uris, email, dns, othernames, directory_names}")
      std::multimap<std::string, std::string, std::less<>> get_attributes() const;

      BOTAN_DEPRECATED("Use AlternativeName::{uris, email, dns, othernames, directory_names}")
      std::string get_first_attribute(std::string_view attr) const;

      BOTAN_DEPRECATED("Use AlternativeName::add_{uri, dns, email, ...}")
      void add_attribute(std::string_view type, std::string_view value);

      BOTAN_DEPRECATED("Use AlternativeName::add_other_name")
      void add_othername(const OID& oid, std::string_view value, ASN1_Type type);

      BOTAN_DEPRECATED("Use AlternativeName::othernames") std::multimap<OID, ASN1_String> get_othernames() const;

      BOTAN_DEPRECATED("Use AlternativeName::directory_names") X509_DN dn() const;

      BOTAN_DEPRECATED("Use plain constructor plus add_{uri,dns,email,ipv4_address}")
      BOTAN_FUTURE_EXPLICIT AlternativeName(std::string_view email_addr,
                                            std::string_view uri = "",
                                            std::string_view dns = "",
                                            std::string_view ip_address = "");

   private:
      std::set<DNSName> m_dns;
      std::set<URI> m_uri;
      std::set<EmailAddress> m_email;
      std::set<IPv4Address> m_ipv4_addrs;
      std::set<IPv6Address> m_ipv6_addrs;
      std::set<X509_DN> m_dn_names;
      std::set<std::pair<OID, ASN1_String>> m_othernames;  // TODO(Botan4) remove this
      std::set<OtherNameValue> m_other_name_values;
      std::set<SmtpUtf8Mailbox> m_smtp_utf8_mailboxes;
      std::set<OID> m_registered_ids;
};

/**
* Attribute
*/
class BOTAN_PUBLIC_API(2, 0) Attribute final : public ASN1_Object {
   public:
      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      Attribute() = default;
      Attribute(const OID& oid, const std::vector<uint8_t>& params);
      Attribute(std::string_view oid_str, const std::vector<uint8_t>& params);

      const OID& oid() const { return m_oid; }

      const std::vector<uint8_t>& parameters() const { return m_parameters; }

      const OID& object_identifier() const { return m_oid; }

      const std::vector<uint8_t>& get_parameters() const { return m_parameters; }

   private:
      OID m_oid;
      std::vector<uint8_t> m_parameters;
};

/**
* @brief X.509 GeneralName Type
*
* Handles parsing GeneralName types in their BER and canonical string
* encoding. Allows matching GeneralNames against each other using
* the rules laid out in the RFC 5280, sec. 4.2.1.10 (Name Constraints).
*
* This entire class is deprecated and will be removed in a future
* major release
*/
class BOTAN_PUBLIC_API(2, 0) GeneralName final : public ASN1_Object {
   public:
      enum MatchResult : uint8_t /* NOLINT(*-use-enum-class) */ {
         All,
         Some,
         None,
         NotFound,
         UnknownType,
      };

      enum class NameType : uint8_t {
         Unknown = 0,
         RFC822 = 1,
         DNS = 2,
         URI = 3,
         DN = 4,
         IPv4 = 5,
         IPv6 = 6,
         Other = 7,
      };

      BOTAN_DEPRECATED("Deprecated use NameConstraints") GeneralName() = default;

      static GeneralName email(std::string_view email);
      static GeneralName dns(std::string_view dns);
      static GeneralName uri(std::string_view uri);
      static GeneralName directory_name(Botan::X509_DN dn);
      static GeneralName ipv4_address(uint32_t ipv4);
      static GeneralName ipv4_address(uint32_t ipv4, uint32_t mask);
      static GeneralName ipv4_address(IPv4Address ipv4);
      static GeneralName ipv4_address(const IPv4Subnet& subnet);
      static GeneralName ipv6_address(const IPv6Address& ipv6);
      static GeneralName ipv6_address(const IPv6Subnet& subnet);

      /**
      * Wrap a URI SAN in a GeneralName, this is used for ffi
      * @warning internal function that may be removed at any time
      */
      static GeneralName _uri_san_value(std::string_view full_uri);

      /**
      * Wrap a DNS SAN in a GeneralName, this is used for ffi
      * @warning internal function that may be removed at any time
      */
      static GeneralName _dns_san_value(std::string_view dns);

      // Encoding is not implemented
      void encode_into(DER_Encoder& to) const override;

      void decode_from(BER_Decoder& from) override;

      /**
      * @return Type of the name expressed in this restriction
      */
      NameType type_code() const { return m_type; }

      /**
      * @return Type of the name. Can be DN, DNS, IP, RFC822 or URI.
      */
      BOTAN_DEPRECATED("Deprecated use type_code") std::string type() const;

      /**
      * @return The name as string. Format depends on type.
      */
      BOTAN_DEPRECATED("Deprecated no replacement") std::string name() const;

      /**
      * @return The name as binary string. Format depends on type.
      */
      BOTAN_DEPRECATED("Deprecated no replacement") std::vector<uint8_t> binary_name() const;

      /**
      * Checks whether a given certificate (partially) matches this name.
      * @param cert certificate to be matched
      * @return the match result
      */
      BOTAN_DEPRECATED("Deprecated use NameConstraints type") MatchResult matches(const X509_Certificate& cert) const;

      bool matches_dns(const std::string& dns_name) const;
      bool matches_dns(const DNSName& dns_name) const;

      bool matches_ipv4(uint32_t ip) const;

      bool matches_ipv4(const IPv4Address& ip) const { return matches_ipv4(ip.address()); }

      bool matches_ipv6(const IPv6Address& ip) const;
      bool matches_dn(const X509_DN& dn) const;
      bool matches_uri(const URI& uri) const;
      bool matches_email(const EmailAddress& addr) const;
      bool matches_email(const SmtpUtf8Mailbox& mailbox) const;

   private:
      friend class NameConstraints;

      class EmailConstraint final {
         public:
            EmailConstraint() = default;

            static std::optional<EmailConstraint> from_string(std::string_view input);

            const std::string& value() const { return m_value; }

            auto operator<=>(const EmailConstraint&) const = default;

         private:
            explicit EmailConstraint(std::string value) : m_value(std::move(value)) {}

            std::string m_value;
      };

      class DNSConstraint final {
         public:
            DNSConstraint() = default;

            static std::optional<DNSConstraint> from_string(std::string_view input);

            static std::optional<DNSConstraint> from_san_value(std::string_view input);

            const std::string& value() const { return m_value; }

            auto operator<=>(const DNSConstraint&) const = default;

         private:
            explicit DNSConstraint(std::string value) : m_value(std::move(value)) {}

            std::string m_value;
      };

      class URIConstraint final {
         public:
            URIConstraint() = default;

            static std::optional<URIConstraint> from_string(std::string_view input);

            static std::optional<URIConstraint> from_san_value(std::string_view full_uri);

            const std::string& value() const { return m_value; }

            auto operator<=>(const URIConstraint&) const = default;

         private:
            explicit URIConstraint(std::string value) : m_value(std::move(value)) {}

            std::string m_value;
      };

      /*
      TODO: consider adding OtherConstraint and UnknownConstraint types here and eliminating m_type,
      using m_name variant choice as the single source of the constraint type
      */
      using NameVariant = std::variant<EmailConstraint, DNSConstraint, URIConstraint, X509_DN, IPv4Subnet, IPv6Subnet>;

      GeneralName(NameType type, NameVariant name) : m_type(type), m_name(std::move(name)) {}

      NameType m_type = NameType::Unknown;
      NameVariant m_name;

      /**
      * Partial DN matching according to RFC 5280, Section 7.1, i.e.,
      * whether the constraint is a prefix of the name.
      */
      static bool matches_dn(const X509_DN& name, const X509_DN& constraint);
};

BOTAN_DEPRECATED("Deprecated no replacement") std::ostream& operator<<(std::ostream& os, const GeneralName& gn);

/**
* @brief A single Name Constraint
*
* The Name Constraint extension adds a minimum and maximum path
* length to a GeneralName to form a constraint. The length limits
* are not used in PKIX.
*
* This entire class is deprecated and will be removed in a future
* major release
*/
class BOTAN_PUBLIC_API(2, 0) GeneralSubtree final : public ASN1_Object {
   public:
      /**
      * Creates an empty name constraint.
      */
      BOTAN_DEPRECATED("Deprecated use NameConstraints") GeneralSubtree();

      void encode_into(DER_Encoder& to) const override;

      void decode_from(BER_Decoder& from) override;

      /**
      * @return name
      */
      const GeneralName& base() const { return m_base; }

   private:
      GeneralName m_base;
};

BOTAN_DEPRECATED("Deprecated no replacement") std::ostream& operator<<(std::ostream& os, const GeneralSubtree& gs);

/**
* @brief Name Constraints
*
* Wraps the Name Constraints associated with a certificate.
*/
class BOTAN_PUBLIC_API(2, 0) NameConstraints final {
   public:
      /**
      * Creates an empty name NameConstraints.
      */
      NameConstraints() = default;

      /**
      * Creates NameConstraints from a list of permitted and excluded subtrees.
      * @param permitted_subtrees names for which the certificate is permitted
      * @param excluded_subtrees names for which the certificate is not permitted
      */
      NameConstraints(std::vector<GeneralSubtree>&& permitted_subtrees,
                      std::vector<GeneralSubtree>&& excluded_subtrees);

      /**
      * @return permitted names
      */
      BOTAN_DEPRECATED("Deprecated no replacement") const std::vector<GeneralSubtree>& permitted() const {
         return m_permitted_subtrees;
      }

      /**
      * @return excluded names
      */
      BOTAN_DEPRECATED("Deprecated no replacement") const std::vector<GeneralSubtree>& excluded() const {
         return m_excluded_subtrees;
      }

      /**
      * Return true if all of the names in the certificate are permitted
      */
      bool is_permitted(const X509_Certificate& cert, bool reject_unknown) const;

      /**
      * Return true if any of the names in the certificate are excluded
      */
      bool is_excluded(const X509_Certificate& cert, bool reject_unknown) const;

   private:
      std::vector<GeneralSubtree> m_permitted_subtrees;
      std::vector<GeneralSubtree> m_excluded_subtrees;

      std::set<GeneralName::NameType> m_permitted_name_types;
      std::set<GeneralName::NameType> m_excluded_name_types;
};

enum class Extension_Context : uint8_t { Certificate, CRL, CRL_Entry, OCSP_Request, OCSP_Response };

/**
* X.509 Certificate Extension
*/
class BOTAN_PUBLIC_API(2, 0) Certificate_Extension /* NOLINT(*-special-member-functions) */ {
   public:
      /**
      * @return OID representing this extension
      */
      virtual OID oid_of() const = 0;

      /*
      * @return specific OID name
      * If possible OIDS table should match oid_name to OIDS, ie
      * OID::from_string(ext->oid_name()) == ext->oid_of()
      * Should return empty string if OID is not known
      */
      virtual std::string oid_name() const = 0;

      /**
      * Make a copy of this extension
      * @return copy of this
      */

      virtual std::unique_ptr<Certificate_Extension> copy() const = 0;

      virtual bool is_appropriate_context(Extension_Context context) const = 0;

      /*
      * Callback visited during path validation.
      *
      * An extension can implement this callback to inspect
      * the path during path validation.
      *
      * If an error occurs during validation of this extension,
      * an appropriate status code shall be added to cert_status.
      *
      * @param subject Subject certificate that contains this extension
      * @param issuer Issuer certificate. nullopt for certificates with no
      *        available issuer (e.g. non self-signed trust anchors).
      * @param cert_path Certificate path which is currently validated
      * @param cert_status Certificate validation status codes for subject certificate
      * @param pos Position of subject certificate in cert_path
      */
      virtual void validate(const X509_Certificate& subject,
                            const std::optional<X509_Certificate>& issuer,
                            const std::vector<X509_Certificate>& cert_path,
                            std::vector<std::set<Certificate_Status_Code>>& cert_status,
                            size_t pos);

      virtual ~Certificate_Extension() = default;

   protected:
      friend class Extensions;

      virtual bool should_encode() const { return true; }

      virtual std::vector<uint8_t> encode_inner() const = 0;
      virtual void decode_inner(const std::vector<uint8_t>&) = 0;
};

/**
* X.509 Certificate Extension List
*/
class BOTAN_PUBLIC_API(2, 0) Extensions final : public ASN1_Object {
   public:
      /**
      * Look up an object in the extensions, based on OID Returns
      * nullptr if not set, if the extension was either absent or not
      * handled. The pointer returned is owned by the Extensions
      * object.
      * This would be better with an optional<T> return value
      */
      const Certificate_Extension* get_extension_object(const OID& oid) const;

      template <typename T>
      const T* get_extension_object_as(const OID& oid = T::static_oid()) const {
         if(const Certificate_Extension* extn = get_extension_object(oid)) {
            // Unknown_Extension oid_name is empty
            if(extn->oid_name().empty()) {
               return nullptr;
            } else if(const T* extn_as_T = dynamic_cast<const T*>(extn)) {
               return extn_as_T;
            } else {
               throw Decoding_Error("Exception::get_extension_object_as dynamic_cast failed");
            }
         }

         return nullptr;
      }

      /**
      * Return the set of extensions in the order they appeared in the certificate
      * (or as they were added, if constructed)
      */
      const std::vector<OID>& get_extension_oids() const { return m_extension_oids; }

      /**
      * Return the set of critical extensions in the order they appeared in the extension list
      * (This may be an empty vector)
      */
      std::vector<OID> critical_extensions() const;

      /**
      * Return true if an extension was set
      */
      bool extension_set(const OID& oid) const;

      /**
      * Return true if an extension was set and marked critical
      */
      bool critical_extension_set(const OID& oid) const;

      /**
      * Return the raw bytes of the extension
      * Will throw if OID was not set as an extension.
      */
      std::vector<uint8_t> get_extension_bits(const OID& oid) const;

      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;
      void decode_from(BER_Decoder& from, std::optional<Extension_Context> context);

      /**
      * Return true if an unrecognized critical extension was encountered
      * during the most recent decode_from. Resets on each call to decode_from
      * and is not affected by subsequent calls to add/replace/remove.
      */
      bool has_unknown_critical_extension() const { return m_has_unknown_critical_extension; }

      /**
      * Adds a new extension to the list.
      * @param extn pointer to the certificate extension (Extensions takes ownership)
      * @param critical whether this extension should be marked as critical
      * @throw Invalid_Argument if the extension is already present in the list
      */
      void add(std::unique_ptr<Certificate_Extension> extn, bool critical = false);

      /**
      * Adds a new extension to the list unless it already exists. If the extension
      * already exists within the Extensions object, the extn pointer will be deleted.
      *
      * @param extn pointer to the certificate extension (Extensions takes ownership)
      * @param critical whether this extension should be marked as critical
      * @return true if the object was added false if the extension was already used
      */
      bool add_new(std::unique_ptr<Certificate_Extension> extn, bool critical = false);

      /**
      * Adds an extension to the list or replaces it.
      * @param extn the certificate extension
      * @param critical whether this extension should be marked as critical
      */
      void replace(std::unique_ptr<Certificate_Extension> extn, bool critical = false);

      /**
      * Remove an extension from the list. Returns true if the
      * extension had been set, false otherwise.
      */
      bool remove(const OID& oid);

      /**
      * Searches for an extension by OID and returns the result.
      * Only the known extensions types declared in this header
      * are searched for by this function.
      * @return Copy of extension with oid, nullptr if not found.
      * Can avoid creating a copy by using get_extension_object function
      */
      std::unique_ptr<Certificate_Extension> get(const OID& oid) const;

      /**
      * Searches for an extension by OID and returns the result decoding
      * it to some arbitrary extension type chosen by the application.
      *
      * Only the unknown extensions, that is, extensions types that
      * are not declared in this header, are searched for by this
      * function.
      *
      * @return Pointer to new extension with oid, nullptr if not found.
      */
      template <typename T>
      std::unique_ptr<T> get_raw(const OID& oid) const {
         auto extn_info = m_extension_info.find(oid);

         if(extn_info != m_extension_info.end()) {
            // Unknown_Extension oid_name is empty
            if(extn_info->second.obj().oid_name().empty()) {
               auto ext = std::make_unique<T>();
               ext->decode_inner(extn_info->second.bits());
               return ext;
            }
         }
         return nullptr;
      }

      /**
      * Returns a copy of the list of extensions together with the corresponding
      * criticality flag. All extensions are encoded as some object, falling back
      * to Unknown_Extension class which simply allows reading the bytes as well
      * as the criticality flag.
      */
      std::vector<std::pair<std::unique_ptr<Certificate_Extension>, bool>> extensions() const;

      /**
      * Returns the list of extensions as raw, encoded bytes
      * together with the corresponding criticality flag.
      * Contains all extensions, including any extensions encoded as Unknown_Extension
      */
      std::map<OID, std::pair<std::vector<uint8_t>, bool>> extensions_raw() const;

      Extensions() = default;

      Extensions(const Extensions&) = default;
      Extensions& operator=(const Extensions&) = default;

      Extensions(Extensions&&) = default;
      Extensions& operator=(Extensions&&) = default;

      ~Extensions() override = default;

   private:
      static std::unique_ptr<Certificate_Extension> create_extn_obj(const OID& oid,
                                                                    bool critical,
                                                                    const std::vector<uint8_t>& body,
                                                                    std::optional<Extension_Context> context);

      class BOTAN_UNSTABLE_API Extensions_Info final {
         public:
            Extensions_Info(bool critical, std::unique_ptr<Certificate_Extension> ext) :
                  m_obj(std::move(ext)), m_bits(m_obj->encode_inner()), m_critical(critical) {}

            Extensions_Info(bool critical,
                            const std::vector<uint8_t>& encoding,
                            std::unique_ptr<Certificate_Extension> ext) :
                  m_obj(std::move(ext)), m_bits(encoding), m_critical(critical) {}

            bool is_critical() const { return m_critical; }

            const std::vector<uint8_t>& bits() const { return m_bits; }

            const Certificate_Extension& obj() const;

         private:
            std::shared_ptr<Certificate_Extension> m_obj;
            std::vector<uint8_t> m_bits;
            bool m_critical = false;
      };

      std::vector<OID> m_extension_oids;
      std::map<OID, Extensions_Info> m_extension_info;
      bool m_has_unknown_critical_extension = false;
};

}  // namespace Botan

#endif

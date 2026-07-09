/*
* X.509 CRL
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_CRL_H_
#define BOTAN_X509_CRL_H_

#include <botan/asn1_obj.h>
#include <botan/pkix_enums.h>
#include <botan/uri.h>
#include <botan/x509_obj.h>
#include <memory>
#include <vector>

namespace Botan {

class Extensions;
class BigInt;
class X509_Certificate;
class X509_DN;

class CRL_Entry_Data;
class CRL_Data;

/**
* This class represents CRL entries
*/
class BOTAN_PUBLIC_API(2, 0) CRL_Entry final : public ASN1_Object {
   public:
      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      /**
      * Get the serial number of the certificate associated with this entry.
      * @return certificate's serial number
      */
      const std::vector<uint8_t>& serial_number() const;

      /**
      * Get the revocation date of the certificate associated with this entry
      * @return certificate's revocation date
      */
      const X509_Time& expire_time() const;

      /**
      * Get the entries reason code
      * @return reason code
      */
      CRL_Code reason_code() const;

      /**
      * Get the extensions on this CRL entry
      */
      const Extensions& extensions() const;

      /**
      * Create uninitialized CRL_Entry object
      */
      CRL_Entry() = default;

      /**
      * Construct an CRL entry.
      * @param cert the certificate to revoke
      * @param reason the reason code to set in the entry
      */
      BOTAN_FUTURE_EXPLICIT CRL_Entry(const X509_Certificate& cert, CRL_Code reason = CRL_Code::Unspecified);

   private:
      friend class X509_CRL;

      const CRL_Entry_Data& data() const;

      std::shared_ptr<const CRL_Entry_Data> m_data;
};

/**
* Test two CRL entries for equality in all fields.
*/
BOTAN_PUBLIC_API(2, 0) bool operator==(const CRL_Entry& lhs, const CRL_Entry& rhs);

/**
* Test two CRL entries for inequality in at least one field.
*/
BOTAN_PUBLIC_API(2, 0) bool operator!=(const CRL_Entry& lhs, const CRL_Entry& rhs);

/**
* This class represents X.509 Certificate Revocation Lists (CRLs).
*/
class BOTAN_PUBLIC_API(2, 0) X509_CRL final : public X509_Object {
   public:
      /**
      * Check if this particular certificate is listed in the CRL
      */
      bool is_revoked(const X509_Certificate& cert) const;

      /**
      * Get the entries of this CRL in the form of a vector.
      * @return vector containing the entries of this CRL.
      */
      const std::vector<CRL_Entry>& get_revoked() const;

      /**
      * Get the X509 version of this CRL object
      * @return X509 version
      */
      uint32_t x509_version() const;

      /**
      * Get the issuer DN of this CRL.
      * @return CRLs issuer DN
      */
      const X509_DN& issuer_dn() const;

      /**
      * @return extension data for this CRL
      */
      const Extensions& extensions() const;

      /**
      * Return true if either the CRL extensions or any CRL entry extensions
      * contained a critical extension which we did not recognize.
      */
      bool has_unknown_critical_extension() const;

      /**
      * Get the AuthorityKeyIdentifier of this CRL.
      * @return this CRLs AuthorityKeyIdentifier
      */
      const std::vector<uint8_t>& authority_key_id() const;

      /**
       * Get the CRL number of this CRL.
       * @return CRL number (or nullopt if not set in the extensions)
       */
      const std::optional<BigInt>& crl_number_bigint() const;

      /**
       * Get the CRL number of this CRL.
       * @return CRL number (or zero if not set in the extensions)
       */
      BOTAN_DEPRECATED("Use crl_number_bigint") uint32_t crl_number() const;

      /**
      * Get the CRL's thisUpdate value.
      * @return CRLs thisUpdate
      */
      const X509_Time& this_update() const;

      /**
      * Get the CRL's nextUpdate value.
      *
      * Technically nextUpdate is optional in the X.509 spec and may be omitted,
      * despite RFC 5280 requiring it. If the nextUpdate field is not set, this
      * will return a time object with time_is_set() returning false.
      *
      * TODO(Botan4) return a `const std::optional<X509_Time>&` instead
      *
      * @return CRLs nextUpdate
      */
      const X509_Time& next_update() const;

      /**
      * Get the CRL's issuing distribution point
      */
      BOTAN_DEPRECATED("Use issuing_distribution_point_uris") std::string crl_issuing_distribution_point() const;

      /**
      * Get the CRL's issuing distribution points
      *
      * See https://www.rfc-editor.org/rfc/rfc5280#section-5.2.5
      */
      BOTAN_DEPRECATED("Use issuing_distribution_point_uris")
      std::vector<std::string> issuing_distribution_points() const;

      /**
      * Get the CRL's issuing distribution points
      *
      * See https://www.rfc-editor.org/rfc/rfc5280#section-5.2.5
      */
      const std::vector<URI>& issuing_distribution_point_uris() const;

      /**
      * Check whether this CRL's scope covers the given certificate per the
      * RFC 5280 6.3.3 (b)(1) and (b)(2)(i) name-matching rules.
      *
      * When the certificate has a CRLDP extension (4.2.1.13), iterates each
      * DistributionPoint and verifies:
      *   - (b)(1): if the DP includes cRLIssuer, this CRL's issuer must
      *     appear in that field and this CRL must carry an IDP with
      *     indirectCRL = TRUE; otherwise this CRL's issuer must match the
      *     certificate's issuer.
      *   - (b)(2)(i): if this CRL's IDP names a distributionPoint, that
      *     name must overlap with the DP's distributionPoint (fullName
      *     GeneralNames) or, if the DP omits distributionPoint, with
      *     the DP's cRLIssuer entries.
      *
      * The trailing paragraph of 6.3.3 supplies an implicit DP: this CRL
      * is also usable if its issuer matches the certificate's issuer and,
      * if its IDP names a distributionPoint, that name overlaps with the
      * certificate's issuer DN or any entry in the certificate's
      * issuerAltName extension. This implicit DP applies both when the
      * certificate has no CRLDP and, as a fallback, when it has a CRLDP
      * but no DistributionPoint matches: a same-issuer complete CRL not
      * named in any DP is still usable.
      *
      * Returns false if none of the above match. Returns true on a name
      * match. Reason coverage is a separate question; this predicate
      * intentionally does not consult the DP's reasons field or the IDP's
      * onlySomeReasons.
      */
      bool has_matching_distribution_point(const X509_Certificate& cert) const;

      /**
      * Create an uninitialized CRL object. Any attempts to access
      * this object will throw an exception.
      */
      X509_CRL() = default;

      /**
      * Construct a CRL from a data source.
      * @param source the data source providing the DER or PEM encoded CRL.
      */
      BOTAN_FUTURE_EXPLICIT X509_CRL(DataSource& source);

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Construct a CRL from a file containing the DER or PEM encoded CRL.
      * @param filename the name of the CRL file
      */
      BOTAN_FUTURE_EXPLICIT X509_CRL(std::string_view filename);
#endif

      /**
      * Construct a CRL from a binary vector
      * @param vec the binary (DER) representation of the CRL
      */
      BOTAN_FUTURE_EXPLICIT X509_CRL(const std::vector<uint8_t>& vec);

      /**
      * Construct a CRL
      * @param issuer issuer of this CRL
      * @param thisUpdate valid from
      * @param nextUpdate valid until
      * @param revoked entries to be included in the CRL
      */
      X509_CRL(const X509_DN& issuer,
               const X509_Time& thisUpdate,
               const X509_Time& nextUpdate,
               const std::vector<CRL_Entry>& revoked);

   private:
      std::string PEM_label() const override;

      std::vector<std::string> alternate_PEM_labels() const override;

      void force_decode() override;

      const CRL_Data& data() const;

      std::shared_ptr<const CRL_Data> m_data;
};

}  // namespace Botan

#endif

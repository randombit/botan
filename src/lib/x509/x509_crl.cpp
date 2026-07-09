/*
* X.509 CRL
* (C) 1999-2007,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_crl.h>

#include <botan/asn1_obj.h>
#include <botan/asn1_time.h>
#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/data_src.h>
#include <botan/x509_ext.h>
#include <botan/x509cert.h>
#include <botan/internal/x509_utils.h>
#include <algorithm>
#include <set>

namespace Botan {

class CRL_Data final {
   public:
      CRL_Data(const X509_DN& issuer,
               const X509_Time& this_update,
               const X509_Time& next_update,
               const std::vector<CRL_Entry>& revoked) :
            m_issuer(issuer), m_this_update(this_update), m_next_update(next_update), m_entries(revoked) {
         this->update_index();
      }

      CRL_Data() = default;

      void update_index() {
         m_revoked_serials.clear();
         for(const auto& entry : m_entries) {
            m_revoked_serials.insert(entry.serial_number());
         }
      }

      // NOLINTBEGIN(*non-private-member-variables-in-classes)
      X509_DN m_issuer;
      size_t m_version{};
      X509_Time m_this_update;
      X509_Time m_next_update;
      std::vector<CRL_Entry> m_entries;
      Extensions m_extensions;

      // cached values from entries
      std::set<std::vector<uint8_t>> m_revoked_serials;

      // cached values from extensions
      std::optional<BigInt> m_crl_number;
      std::vector<uint8_t> m_auth_key_id;
      std::vector<URI> m_idp_urls;
      bool m_has_unknown_critical_extension = false;
      // NOLINTEND(*non-private-member-variables-in-classes)
};

std::string X509_CRL::PEM_label() const {
   return "X509 CRL";
}

std::vector<std::string> X509_CRL::alternate_PEM_labels() const {
   return {"CRL"};
}

X509_CRL::X509_CRL(DataSource& src) {
   load_data(src);
}

X509_CRL::X509_CRL(const std::vector<uint8_t>& vec) {
   DataSource_Memory src(vec.data(), vec.size());
   load_data(src);
}

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
X509_CRL::X509_CRL(std::string_view fsname) {
   DataSource_Stream src(fsname, true);
   load_data(src);
}
#endif

X509_CRL::X509_CRL(const X509_DN& issuer,
                   const X509_Time& this_update,
                   const X509_Time& next_update,
                   const std::vector<CRL_Entry>& revoked) {
   m_data = std::make_shared<CRL_Data>(issuer, this_update, next_update, revoked);
}

/**
* Check if this particular certificate is listed in the CRL
*/
bool X509_CRL::is_revoked(const X509_Certificate& cert) const {
   const bool serial_appears = data().m_revoked_serials.contains(cert.serial_number());

   // If the serial number does not appear in the revocation list then
   // the later checks are not necessary anyway
   if(!serial_appears) {
      return false;
   }

   /*
   If the cert wasn't issued by the CRL issuer, it's possible the cert
   is revoked, but not by this CRL. Maybe throw an exception instead?
   */
   if(cert.issuer_dn() != issuer_dn()) {
      return false;
   }

   const std::vector<uint8_t> crl_akid = authority_key_id();
   const std::vector<uint8_t>& cert_akid = cert.authority_key_id();

   if(!crl_akid.empty() && !cert_akid.empty()) {
      if(crl_akid != cert_akid) {
         return false;
      }
   }

   return serial_appears;
}

namespace {

/*
* Decode the TBSCertList data
*/
std::unique_ptr<CRL_Data> decode_crl_body(const std::vector<uint8_t>& body, const AlgorithmIdentifier& sig_algo) {
   auto data = std::make_unique<CRL_Data>();

   BER_Decoder tbs_crl(body, BER_Decoder::Limits::DER());

   tbs_crl.decode_optional(data->m_version, ASN1_Type::Integer, ASN1_Class::Universal);
   data->m_version += 1;  // wire-format is 0-based

   if(data->m_version != 1 && data->m_version != 2) {
      throw Decoding_Error("Unknown X.509 CRL version " + std::to_string(data->m_version));
   }

   // Extensions are only defined for v2 CRLs
   const bool supports_extensions = data->m_version > 1;

   AlgorithmIdentifier sig_algo_inner;
   tbs_crl.decode(sig_algo_inner);

   if(sig_algo != sig_algo_inner) {
      throw Decoding_Error("Algorithm identifier mismatch in CRL");
   }

   tbs_crl.decode(data->m_issuer).decode(data->m_this_update);

   // According to RFC 5280 Section 5.1, nextUpdate is OPTIONAL and may be
   // encoded as either a UTCTime or a GeneralizedTime. Section 5.1.2.5
   // further states that "[c]onforming CRL issuers MUST include the nextUpdate
   // field in all CRLs". Obviously, not everyone complies...
   //
   // See https://github.com/randombit/botan/issues/4722 for more details.
   {
      const auto& next_update = tbs_crl.peek_next_object();
      if(next_update.is_a(ASN1_Type::UtcTime, ASN1_Class::Universal) ||
         next_update.is_a(ASN1_Type::GeneralizedTime, ASN1_Class::Universal)) {
         tbs_crl.decode(data->m_next_update);
      }
   }

   BER_Object next = tbs_crl.get_next_object();

   if(next.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
      BER_Decoder cert_list(next, tbs_crl.limits());

      while(cert_list.more_items()) {
         CRL_Entry entry;
         cert_list.decode(entry);

         if(entry.extensions().has_unknown_critical_extension()) {
            data->m_has_unknown_critical_extension = true;
         }

         if(!supports_extensions && entry.extensions().count() > 0) {
            throw Decoding_Error("X509 CRL included extensions in a version that doesn't support them");
         }

         data->m_entries.push_back(std::move(entry));
      }

      /*
      RFC 5280 Section 5.1.2.6
         When there are no revoked certificates, the revoked certificates list MUST be absent.

      So strictly speaking we should be checking that m_entries is not empty. But practically,
      it seems nearly all implementations accept a present-but-empty SEQUENCE as equivalent
      to an absent one, and several major ones (including GnuTLS) will emit it. Considering
      this situation, and the benign nature of the deviation, accept the non-conforming encoding.
      */

      next = tbs_crl.get_next_object();
   }

   if(next.is_a(0, ASN1_Class::Constructed | ASN1_Class::ContextSpecific)) {
      if(!supports_extensions) {
         throw Decoding_Error("X509 CRL included extensions in a version that doesn't support them");
      }
      BER_Decoder crl_options(next, tbs_crl.limits());
      data->m_extensions.decode_from(crl_options, Extension_Context::CRL);
      crl_options.verify_end();
      if(data->m_extensions.has_unknown_critical_extension()) {
         data->m_has_unknown_critical_extension = true;
      }

      if(tbs_crl.get_next_object().is_set()) {
         throw Decoding_Error("Unknown tag following extensions in CRL");
      }
   }

   tbs_crl.verify_end("Unexpected trailing data after CRL");

   // Now cache some fields from the extensions
   if(const auto* ext = data->m_extensions.get_extension_object_as<Cert_Extension::CRL_Number>()) {
      data->m_crl_number = ext->crl_number();
   }
   if(const auto* ext = data->m_extensions.get_extension_object_as<Cert_Extension::Authority_Key_ID>()) {
      data->m_auth_key_id = ext->get_key_id();
   }
   if(const auto* ext = data->m_extensions.get_extension_object_as<Cert_Extension::CRL_Issuing_Distribution_Point>()) {
      const auto& dpn = ext->distribution_point_name();
      if(dpn.has_value() && dpn->full_name().has_value()) {
         for(const auto& uri : dpn->full_name()->uri_names()) {
            data->m_idp_urls.push_back(uri);
         }
      }
   }

   data->update_index();

   return data;
}

}  // namespace

void X509_CRL::force_decode() {
   m_data.reset(decode_crl_body(signed_body(), signature_algorithm()).release());
}

const CRL_Data& X509_CRL::data() const {
   if(!m_data) {
      throw Invalid_State("X509_CRL uninitialized");
   }
   return *m_data;
}

const Extensions& X509_CRL::extensions() const {
   return data().m_extensions;
}

/*
* Return the list of revoked certificates
*/
const std::vector<CRL_Entry>& X509_CRL::get_revoked() const {
   return data().m_entries;
}

uint32_t X509_CRL::x509_version() const {
   return static_cast<uint32_t>(data().m_version);
}

bool X509_CRL::has_unknown_critical_extension() const {
   return data().m_has_unknown_critical_extension;
}

/*
* Return the distinguished name of the issuer
*/
const X509_DN& X509_CRL::issuer_dn() const {
   return data().m_issuer;
}

/*
* Return the key identifier of the issuer
*/
const std::vector<uint8_t>& X509_CRL::authority_key_id() const {
   return data().m_auth_key_id;
}

/*
* Return the CRL number of this CRL
*/
const std::optional<BigInt>& X509_CRL::crl_number_bigint() const {
   return data().m_crl_number;
}

uint32_t X509_CRL::crl_number() const {
   if(const auto num = this->crl_number_bigint()) {
      // This should already be caught at decode time
      BOTAN_ASSERT_NOMSG(num->signum() >= 0);

      if(num->bits() > 32) {
         throw Encoding_Error("CRL number is too large to fit in uint32_t");
      }

      return num->to_u32bit();
   } else {
      return 0;
   }
}

/*
* Return the issue data of the CRL
*/
const X509_Time& X509_CRL::this_update() const {
   return data().m_this_update;
}

/*
* Return the date when a new CRL will be issued
*/
const X509_Time& X509_CRL::next_update() const {
   return data().m_next_update;
}

/*
* Return the CRL's distribution point
*/
std::string X509_CRL::crl_issuing_distribution_point() const {
   if(!data().m_idp_urls.empty()) {
      return data().m_idp_urls[0].original_input();
   }
   return "";
}

/*
* Return the CRL's issuing distribution point
*/
std::vector<std::string> X509_CRL::issuing_distribution_points() const {
   std::vector<std::string> out;
   out.reserve(data().m_idp_urls.size());
   for(const auto& uri : data().m_idp_urls) {
      out.push_back(uri.original_input());
   }
   return out;
}

const std::vector<URI>& X509_CRL::issuing_distribution_point_uris() const {
   return data().m_idp_urls;
}

namespace {

/*
* Compare two distribution point names for overlap, per RFC 5280 section 6.3.3
* step (b)(2). In practice CRLDP/IDP general names are either uniformResourceIdentifier
* or directoryName; the other GeneralName variants have no defined semantics for a
* distribution point (RFC 5280 4.2.1.13 and 5.2.5) so they are ignored here.
*/
bool dp_names_overlap(const AlternativeName& a, const AlternativeName& b) {
   auto has_common = [](const auto& s1, const auto& s2) {
      return std::ranges::any_of(s1, [&](const auto& e) { return s2.contains(e); });
   };

   return has_common(a.uri_names(), b.uri_names()) || has_common(a.directory_names(), b.directory_names());
}

bool dp_issuer_and_scope_ok(const Cert_Extension::CRL_Distribution_Points::Distribution_Point& dp,
                            const X509_DN& crl_issuer_dn,
                            const Cert_Extension::CRL_Issuing_Distribution_Point* idp_ext,
                            const X509_Certificate& cert) {
   /*
   * RFC 5280 6.3.3 step (b)(1):
   *    If the DP includes cRLIssuer, then verify that the issuer field in
   *    the complete CRL matches cRLIssuer in the DP and that the complete
   *    CRL contains an issuing distribution point extension with the
   *    indirectCRL boolean asserted.  Otherwise, verify that the CRL
   *    issuer matches the certificate issuer.
   */

   if(dp.crl_issuer().has_value()) {
      // Verify that the DP cRLIssuer field matches the CRL issuer
      if(!dp.crl_issuer()->directory_names().contains(crl_issuer_dn)) {
         return false;
      }
      // Verify that the IDP with the indirectCRL boolean asserted
      if(idp_ext == nullptr || !idp_ext->indirect_crl()) {
         return false;
      }
      return true;
   } else {
      // Verify that the CRL issuer matches the certificate issuer
      return crl_issuer_dn == cert.issuer_dn();
   }
}

bool dp_idp_name_matches(const Cert_Extension::CRL_Distribution_Points::Distribution_Point& dp,
                         const Cert_Extension::CRL_Issuing_Distribution_Point* idp_ext) {
   /*
   * RFC 5280 6.3.3 step (b)(2)(i):
   *    If the distribution point name is present in the IDP CRL extension
   *    and the distribution field is present in the DP, then verify that
   *    one of the names in the IDP matches one of the names in the DP.
   *    If the distribution point name is present in the IDP CRL extension
   *    and the distribution field is omitted from the DP, then verify
   *    that one of the names in the IDP matches one of the names in the
   *    cRLIssuer field of the DP.
   */
   if(idp_ext != nullptr) {
      const auto& idp_dpn = idp_ext->distribution_point_name();
      if(!idp_dpn.has_value()) {
         return true;
      }
      const auto& cert_dpn = dp.distribution_point_name();
      if(cert_dpn.has_value()) {
         // Match the cert's DistributionPoint name against the CRL's IDP DistributionPoint name.
         if(cert_dpn->full_name().has_value() && idp_dpn->full_name().has_value()) {
            return dp_names_overlap(*cert_dpn->full_name(), *idp_dpn->full_name());
         } else {
            return false;
         }
      }
      // DP omits distributionPoint: match IDP name against names in dp.cRLIssuer.
      if(dp.crl_issuer().has_value() && idp_dpn->full_name().has_value()) {
         return dp_names_overlap(*idp_dpn->full_name(), *dp.crl_issuer());
      }
      return false;
   } else {
      return true;
   }
}

/*
* True if the cert has no CDP, in which case RFC 5280 6.3.3 trailing
* paragraph applies: assume an implicit DP whose name is the certificate
* issuer field plus the certificate issuerAltName entries, and whose
* cRLIssuer and reasons are omitted.
*/
bool implicit_dp_matches(const X509_CRL& crl,
                         const X509_Certificate& cert,
                         const Cert_Extension::CRL_Issuing_Distribution_Point* idp_ext) {
   if(crl.issuer_dn() != cert.issuer_dn()) {
      return false;
   }
   if(idp_ext == nullptr) {
      return true;
   }
   const auto& idp_dpn = idp_ext->distribution_point_name();
   if(!idp_dpn.has_value()) {
      return true;
   }
   if(!idp_dpn->full_name().has_value()) {
      return false;
   }
   AlternativeName implicit_full_name = cert.issuer_alt_name();
   implicit_full_name.add_dn(cert.issuer_dn());
   return dp_names_overlap(*idp_dpn->full_name(), implicit_full_name);
}

}  // namespace

DistributionPointMatch distribution_point_match(const X509_CRL& crl, const X509_Certificate& cert) {
   const auto* idp_ext = crl.extensions().get_extension_object_as<Cert_Extension::CRL_Issuing_Distribution_Point>();
   const auto* cdp_ext = cert.v3_extensions().get_extension_object_as<Cert_Extension::CRL_Distribution_Points>();

   /*
   * RFC 5280 6.3.3 trailing paragraph: "If the revocation status has not
   * been determined, repeat the process above with any available CRLs not
   * specified in a distribution point but issued by the certificate issuer.
   * For the processing of such a CRL, assume a DP with both the reasons and
   * the cRLIssuer fields omitted and a distribution point name of the
   * certificate issuer."
   *
   * When the cert has no CDP this implicit DP is the only DP; with no reasons
   * field it covers all reasons by construction.
   */
   if(cdp_ext == nullptr || cdp_ext->distribution_points().empty()) {
      const bool match = implicit_dp_matches(crl, cert, idp_ext);
      return {match, match};
   }

   /*
   * Walk the cert's CDP once, recording both the bare name-match and whether
   * any matching DP omits the reasons field. (b)(1) cRLIssuer + indirectCRL
   * and (b)(2)(i) IDP-vs-DP name overlap live in the helpers; reason coverage
   * is decided per (d)(3): a matching DP whose reasons field is set narrows
   * the CRL's coverage to that subset, so full coverage requires a
   * matching DP with no reasons field.
   */
   const auto name_matches = [&](const auto& dp) {
      return dp_issuer_and_scope_ok(dp, crl.issuer_dn(), idp_ext, cert) && dp_idp_name_matches(dp, idp_ext);
   };

   bool any = false;
   bool any_with_absent_reasons = false;
   for(const auto& dp : cdp_ext->distribution_points()) {
      if(name_matches(dp)) {
         any = true;
         if(!dp.reasons().has_value()) {
            any_with_absent_reasons = true;
         }
      }
   }
   if(any) {
      return {true, any_with_absent_reasons};
   }

   /*
   * Implicit-DP fallback: a same-issuer complete CRL that matches no explicit
   * DP is still usable, unless its own IDP scopes it to a distribution point
   * (see crl_eligible_for_implicit_dp_fallback). The implicit DP omits
   * reasons, so a name match here also gives full reason coverage.
   */
   const bool implicit_dp_fallback = (idp_ext == nullptr || !idp_ext->distribution_point_name().has_value());
   const bool implicit = implicit_dp_fallback && implicit_dp_matches(crl, cert, idp_ext);
   return {implicit, implicit};
}

bool X509_CRL::has_matching_distribution_point(const X509_Certificate& cert) const {
   return distribution_point_match(*this, cert).any;
}

}  // namespace Botan

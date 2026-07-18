/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
   #include <botan/ber_dec.h>
   #include <botan/certstor.h>
   #include <botan/der_enc.h>
   #include <botan/hex.h>
   #include <botan/pkix_types.h>
   #include <botan/x509_crl.h>
   #include <botan/x509_ext.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/internal/fmt.h>
   #include <chrono>
   #include <string_view>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

Botan::X509_Certificate load_cert(const std::string& name) {
   return Botan::X509_Certificate(Test::data_file("x509/cdp_aia/" + name));
}

Botan::X509_CRL load_crl(const std::string& name) {
   return Botan::X509_CRL(Test::data_file("x509/cdp_aia/" + name));
}

const Botan::Cert_Extension::CRL_Issuing_Distribution_Point* require_idp(Test::Result& result,
                                                                         const Botan::X509_CRL& crl) {
   const auto* idp = crl.extensions().get_extension_object_as<Botan::Cert_Extension::CRL_Issuing_Distribution_Point>();
   result.test_not_null("IDP parsed as known extension", idp);
   result.test_is_false("IDP decoded cleanly (not Unknown_Extension)", crl.has_unknown_critical_extension());
   return idp;
}

const Botan::Cert_Extension::CRL_Distribution_Points* require_crldp(Test::Result& result,
                                                                    const Botan::X509_Certificate& cert) {
   const auto* crldp = cert.v3_extensions().get_extension_object_as<Botan::Cert_Extension::CRL_Distribution_Points>();
   result.test_not_null("CRLDP parsed as known extension", crldp);
   return crldp;
}

const Botan::Cert_Extension::Authority_Information_Access* require_aia(Test::Result& result,
                                                                       const Botan::X509_Certificate& cert) {
   const auto* aia =
      cert.v3_extensions().get_extension_object_as<Botan::Cert_Extension::Authority_Information_Access>();
   result.test_not_null("AIA parsed as known extension", aia);
   return aia;
}

// Wrap a single extension (oid, optional critical flag, extn_value OCTET STRING)
// in the Extensions wire form (SEQUENCE OF Extension) and decode it. This is the
// public path that reaches an extension's decode_inner; a body that fails to
// decode surfaces as Unknown_Extension(failed_to_decode=true) rather than the
// typed extension. Used by the hand-built-DER strictness tests below.
Botan::Extensions decode_extension(const Botan::OID& oid,
                                   const std::vector<uint8_t>& extn_value,
                                   Botan::Extension_Context ctx,
                                   bool critical = false) {
   std::vector<uint8_t> wire;
   Botan::DER_Encoder enc(wire);
   enc.start_sequence().start_sequence().encode(oid);
   if(critical) {
      enc.encode(true);
   }
   enc.encode(extn_value, Botan::ASN1_Type::OctetString).end_cons().end_cons();

   Botan::Extensions parsed;
   Botan::BER_Decoder dec(wire);
   parsed.decode_from(dec, ctx);
   return parsed;
}

Botan::Extensions decode_extension(const Botan::OID& oid,
                                   std::string_view extn_value_hex,
                                   Botan::Extension_Context ctx,
                                   bool critical = false) {
   return decode_extension(oid, Botan::hex_decode(extn_value_hex), ctx, critical);
}

// True if extn_value surfaces as the typed extension T, false if it was rejected
// into Unknown_Extension.
template <typename T>
bool extension_surfaces(const std::vector<uint8_t>& extn_value, Botan::Extension_Context ctx, bool critical = false) {
   return decode_extension(T::static_oid(), extn_value, ctx, critical).template get_extension_object_as<T>() != nullptr;
}

template <typename T>
bool extension_surfaces(std::string_view extn_value_hex, Botan::Extension_Context ctx, bool critical = false) {
   return extension_surfaces<T>(Botan::hex_decode(extn_value_hex), ctx, critical);
}

// Returns true if the CDP extn-value body surfaces as the typed extension.
bool cdp_decodes_cleanly(const std::vector<uint8_t>& extn_value) {
   return extension_surfaces<Botan::Cert_Extension::CRL_Distribution_Points>(extn_value,
                                                                             Botan::Extension_Context::Certificate);
}

bool cdp_decodes_cleanly(std::string_view extn_value_hex) {
   return extension_surfaces<Botan::Cert_Extension::CRL_Distribution_Points>(extn_value_hex,
                                                                             Botan::Extension_Context::Certificate);
}

// Encode `ext` through the Extensions wire form and decode it back into `parsed`
// (which must outlive the returned pointer), returning the typed T or nullptr.
template <typename T>
const T* roundtrip_extension(std::unique_ptr<Botan::Certificate_Extension> ext, Botan::Extensions& parsed) {
   Botan::Extensions exts;
   exts.add(std::move(ext), /*critical=*/false);
   std::vector<uint8_t> wire;
   // Extensions::encode_into skips the outer SEQUENCE
   Botan::DER_Encoder(wire).start_sequence().encode(exts).end_cons();
   Botan::BER_Decoder dec(wire);
   parsed.decode_from(dec, Botan::Extension_Context::Certificate);
   return parsed.get_extension_object_as<T>();
}

// ---------------------------------------------------------------------------
// IDP decoding (CRL-side IssuingDistributionPoint, RFC 5280 5.2.5)
// ---------------------------------------------------------------------------

Test::Result test_idp_only_user_certs() {
   Test::Result result("IDP onlyContainsUserCerts decodes cleanly");
   const auto crl = load_crl("crl_idp_user_certs.crl");
   if(const auto* idp = require_idp(result, crl)) {
      result.test_is_true("onlyContainsUserCerts", idp->only_contains_user_certs());
      result.test_is_false("onlyContainsCACerts", idp->only_contains_ca_certs());
      result.test_is_false("indirectCRL", idp->indirect_crl());
      result.test_is_false("onlyContainsAttributeCerts", idp->only_contains_attribute_certs());
      result.test_is_true("onlySomeReasons absent", !idp->only_some_reasons().has_value());
      result.test_is_false("distributionPoint absent", idp->distribution_point_name().has_value());
   }
   return result;
}

Test::Result test_idp_only_ca_certs() {
   Test::Result result("IDP onlyContainsCACerts decodes cleanly");
   const auto crl = load_crl("crl_idp_ca_certs.crl");
   if(const auto* idp = require_idp(result, crl)) {
      result.test_is_true("onlyContainsCACerts", idp->only_contains_ca_certs());
      result.test_is_false("onlyContainsUserCerts", idp->only_contains_user_certs());
   }
   return result;
}

Test::Result test_idp_some_reasons() {
   Test::Result result("IDP onlySomeReasons decodes cleanly");
   const auto crl = load_crl("crl_idp_some_reasons.crl");
   if(const auto* idp = require_idp(result, crl)) {
      const auto reasons = idp->only_some_reasons();
      if(result.test_is_true("onlySomeReasons present", reasons.has_value())) {
         result.test_is_true("includes keyCompromise", reasons->includes(Botan::ReasonFlags::KeyCompromise));
         result.test_is_false("excludes superseded", reasons->includes(Botan::ReasonFlags::Superseded));
      }
   }
   return result;
}

Test::Result test_idp_indirect() {
   Test::Result result("IDP indirectCRL decodes cleanly");
   const auto crl = load_crl("crl_idp_indirect.crl");
   if(const auto* idp = require_idp(result, crl)) {
      result.test_is_true("indirectCRL", idp->indirect_crl());
   }
   return result;
}

Test::Result test_idp_full() {
   Test::Result result("IDP multi-field decode (DPName + booleans + reasons)");
   const auto crl = load_crl("crl_idp_full.crl");
   if(const auto* idp = require_idp(result, crl)) {
      const auto& idp_dpn = idp->distribution_point_name();
      if(result.test_is_true("distributionPoint present and is fullName",
                             idp_dpn.has_value() && idp_dpn->full_name().has_value())) {
         const auto& uris = idp_dpn->full_name()->uri_names();
         result.test_sz_eq("one URI", uris.size(), 1);
         if(!uris.empty()) {
            result.test_str_eq("URI value", uris.begin()->original_input(), "http://crl.example.com/users.crl");
         }
      }
      result.test_is_true("onlyContainsUserCerts", idp->only_contains_user_certs());

      if(result.test_is_true("only_some_reasons is present", idp->only_some_reasons().has_value())) {
         result.test_is_true("only_some_reasons includes keyCompromise",
                             idp->only_some_reasons()->includes(Botan::ReasonFlags::KeyCompromise));
      }
   }
   return result;
}

// ---------------------------------------------------------------------------
// CDP decoding (cert-side, RFC 5280 4.2.1.13)
// ---------------------------------------------------------------------------

Test::Result test_cdp_multi_uri_fullname() {
   Test::Result result("Leaf cert: single DP with two URIs in fullName");
   const auto cert = load_cert("leaf_cdp_multi_uri.crt");

   if(const auto* cdp = require_crldp(result, cert)) {
      const auto& dps = cdp->distribution_points();
      result.test_sz_eq("one DistributionPoint", dps.size(), 1);
      if(!dps.empty()) {
         const auto& dp = dps.front();
         const auto& dpn = dp.distribution_point_name();
         if(result.test_is_true("fullName present", dpn.has_value() && dpn->full_name().has_value())) {
            result.test_sz_eq("two URIs in fullName", dpn->full_name()->uri_names().size(), 2);
         }
         result.test_is_false("crlIssuer absent", dp.crl_issuer().has_value());
         result.test_is_false("reasons absent", dp.reasons().has_value());
      }
   }
   return result;
}

Test::Result test_cdp_constructor_populates_cached_uris() {
   Test::Result result("CRL_Distribution_Points constructor populates distribution-point URIs");

   const std::string uri = "http://crl.example.com/constructor.crl";
   Botan::AlternativeName full_name;
   full_name.add_uri(uri);

   std::vector<Botan::Cert_Extension::CRL_Distribution_Points::Distribution_Point> dps;
   dps.emplace_back(full_name);

   const Botan::Cert_Extension::CRL_Distribution_Points cdp(dps);
   result.test_sz_eq("distribution points preserved", cdp.distribution_points().size(), 1);
   result.test_sz_eq("URI accessor populated", cdp.crl_distribution_point_uris().size(), 1);
   if(!cdp.crl_distribution_point_uris().empty()) {
      result.test_str_eq("URI value", cdp.crl_distribution_point_uris().front().original_input(), uri);
   }

   const auto legacy_uris = cdp.crl_distribution_urls();
   result.test_sz_eq("legacy URI accessor populated", legacy_uris.size(), 1);
   if(!legacy_uris.empty()) {
      result.test_str_eq("legacy URI value", legacy_uris.front(), uri);
   }

   const auto copied = cdp.copy();
   const auto* cdp_copy = dynamic_cast<const Botan::Cert_Extension::CRL_Distribution_Points*>(copied.get());
   if(!result.test_not_null("copy returns a CRL_Distribution_Points", cdp_copy)) {
      return result;
   }
   result.test_sz_eq("copy preserves constructor-populated URI", cdp_copy->crl_distribution_point_uris().size(), 1);

   return result;
}

Test::Result test_cdp_crl_issuer_only() {
   Test::Result result("Leaf cert: DP with cRLIssuer only, no distributionPoint");
   const auto cert = load_cert("leaf_cdp_crl_issuer.crt");

   if(const auto* crldp = require_crldp(result, cert)) {
      const auto& dps = crldp->distribution_points();
      result.test_sz_eq("one DistributionPoint", dps.size(), 1);
      if(!dps.empty()) {
         const auto& dp = dps.front();
         result.test_is_false("DP name absent", dp.distribution_point_name().has_value());
         result.test_is_true("crlIssuer present", dp.crl_issuer().has_value());
         if(dp.crl_issuer().has_value()) {
            result.test_sz_eq("crlIssuer has one DN", dp.crl_issuer()->directory_names().size(), 1);
         }
      }
   }
   return result;
}

Test::Result test_indirect_crl_requires_idp_indirect_crl_flag() {
   /*
   * RFC 5280 6.3.3(b)(1): "If the DP includes cRLIssuer, then verify that
   * the issuer field in the complete CRL matches cRLIssuer in the DP and
   * that the complete CRL contains an issuing distribution point extension
   * with the indirectCRL boolean asserted."
   *
   * leaf_cdp_crl_issuer.crt has a DP whose only field is cRLIssuer naming
   * the "Indirect CRL Issuer" DN. A CRL from that issuer matches the
   * explicit DP only when its IDP asserts indirectCRL. (These CRLs are from
   * a different issuer than the certificate issuer, so the implicit-DP
   * fallback of the trailing 6.3.3 paragraph does not apply to them.)
   */
   Test::Result result("Indirect-CRL DP matches a cRLIssuer CRL only with indirectCRL=TRUE");
   const auto cert = load_cert("leaf_cdp_crl_issuer.crt");

   const auto with_flag = load_crl("crl_indirect_with_flag.crl");
   result.test_is_true("cRLIssuer CRL with indirectCRL=TRUE matches", with_flag.has_matching_distribution_point(cert));

   const auto no_flag = load_crl("crl_indirect_no_flag.crl");
   result.test_is_false("cRLIssuer CRL without indirectCRL=TRUE does not match",
                        no_flag.has_matching_distribution_point(cert));
   return result;
}

Test::Result test_self_scoped_crl_not_rescued_by_implicit_dp() {
   /*
   * Mirrors BSI CERT_PATH_CRL_13. The certificate's CDP names a directoryName
   * partition ("Different Partition") that no CRL covers. The only same-issuer
   * CRL carries a critical IDP scoping it to the issuer's own DN, a different
   * distribution point. RFC 5280 6.3.3's implicit-DP fallback covers only CRLs
   * "not specified in a distribution point"; a CRL that scopes itself via its
   * IDP is specified in one and must match an explicit cert DP. So this CRL
   * must NOT match. This matches OpenSSL ("error 44: different CRL scope") and
   * BoringSSL (CheckCRL returns UNKNOWN on the IDP/DP name mismatch).
   */
   Test::Result result("Self-scoped same-issuer CRL does not match a cert assigned to a different DP");
   const auto cert = load_cert("leaf_cdp_dirname_partition.crt");
   const auto crl = load_crl("crl_idp_dirname_self.crl");
   result.test_is_false("IDP-scoped CRL for a different partition does not match via implicit DP",
                        crl.has_matching_distribution_point(cert));
   return result;
}

Test::Result test_same_issuer_crl_matches_via_implicit_dp_fallback() {
   /*
   * RFC 5280 6.3.3 trailing paragraph: "If the revocation status has not
   * been determined, repeat the process above with any available CRLs not
   * specified in a distribution point but issued by the certificate issuer.
   * For the processing of such a CRL, assume a DP with both the reasons and
   * the cRLIssuer fields omitted and a distribution point name of the
   * certificate issuer."
   *
   * leaf_cdp_crl_issuer.crt delegates revocation to an indirect cRLIssuer,
   * so its explicit DP does not match a CRL from the certificate's own
   * issuer. A same-issuer complete CRL must still be usable via the implicit
   * DP rather than skipped.
   */
   Test::Result result("Same-issuer CRL matches a cert with non-matching CDP via implicit DP");
   const auto cert = load_cert("leaf_cdp_crl_issuer.crt");
   const auto crl = load_crl("crl_no_idp.crl");
   result.test_is_true("same-issuer no-IDP CRL matches via implicit DP", crl.has_matching_distribution_point(cert));
   return result;
}

Test::Result test_direct_crl_requires_matching_issuer() {
   /*
   * RFC 5280 6.3.3(b)(1): "if the DP does not include cRLIssuer, then verify
   * that the CRL issuer matches the certificate issuer." Positive control:
   * leaf_basic (DP without cRLIssuer) and a same-issuer CRL match. (The
   * cross-issuer negative is covered by test_indirect_crl_requires_idp_indirect_crl_flag.)
   */
   Test::Result result("Direct CRL applies only when CRL issuer matches cert issuer");
   const auto cert = load_cert("leaf_basic.crt");
   const auto crl = load_crl("crl_no_idp.crl");
   result.test_is_true("matching-issuer direct CRL applies", crl.has_matching_distribution_point(cert));
   return result;
}

Test::Result test_relative_name_decode_rejected() {
   /*
   * The nameRelativeToCRLIssuer [1] CHOICE arm of DistributionPointName is not
   * supported; a DP or IDP that uses it must not surface as a typed extension.
   *
   * DistributionPointName here is distributionPoint [0] EXPLICIT holding a
   * nameRelativeToCRLIssuer [1] IMPLICIT SET OF AttributeTypeAndValue with a
   * single CN=A AVA.
   */
   Test::Result result("DistributionPointName decoder rejects nameRelativeToCRLIssuer");

   result.test_is_false("CDP nameRelativeToCRLIssuer is not exposed as typed",
                        cdp_decodes_cleanly("3010300ea00ca10a300806035504030c0141"));

   result.test_is_false("IDP nameRelativeToCRLIssuer is not exposed as typed",
                        extension_surfaces<Botan::Cert_Extension::CRL_Issuing_Distribution_Point>(
                           "300ea00ca10a300806035504030c0141", Botan::Extension_Context::CRL));
   return result;
}

// ---------------------------------------------------------------------------
// AIA decoding (cert-side, RFC 5280 4.2.2.1)
// ---------------------------------------------------------------------------

Test::Result test_aia_stir_tn_list() {
   Test::Result result("Leaf cert: AIA id-ad-stirTNList preserved");
   const auto cert = load_cert("leaf_aia_stir_tn_list.crt");

   if(const auto* aia = require_aia(result, cert)) {
      const auto& access = aia->access_descriptions();
      result.test_sz_eq("one AccessDescription", access.size(), 1);
      if(!access.empty()) {
         const Botan::OID stir_tn_list({1, 3, 6, 1, 5, 5, 7, 48, 14});
         result.test_is_true("method is id-ad-stirTNList", access.front().access_method() == stir_tn_list);
         const auto uri = access.front().location_as_uri_string();
         if(result.test_is_true("location is URI", uri.has_value())) {
            result.test_str_eq("URI value", *uri, "https://tnlist.example.com/list");
         }
      }
      // Method is neither OCSP nor caIssuers, so the URI-typed accessors stay empty.
      result.test_is_true("ocsp_responder_uris empty", aia->ocsp_responder_uris().empty());
      result.test_is_true("ca_issuer_uris empty", aia->ca_issuer_uris().empty());
   }
   return result;
}

Test::Result test_aia_ocsp_directoryname() {
   Test::Result result("Leaf cert: AIA id-ad-ocsp with directoryName location");
   const auto cert = load_cert("leaf_aia_ocsp_dirname.crt");

   if(const auto* aia = require_aia(result, cert)) {
      // Non-URI accessLocation: legacy URI-typed accessor empty.
      result.test_is_true("ocsp_responder_uris empty", aia->ocsp_responder_uris().empty());
      // But the raw AccessDescription list preserves it so RFC 9608 noRevAvail
      // enforcement can still see the id-ad-ocsp accessMethod is present.
      const auto& access = aia->access_descriptions();
      result.test_sz_eq("one AccessDescription", access.size(), 1);
      if(!access.empty()) {
         const Botan::OID id_ad_ocsp = Botan::OID::from_string("PKIX.OCSP");
         result.test_is_true("method is id-ad-ocsp", access.front().access_method() == id_ad_ocsp);
         result.test_is_false("location is not a URI", access.front().location_as_uri_string().has_value());
      }
   }
   return result;
}

// ---------------------------------------------------------------------------
// Path-validation regressions
// ---------------------------------------------------------------------------

Botan::Path_Validation_Result validate_with_crl(const Botan::X509_Certificate& leaf,
                                                const Botan::X509_Certificate& root,
                                                const Botan::X509_CRL& crl) {
   Botan::Certificate_Store_In_Memory trusted;
   trusted.add_certificate(root);
   trusted.add_crl(crl);

   const Botan::Path_Validation_Restrictions restrictions(/*require_rev=*/true, /*minimum_key_strength=*/80);
   const std::vector<Botan::Certificate_Store*> stores{&trusted};
   const auto ref_time = std::chrono::system_clock::from_time_t(1893456000);  // 2030-01-01T00:00:00Z, mid-window
   return Botan::x509_path_validate(leaf, restrictions, stores, "", Botan::Usage_Type::UNSPECIFIED, ref_time);
}

// Validate leaf_file against root_ca.crt with crl_file as the only revocation
// source under a strict (require_revocation) policy, and check the outcome.
// `expected == std::nullopt` means the chain must validate; otherwise validation
// must fail with exactly that overall status code. Centralizes the
// load/validate/assert mechanics the revocation regressions share so each test
// is just its rationale comment plus the scenario inputs.
Test::Result strict_revocation_case(const std::string& test_name,
                                    const std::string& leaf_file,
                                    const std::string& crl_file,
                                    std::optional<Botan::Certificate_Status_Code> expected) {
   Test::Result result(test_name);
   const auto root = load_cert("root_ca.crt");
   const auto leaf = load_cert(leaf_file);
   const auto crl = load_crl(crl_file);
   const auto pv = validate_with_crl(leaf, root, crl);
   if(expected.has_value()) {
      result.test_is_false("chain does not validate", pv.successful_validation());
      result.test_is_true("overall result matches expected status", pv.result() == *expected);
   } else {
      result.test_is_true("chain validates", pv.successful_validation());
   }
   return result;
}

Test::Result test_revoked_by_reason_limited_crl_does_not_emit_no_revocation_data() {
   /*
   * Regression: PKIX::merge_revocation_status counted only VALID_CRL_CHECKED as
   * CRL evidence, so a cert listed on a reason-limited CRL (CERT_IS_REVOKED
   * inserted by check_crls but no VALID_CRL_CHECKED) under a strict policy got
   * NO_REVOCATION_DATA stamped alongside the revocation. The overall status
   * still came back CERT_IS_REVOKED because 5000 > 1002, but the per-cert
   * status set leaked an inapplicable NO_REVOCATION_DATA. RFC 5280 6.3.3
   * treats revocation status as determined once cert_status is not UNREVOKED.
   */
   Test::Result result("Revoked cert from reason-limited CRL does not surface NO_REVOCATION_DATA");
   const auto root = load_cert("root_ca.crt");
   const auto leaf = load_cert("leaf_basic.crt");
   const auto crl = load_crl("crl_idp_some_reasons_revoking_leaf.crl");

   const auto pv = validate_with_crl(leaf, root, crl);

   result.test_is_false("chain does not validate", pv.successful_validation());
   result.test_is_true("overall status is CERT_IS_REVOKED",
                       pv.result() == Botan::Certificate_Status_Code::CERT_IS_REVOKED);

   bool revoked = false;
   bool no_rev_data = false;
   for(const auto& s : pv.all_statuses()) {
      if(s.contains(Botan::Certificate_Status_Code::CERT_IS_REVOKED)) {
         revoked = true;
      }
      if(s.contains(Botan::Certificate_Status_Code::NO_REVOCATION_DATA)) {
         no_rev_data = true;
      }
   }
   result.test_is_true("per-cert status set carries CERT_IS_REVOKED", revoked);
   result.test_is_false("per-cert status set does not carry NO_REVOCATION_DATA", no_rev_data);
   return result;
}

Test::Result test_idp_user_certs_does_not_falsely_revoke() {
   /*
   * Pre-fix: a CRL whose IDP was just "[1] onlyContainsUserCerts = TRUE"
   * fell through to Unknown_Extension(failed_to_decode=true). PKIX::check_crl
   * then inserted CRL_HAS_UNKNOWN_CRITICAL_EXTENSION for every cert chain
   * that supplied this CRL, even though the leaf was not on the revocation
   * list.
   *
   * Post-fix: the IDP decodes correctly and the chain validates. This also
   * confirms the positive direction of RFC 5280 6.3.3 step (b)(2)(ii): an
   * onlyContainsUserCerts CRL is in scope for (and consulted on) an end-entity.
   */
   Test::Result result("CRL with IDP onlyContainsUserCerts does not falsely reject the chain");
   const auto root = load_cert("root_ca.crt");
   const auto leaf = load_cert("leaf_basic.crt");
   const auto crl = load_crl("crl_idp_user_certs.crl");

   const auto pv = validate_with_crl(leaf, root, crl);

   result.test_is_true("chain validates", pv.successful_validation());
   const auto& all = pv.all_statuses();
   bool unknown_crit = false;
   bool revoked = false;
   for(const auto& s : all) {
      if(s.contains(Botan::Certificate_Status_Code::CRL_HAS_UNKNOWN_CRITICAL_EXTENSION)) {
         unknown_crit = true;
      }
      if(s.contains(Botan::Certificate_Status_Code::CERT_IS_REVOKED)) {
         revoked = true;
      }
   }
   result.test_is_false("no CRL_HAS_UNKNOWN_CRITICAL_EXTENSION", unknown_crit);
   result.test_is_false("no false CERT_IS_REVOKED", revoked);
   return result;
}

// Strict-revocation regressions that share the load/validate/assert shape, one
// table row each: {test name, leaf, crl, expected overall status} where a
// nullopt status means the chain must validate. The one-line comment on each row
// is the rationale; test_idp_user_certs_does_not_falsely_revoke stays a separate
// function because it inspects individual status codes rather than the overall
// result.
std::vector<Test::Result> strict_revocation_regressions() {
   using Code = Botan::Certificate_Status_Code;

   struct Case {
         const char* name;
         const char* leaf;
         const char* crl;
         std::optional<Code> expected;
   };

   const std::vector<Case> cases = {
      // RFC 5280 6.3.3(b)(2)(iii): an onlyContainsCACerts CRL is out of scope for
      // an end-entity, so it must not be consulted; strict policy then surfaces
      // NO_REVOCATION_DATA rather than treating the empty list as validation.
      {"CRL scope onlyContainsCACerts is not consulted for end-entity certs",
       "leaf_basic.crt",
       "crl_idp_ca_certs.crl",
       Code::NO_REVOCATION_DATA},
      // RFC 5280 6.3.3(d)-(l) reason-mask accumulation is unimplemented, so an
      // onlySomeReasons CRL can only ever give partial coverage.
      {"CRL with IDP onlySomeReasons does not satisfy strict revocation policy",
       "leaf_basic.crt",
       "crl_idp_some_reasons.crl",
       Code::NO_REVOCATION_DATA},
      // RFC 5280 6.3.3(d): the reason mask is computed per matching (DP, IDP)
      // pair, so a no-reasons DP that matches gives full coverage even when
      // another DP in the same CDP carries reasons.
      {"Cert with multi-DP CDP: full coverage when a no-reasons DP matches",
       "leaf_cdp_two_dps.crt",
       "crl_no_idp.crl",
       std::nullopt},
      // A reason-limited CRL still proves a positive revocation when the cert is
      // listed: the entry is authoritative for whichever reason the CRL covers.
      {"CRL with IDP onlySomeReasons still reports CERT_IS_REVOKED when the cert is listed",
       "leaf_basic.crt",
       "crl_idp_some_reasons_revoking_leaf.crl",
       Code::CERT_IS_REVOKED},
      // RFC 5280 6.3.3(f)-(g): an indirect CRL needs the cRLIssuer's path and key
      // to verify; PKIX::check_crl only has the direct issuer key, so it is
      // inapplicable rather than authoritative.
      {"CRL with IDP indirectCRL is rejected as inapplicable",
       "leaf_basic.crt",
       "crl_idp_indirect.crl",
       Code::NO_REVOCATION_DATA},
      // Cert-side mirror of the onlySomeReasons case: a DP whose reasons field is
      // set describes only partial-coverage CRLs until accumulation is implemented.
      {"Cert CDP with limited reasons does not satisfy strict revocation policy",
       "leaf_cdp_reasons.crt",
       "crl_no_idp.crl",
       Code::NO_REVOCATION_DATA},
      // RFC 5280 6.3.3 trailing paragraph: with no CDP the implicit DP name is the
      // cert issuer DN, so a CRL whose IDP fullName is a URI is out of scope.
      {"Cert without CDP rejects CRL whose IDP fullName misses cert issuer DN",
       "leaf_aia_stir_tn_list.crt",
       "crl_idp_full.crl",
       Code::NO_REVOCATION_DATA},
      // RFC 5280 6.3.3(b)(2)(i): DP-name matching only applies when the CRL has an
      // IDP; a no-IDP CRL applies to all certs from the issuer.
      {"CRL without IDP applies to cert with CDP (RFC 5280 6.3.3)", "leaf_basic.crt", "crl_no_idp.crl", std::nullopt},
   };

   std::vector<Test::Result> out;
   out.reserve(cases.size());
   for(const auto& c : cases) {
      out.push_back(strict_revocation_case(c.name, c.leaf, c.crl, c.expected));
   }
   return out;
}

// ---------------------------------------------------------------------------
// Encoder strictness regressions
//
// Extensions::add() invokes encode_inner() when storing an extension, so adding
// a malformed extension to an Extensions container is the public path that
// reaches encode_inner from outside this translation unit.
// ---------------------------------------------------------------------------

Test::Result test_idp_empty_encode_rejected() {
   /* RFC 5280 5.2.5: "Conforming CRL issuers MUST NOT issue CRLs where the
   * DER encoding of the issuing distribution point extension is an empty
   * sequence." A default-constructed IDP carries no fields. */
   Test::Result result("IDP encoder rejects empty IssuingDistributionPoint");
   Botan::Extensions exts;
   result.test_throws("Extensions::add throws on empty IDP", [&] {
      exts.add(std::make_unique<Botan::Cert_Extension::CRL_Issuing_Distribution_Point>(), true);
   });
   return result;
}

Test::Result test_idp_mutex_scope_booleans_encode_rejected() {
   /* RFC 5280 5.2.5: "at most one of onlyContainsUserCerts,
   * onlyContainsCACerts, and onlyContainsAttributeCerts may be set to TRUE". */
   Test::Result result("IDP encoder rejects multiple scope booleans");
   auto idp = std::make_unique<Botan::Cert_Extension::CRL_Issuing_Distribution_Point>(
      Botan::Cert_Extension::DistributionPointName{},
      /*only_contains_user_certs=*/true,
      /*only_contains_ca_certs=*/true,
      /*only_some_reasons=*/std::nullopt,
      /*indirect_crl=*/false,
      /*only_contains_attribute_certs=*/false);
   Botan::Extensions exts;
   result.test_throws("Extensions::add throws when both user and CA bits are TRUE",
                      [&] { exts.add(std::move(idp), true); });
   return result;
}

Test::Result test_empty_general_names_in_fullname_rejected() {
   /* RFC 5280 4.2.1.6: GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName. */
   Test::Result result("DistributionPoint encoder rejects malformed fullName");
   Botan::Cert_Extension::DistributionPointName dpn(Botan::AlternativeName{});
   std::vector<Botan::Cert_Extension::CRL_Distribution_Points::Distribution_Point> dps;
   dps.emplace_back(std::move(dpn), std::nullopt, std::nullopt);
   auto cdp = std::make_unique<Botan::Cert_Extension::CRL_Distribution_Points>(dps);
   Botan::Extensions exts;
   result.test_throws("Extensions::add throws on DP with empty fullName GeneralNames",
                      [&] { exts.add(std::move(cdp), false); });

   Botan::AlternativeName empty_dn;
   empty_dn.add_dn(Botan::X509_DN{});
   Botan::Cert_Extension::DistributionPointName empty_dn_dpn(std::move(empty_dn));
   std::vector<Botan::Cert_Extension::CRL_Distribution_Points::Distribution_Point> dps2;
   dps2.emplace_back(std::move(empty_dn_dpn), std::nullopt, std::nullopt);
   auto cdp2 = std::make_unique<Botan::Cert_Extension::CRL_Distribution_Points>(dps2);
   Botan::Extensions exts2;
   result.test_throws("Extensions::add throws on DP with empty directoryName in fullName",
                      [&] { exts2.add(std::move(cdp2), false); });
   return result;
}

Test::Result test_empty_directory_name_in_fullname_decode_rejected() {
   Test::Result result("DistributionPoint decoder rejects empty directoryName in fullName");

   // The CDP extn_value from the reviewer report.
   result.test_is_false("CDP empty directoryName fullName is not exposed as typed",
                        cdp_decodes_cleanly("300a3008a006a004a4023000"));

   // The same malformed DistributionPointName wrapped as an IDP extn_value.
   result.test_is_false("IDP empty directoryName fullName is not exposed as typed",
                        extension_surfaces<Botan::Cert_Extension::CRL_Issuing_Distribution_Point>(
                           "3008a006a004a4023000", Botan::Extension_Context::CRL));
   return result;
}

Test::Result test_crl_issuer_must_be_single_directory_name_encode() {
   /*
   * RFC 5280 4.2.1.13: "If present, the cRLIssuer MUST only contain the
   * distinguished name (DN) from the issuer field of the CRL to which the
   * DistributionPoint is pointing." Structurally, that is exactly one
   * directoryName GeneralName. Reject other GeneralName kinds at encode.
   */
   Test::Result result("Encoder rejects cRLIssuer that is not a single directoryName");

   Botan::AlternativeName uri_only;
   uri_only.add_uri("http://crl.example.com/c.crl");
   std::vector<Botan::Cert_Extension::CRL_Distribution_Points::Distribution_Point> dps;
   dps.emplace_back(std::optional<Botan::Cert_Extension::DistributionPointName>{}, std::nullopt, uri_only);
   auto cdp = std::make_unique<Botan::Cert_Extension::CRL_Distribution_Points>(dps);
   Botan::Extensions exts;
   result.test_throws("Extensions::add throws when cRLIssuer is a URI rather than a DN",
                      [&] { exts.add(std::move(cdp), false); });

   // Two DNs is also disallowed.
   Botan::AlternativeName two_dns;
   two_dns.add_dn(Botan::X509_DN({{"X520.CommonName", "Issuer A"}}));
   two_dns.add_dn(Botan::X509_DN({{"X520.CommonName", "Issuer B"}}));
   std::vector<Botan::Cert_Extension::CRL_Distribution_Points::Distribution_Point> dps2;
   dps2.emplace_back(std::optional<Botan::Cert_Extension::DistributionPointName>{}, std::nullopt, two_dns);
   auto cdp2 = std::make_unique<Botan::Cert_Extension::CRL_Distribution_Points>(dps2);
   Botan::Extensions exts2;
   result.test_throws("Extensions::add throws when cRLIssuer carries two DNs",
                      [&] { exts2.add(std::move(cdp2), false); });

   // An empty DN is a directoryName GeneralName, but not a usable cRLIssuer.
   Botan::AlternativeName empty_dn;
   empty_dn.add_dn(Botan::X509_DN{});
   std::vector<Botan::Cert_Extension::CRL_Distribution_Points::Distribution_Point> dps3;
   dps3.emplace_back(std::optional<Botan::Cert_Extension::DistributionPointName>{}, std::nullopt, empty_dn);
   auto cdp3 = std::make_unique<Botan::Cert_Extension::CRL_Distribution_Points>(dps3);
   Botan::Extensions exts3;
   result.test_throws("Extensions::add throws when cRLIssuer carries an empty DN",
                      [&] { exts3.add(std::move(cdp3), false); });
   return result;
}

Test::Result test_crl_issuer_must_be_single_directory_name_decode() {
   /*
   * The decoder rejects a CDP whose cRLIssuer is not exactly the required one DN.
   * Specifically test cRLIssuer fields with either 2 or zero directory names.
   */
   Test::Result result("Decoder rejects cRLIssuer that is not a single directoryName");

   // A DistributionPoint whose [2] cRLIssuer carries two directoryName entries.
   //
   //   ascii2der <<EOF
   //   SEQUENCE { SEQUENCE { [2] {
   //     [4] { SEQUENCE { SET { SEQUENCE {
   //       OBJECT_IDENTIFIER { 2.5.4.3 } UTF8String { "A" } } } } }
   //     [4] { SEQUENCE { SET { SEQUENCE {
   //       OBJECT_IDENTIFIER { 2.5.4.3 } UTF8String { "B" } } } } }
   //   } } }
   //   EOF
   result.test_is_false(
      "cRLIssuer with 2 DNs is rejected",
      cdp_decodes_cleanly("30243022A220A40E300C310A300806035504030C0141A40E300C310A300806035504030C0142"));

   // A CRLDistributionPoints whose cRLIssuer field is an empty DN
   //
   // ascii2der:
   //  SEQUENCE { SEQUENCE { [2] { [4] { SEQUENCE {} } } } }
   result.test_is_false("cRLIssuer with 0 DNs is rejected", cdp_decodes_cleanly("30083006a204a4023000"));
   return result;
}

Test::Result test_distribution_point_rejects_out_of_order_fields() {
   /*
   * DER: SEQUENCE fields must appear in strictly increasing tag order, and
   * each OPTIONAL field appears at most once.
   */
   Test::Result result("DistributionPoint decoder rejects out-of-order and duplicate fields");

   // [0] { [0] { [6 PRIMITIVE] { "http://x/" } } }'
   constexpr std::string_view dp_name = "a00da00b8609687474703a2f2f782f";

   // [2] { [4] { SEQUENCE { SET { SEQUENCE { OBJECT_IDENTIFIER { 2.5.4.3 } UTF8String { "R" } } } } } }
   constexpr std::string_view crl_issuer = "a210a40e300c310a300806035504030c0152";
   constexpr std::string_view empty_crl_issuer = "a200";  // [2] cRLIssuer, length 0 (RFC 5280 4.2.1.6 violation)

   const auto cat = [](std::initializer_list<std::string_view> parts) {
      std::string out;
      for(const auto& p : parts) {
         out += p;
      }
      return out;
   };

   // Wrap a DistributionPoint body as a single-DP CRLDistributionPoints extn value.
   const auto as_cdp = [](std::string_view dp_body_hex) {
      const auto dp_body = Botan::hex_decode(dp_body_hex);
      std::vector<uint8_t> ev;
      Botan::DER_Encoder(ev).start_sequence().start_sequence().raw_bytes(dp_body).end_cons().end_cons();
      return ev;
   };

   const std::vector<std::pair<const char*, std::string>> cases = {
      {"cRLIssuer [2] before distributionPoint [0]", cat({crl_issuer, dp_name})},
      {"distributionPoint [0] appears twice", cat({dp_name, dp_name})},
      {"cRLIssuer GeneralNames present but empty", cat({dp_name, empty_crl_issuer})},
   };

   for(const auto& [name, dp_body] : cases) {
      result.test_is_false(std::string(name) + " is not surfaced as typed", cdp_decodes_cleanly(as_cdp(dp_body)));
   }
   return result;
}

Test::Result test_aia_writable_via_access_descriptions() {
   /*
   * The decoder preserves arbitrary AccessDescription entries via
   * access_descriptions(). The matching write-side API:
   *
   *   - Authority_Information_Access(std::vector<AccessDescription>)
   *   - add_access_description(AccessDescription)
   *
   * Build an AIA carrying an id-ad-stirTNList URI plus an id-ad-ocsp URI,
   * encode through Extensions, decode back, and verify both forms surface.
   * Confirms the typed URI accessors are auto-populated from URI-form
   * OCSP / caIssuers entries so the two views stay consistent.
   */
   Test::Result result("AIA constructible and mutable via AccessDescription");

   const Botan::OID stir_tn_list({1, 3, 6, 1, 5, 5, 7, 48, 14});
   const Botan::OID ocsp = Botan::OID::from_string("PKIX.OCSP");

   const std::string stir_uri = "https://tnlist.example.com/list";
   const std::string ocsp_uri = "http://ocsp.example.com/ocsp";

   const std::vector<uint8_t> stir_bytes(stir_uri.begin(), stir_uri.end());
   const std::vector<uint8_t> ocsp_bytes(ocsp_uri.begin(), ocsp_uri.end());

   Botan::Cert_Extension::Authority_Information_Access aia(
      std::vector<Botan::Cert_Extension::Authority_Information_Access::AccessDescription>{
         {stir_tn_list, Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, stir_bytes},
      });
   aia.add_access_description({ocsp, Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, ocsp_bytes});

   // Typed view auto-populated for the OCSP URI; stirTNList stays only in
   // the raw list because it's neither id-ad-ocsp nor id-ad-caIssuers.
   result.test_sz_eq("ocsp_responder_uris populated from URI-form OCSP entry", aia.ocsp_responder_uris().size(), 1);
   if(!aia.ocsp_responder_uris().empty()) {
      result.test_str_eq("OCSP URI value", aia.ocsp_responder_uris().front().original_input(), ocsp_uri);
   }
   result.test_sz_eq("ca_issuer_uris empty (no caIssuers entry)", aia.ca_issuer_uris().size(), 0);
   result.test_sz_eq("access_descriptions size", aia.access_descriptions().size(), 2);

   // Round-trip through Extensions to confirm the new constructor's
   // m_access_descriptions makes it to the wire and back.
   Botan::Extensions parsed;
   const auto* parsed_aia =
      roundtrip_extension<Botan::Cert_Extension::Authority_Information_Access>(aia.copy(), parsed);
   if(!result.test_not_null("AIA round-trips", parsed_aia)) {
      return result;
   }
   result.test_sz_eq("two AccessDescriptions preserved", parsed_aia->access_descriptions().size(), 2);
   bool stir_found = false;
   bool ocsp_found = false;
   for(const auto& ad : parsed_aia->access_descriptions()) {
      if(ad.access_method() == stir_tn_list) {
         stir_found = true;
      }
      if(ad.access_method() == ocsp) {
         ocsp_found = true;
      }
   }
   result.test_is_true("stirTNList preserved", stir_found);
   result.test_is_true("OCSP preserved", ocsp_found);
   return result;
}

Test::Result test_aia_uri_constructor_then_add_access_description_keeps_all() {
   Test::Result result("AIA URI constructor + add_access_description preserves all entries");

   const std::string ocsp1 = "http://ocsp.example.com/";
   const std::string ca_issuer = "http://ca.example.com/ca.cer";
   const std::string ocsp2 = "http://ocsp2.example.com/";

   Botan::Cert_Extension::Authority_Information_Access aia(
      std::vector<Botan::URI>{Botan::URI::parse(ocsp1).value()},
      std::vector<Botan::URI>{Botan::URI::parse(ca_issuer).value()});

   const Botan::OID ocsp_oid = Botan::OID::from_string("PKIX.OCSP");
   const std::vector<uint8_t> ocsp2_bytes(ocsp2.begin(), ocsp2.end());
   aia.add_access_description({ocsp_oid, Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, ocsp2_bytes});

   // In-memory views: two OCSP URIs (constructor + appended), one caIssuers.
   result.test_sz_eq("two OCSP URIs in view", aia.ocsp_responder_uris().size(), 2);
   result.test_sz_eq("one caIssuers URI in view", aia.ca_issuer_uris().size(), 1);
   result.test_sz_eq("three AccessDescriptions", aia.access_descriptions().size(), 3);

   Botan::Extensions parsed;
   const auto* parsed_aia =
      roundtrip_extension<Botan::Cert_Extension::Authority_Information_Access>(aia.copy(), parsed);
   if(!result.test_not_null("AIA round-trips", parsed_aia)) {
      return result;
   }

   // The constructor-supplied OCSP URI must survive to the wire.
   result.test_sz_eq("both OCSP URIs survive encode", parsed_aia->ocsp_responder_uris().size(), 2);
   result.test_sz_eq("caIssuers URI survives encode", parsed_aia->ca_issuer_uris().size(), 1);
   result.test_sz_eq("all three AccessDescriptions survive encode", parsed_aia->access_descriptions().size(), 3);

   bool ocsp1_found = false;
   for(const auto& uri : parsed_aia->ocsp_responder_uris()) {
      if(uri.original_input() == ocsp1) {
         ocsp1_found = true;
      }
   }
   result.test_is_true("constructor-supplied OCSP URI not dropped", ocsp1_found);
   return result;
}

Test::Result test_aia_builder_rejects_malformed_uri_access_locations() {
   /*
   * decode_inner validates accessLocation as a GeneralName. The programmatic
   * AccessDescription path must reject the same inputs: otherwise an AIA built
   * via AccessDescriptions could re-encode bytes that its own decoder would
   * then reject (round-trip asymmetry).
   */
   Test::Result result("AIA builder rejects malformed URI accessLocations");

   const Botan::OID ocsp = Botan::OID::from_string("PKIX.OCSP");
   const Botan::OID ca_issuer = Botan::OID::from_string("PKIX.CertificateAuthorityIssuers");

   // URI::parse rejects strings that don't begin with an ASCII-alpha scheme
   // followed by ':'. "not a uri" fails the first-character ALPHA check.
   const std::string bad_uri = "not a uri";
   const std::vector<uint8_t> bad_bytes(bad_uri.begin(), bad_uri.end());

   using AIA = Botan::Cert_Extension::Authority_Information_Access;
   using AD = AIA::AccessDescription;

   result.test_throws<Botan::Invalid_Argument>("vector<AccessDescription> ctor rejects bad OCSP URI", [&] {
      const AIA aia(std::vector<AD>{{ocsp, Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, bad_bytes}});
   });

   result.test_throws<Botan::Invalid_Argument>("vector<AccessDescription> ctor rejects bad caIssuers URI", [&] {
      const AIA aia(std::vector<AD>{{ca_issuer, Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, bad_bytes}});
   });

   result.test_throws<Botan::Invalid_Argument>("add_access_description rejects bad OCSP URI", [&] {
      AIA aia;
      aia.add_access_description({ocsp, Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, bad_bytes});
   });

   const Botan::OID stir_tn_list({1, 3, 6, 1, 5, 5, 7, 48, 14});
   result.test_throws<Botan::Invalid_Argument>("add_access_description rejects bad URI under non-PKIX OID", [&] {
      AIA aia;
      aia.add_access_description({stir_tn_list, Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, bad_bytes});
   });

   return result;
}

Test::Result test_aia_builder_rejects_invalid_general_name() {
   /*
   * encode_inner rejects an AccessDescription whose accessLocation is not a
   * valid GeneralName. The construction-time entry points (vector ctor and
   * add_access_description) must reject the same inputs so the throw lands
   * where the caller is building the AIA, not mid-cert.
   *
   * Test cases:
   *  - ASN1_Type(9) ContextSpecific: no [9] alternative exists.
   *  - ASN1_Type(0) ContextSpecific primitive: [0] otherName is constructed.
   *  - ASN1_Type(6) ContextSpecific with non-IA5 byte: [6] uniformResourceIdentifier
   *    is IA5String, so bytes > 127 violate the charset.
   *  - ASN1_Type(7) ContextSpecific with five bytes: [7] iPAddress must decode
   *    as an IPv4 or IPv6 address in AlternativeName.
   */
   Test::Result result("AIA builder rejects invalid GeneralName at construction");

   const Botan::OID stir_tn_list({1, 3, 6, 1, 5, 5, 7, 48, 14});  // arbitrary non-PKIX OID

   using AIA = Botan::Cert_Extension::Authority_Information_Access;
   using AD = AIA::AccessDescription;

   const auto ad_from_hex = [&](Botan::ASN1_Type tag, Botan::ASN1_Class cls, std::string_view contents_hex) {
      return AD{stir_tn_list, tag, cls, Botan::hex_decode(contents_hex)};
   };

   constexpr std::string_view any_bytes = "616263";

   result.test_throws<Botan::Invalid_Argument>("vector ctor rejects ASN1_Type(9) ContextSpecific", [&] {
      // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
      const auto tag = Botan::ASN1_Type(9);
      const AIA aia(std::vector<AD>{ad_from_hex(tag, Botan::ASN1_Class::ContextSpecific, any_bytes)});
   });

   result.test_throws<Botan::Invalid_Argument>("add_access_description rejects primitive [0] otherName", [&] {
      AIA aia;
      aia.add_access_description(ad_from_hex(Botan::ASN1_Type(0), Botan::ASN1_Class::ContextSpecific, any_bytes));
   });

   result.test_throws<Botan::Invalid_Argument>(
      "add_access_description rejects non-IA5 [6] URI under non-PKIX OID", [&] {
         AIA aia;
         aia.add_access_description(
            ad_from_hex(Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, "687474703a2f2f8061"));
      });

   result.test_throws<Botan::Invalid_Argument>("add_access_description rejects invalid [7] IP length", [&] {
      AIA aia;
      // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
      const auto ip_tag = Botan::ASN1_Type(7);
      aia.add_access_description(ad_from_hex(ip_tag, Botan::ASN1_Class::ContextSpecific, "0102030405"));
   });

   return result;
}

Test::Result test_aia_rejects_empty_general_name_access_locations() {
   Test::Result result("AIA rejects empty GeneralName accessLocations");

   const Botan::OID stir_tn_list({1, 3, 6, 1, 5, 5, 7, 48, 14});

   using AIA = Botan::Cert_Extension::Authority_Information_Access;
   using AD = AIA::AccessDescription;

   const std::vector<uint8_t> empty;

   const auto reject_builder =
      [&](std::string_view what, Botan::ASN1_Type tag, Botan::ASN1_Class cls, const std::vector<uint8_t>& value) {
         result.test_throws<Botan::Invalid_Argument>(Botan::fmt("{} builder rejects empty accessLocation", what), [&] {
            const AIA aia(std::vector<AD>{{stir_tn_list, tag, cls, value}});
         });
      };

   const auto reject_builder_hex =
      [&](std::string_view what, Botan::ASN1_Type tag, Botan::ASN1_Class cls, std::string_view value_hex) {
         reject_builder(what, tag, cls, Botan::hex_decode(value_hex));
      };

   reject_builder("rfc822Name", Botan::ASN1_Type(1), Botan::ASN1_Class::ContextSpecific, empty);
   reject_builder("dNSName", Botan::ASN1_Type(2), Botan::ASN1_Class::ContextSpecific, empty);
   reject_builder("URI", Botan::ASN1_Type(6), Botan::ASN1_Class::ContextSpecific, empty);
   reject_builder_hex("directoryName", Botan::ASN1_Type(4), Botan::ASN1_Class::ExplicitContextSpecific, "3000");

   const auto reject_decode = [&](std::string_view what, std::string_view bad_aia_extn_value_hex) {
      result.test_is_false(Botan::fmt("{}: AIA does not surface as typed extension", what),
                           extension_surfaces<Botan::Cert_Extension::Authority_Information_Access>(
                              bad_aia_extn_value_hex, Botan::Extension_Context::Certificate));
   };

   reject_decode("empty rfc822Name", "300e300c06082b0601050507300e8100");
   reject_decode("empty dNSName", "300e300c06082b0601050507300e8200");
   reject_decode("empty URI", "300e300c06082b0601050507300e8600");
   reject_decode("empty directoryName", "3010300e06082b0601050507300ea4023000");

   return result;
}

Test::Result test_aia_access_description_must_have_access_location() {
   /*
   * RFC 5280 4.2.2.1:
   *    AccessDescription  ::=  SEQUENCE {
   *         accessMethod          OBJECT IDENTIFIER,
   *         accessLocation        GeneralName  }
   *
   * Both fields are required and accessLocation must be a valid GeneralName.
   * An AccessDescription that omits accessLocation, supplies a non-GeneralName
   * ASN.1 object (e.g. NULL), or supplies malformed GeneralName contents must
   * be rejected at decode. These cases mirror validate_access_description so
   * the wire and programmatic builder agree on what an AccessDescription can
   * carry.
   */
   Test::Result result("AIA decoder rejects AccessDescription with malformed accessLocation");

   const auto reject = [&](const std::string& what, std::string_view bad_aia_extn_value_hex) {
      result.test_is_false(Botan::fmt("{}: AIA does not surface as typed extension", what),
                           extension_surfaces<Botan::Cert_Extension::Authority_Information_Access>(
                              bad_aia_extn_value_hex, Botan::Extension_Context::Certificate));
   };

   // AccessDescription carrying id-ad-ocsp with no accessLocation.
   // ascii2der:
   //   SEQUENCE { SEQUENCE { OBJECT_IDENTIFIER { 1.3.6.1.5.5.7.48.1 } } }
   reject("missing accessLocation", "300c300a06082b06010505073001");

   // AccessDescription carrying id-ad-caIssuers followed by NULL, where a
   // context-specific GeneralName tag is required.
   //
   // ascii2der:
   //   SEQUENCE { SEQUENCE { OBJECT_IDENTIFIER { 1.3.6.1.5.5.7.48.2 } NULL {} } }
   reject("accessLocation is Universal NULL", "300e300c06082b060105050730020500");

   // AccessDescription under a non-PKIX accessMethod (id-ad-stirTNList) with a
   // URI containing non-ASCII byte 0x80.
   //
   // ascii2der:
   //   SEQUENCE { SEQUENCE { OBJECT_IDENTIFIER { 1.3.6.1.5.5.7.48.14 } [6 PRIMITIVE] { `687474703a2f2f80616263646566` } } }
   reject("non-IA5 [6] URI under non-PKIX accessMethod",
          "301c301a06082b0601050507300e860e687474703a2f2f80616263646566");

   // Valid GeneralName tag/class, malformed iPAddress
   // ascii2der:
   //   SEQUENCE { SEQUENCE { OBJECT_IDENTIFIER { 1.3.6.1.5.5.7.48.14 } [7 PRIMITIVE] { `0102030405` } } }
   reject("invalid [7] iPAddress length", "3013301106082b0601050507300e87050102030405");

   return result;
}

Test::Result test_reason_flags_decoder_rejects_malformed_values() {
   Test::Result result("ReasonFlags decoder rejects malformed BIT STRING values");

   using IDP = Botan::Cert_Extension::CRL_Issuing_Distribution_Point;

   const auto reject_idp = [&](const std::string& what, std::string_view bad_idp_value_hex) {
      const auto parsed = decode_extension(IDP::static_oid(), bad_idp_value_hex, Botan::Extension_Context::CRL, true);
      result.test_is_true(what + ": surfaces as unknown-critical", parsed.has_unknown_critical_extension());
      result.test_is_true(what + ": typed IDP is null", parsed.get_extension_object_as<IDP>() == nullptr);
   };

   const auto reject_cdp = [&](const std::string& what, std::string_view reasons_hex) {
      const auto dp_name = Botan::hex_decode("a00da00b8609687474703a2f2f782f");
      const auto reasons = Botan::hex_decode(reasons_hex);
      std::vector<uint8_t> dp;
      Botan::DER_Encoder(dp).start_sequence().raw_bytes(dp_name).raw_bytes(reasons).end_cons();

      std::vector<uint8_t> cdp_extn_value;
      Botan::DER_Encoder(cdp_extn_value).start_sequence().raw_bytes(dp).end_cons();
      result.test_is_false(what + ": typed CDP is null", cdp_decodes_cleanly(cdp_extn_value));
   };

   result.test_throws<Botan::Decoding_Error>("ReasonFlags constructor rejects unused bit only",
                                             [] { (void)Botan::ReasonFlags(static_cast<uint16_t>(0x0100)); });
   result.test_throws<Botan::Decoding_Error>("ReasonFlags constructor rejects undefined bit with reason",
                                             [] { (void)Botan::ReasonFlags(static_cast<uint16_t>(0x0180)); });

   reject_idp("non-minimal valid reason", "300483020040");
   reject_cdp("non-minimal valid reason", "81020040");

   // Reason bits beyond bit 8 set
   //
   // ascii2der:
   //   SEQUENCE { [3 PRIMITIVE] { `008001` } }
   reject_idp("extra bits", "30058303008001");

   // Reason bits of zero
   //
   // ascii2der:
   //   SEQUENCE { [1 PRIMITIVE] { `ff` } [3 PRIMITIVE] { `0000` } }
   reject_idp("all-zero", "30078101ff83020000");

   // Reason with just the "unused" bit 0 set:
   //
   // ascii2der:
   //   SEQUENCE { [1 PRIMITIVE] { `ff` } [3 PRIMITIVE] { `0780` } }
   reject_idp("unused bit only", "30078101ff83020780");
   reject_cdp("unused bit only", "81020780");

   return result;
}

class X509_CDP_AIA_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(test_idp_only_user_certs());
         results.push_back(test_idp_only_ca_certs());
         results.push_back(test_idp_some_reasons());
         results.push_back(test_idp_indirect());
         results.push_back(test_idp_full());
         results.push_back(test_cdp_multi_uri_fullname());
         results.push_back(test_cdp_constructor_populates_cached_uris());
         results.push_back(test_cdp_crl_issuer_only());
         results.push_back(test_indirect_crl_requires_idp_indirect_crl_flag());
         results.push_back(test_same_issuer_crl_matches_via_implicit_dp_fallback());
         results.push_back(test_self_scoped_crl_not_rescued_by_implicit_dp());
         results.push_back(test_direct_crl_requires_matching_issuer());
         results.push_back(test_relative_name_decode_rejected());
         results.push_back(test_idp_empty_encode_rejected());
         results.push_back(test_idp_mutex_scope_booleans_encode_rejected());
         results.push_back(test_empty_general_names_in_fullname_rejected());
         results.push_back(test_empty_directory_name_in_fullname_decode_rejected());
         results.push_back(test_reason_flags_decoder_rejects_malformed_values());
         results.push_back(test_aia_access_description_must_have_access_location());
         results.push_back(test_aia_writable_via_access_descriptions());
         results.push_back(test_aia_uri_constructor_then_add_access_description_keeps_all());
         results.push_back(test_aia_builder_rejects_malformed_uri_access_locations());
         results.push_back(test_aia_builder_rejects_invalid_general_name());
         results.push_back(test_aia_rejects_empty_general_name_access_locations());
         results.push_back(test_distribution_point_rejects_out_of_order_fields());
         results.push_back(test_crl_issuer_must_be_single_directory_name_encode());
         results.push_back(test_crl_issuer_must_be_single_directory_name_decode());
         results.push_back(test_aia_stir_tn_list());
         results.push_back(test_aia_ocsp_directoryname());
         results.push_back(test_idp_user_certs_does_not_falsely_revoke());
         results.push_back(test_revoked_by_reason_limited_crl_does_not_emit_no_revocation_data());
         for(auto& r : strict_revocation_regressions()) {
            results.push_back(std::move(r));
         }
         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_cdp_aia", X509_CDP_AIA_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests

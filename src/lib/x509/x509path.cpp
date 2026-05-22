/*
* X.509 Certificate Path Validation
* (C) 2010,2011,2012,2014,2016,2026 Jack Lloyd
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509path.h>

#include <botan/assert.h>
#include <botan/ocsp.h>
#include <botan/pk_keys.h>
#include <botan/x509_ext.h>
#include <botan/internal/concat_util.h>
#include <algorithm>
#include <chrono>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)
   #include <botan/uri.h>
   #include <botan/internal/http_util.h>
   #include <future>
#endif

namespace Botan {

namespace {

/*
* RFC 9608 Section 4:
*
*   Section 6.1.3 of [RFC5280] describes basic certificate processing
*   within the certification path validation procedures.  In particular,
*   Step (a)(3) says:
*
*   |  At the current time, the certificate is not revoked.  This may be
*   |  determined by obtaining the appropriate CRL (Section 6.3), by
*   |  status information, or by out-of-band mechanisms.
*
*   If the noRevAvail certificate extension specified in this document is
*   present or the ocsp-nocheck certificate extension [RFC6960] is
*   present, then Step (a)(3) is skipped.  Otherwise, revocation status
*   determination of the certificate is performed.
*/
bool skip_revocation_check(const X509_Certificate& cert) {
   const Extensions& exts = cert.v3_extensions();
   return exts.extension_set(Cert_Extension::NoRevocationAvailable::static_oid()) ||
          exts.extension_set(Cert_Extension::OCSP_NoCheck::static_oid());
}

}  // namespace

namespace {

/**
 * Lazy DFS iterator that yields certificate paths one at a time.
 *
 * Build all possible certificate paths from the end certificate to self-signed trusted roots.
 *
 * Basically, a DFS is performed starting from the end certificate. A stack (vector)
 * serves to control the DFS. At the beginning of each iteration, a pair is popped from
 * the stack that contains (1) the next certificate to add to the path (2) a bool that
 * indicates if the certificate is part of a trusted certstore. Ideally, we follow the
 * unique issuer of the current certificate until a trusted root is reached. However, the
 * issuer DN + authority key id need not be unique among the certificates used for
 * building the path. In such a case, we consider all the matching issuers by pushing
 * <IssuerCert, trusted?> on the stack for each of them.
 *
 * Each call to next() resumes the search and returns the next discovered path, or nullopt
 * when the search space is exhausted.
*/
class CertificatePathBuilder final {
   public:
      CertificatePathBuilder(const std::vector<Certificate_Store*>& trusted_certstores,
                             const X509_Certificate& end_entity,
                             const std::vector<X509_Certificate>& end_entity_extra,
                             bool require_self_signed = false) :
            m_trusted_certstores(trusted_certstores), m_require_self_signed(require_self_signed) {
         if(std::ranges::any_of(trusted_certstores, [](auto* ptr) { return ptr == nullptr; })) {
            throw Invalid_Argument("Certificate store list must not contain nullptr");
         }

         for(const auto& cert : end_entity_extra) {
            if(!cert_in_any_trusted_store(cert)) {
               m_ee_extras.add_certificate(cert);
            }
         }

         m_stack.push_back({end_entity, cert_in_any_trusted_store(end_entity)});
      }

      std::optional<std::vector<X509_Certificate>> next() {
         size_t steps = 0;

         while(!m_stack.empty()) {
            constexpr size_t MAX_DFS_STEPS = 1000;

            steps++;

            if(steps > MAX_DFS_STEPS) {
               // Intentionally overwrite any previous builder error
               m_error = Certificate_Status_Code::CERT_ISSUER_NOT_FOUND;
               return std::nullopt;
            }

            auto [last, trusted] = std::move(m_stack.back());  // move before pop_back
            m_stack.pop_back();

            // Found a deletion marker that guides the DFS, backtracking
            if(!last.has_value()) {
               m_certs_seen.erase(m_path_so_far.back().tag());
               m_path_so_far.pop_back();
               continue;
            }

            // Certificate already seen in this path?
            const auto tag = last->tag();
            if(m_certs_seen.contains(tag)) {
               if(!m_error.has_value()) {
                  m_error = Certificate_Status_Code::CERT_CHAIN_LOOP;
               }
               continue;
            }

            // A valid path has been discovered. It includes endpoints that may end
            // with either a self-signed or a non-self-signed certificate. For
            // certificates that are not self-signed, additional paths could
            // potentially extend from the current one.
            if(trusted) {
               auto path = m_path_so_far;
               path.push_back(*last);
               push_issuers(*last);

               if(!m_require_self_signed || last->is_self_signed()) {
                  return path;
               }

               /*
               This unconditionally overwrites the error because it's likely the most
               informative error in this context - we found a path that seemed entirely
               suitable, except that self-signed roots are required so it was skipped.
               */
               m_error = Certificate_Status_Code::CANNOT_ESTABLISH_TRUST;
               continue;
            }

            if(last->is_self_signed()) {
               if(!m_error.has_value()) {
                  m_error = Certificate_Status_Code::CANNOT_ESTABLISH_TRUST;
               }
               continue;
            }

            push_issuers(*last);
         }

         return std::nullopt;
      }

      /**
      * Return the first error encountered during path building
      *
      * Only used as a last resort if there were no successful paths
      */
      Certificate_Status_Code error() const {
         if(m_error.has_value()) {
            // Confirm it is an actual error code and not accidentally OK...
            BOTAN_ASSERT_NOMSG(static_cast<uint32_t>(m_error.value()) >= 3000);
            return m_error.value();
         } else {
            return Certificate_Status_Code::CERT_ISSUER_NOT_FOUND;
         }
      }

   private:
      bool cert_in_any_trusted_store(const X509_Certificate& cert) const {
         return std::ranges::any_of(m_trusted_certstores,
                                    [&](const Certificate_Store* store) { return store->contains(cert); });
      }

      void push_issuers(const X509_Certificate& cert) {
         const X509_DN& issuer_dn = cert.issuer_dn();
         const std::vector<uint8_t>& auth_key_id = cert.authority_key_id();

         // Search for trusted issuers
         std::vector<X509_Certificate> trusted_issuers;
         for(const Certificate_Store* store : m_trusted_certstores) {
            auto new_issuers = store->find_all_certs(issuer_dn, auth_key_id);
            trusted_issuers.insert(trusted_issuers.end(), new_issuers.begin(), new_issuers.end());
         }

         // Search the supplemental certs
         const std::vector<X509_Certificate> misc_issuers = m_ee_extras.find_all_certs(issuer_dn, auth_key_id);

         // If we could not find any issuers, the current path ends here
         if(trusted_issuers.empty() && misc_issuers.empty()) {
            if(!m_error.has_value()) {
               m_error = Certificate_Status_Code::CERT_ISSUER_NOT_FOUND;
            }
            return;
         }

         m_path_so_far.push_back(cert);
         m_certs_seen.emplace(cert.tag());

         // Push a deletion marker on the stack for backtracking later
         m_stack.push_back({std::nullopt, false});

         for(const auto& trusted_cert : trusted_issuers) {
            m_stack.push_back({trusted_cert, true});
         }
         for(const auto& misc : misc_issuers) {
            m_stack.push_back({misc, false});
         }
      }

      const std::vector<Certificate_Store*> m_trusted_certstores;
      const bool m_require_self_signed;
      Certificate_Store_In_Memory m_ee_extras;
      std::vector<std::pair<std::optional<X509_Certificate>, bool>> m_stack;
      std::vector<X509_Certificate> m_path_so_far;
      std::unordered_set<X509_Certificate::Tag, X509_Certificate::TagHash> m_certs_seen;
      std::optional<Certificate_Status_Code> m_error;
};

}  // namespace

/*
* PKIX path validation
*/
CertificatePathStatusCodes PKIX::check_chain(const std::vector<X509_Certificate>& cert_path,
                                             std::chrono::system_clock::time_point ref_time,
                                             std::string_view hostname,
                                             Usage_Type usage,
                                             const Path_Validation_Restrictions& restrictions) {
   if(cert_path.empty()) {
      throw Invalid_Argument("PKIX::check_chain cert_path empty");
   }

   const bool is_end_entity_trust_anchor = (cert_path.size() == 1);

   const X509_Time validation_time(ref_time);

   CertificatePathStatusCodes cert_status(cert_path.size());

   // Before anything else verify the entire chain of signatures
   for(size_t i = 0; i != cert_path.size(); ++i) {
      std::set<Certificate_Status_Code>& status = cert_status.at(i);

      const bool at_trust_anchor = (i == cert_path.size() - 1);

      const X509_Certificate& subject = cert_path[i];

      // If using intermediate CAs as trust anchors, the signature of the trust
      // anchor cannot be verified since the issuer is not part of the
      // certificate chain
      if(!restrictions.require_self_signed_trust_anchors() && at_trust_anchor && !subject.is_self_signed()) {
         continue;
      }

      const X509_Certificate& issuer = cert_path[at_trust_anchor ? (i) : (i + 1)];

      // Check the signature algorithm is known
      if(!subject.signature_algorithm().oid().registered_oid()) {
         status.insert(Certificate_Status_Code::SIGNATURE_ALGO_UNKNOWN);
      } else {
         std::unique_ptr<Public_Key> issuer_key;
         try {
            issuer_key = issuer.subject_public_key();
         } catch(...) {
            status.insert(Certificate_Status_Code::CERT_PUBKEY_INVALID);
         }

         if(issuer_key) {
            if(issuer_key->estimated_strength() < restrictions.minimum_key_strength()) {
               status.insert(Certificate_Status_Code::SIGNATURE_METHOD_TOO_WEAK);
            }

            const auto sig_status = subject.verify_signature(*issuer_key);

            if(sig_status.first != Certificate_Status_Code::VERIFIED) {
               status.insert(sig_status.first);
            } else {
               // Signature is valid, check if hash used was acceptable
               const std::string hash_used_for_signature = sig_status.second;
               BOTAN_ASSERT_NOMSG(!hash_used_for_signature.empty());
               const auto& trusted_hashes = restrictions.trusted_hashes();

               // Ignore untrusted hashes on self-signed roots
               if(!trusted_hashes.empty() && !at_trust_anchor) {
                  if(!trusted_hashes.contains(hash_used_for_signature)) {
                     status.insert(Certificate_Status_Code::UNTRUSTED_HASH);
                  }
               }
            }
         }
      }
   }

   // If any of the signatures were invalid, return immediately; we know the
   // chain is invalid and signature failure is always considered the most
   // critical result. This does mean other problems in the certificate (eg
   // expired) will not be reported, but we'd have to assume any such data is
   // anyway arbitrary considering we couldn't verify the signature chain

   for(size_t i = 0; i != cert_path.size(); ++i) {
      for(auto status : cert_status.at(i)) {
         // This ignores errors relating to the key or hash being weak since
         // these are somewhat advisory
         if(static_cast<uint32_t>(status) >= 5000) {
            return cert_status;
         }
      }
   }

   if(!hostname.empty() && !cert_path[0].matches_dns_name(hostname)) {
      cert_status[0].insert(Certificate_Status_Code::CERT_NAME_NOMATCH);
   }

   if(!cert_path[0].allowed_usage(usage)) {
      if(usage == Usage_Type::OCSP_RESPONDER) {
         cert_status[0].insert(Certificate_Status_Code::OCSP_RESPONSE_MISSING_KEYUSAGE);
      }
      cert_status[0].insert(Certificate_Status_Code::INVALID_USAGE);
   }

   if(cert_path[0].has_constraints(Key_Constraints::KeyCertSign) && cert_path[0].is_CA_cert() == false) {
      /*
      "If the keyCertSign bit is asserted, then the cA bit in the
      basic constraints extension (Section 4.2.1.9) MUST also be
      asserted." - RFC 5280

      We don't bother doing this check on the rest of the path since they
      must have the cA bit asserted or the validation will fail anyway.
      */
      cert_status[0].insert(Certificate_Status_Code::INVALID_USAGE);
   }

   for(size_t i = 0; i != cert_path.size(); ++i) {
      std::set<Certificate_Status_Code>& status = cert_status.at(i);

      const bool at_trust_anchor = (i == cert_path.size() - 1);

      const X509_Certificate& subject = cert_path[i];
      const auto issuer = [&]() -> std::optional<X509_Certificate> {
         if(!at_trust_anchor) {
            return cert_path[i + 1];
         } else if(subject.is_self_signed()) {
            return cert_path[i];
         } else {
            return {};  // Non self-signed trust anchors have no checkable issuers.
         }
      }();

      if(restrictions.require_self_signed_trust_anchors() && !issuer.has_value()) {
         status.insert(Certificate_Status_Code::CHAIN_LACKS_TRUST_ROOT);
      }

      // This should never happen; it indicates a bug in path building
      if(issuer.has_value() && subject.issuer_dn() != issuer->subject_dn()) {
         status.insert(Certificate_Status_Code::CHAIN_NAME_MISMATCH);
      }

      // Check the serial number
      if(subject.is_serial_negative()) {
         status.insert(Certificate_Status_Code::CERT_SERIAL_NEGATIVE);
      }

      // Check the subject's DN components' length

      for(const auto& rdn : subject.subject_dn().rdns()) {
         for(const auto& ava : rdn) {
            const size_t dn_ub = X509_DN::lookup_ub(ava.first);
            if(dn_ub > 0 && ava.second.size() > dn_ub) {
               status.insert(Certificate_Status_Code::DN_TOO_LONG);
            }
         }
      }

      // If so configured, allow trust anchors outside the validity period with
      // a warning rather than a hard error
      const bool enforce_validity_period = !at_trust_anchor || !restrictions.ignore_trusted_root_time_range();
      // Check all certs for valid time range
      if(validation_time < subject.not_before()) {
         if(enforce_validity_period) {
            status.insert(Certificate_Status_Code::CERT_NOT_YET_VALID);
         } else {
            status.insert(Certificate_Status_Code::TRUSTED_CERT_NOT_YET_VALID);  // only warn
         }
      }

      if(validation_time > subject.not_after()) {
         if(enforce_validity_period) {
            status.insert(Certificate_Status_Code::CERT_HAS_EXPIRED);
         } else {
            status.insert(Certificate_Status_Code::TRUSTED_CERT_HAS_EXPIRED);  // only warn
         }
      }

      // Check issuer constraints
      if(issuer.has_value() && !issuer->is_CA_cert() && !is_end_entity_trust_anchor) {
         status.insert(Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER);
      }

      // Check cert extensions

      if(subject.x509_version() == 1) {
         if(subject.v2_issuer_key_id().empty() == false || subject.v2_subject_key_id().empty() == false) {
            status.insert(Certificate_Status_Code::V2_IDENTIFIERS_IN_V1_CERT);
         }
      }

      const Extensions& extensions = subject.v3_extensions();
      const auto& extensions_vec = extensions.extensions();
      if(subject.x509_version() < 3 && !extensions_vec.empty()) {
         status.insert(Certificate_Status_Code::EXT_IN_V1_V2_CERT);
      }

      for(const auto& extension : extensions_vec) {
         extension.first->validate(subject, issuer, cert_path, cert_status, i);
      }

      if(extensions_vec.size() != extensions.get_extension_oids().size()) {
         status.insert(Certificate_Status_Code::DUPLICATE_CERT_EXTENSION);
      }
   }

   // path len check
   size_t max_path_length = cert_path.size();
   for(size_t i = cert_path.size() - 1; i > 0; --i) {
      std::set<Certificate_Status_Code>& status = cert_status.at(i);
      const X509_Certificate& subject = cert_path[i];

      /*
      * If the certificate was not self-issued, verify that max_path_length is
      * greater than zero and decrement max_path_length by 1.
      */
      if(subject.subject_dn() != subject.issuer_dn()) {
         if(max_path_length > 0) {
            max_path_length -= 1;
         } else {
            status.insert(Certificate_Status_Code::CERT_CHAIN_TOO_LONG);
         }
      }

      /*
      * If pathLenConstraint is present in the certificate and is less than max_path_length,
      * set max_path_length to the value of pathLenConstraint.
      */
      if(auto path_len_constraint = subject.path_length_constraint()) {
         max_path_length = std::min(max_path_length, *path_len_constraint);
      }
   }

   return cert_status;
}

namespace {

Certificate_Status_Code verify_ocsp_signing_cert(const X509_Certificate& signing_cert,
                                                 const X509_Certificate& ca,
                                                 const std::vector<X509_Certificate>& extra_certs,
                                                 const std::vector<Certificate_Store*>& certstores,
                                                 std::chrono::system_clock::time_point ref_time,
                                                 const Path_Validation_Restrictions& restrictions) {
   // RFC 6960 4.2.2.2
   //    [Applications] MUST reject the response if the certificate
   //    required to validate the signature on the response does not
   //    meet at least one of the following criteria:
   //
   //    1. Matches a local configuration of OCSP signing authority
   //       for the certificate in question, or
   if(restrictions.trusted_ocsp_responders() != nullptr &&
      restrictions.trusted_ocsp_responders()->contains(signing_cert)) {
      return Certificate_Status_Code::OK;
   }

   // RFC 6960 4.2.2.2
   //
   //    2. Is the certificate of the CA that issued the certificate
   //       in question, or
   if(signing_cert == ca) {
      return Certificate_Status_Code::OK;
   }

   // RFC 6960 4.2.2.2
   //
   //    3. Includes a value of id-kp-OCSPSigning in an extended key
   //       usage extension and is issued by the CA that issued the
   //       certificate in question as stated above.

   // Verify the delegated responder was issued by the CA that issued
   // the certificate in question (the EKU and signature chain are
   // verified by the path validation below).
   //
   // RFC 6960 4.2.2.2 again
   //
   //    Systems relying on OCSP responses MUST recognize a delegation
   //    certificate as being issued by the CA that issued the
   //    certificate in question only if the delegation certificate
   //    and the certificate being checked for revocation were signed
   //    by the same key.
   if(signing_cert.issuer_dn() != ca.subject_dn()) {
      return Certificate_Status_Code::OCSP_ISSUER_NOT_TRUSTED;
   } else {
      // If both key identifiers are available, verify they match to
      // handle CAs that share a subject DN but have different keys
      // (eg re-keyed or cross-certified CAs).
      const auto& aki = signing_cert.authority_key_id();
      const auto& ski = ca.subject_key_id();
      if(!aki.empty() && !ski.empty() && aki != ski) {
         return Certificate_Status_Code::OCSP_ISSUER_NOT_TRUSTED;
      }
   }

   try {
      const auto ca_pub_key = ca.subject_public_key();
      if(!ca_pub_key || !signing_cert.check_signature(*ca_pub_key)) {
         return Certificate_Status_Code::OCSP_ISSUER_NOT_TRUSTED;
      }
   } catch(...) {
      return Certificate_Status_Code::OCSP_ISSUER_NOT_TRUSTED;
   }

   // TODO: Implement OCSP revocation check of OCSP signer certificate
   // Note: This needs special care to prevent endless loops on specifically
   //       forged chains of OCSP responses referring to each other.
   //
   // RFC 6960 4.2.2.2.1 seems to imply that generally OCSP checking of OCSP
   // signers is not realistic; it suggests either using the nocheck extension,
   // "using CRL Distribution Points if the check should be done using CRLs",
   // or just punts with
   //    A CA may choose not to specify any method of revocation checking
   //    for the responder's certificate, in which case it would be up to
   //    the OCSP client's local security policy to decide whether that
   //    certificate should be checked for revocation or not.
   //
   // Currently, we're disabling OCSP-based revocation checks by setting the
   // timeout to 0. Additionally, the library's API would not allow an
   // application to pass in the required "second order" OCSP responses. I.e.
   // "second order" OCSP checks would need to rely on `check_ocsp_online()`
   // which is not an option for some applications (e.g. that require a proxy
   // for external HTTP requests).
   const auto ocsp_timeout = std::chrono::milliseconds::zero();
   const auto relaxed_restrictions =
      Path_Validation_Restrictions(false /* do not enforce revocation data */,
                                   restrictions.minimum_key_strength(),
                                   false /* OCSP is not available, so don't try for intermediates */,
                                   restrictions.trusted_hashes());

   const auto validation_result = x509_path_validate(concat(std::vector{signing_cert}, extra_certs),
                                                     relaxed_restrictions,
                                                     certstores,
                                                     {} /* hostname */,
                                                     Botan::Usage_Type::OCSP_RESPONDER,
                                                     ref_time,
                                                     ocsp_timeout);

   return validation_result.result();
}

std::set<Certificate_Status_Code> evaluate_ocsp_response(const OCSP::Response& ocsp_response,
                                                         const X509_Certificate& subject,
                                                         const X509_Certificate& ca,
                                                         const std::vector<X509_Certificate>& cert_path,
                                                         const std::vector<Certificate_Store*>& certstores,
                                                         std::chrono::system_clock::time_point ref_time,
                                                         const Path_Validation_Restrictions& restrictions) {
   // Handle softfail conditions (eg. OCSP unavailable)
   if(auto dummy_status = ocsp_response.dummy_status()) {
      return {dummy_status.value()};
   }

   // Find the certificate that signed this OCSP response
   auto signing_cert = ocsp_response.find_signing_certificate(ca, restrictions.trusted_ocsp_responders());
   if(!signing_cert) {
      return {Certificate_Status_Code::OCSP_ISSUER_NOT_FOUND};
   }

   // Verify the signing certificate is trusted
   auto cert_status = verify_ocsp_signing_cert(
      signing_cert.value(), ca, concat(ocsp_response.certificates(), cert_path), certstores, ref_time, restrictions);
   if(cert_status >= Certificate_Status_Code::FIRST_ERROR_STATUS) {
      return {cert_status, Certificate_Status_Code::OCSP_ISSUER_NOT_TRUSTED};
   }

   // Verify the cryptographic signature on the OCSP response
   auto sig_status = ocsp_response.verify_signature(signing_cert.value(), restrictions);
   if(sig_status != Certificate_Status_Code::OCSP_SIGNATURE_OK) {
      return {sig_status};
   }

   // All checks passed, return the certificate's revocation status
   return {ocsp_response.status_for(ca, subject, ref_time, restrictions.max_ocsp_age())};
}

}  // namespace

CertificatePathStatusCodes PKIX::check_ocsp(const std::vector<X509_Certificate>& cert_path,
                                            const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
                                            const std::vector<Certificate_Store*>& certstores,
                                            std::chrono::system_clock::time_point ref_time,
                                            const Path_Validation_Restrictions& restrictions) {
   if(cert_path.empty()) {
      throw Invalid_Argument("PKIX::check_ocsp cert_path empty");
   }

   CertificatePathStatusCodes cert_status(cert_path.size() - 1);

   for(size_t i = 0; i != cert_path.size() - 1; ++i) {
      const X509_Certificate& subject = cert_path.at(i);
      const X509_Certificate& ca = cert_path.at(i + 1);

      if(skip_revocation_check(subject)) {
         continue;
      }

      if(i < ocsp_responses.size() && ocsp_responses.at(i).has_value() &&
         ocsp_responses.at(i)->status() == OCSP::Response_Status_Code::Successful) {
         try {
            cert_status.at(i) = evaluate_ocsp_response(
               ocsp_responses.at(i).value(), subject, ca, cert_path, certstores, ref_time, restrictions);
         } catch(Exception&) {
            cert_status.at(i).insert(Certificate_Status_Code::OCSP_RESPONSE_INVALID);
         }
      }
   }

   return cert_status;
}

CertificatePathStatusCodes PKIX::check_crl(const std::vector<X509_Certificate>& cert_path,
                                           const std::vector<std::optional<X509_CRL>>& crls,
                                           std::chrono::system_clock::time_point ref_time) {
   if(cert_path.empty()) {
      throw Invalid_Argument("PKIX::check_crl cert_path empty");
   }

   CertificatePathStatusCodes cert_status(cert_path.size());
   const X509_Time validation_time(ref_time);

   for(size_t i = 0; i != cert_path.size() - 1; ++i) {
      std::set<Certificate_Status_Code>& status = cert_status.at(i);

      if(skip_revocation_check(cert_path.at(i))) {
         continue;
      }

      if(i < crls.size() && crls[i].has_value()) {
         const X509_Certificate& subject = cert_path.at(i);
         const X509_Certificate& ca = cert_path.at(i + 1);

         if(!ca.allowed_usage(Key_Constraints::CrlSign)) {
            status.insert(Certificate_Status_Code::CA_CERT_NOT_FOR_CRL_ISSUER);
         }

         if(validation_time < crls[i]->this_update()) {
            status.insert(Certificate_Status_Code::CRL_NOT_YET_VALID);
         }

         if(crls[i]->next_update().time_is_set() && validation_time > crls[i]->next_update()) {
            status.insert(Certificate_Status_Code::CRL_HAS_EXPIRED);
         }

         auto ca_key = ca.subject_public_key();
         if(crls[i]->check_signature(*ca_key) == false) {
            status.insert(Certificate_Status_Code::CRL_BAD_SIGNATURE);
         } else {
            /*
            RFC 5280 5.2 "If a CRL contains a critical extension that the
            application cannot process, then the application MUST NOT use that
            CRL to determine the status of certificates."

            RFC 5280 5.3 "If a CRL contains a critical CRL entry extension that
            the application cannot process, then the application MUST NOT use
            that CRL to determine the status of any certificates."
            */
            const bool crl_is_not_usable = crls[i]->has_unknown_critical_extension();

            if(crl_is_not_usable) {
               status.insert(Certificate_Status_Code::CRL_HAS_UNKNOWN_CRITICAL_EXTENSION);
            } else {
               status.insert(Certificate_Status_Code::VALID_CRL_CHECKED);

               if(crls[i]->is_revoked(subject)) {
                  status.insert(Certificate_Status_Code::CERT_IS_REVOKED);
               }

               if(!crls[i]->has_matching_distribution_point(subject)) {
                  status.insert(Certificate_Status_Code::NO_MATCHING_CRLDP);
               }
            }
         }
      }
   }

   while(!cert_status.empty() && cert_status.back().empty()) {
      cert_status.pop_back();
   }

   return cert_status;
}

CertificatePathStatusCodes PKIX::check_crl(const std::vector<X509_Certificate>& cert_path,
                                           const std::vector<Certificate_Store*>& certstores,
                                           std::chrono::system_clock::time_point ref_time) {
   if(cert_path.empty()) {
      throw Invalid_Argument("PKIX::check_crl cert_path empty");
   }

   if(certstores.empty()) {
      throw Invalid_Argument("PKIX::check_crl certstores empty");
   }

   std::vector<std::optional<X509_CRL>> crls(cert_path.size());

   for(size_t i = 0; i != cert_path.size(); ++i) {
      if(skip_revocation_check(cert_path[i])) {
         continue;
      }
      for(auto* certstore : certstores) {
         crls[i] = certstore->find_crl_for(cert_path[i]);
         if(crls[i]) {
            break;
         }
      }
   }

   return PKIX::check_crl(cert_path, crls, ref_time);
}

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)

CertificatePathStatusCodes PKIX::check_ocsp_online(const std::vector<X509_Certificate>& cert_path,
                                                   const std::vector<Certificate_Store*>& trusted_certstores,
                                                   std::chrono::system_clock::time_point ref_time,
                                                   std::chrono::milliseconds timeout,
                                                   const Path_Validation_Restrictions& restrictions) {
   if(cert_path.empty()) {
      throw Invalid_Argument("PKIX::check_ocsp_online cert_path empty");
   }

   std::vector<std::future<std::optional<OCSP::Response>>> ocsp_response_futures;

   size_t to_ocsp = 1;

   if(restrictions.ocsp_all_intermediates()) {
      to_ocsp = cert_path.size() - 1;
   }
   if(cert_path.size() == 1) {
      to_ocsp = 0;
   }

   for(size_t i = 0; i < to_ocsp; ++i) {
      const auto& subject = cert_path.at(i);
      const auto& issuer = cert_path.at(i + 1);

      if(skip_revocation_check(subject)) {
         ocsp_response_futures.emplace_back(
            std::async(std::launch::deferred, []() -> std::optional<OCSP::Response> { return std::nullopt; }));
      } else {
         const auto ocsp_urls = URI::filter_scheme("http", subject.ocsp_responder_uris());

         if(ocsp_urls.empty()) {
            ocsp_response_futures.emplace_back(std::async(std::launch::deferred, []() -> std::optional<OCSP::Response> {
               return OCSP::Response(Certificate_Status_Code::OCSP_NO_REVOCATION_URL);
            }));
         } else {
            auto ocsp_req = OCSP::Request(issuer, BigInt::from_bytes(subject.serial_number()));
            ocsp_response_futures.emplace_back(
               std::async(std::launch::async, [ocsp_urls, ocsp_req, timeout]() -> std::optional<OCSP::Response> {
                  HTTP::Response http;
                  try {
                     http = HTTP::POST_sync(ocsp_urls[0],
                                            "application/ocsp-request",
                                            ocsp_req.BER_encode(),
                                            HTTP::RequestLimits().set_timeout(timeout).set_max_body_size(64 * 1024));

                     if(http.status_code() != 200) {
                        return OCSP::Response(Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE);
                     }

                     return OCSP::Response(http.body());
                  } catch(std::exception&) {
                     return OCSP::Response(Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE);
                  }
               }));
         }
      }
   }

   std::vector<std::optional<OCSP::Response>> ocsp_responses;
   ocsp_responses.reserve(ocsp_response_futures.size());

   for(auto& ocsp_response_future : ocsp_response_futures) {
      ocsp_responses.push_back(ocsp_response_future.get());
   }

   return PKIX::check_ocsp(cert_path, ocsp_responses, trusted_certstores, ref_time, restrictions);
}

CertificatePathStatusCodes PKIX::check_crl_online(const std::vector<X509_Certificate>& cert_path,
                                                  const std::vector<Certificate_Store*>& certstores,
                                                  Certificate_Store_In_Memory* crl_store,
                                                  std::chrono::system_clock::time_point ref_time,
                                                  std::chrono::milliseconds timeout) {
   if(cert_path.empty()) {
      throw Invalid_Argument("PKIX::check_crl_online cert_path empty");
   }
   if(certstores.empty()) {
      throw Invalid_Argument("PKIX::check_crl_online certstores empty");
   }

   std::vector<std::future<std::optional<X509_CRL>>> future_crls;
   std::vector<std::optional<X509_CRL>> crls(cert_path.size());

   for(size_t i = 0; i != cert_path.size(); ++i) {
      const auto& cert = cert_path.at(i);

      if(skip_revocation_check(cert)) {
         future_crls.emplace_back(
            std::async(std::launch::deferred, []() -> std::optional<X509_CRL> { return std::nullopt; }));
         continue;
      }

      for(auto* certstore : certstores) {
         crls[i] = certstore->find_crl_for(cert);
         if(crls[i].has_value()) {
            break;
         }
      }

      // TODO: check if CRL is expired and re-request?

      // Only request if we don't already have a CRL
      if(crls[i]) {
         /*
         We already have a CRL, so just insert this empty one to hold a place in the vector
         so that indexes match up
         */
         future_crls.emplace_back(std::future<std::optional<X509_CRL>>());
      } else {
         const auto cdp_uris = URI::filter_scheme("http", cert.crl_distribution_point_uris());

         if(cdp_uris.empty()) {
            future_crls.emplace_back(std::async(std::launch::deferred, []() -> std::optional<X509_CRL> {
               throw Not_Implemented("No CRL distribution point for this certificate");
            }));
         } else {
            future_crls.emplace_back(std::async(std::launch::async, [cdp_uris, timeout]() -> std::optional<X509_CRL> {
               auto http = HTTP::GET_sync(
                  cdp_uris[0], HTTP::RequestLimits().set_timeout(timeout).set_max_body_size(32 * 1024 * 1024));

               http.throw_unless_ok();
               // check the mime type?
               return X509_CRL(http.body());
            }));
         }
      }
   }

   for(size_t i = 0; i != future_crls.size(); ++i) {
      if(future_crls[i].valid()) {
         try {
            crls[i] = future_crls[i].get();
         } catch(std::exception&) {
            // crls[i] left null
            // todo: log exception e.what() ?
         }
      }
   }

   auto crl_status = PKIX::check_crl(cert_path, crls, ref_time);

   if(crl_store != nullptr) {
      for(size_t i = 0; i != crl_status.size(); ++i) {
         if(crl_status[i].contains(Certificate_Status_Code::VALID_CRL_CHECKED)) {
            // better be non-null, we supposedly validated it
            BOTAN_ASSERT_NOMSG(crls[i].has_value());
            crl_store->add_crl(*crls[i]);
         }
      }
   }

   return crl_status;
}

#endif

Certificate_Status_Code PKIX::build_certificate_path(std::vector<X509_Certificate>& cert_path,
                                                     const std::vector<Certificate_Store*>& trusted_certstores,
                                                     const X509_Certificate& end_entity,
                                                     const std::vector<X509_Certificate>& end_entity_extra) {
   CertificatePathBuilder builder(trusted_certstores, end_entity, end_entity_extra);

   std::vector<X509_Certificate> first_path;

   while(auto path = builder.next()) {
      BOTAN_ASSERT_NOMSG(path->empty() == false);

      // Prefer paths ending in self-signed certificates.
      if(path->back().is_self_signed()) {
         cert_path.insert(cert_path.end(), path->begin(), path->end());
         return Certificate_Status_Code::OK;
      }

      // Save the first path for later just in case we find nothing better
      if(first_path.empty()) {
         first_path = std::move(*path);
      }
   }

   if(!first_path.empty()) {
      // We found a path, it's not self-signed but it's as good as can be formed...
      cert_path.insert(cert_path.end(), first_path.begin(), first_path.end());
      return Certificate_Status_Code::OK;
   }

   // Failed to build any path at all
   return builder.error();
}

Certificate_Status_Code PKIX::build_all_certificate_paths(std::vector<std::vector<X509_Certificate>>& cert_paths_out,
                                                          const std::vector<Certificate_Store*>& trusted_certstores,
                                                          const X509_Certificate& end_entity,
                                                          const std::vector<X509_Certificate>& end_entity_extra) {
   if(!cert_paths_out.empty()) {
      throw Invalid_Argument("PKIX::build_all_certificate_paths: cert_paths_out must be empty");
   }
   CertificatePathBuilder builder(trusted_certstores, end_entity, end_entity_extra);

   while(auto path = builder.next()) {
      BOTAN_ASSERT_NOMSG(path->empty() == false);
      cert_paths_out.push_back(std::move(*path));
   }

   if(!cert_paths_out.empty()) {
      // Was able to generate at least one potential path
      return Certificate_Status_Code::OK;
   } else {
      // Could not construct any potentially valid path...
      return builder.error();
   }
}

void PKIX::merge_revocation_status(CertificatePathStatusCodes& chain_status,
                                   const CertificatePathStatusCodes& crl_status,
                                   const CertificatePathStatusCodes& ocsp_status,
                                   const Path_Validation_Restrictions& restrictions) {
   if(chain_status.empty()) {
      throw Invalid_Argument("PKIX::merge_revocation_status chain_status was empty");
   }

   for(size_t i = 0; i != chain_status.size() - 1; ++i) {
      bool had_crl = false;
      bool had_ocsp = false;

      if(i < crl_status.size() && !crl_status[i].empty()) {
         for(auto&& code : crl_status[i]) {
            if(code == Certificate_Status_Code::VALID_CRL_CHECKED) {
               had_crl = true;
            }
            chain_status[i].insert(code);
         }
      }

      if(i < ocsp_status.size() && !ocsp_status[i].empty()) {
         for(auto&& code : ocsp_status[i]) {
            // NO_REVOCATION_URL and OCSP_SERVER_NOT_AVAILABLE are softfail
            if(code == Certificate_Status_Code::OCSP_RESPONSE_GOOD ||
               code == Certificate_Status_Code::OCSP_NO_REVOCATION_URL ||
               code == Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE) {
               had_ocsp = true;
            }

            chain_status[i].insert(code);
         }
      }

      if(had_crl == false && had_ocsp == false) {
         if((restrictions.require_revocation_information() && i == 0) ||
            (restrictions.ocsp_all_intermediates() && i > 0)) {
            chain_status[i].insert(Certificate_Status_Code::NO_REVOCATION_DATA);
         }
      }
   }
}

Certificate_Status_Code PKIX::overall_status(const CertificatePathStatusCodes& cert_status) {
   if(cert_status.empty()) {
      throw Invalid_Argument("PKIX::overall_status empty cert status");
   }

   Certificate_Status_Code overall_status = Certificate_Status_Code::OK;

   // take the "worst" error as overall
   for(const std::set<Certificate_Status_Code>& s : cert_status) {
      if(!s.empty()) {
         auto worst = *s.rbegin();
         // Leave informative OCSP/CRL confirmations on cert-level status only
         if(worst >= Certificate_Status_Code::FIRST_ERROR_STATUS && worst > overall_status) {
            overall_status = worst;
         }
      }
   }
   return overall_status;
}

Path_Validation_Result x509_path_validate(const std::vector<X509_Certificate>& end_certs,
                                          const Path_Validation_Restrictions& restrictions,
                                          const std::vector<Certificate_Store*>& trusted_roots,
                                          std::string_view hostname,
                                          Usage_Type usage,
                                          std::chrono::system_clock::time_point ref_time,
                                          std::chrono::milliseconds ocsp_timeout,
                                          const std::vector<std::optional<OCSP::Response>>& ocsp_resp) {
   if(end_certs.empty()) {
      throw Invalid_Argument("x509_path_validate called with no subjects");
   }

   const X509_Certificate& end_entity = end_certs[0];
   std::vector<X509_Certificate> end_entity_extra;
   for(size_t i = 1; i < end_certs.size(); ++i) {
      end_entity_extra.push_back(end_certs[i]);
   }

   const bool require_self_signed = restrictions.require_self_signed_trust_anchors();

   CertificatePathBuilder builder(trusted_roots, end_entity, end_entity_extra, require_self_signed);

   constexpr size_t max_paths = 50;
   constexpr size_t max_verifications = 200;

   std::optional<Path_Validation_Result> first_path_error;
   size_t paths_checked = 0;
   size_t certs_checked = 0;

   while(auto cert_path = builder.next()) {
      BOTAN_ASSERT_NOMSG(cert_path->empty() == false);

      paths_checked += 1;
      certs_checked += cert_path->size();
      if(paths_checked > max_paths || certs_checked > max_verifications) {
         first_path_error = Path_Validation_Result(Certificate_Status_Code::EXCEEDED_SEARCH_LIMITS);
         break;
      }

      CertificatePathStatusCodes status = PKIX::check_chain(*cert_path, ref_time, hostname, usage, restrictions);

      // Skip revocation checks if the chain already has fatal errors.
      if(PKIX::overall_status(status) < Certificate_Status_Code::FIRST_ERROR_STATUS_TO_SKIP_REVOCATION) {
         const CertificatePathStatusCodes crl_status = PKIX::check_crl(*cert_path, trusted_roots, ref_time);

         CertificatePathStatusCodes ocsp_status;

         if(!ocsp_resp.empty()) {
            ocsp_status = PKIX::check_ocsp(*cert_path, ocsp_resp, trusted_roots, ref_time, restrictions);
         }

         if(ocsp_timeout != std::chrono::milliseconds(0)) {
            const size_t to_online = restrictions.ocsp_all_intermediates() ? (cert_path->size() - 1) : 1;
            bool need_online = false;
            for(size_t i = 0; i < to_online; ++i) {
               if(skip_revocation_check((*cert_path)[i])) {
                  continue;
               }
               if(i >= ocsp_status.size() || ocsp_status[i].empty()) {
                  need_online = true;
                  break;
               }
            }

            if(need_online) {
#if defined(BOTAN_TARGET_OS_HAS_THREADS) && defined(BOTAN_HAS_HTTP_UTIL)
               auto online_status =
                  PKIX::check_ocsp_online(*cert_path, trusted_roots, ref_time, ocsp_timeout, restrictions);
               if(ocsp_status.size() < online_status.size()) {
                  ocsp_status.resize(online_status.size());
               }
               for(size_t i = 0; i < online_status.size(); ++i) {
                  if(ocsp_status[i].empty()) {
                     ocsp_status[i] = std::move(online_status[i]);
                  }
               }
#else
               if(ocsp_status.size() < to_online) {
                  ocsp_status.resize(to_online);
               }
               for(size_t i = 0; i < to_online; ++i) {
                  if(ocsp_status[i].empty()) {
                     ocsp_status[i].insert(Certificate_Status_Code::OCSP_NO_HTTP);
                  }
               }
#endif
            }
         }

         PKIX::merge_revocation_status(status, crl_status, ocsp_status, restrictions);

         // merge_revocation_status flags NO_REVOCATION_DATA when require_revocation
         // is set; clear it for certs where RFC 9608 Section 4 says to skip the check.
         for(size_t i = 0; i + 1 < cert_path->size() && i < status.size(); ++i) {
            if(skip_revocation_check((*cert_path)[i])) {
               status[i].erase(Certificate_Status_Code::NO_REVOCATION_DATA);
            }
         }
      }

      Path_Validation_Result pvd(status, std::move(*cert_path));
      if(pvd.successful_validation()) {
         return pvd;
      } else if(!first_path_error.has_value()) {
         // Save the errors from the first path we attempted
         first_path_error = std::move(pvd);
      }
   }

   if(first_path_error.has_value()) {
      // We found at least one path, but none of them verified
      // Return arbitrarily the error from the first path attempted
      return first_path_error.value();
   } else {
      // Failed to build any path at all
      return Path_Validation_Result(builder.error());
   }
}

Path_Validation_Result x509_path_validate(const X509_Certificate& end_cert,
                                          const Path_Validation_Restrictions& restrictions,
                                          const std::vector<Certificate_Store*>& trusted_roots,
                                          std::string_view hostname,
                                          Usage_Type usage,
                                          std::chrono::system_clock::time_point when,
                                          std::chrono::milliseconds ocsp_timeout,
                                          const std::vector<std::optional<OCSP::Response>>& ocsp_resp) {
   std::vector<X509_Certificate> certs;
   certs.push_back(end_cert);
   return x509_path_validate(certs, restrictions, trusted_roots, hostname, usage, when, ocsp_timeout, ocsp_resp);
}

Path_Validation_Result x509_path_validate(const std::vector<X509_Certificate>& end_certs,
                                          const Path_Validation_Restrictions& restrictions,
                                          const Certificate_Store& store,
                                          std::string_view hostname,
                                          Usage_Type usage,
                                          std::chrono::system_clock::time_point when,
                                          std::chrono::milliseconds ocsp_timeout,
                                          const std::vector<std::optional<OCSP::Response>>& ocsp_resp) {
   std::vector<Certificate_Store*> trusted_roots;
   trusted_roots.push_back(const_cast<Certificate_Store*>(&store));

   return x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage, when, ocsp_timeout, ocsp_resp);
}

Path_Validation_Result x509_path_validate(const X509_Certificate& end_cert,
                                          const Path_Validation_Restrictions& restrictions,
                                          const Certificate_Store& store,
                                          std::string_view hostname,
                                          Usage_Type usage,
                                          std::chrono::system_clock::time_point when,
                                          std::chrono::milliseconds ocsp_timeout,
                                          const std::vector<std::optional<OCSP::Response>>& ocsp_resp) {
   std::vector<X509_Certificate> certs;
   certs.push_back(end_cert);

   std::vector<Certificate_Store*> trusted_roots;
   trusted_roots.push_back(const_cast<Certificate_Store*>(&store));

   return x509_path_validate(certs, restrictions, trusted_roots, hostname, usage, when, ocsp_timeout, ocsp_resp);
}

Path_Validation_Restrictions::Path_Validation_Restrictions(bool require_rev,
                                                           size_t key_strength,
                                                           bool ocsp_intermediates,
                                                           std::chrono::seconds max_ocsp_age,
                                                           std::unique_ptr<Certificate_Store> trusted_ocsp_responders,
                                                           bool ignore_trusted_root_time_range,
                                                           bool require_self_signed_trust_anchors) :
      m_require_revocation_information(require_rev),
      m_ocsp_all_intermediates(ocsp_intermediates),
      m_minimum_key_strength(key_strength),
      m_max_ocsp_age(max_ocsp_age),
      m_trusted_ocsp_responders(std::move(trusted_ocsp_responders)),
      m_ignore_trusted_root_time_range(ignore_trusted_root_time_range),
      m_require_self_signed_trust_anchors(require_self_signed_trust_anchors) {
   if(key_strength <= 80) {
      m_trusted_hashes.insert("SHA-1");
   }

   m_trusted_hashes.insert("SHA-224");
   m_trusted_hashes.insert("SHA-256");
   m_trusted_hashes.insert("SHA-384");
   m_trusted_hashes.insert("SHA-512");
   m_trusted_hashes.insert("SHAKE-256(512)");  // Dilithium/ML-DSA
   m_trusted_hashes.insert("SHAKE-256(912)");  // Ed448
}

namespace {
CertificatePathStatusCodes find_warnings(const CertificatePathStatusCodes& all_statuses) {
   CertificatePathStatusCodes warnings;
   for(const auto& status_set_i : all_statuses) {
      std::set<Certificate_Status_Code> warning_set_i;
      for(const auto& code : status_set_i) {
         if(code >= Certificate_Status_Code::FIRST_WARNING_STATUS &&
            code < Certificate_Status_Code::FIRST_ERROR_STATUS) {
            warning_set_i.insert(code);
         }
      }
      warnings.push_back(warning_set_i);
   }
   return warnings;
}
}  // namespace

Path_Validation_Result::Path_Validation_Result(CertificatePathStatusCodes status,
                                               std::vector<X509_Certificate>&& cert_chain) :
      m_all_status(std::move(status)),
      m_warnings(find_warnings(m_all_status)),
      m_cert_path(std::move(cert_chain)),
      m_overall(PKIX::overall_status(m_all_status)) {}

const X509_Certificate& Path_Validation_Result::trust_root() const {
   if(m_cert_path.empty()) {
      throw Invalid_State("Path_Validation_Result::trust_root no path set");
   }
   if(result() != Certificate_Status_Code::VERIFIED) {
      throw Invalid_State("Path_Validation_Result::trust_root meaningless with invalid status");
   }

   return m_cert_path[m_cert_path.size() - 1];
}

bool Path_Validation_Result::successful_validation() const {
   return (result() == Certificate_Status_Code::VERIFIED || result() == Certificate_Status_Code::OCSP_RESPONSE_GOOD ||
           result() == Certificate_Status_Code::VALID_CRL_CHECKED);
}

bool Path_Validation_Result::no_warnings() const {
   for(const auto& status_set_i : m_warnings) {
      if(!status_set_i.empty()) {
         return false;
      }
   }
   return true;
}

CertificatePathStatusCodes Path_Validation_Result::warnings() const {
   return m_warnings;
}

std::string Path_Validation_Result::result_string() const {
   return status_string(result());
}

const char* Path_Validation_Result::status_string(Certificate_Status_Code code) {
   if(const char* s = to_string(code)) {
      return s;
   }

   return "Unknown error";
}

std::string Path_Validation_Result::warnings_string() const {
   const std::string sep(", ");
   std::ostringstream oss;
   for(size_t i = 0; i < m_warnings.size(); i++) {
      for(auto code : m_warnings[i]) {
         oss << "[" << std::to_string(i) << "] " << status_string(code) << sep;
      }
   }

   std::string res = oss.str();
   // remove last sep
   if(res.size() >= sep.size()) {
      res = res.substr(0, res.size() - sep.size());
   }
   return res;
}
}  // namespace Botan

/*
* X.509 Cert Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_CERT_PATH_VALIDATION_H_
#define BOTAN_X509_CERT_PATH_VALIDATION_H_

#include <botan/certstor.h>
#include <botan/ocsp.h>
#include <botan/pkix_enums.h>
#include <botan/x509cert.h>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#if defined(BOTAN_TARGET_OS_HAS_THREADS) && defined(BOTAN_HAS_HTTP_UTIL)
   #define BOTAN_HAS_ONLINE_REVOCATION_CHECKS
#endif

namespace Botan {

/**
* This type represents the validation status of an entire certificate path.
* There is one set of status codes for each certificate in the path.
*/
typedef std::vector<std::set<Certificate_Status_Code>> CertificatePathStatusCodes;

/**
* The policy applied during PKIX path validation
*
* Each decision can be customized by overriding the relevant function, or
* by using Path_Validation_Options. An object of this type applies the
* default for every decision.
*/
class BOTAN_PUBLIC_API(3, 15) Path_Validation_Policy /* NOLINT(*-special-member-functions) */ {
   public:
      virtual ~Path_Validation_Policy() = default;

      /**
      * The default trusts SHA-2, and the hash functions which are fixed by
      * the signature scheme for Ed448, ML-DSA, SLH-DSA, XMSS and HSS-LMS
      *
      * @param hash_name the hash function used for a signature on a
      * certificate, CRL, or OCSP response
      * @return true if signatures using this hash function are accepted
      */
      virtual bool hash_is_trusted(std::string_view hash_name) const;

      /**
      * This is consulted for each key which signed a certificate, CRL or OCSP
      * response. It is not consulted for the key of the end entity certificate.
      *
      * The default accepts keys with an estimated strength of at least 110 bits
      *
      * @param key the public key of a CA or OCSP responder
      * @return true if signatures created by this key are accepted
      */
      virtual bool key_is_acceptable(const Public_Key& key) const;

      /**
      * @return whether revocation information is required. Default is false
      */
      virtual bool require_revocation_information() const;

      /**
      * @return whether all intermediate CAs should also be OCSPed. If false
      * then only end entity OCSP is required/requested. Default is false
      */
      virtual bool ocsp_all_intermediates() const;

      /**
      * @return maximum age of OCSP responses w/o next_update.
      * If zero, there is no maximum age. Default is one week
      */
      virtual std::chrono::seconds max_ocsp_age() const;

      /**
      * Certificates in this store are trusted to sign OCSP responses
      * additionally to the CA's responder certificates.
      * @return certificate store containing trusted OCSP responder certs,
      * or nullptr if there are none, which is the default
      */
      virtual const Certificate_Store* trusted_ocsp_responders() const;

      /**
      * @return true if a trust anchor outside of its validity period
      * should result in a warning rather than an error. Default is false
      */
      virtual bool ignore_trusted_root_time_range() const;

      /**
      * @return true if only certificates which appear to be self-signed
      * are allowed as trust anchors. The self-signature itself is not verified.
      * Default is true
      */
      virtual bool require_self_signed_trust_anchors() const;

      /**
      * @return true if OCSP soft fail conditions (such as a network error)
      * count as satisfying revocation requirements. Default is false
      */
      virtual bool accept_ocsp_softfail() const;
};

/**
* A Path_Validation_Policy which is set up in a builder style, eg
*
* Path_Validation_Options()
*   .with_required_revocation_information()
*   .with_trusted_hash("SHA-3(256)")
*
* Anything which is not set follows the default policy.
*/
class BOTAN_PUBLIC_API(3, 15) Path_Validation_Options final : public Path_Validation_Policy {
   public:
      /**
      * Require revocation information for the end entity certificate
      */
      Path_Validation_Options with_required_revocation_information(bool required = true) const;

      /**
      * Require revocation information for all intermediate CA certificates,
      * and make OCSP requests for them if OCSP is enabled
      */
      Path_Validation_Options with_ocsp_for_all_intermediates(bool enabled = true) const;

      /**
      * Set the maximum age of OCSP responses w/o next_update.
      * If zero, there is no maximum age
      */
      Path_Validation_Options with_max_ocsp_age(std::chrono::seconds max_age) const;

      /**
      * Trust the certificates in this store to sign OCSP responses,
      * additionally to the CA's responder certificates.
      */
      Path_Validation_Options with_trusted_ocsp_responders(std::shared_ptr<const Certificate_Store> responders) const;

      /**
      * Accept OCSP soft fail conditions (such as a network error) as
      * satisfying revocation requirements. Not recommended.
      */
      Path_Validation_Options with_accepted_ocsp_softfail(bool accepted = true) const;

      /**
      * Only warn about a trust anchor which is outside of its validity period
      */
      Path_Validation_Options with_ignored_trusted_root_time_range(bool ignored = true) const;

      /**
      * Allow certificates which do not appear to be self-signed, such as
      * intermediate or leaf certificates, to be used as trust anchors
      */
      Path_Validation_Options with_non_self_signed_trust_anchors(bool allowed = true) const;

      /**
      * Set the minimum estimated strength (in terms of operations, eg 80
      * means 2^80) of a key. This applies to any key whose algorithm was
      * not named to with_accepted_key_algorithm or with_forbidden_key_algorithm.
      */
      Path_Validation_Options with_minimum_key_strength(size_t strength) const;

      /**
      * Accept keys of an algorithm if they are at least a certain length.
      * For this algorithm, this takes the place of the minimum key strength.
      *
      * @param algo an algorithm name as returned by Public_Key::algo_name
      * @param minimum_key_bits the minimum acceptable Public_Key::key_length
      */
      Path_Validation_Options with_accepted_key_algorithm(std::string_view algo, size_t minimum_key_bits) const;

      /**
      * Reject all keys of an algorithm
      *
      * @param algo an algorithm name as returned by Public_Key::algo_name
      */
      Path_Validation_Options with_forbidden_key_algorithm(std::string_view algo) const;

      /**
      * Trust a hash function, in addition to the defaults
      */
      Path_Validation_Options with_trusted_hash(std::string_view hash_name) const;

      /**
      * Do not trust a hash function, even if it is trusted by default
      */
      Path_Validation_Options with_untrusted_hash(std::string_view hash_name) const;

      bool hash_is_trusted(std::string_view hash_name) const override;

      bool key_is_acceptable(const Public_Key& key) const override;

      bool require_revocation_information() const override;

      bool ocsp_all_intermediates() const override;

      std::chrono::seconds max_ocsp_age() const override;

      const Certificate_Store* trusted_ocsp_responders() const override;

      bool ignore_trusted_root_time_range() const override;

      bool require_self_signed_trust_anchors() const override;

      bool accept_ocsp_softfail() const override;

   private:
      std::optional<bool> m_require_revocation_information;
      std::optional<bool> m_ocsp_all_intermediates;
      std::optional<std::chrono::seconds> m_max_ocsp_age;
      std::shared_ptr<const Certificate_Store> m_trusted_ocsp_responders;
      std::optional<bool> m_accept_ocsp_softfail;
      std::optional<bool> m_ignore_trusted_root_time_range;
      std::optional<bool> m_require_self_signed_trust_anchors;
      std::optional<size_t> m_minimum_key_strength;
      // Minimum key length for each named algorithm, or nullopt if forbidden
      std::map<std::string, std::optional<size_t>, std::less<>> m_key_algorithms;
      std::map<std::string, bool, std::less<>> m_hashes;
};

/**
* Specifies restrictions on the PKIX path validation
*/
class BOTAN_DEPRECATED_API("Use Path_Validation_Options") Path_Validation_Restrictions final
      : public Path_Validation_Policy {
   public:
      /**
      * @param require_rev if true, revocation information is required

      * @param minimum_key_strength is the minimum strength (in terms of
      *    operations, eg 80 means 2^80) of a signature. Signatures weaker than
      *    this are rejected. If more than 80, SHA-1 signatures are also
      *    rejected. If possible use at least setting 110.
      *
      *        80 bit strength requires 1024 bit RSA
      *        110 bit strength requires 2k bit RSA
      *        128 bit strength requires ~3k bit RSA or P-256
      * @param ocsp_all_intermediates Make OCSP requests for all CAs as
      * well as end entity (if OCSP enabled in path validation request)
      * @param max_ocsp_age maximum age of OCSP responses w/o next_update.
      *        If zero, there is no maximum age
      * @param trusted_ocsp_responders optional certificate store containing certificates
      *        of trusted OCSP responders (additionally to the CA's responders)
      * @param ignore_trusted_root_time_range if true, validity checks on the
      *        time range of the trusted root certificate only produce warnings
      * @param require_self_signed_trust_anchors if true, only certificates which
      *        appear to be self-signed are allowed as trust anchors. Trust anchors
      *        based on intermediate and leaf certificates are forbidden in this case.
      *        The self-signature itself is not verified.
      * @param accept_ocsp_softfail if true then soft fail conditions (the OCSP
      *        responder being unavailable or returning an error status, no
      *        responder URL, or the library being built without HTTP support)
      *        will be accepted as satisfying revocation requirements.
      *        Not recommended.
      */
      BOTAN_FUTURE_EXPLICIT Path_Validation_Restrictions(
         bool require_rev = false,
         size_t minimum_key_strength = 110,
         bool ocsp_all_intermediates = false,
         std::chrono::seconds max_ocsp_age = std::chrono::hours(24 * 7),
         std::unique_ptr<Certificate_Store> trusted_ocsp_responders = nullptr,
         bool ignore_trusted_root_time_range = false,
         bool require_self_signed_trust_anchors = true,
         bool accept_ocsp_softfail = false);

      /**
      * @param require_rev if true, revocation information is required
      * @param minimum_key_strength is the minimum strength (in terms of
      *        operations, eg 80 means 2^80) of a signature. Signatures
      *        weaker than this are rejected.
      * @param ocsp_all_intermediates Make OCSP requests for all CAs as
      * well as end entity (if OCSP enabled in path validation request)
      * @param trusted_hashes a set of trusted hashes. Any signatures
      *        created using a hash other than one of these will be
      *        rejected.
      * @param max_ocsp_age maximum age of OCSP responses w/o next_update.
      *        If zero, there is no maximum age
      * @param trusted_ocsp_responders optional certificate store containing certificates
      *        of trusted OCSP responders (additionally to the CA's responders)
      * @param ignore_trusted_root_time_range if true, validity checks on the
      *        time range of the trusted root certificate only produce warnings
      * @param require_self_signed_trust_anchors if true, only certificates which
      *        appear to be self-signed are allowed as trust anchors. Trust anchors
      *        based on intermediate and leaf certificates are forbidden in this case.
      *        The self-signature itself is not verified.
      * @param accept_ocsp_softfail if true then soft fail conditions (the OCSP
      *        responder being unavailable or returning an error status, no
      *        responder URL, or the library being built without HTTP support)
      *        will be accepted as satisfying revocation requirements.
      *        Not recommended.
      */
      Path_Validation_Restrictions(bool require_rev,
                                   size_t minimum_key_strength,
                                   bool ocsp_all_intermediates,
                                   const std::set<std::string>& trusted_hashes,
                                   std::chrono::seconds max_ocsp_age = std::chrono::hours(24 * 7),
                                   std::unique_ptr<Certificate_Store> trusted_ocsp_responders = nullptr,
                                   bool ignore_trusted_root_time_range = false,
                                   bool require_self_signed_trust_anchors = true,
                                   bool accept_ocsp_softfail = false) :
            m_require_revocation_information(require_rev),
            m_ocsp_all_intermediates(ocsp_all_intermediates),
            m_trusted_hashes(trusted_hashes),
            m_minimum_key_strength(minimum_key_strength),
            m_max_ocsp_age(max_ocsp_age),
            m_trusted_ocsp_responders(std::move(trusted_ocsp_responders)),
            m_ignore_trusted_root_time_range(ignore_trusted_root_time_range),
            m_require_self_signed_trust_anchors(require_self_signed_trust_anchors),
            m_accept_ocsp_softfail(accept_ocsp_softfail) {}

      /**
      * @return true if hash_name is one of the trusted hashes, or if the set
      * of trusted hashes given to the constructor was empty
      */
      bool hash_is_trusted(std::string_view hash_name) const override;

      /**
      * @return true if the estimated strength of the key is at least the
      * minimum key strength given to the constructor
      */
      bool key_is_acceptable(const Public_Key& key) const override;

      /**
      * @return whether revocation information is required
      */
      bool require_revocation_information() const override { return m_require_revocation_information; }

      /**
      * @return whether all intermediate CAs should also be OCSPed. If false
      * then only end entity OCSP is required/requested.
      */
      bool ocsp_all_intermediates() const override { return m_ocsp_all_intermediates; }

      /**
      * @return trusted signature hash functions
      */
      BOTAN_DEPRECATED("Use hash_is_trusted") const std::set<std::string>& trusted_hashes() const {
         return m_trusted_hashes;
      }

      /**
      * @return minimum required key strength
      */
      BOTAN_DEPRECATED("Use key_is_acceptable") size_t minimum_key_strength() const { return m_minimum_key_strength; }

      /**
      * @return maximum age of OCSP responses w/o next_update.
      * If zero, there is no maximum age
      */
      std::chrono::seconds max_ocsp_age() const override { return m_max_ocsp_age; }

      /**
       * Certificates in this store are trusted to sign OCSP responses
       * additionally to the CA's responder certificates.
       * @return certificate store containing trusted OCSP responder certs
       */
      const Certificate_Store* trusted_ocsp_responders() const override { return m_trusted_ocsp_responders.get(); }

      /**
       * RFC 5280 does not disallow trusted anchors signing certificates with wider validity
       * ranges than theirs. When checking a certificate chain at a specific
       * point in time, this can lead to situations where a root certificate is expired, but
       * the lower-chain certificates are not.
       *
       * If this flag is set to true, such chains are considered valid (with warning
       * TRUSTED_CERT_HAS_EXPIRED). Otherwise, the chain is rejected with the error
       * code CERT_HAS_EXPIRED. The same holds for not yet valid certificates with the
       * error code CERT_NOT_YET_VALID (or warning TRUSTED_CERT_NOT_YET_VALID).
       */
      bool ignore_trusted_root_time_range() const override { return m_ignore_trusted_root_time_range; }

      /**
       * By default Botan requires trust anchors to appear self-signed; the
       * self-signature itself is not verified.
       * This prevents using intermediate CA certificates and leaf certificates
       * as trust anchors, even if they are included in the Certificate Store.
       * This restriction can be removed by setting
       * require_self_signed_trust_anchors=false in the constructor.
       */
      bool require_self_signed_trust_anchors() const override { return m_require_self_signed_trust_anchors; }

      /**
       * By default OCSP soft-fail conditions (such as a network error)
       * do not count as satisfying revocation requirements.
       * This restriction can be removed by setting
       * accept_ocsp_softfail=true in the constructor.
       */
      bool accept_ocsp_softfail() const override { return m_accept_ocsp_softfail; }

   private:
      bool m_require_revocation_information;
      bool m_ocsp_all_intermediates;
      std::set<std::string> m_trusted_hashes;
      size_t m_minimum_key_strength;
      std::chrono::seconds m_max_ocsp_age;
      std::unique_ptr<Certificate_Store> m_trusted_ocsp_responders;
      bool m_ignore_trusted_root_time_range;
      bool m_require_self_signed_trust_anchors;
      bool m_accept_ocsp_softfail;
};

/**
* Represents the result of a PKIX path validation
*/
class BOTAN_PUBLIC_API(2, 0) Path_Validation_Result final {
   public:
      typedef Certificate_Status_Code Code;

      /**
      * @return the trust root of the validation if successful
      * throws an exception if the validation failed
      */
      const X509_Certificate& trust_root() const;

      /**
      * @return the full path from subject to trust root
      * This path may be empty
      */
      const std::vector<X509_Certificate>& cert_path() const { return m_cert_path; }

      /**
      * @return true iff the validation was successful
      */
      bool successful_validation() const;

      /**
      * @return true iff no warnings occurred during validation
      */
      bool no_warnings() const;

      /**
      * @return overall validation result code
      */
      Certificate_Status_Code result() const { return m_overall; }

      /**
      * @return a set of status codes for each certificate in the chain
      */
      const CertificatePathStatusCodes& all_statuses() const { return m_all_status; }

      /**
      * @return the subset of status codes that are warnings
      */
      CertificatePathStatusCodes warnings() const;

      /**
      * @return string representation of the validation result
      */
      std::string result_string() const;

      /**
      * @return string representation of the warnings
      */
      std::string warnings_string() const;

      /**
      * @param code validation status code
      * @return corresponding validation status message
      */
      static const char* status_string(Certificate_Status_Code code);

      /**
      * Create a Path_Validation_Result
      * @param status list of validation status codes
      * @param cert_chain the certificate chain that was validated
      */
      Path_Validation_Result(CertificatePathStatusCodes status, std::vector<X509_Certificate>&& cert_chain);

      /**
      * Create a Path_Validation_Result
      * @param status validation status code
      */
      explicit Path_Validation_Result(Certificate_Status_Code status) : m_overall(status) {}

   private:
      CertificatePathStatusCodes m_all_status;
      CertificatePathStatusCodes m_warnings;
      std::vector<X509_Certificate> m_cert_path;
      Certificate_Status_Code m_overall;
};

/**
* PKIX Path Validation
*
* A successful validation establishes that the contents of the end entity
* certificate, including its public key, were attested to by a trusted
* authority. It says nothing about the end entity key itself, which is not
* examined: it may be weak, malformed, or of an unsupported algorithm.
* Applications must check the key is suitable before using it.
*
* @param end_certs certificate chain to validate (with end entity certificate in end_certs[0])
* @param restrictions path validation restrictions
* @param trusted_roots list of certificate stores that contain trusted certificates
* @param hostname if not empty, compared against the DNS name in end_certs[0]
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_certs[0]
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeout for OCSP operations, 0 disables OCSP check
* @param ocsp_resp additional OCSP responses to consider (eg from peer)
* @return result of the path validation
*/
Path_Validation_Result BOTAN_PUBLIC_API(2, 0)
   x509_path_validate(const std::vector<X509_Certificate>& end_certs,
                      const Path_Validation_Policy& restrictions,
                      const std::vector<Certificate_Store*>& trusted_roots,
                      std::string_view hostname = "",
                      Usage_Type usage = Usage_Type::UNSPECIFIED,
                      std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
                      std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
                      const std::vector<std::optional<OCSP::Response>>& ocsp_resp = {});

/**
* PKIX Path Validation
* @param end_cert certificate to validate
* @param restrictions path validation restrictions
* @param trusted_roots list of stores that contain trusted certificates
* @param hostname if not empty, compared against the DNS name in end_cert
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_cert
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeout for OCSP operations, 0 disables OCSP check
* @param ocsp_resp additional OCSP responses to consider (eg from peer)
* @return result of the path validation
*/
Path_Validation_Result BOTAN_PUBLIC_API(2, 0)
   x509_path_validate(const X509_Certificate& end_cert,
                      const Path_Validation_Policy& restrictions,
                      const std::vector<Certificate_Store*>& trusted_roots,
                      std::string_view hostname = "",
                      Usage_Type usage = Usage_Type::UNSPECIFIED,
                      std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
                      std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
                      const std::vector<std::optional<OCSP::Response>>& ocsp_resp = {});

/**
* PKIX Path Validation
* @param end_cert certificate to validate
* @param restrictions path validation restrictions
* @param store store that contains trusted certificates
* @param hostname if not empty, compared against the DNS name in end_cert
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_cert
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeout for OCSP operations, 0 disables OCSP check
* @param ocsp_resp additional OCSP responses to consider (eg from peer)
* @return result of the path validation
*/
Path_Validation_Result BOTAN_PUBLIC_API(2, 0)
   x509_path_validate(const X509_Certificate& end_cert,
                      const Path_Validation_Policy& restrictions,
                      const Certificate_Store& store,
                      std::string_view hostname = "",
                      Usage_Type usage = Usage_Type::UNSPECIFIED,
                      std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
                      std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
                      const std::vector<std::optional<OCSP::Response>>& ocsp_resp = {});

/**
* PKIX Path Validation
* @param end_certs certificate chain to validate
* @param restrictions path validation restrictions
* @param store store that contains trusted certificates
* @param hostname if not empty, compared against the DNS name in end_certs[0]
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_certs[0]
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeout for OCSP operations, 0 disables OCSP check
* @param ocsp_resp additional OCSP responses to consider (eg from peer)
* @return result of the path validation
*/
Path_Validation_Result BOTAN_PUBLIC_API(2, 0)
   x509_path_validate(const std::vector<X509_Certificate>& end_certs,
                      const Path_Validation_Policy& restrictions,
                      const Certificate_Store& store,
                      std::string_view hostname = "",
                      Usage_Type usage = Usage_Type::UNSPECIFIED,
                      std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
                      std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
                      const std::vector<std::optional<OCSP::Response>>& ocsp_resp = {});

/**
* namespace PKIX holds the building blocks that are called by x509_path_validate.
* This allows custom validation logic to be written by applications and makes
* for easier testing, but unless you're positive you know what you're doing you
* probably want to just call x509_path_validate instead.
*/
namespace PKIX {

/**
* Create all certificate paths by identifying all possible routes from the
* end-entity certificate to any certificate in the certificate store list. Paths
* may also end in intermediate or leaf certificates found in the certificate
* stores.
*
* WARNING: The validity (e.g. signatures or constraints) of the output path IS
* NOT checked.
*
* @param cert_paths output parameter to be filled with all discovered certificate paths
* @param trusted_certstores list of certificate stores that contain trusted certificates
* @param end_entity the cert to be validated
* @param end_entity_extra optional list of additional untrusted certs for path building
* @param max_paths if set, enumerate at most this many paths and return
*        EXCEEDED_SEARCH_LIMITS if more paths exist; if nullopt, unbounded
* @return result of the path building operation (OK or error)
*/
Certificate_Status_Code BOTAN_PUBLIC_API(3, 11)
   build_all_certificate_paths(std::vector<std::vector<X509_Certificate>>& cert_paths,
                               const std::vector<Certificate_Store*>& trusted_certstores,
                               const X509_Certificate& end_entity,
                               const std::vector<X509_Certificate>& end_entity_extra,
                               std::optional<size_t> max_paths = std::nullopt);

/**
* Same as build_all_certificate_paths but only outputs a single path. If there are
* paths ending in self-signed certificates, these are prioritized over paths ending
* in intermediate or leaf certificates of the certificate store.
*
* WARNING: The validity (e.g. signatures or constraints) of the output path IS
* NOT checked.
*
* @param cert_path_out output parameter, cert_path will be appended to this vector
* @param trusted_certstores list of certificate stores that contain trusted certificates
* @param end_entity the cert to be validated
* @param end_entity_extra optional list of additional untrusted certs for path building
* @param max_paths if set, examine at most this many candidate paths; if nullopt, unbounded
* @return result of the path building operation (OK or error)
*/
BOTAN_DEPRECATED("Use build_all_certificate_paths")
Certificate_Status_Code BOTAN_PUBLIC_API(2, 0)
   build_certificate_path(std::vector<X509_Certificate>& cert_path_out,
                          const std::vector<Certificate_Store*>& trusted_certstores,
                          const X509_Certificate& end_entity,
                          const std::vector<X509_Certificate>& end_entity_extra,
                          std::optional<size_t> max_paths = std::nullopt);

/**
* Check the certificate chain, but not any revocation data
*
* The public key of the end entity certificate is not examined.
*
* @param cert_path path built by build_certificate_path with OK result.
* The first element is the end entity certificate, the last element is
* the trusted root certificate. The signature on the trusted root is
* not verified; it is trusted because it was provided as a trust anchor.
* @param ref_time whatever time you want to perform the validation
* against (normally current system clock)
* @param hostname the hostname
* @param usage end entity usage checks
* @param restrictions the relevant path validation restrictions object
* @return vector of results on per certificate in the path, each containing a set of
* results. If all codes in the set are < Certificate_Status_Code::FIRST_ERROR_STATUS,
* then the result for that certificate is successful. If all results are
*/
CertificatePathStatusCodes BOTAN_PUBLIC_API(3, 0) check_chain(const std::vector<X509_Certificate>& cert_path,
                                                              std::chrono::system_clock::time_point ref_time,
                                                              std::string_view hostname,
                                                              Usage_Type usage,
                                                              const Path_Validation_Policy& restrictions);

/**
* Check OCSP responses for revocation information
* @param cert_path path already validated by check_chain
* @param ocsp_responses the OCSP responses to consider
* @param certstores trusted roots
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @param restrictions the relevant path validation restrictions object
* @return revocation status
*/
CertificatePathStatusCodes BOTAN_PUBLIC_API(3, 0)
   check_ocsp(const std::vector<X509_Certificate>& cert_path,
              const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
              const std::vector<Certificate_Store*>& certstores,
              std::chrono::system_clock::time_point ref_time,
              const Path_Validation_Policy& restrictions);

/**
* Check CRLs for revocation information
* @param cert_path path already validated by check_chain
* @param crls the list of CRLs to check, it is assumed that crls[i] (if not null)
* is the associated CRL for the subject in cert_path[i].
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @param restrictions the relevant path validation restrictions object
* @return revocation status
*/
CertificatePathStatusCodes BOTAN_PUBLIC_API(3, 14) check_crl(const std::vector<X509_Certificate>& cert_path,
                                                             const std::vector<std::optional<X509_CRL>>& crls,
                                                             std::chrono::system_clock::time_point ref_time,
                                                             const Path_Validation_Policy& restrictions);

/**
* Check CRLs for revocation information
*
* Equivalent to calling check_crl with a default Path_Validation_Policy
*/
BOTAN_DEPRECATED("Use overload taking Path_Validation_Policy")
CertificatePathStatusCodes BOTAN_PUBLIC_API(2, 0) check_crl(const std::vector<X509_Certificate>& cert_path,
                                                            const std::vector<std::optional<X509_CRL>>& crls,
                                                            std::chrono::system_clock::time_point ref_time);

/**
* Check CRLs for revocation information
* @param cert_path path already validated by check_chain
* @param certstores a list of certificate stores to query for the CRL
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @param restrictions the relevant path validation restrictions object
* @return revocation status
*/
CertificatePathStatusCodes BOTAN_PUBLIC_API(3, 14) check_crl(const std::vector<X509_Certificate>& cert_path,
                                                             const std::vector<Certificate_Store*>& certstores,
                                                             std::chrono::system_clock::time_point ref_time,
                                                             const Path_Validation_Policy& restrictions);

/**
* Check CRLs for revocation information
*
* Equivalent to calling check_crl with a default Path_Validation_Policy
*/
BOTAN_DEPRECATED("Use overload taking Path_Validation_Policy")
CertificatePathStatusCodes BOTAN_PUBLIC_API(2, 0) check_crl(const std::vector<X509_Certificate>& cert_path,
                                                            const std::vector<Certificate_Store*>& certstores,
                                                            std::chrono::system_clock::time_point ref_time);

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)

/**
* Check OCSP using online (HTTP) access. Current version creates a thread and
* network connection per OCSP request made.
*
* @param cert_path path already validated by check_chain
* @param trusted_certstores a list of certstores with trusted certs
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @param timeout for timing out the responses, though actually this function
* may block for up to timeout*cert_path.size()*C for some small C.
* @param restrictions the relevant path validation restrictions object
* @return revocation status
*/
CertificatePathStatusCodes BOTAN_PUBLIC_API(3, 0)
   check_ocsp_online(const std::vector<X509_Certificate>& cert_path,
                     const std::vector<Certificate_Store*>& trusted_certstores,
                     std::chrono::system_clock::time_point ref_time,
                     std::chrono::milliseconds timeout,
                     const Path_Validation_Policy& restrictions);

/**
* Check CRL using online (HTTP) access. Current version creates a thread and
* network connection per CRL access.

* @param cert_path path already validated by check_chain
* @param trusted_certstores a list of certstores with trusted certs
* @param certstore_to_recv_crls optional (nullptr to disable), all CRLs
* retrieved will be saved to this cert store.
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @param timeout for timing out the responses, though actually this function
* may block for up to timeout*cert_path.size()*C for some small C.
* @param restrictions the relevant path validation restrictions object
* @return revocation status
*/
CertificatePathStatusCodes BOTAN_PUBLIC_API(3, 14)
   check_crl_online(const std::vector<X509_Certificate>& cert_path,
                    const std::vector<Certificate_Store*>& trusted_certstores,
                    Certificate_Store_In_Memory* certstore_to_recv_crls,
                    std::chrono::system_clock::time_point ref_time,
                    std::chrono::milliseconds timeout,
                    const Path_Validation_Policy& restrictions);

/**
* Check CRL using online (HTTP) access.
*
* Equivalent to calling check_crl_online with a default Path_Validation_Policy
*/
BOTAN_DEPRECATED("Use overload taking Path_Validation_Policy")
CertificatePathStatusCodes BOTAN_PUBLIC_API(2, 0)
   check_crl_online(const std::vector<X509_Certificate>& cert_path,
                    const std::vector<Certificate_Store*>& trusted_certstores,
                    Certificate_Store_In_Memory* certstore_to_recv_crls,
                    std::chrono::system_clock::time_point ref_time,
                    std::chrono::milliseconds timeout);

#endif

/**
* Find overall status (OK, error) of a validation
* @param cert_status result of merge_revocation_status or check_chain
*/
Certificate_Status_Code BOTAN_PUBLIC_API(2, 0) overall_status(const CertificatePathStatusCodes& cert_status);

/**
* Merge the results from CRL and/or OCSP checks into chain_status
* @param chain_status the certificate status
* @param crl_status results from check_crl
* @param ocsp_status results from check_ocsp
* @param restrictions the relevant path validation restrictions object
*/
void BOTAN_PUBLIC_API(3, 0) merge_revocation_status(CertificatePathStatusCodes& chain_status,
                                                    const CertificatePathStatusCodes& crl_status,
                                                    const CertificatePathStatusCodes& ocsp_status,
                                                    const Path_Validation_Policy& restrictions);

}  // namespace PKIX

}  // namespace Botan

#endif

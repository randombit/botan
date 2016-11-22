/*
* X.509 Cert Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_CERT_PATH_VALIDATION_H__
#define BOTAN_X509_CERT_PATH_VALIDATION_H__

#include <botan/cert_status.h>
#include <botan/x509cert.h>
#include <botan/certstor.h>
#include <botan/ocsp.h>
#include <functional>
#include <set>
#include <chrono>

#if defined(BOTAN_TARGET_OS_HAS_THREADS) && defined(BOTAN_HAS_HTTP_UTIL)
  #define BOTAN_HAS_ONLINE_REVOCATION_CHECKS
#endif

namespace Botan {

/**
* Specifies restrictions on the PKIX path validation
*/
class BOTAN_DLL Path_Validation_Restrictions
   {
   public:
      /**
      * @param require_rev if true, revocation information is required
      * @param minimum_key_strength is the minimum strength (in terms of
      *        operations, eg 80 means 2^80) of a signature. Signatures
      *        weaker than this are rejected. If more than 80, SHA-1
      *        signatures are also rejected.
      * @param ocsp_all_intermediates Make OCSP requests for all CAs as
      * well as end entity (if OCSP enabled in path validation request)
      */
      Path_Validation_Restrictions(bool require_rev = false,
                                   size_t minimum_key_strength = 80,
                                   bool ocsp_all_intermediates = false);

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
      */
      Path_Validation_Restrictions(bool require_rev,
                                   size_t minimum_key_strength,
                                   bool ocsp_all_intermediates,
                                   const std::set<std::string>& trusted_hashes) :
         m_require_revocation_information(require_rev),
         m_ocsp_all_intermediates(ocsp_all_intermediates),
         m_trusted_hashes(trusted_hashes),
         m_minimum_key_strength(minimum_key_strength) {}

      /**
      * @return whether revocation information is required
      */
      bool require_revocation_information() const
         { return m_require_revocation_information; }

      /**
      * FIXME add doc
      */
      bool ocsp_all_intermediates() const
         { return m_ocsp_all_intermediates; }

      /**
      * @return trusted signature hash functions
      */
      const std::set<std::string>& trusted_hashes() const
         { return m_trusted_hashes; }

      /**
      * @return minimum required key strength
      */
      size_t minimum_key_strength() const
         { return m_minimum_key_strength; }

   private:
      bool m_require_revocation_information;
      bool m_ocsp_all_intermediates;
      std::set<std::string> m_trusted_hashes;
      size_t m_minimum_key_strength;
   };

/**
* Represents the result of a PKIX path validation
*/
class BOTAN_DLL Path_Validation_Result
   {
   public:
      typedef Certificate_Status_Code Code;

      /**
      * @return the set of hash functions you are implicitly
      * trusting by trusting this result.
      */
      std::set<std::string> trusted_hashes() const;

      /**
      * @return the trust root of the validation if successful
      * throws an exception if the validation failed
      */
      const X509_Certificate& trust_root() const;

      /**
      * @return the full path from subject to trust root
      * This path may be empty
      */
      const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path() const { return m_cert_path; }

      /**
      * @return true iff the validation was successful
      */
      bool successful_validation() const;

      /**
      * @return overall validation result code
      */
      Certificate_Status_Code result() const { return m_overall; }

      /**
      * @return a set of status codes for each certificate in the chain
      */
      const std::vector<std::set<Certificate_Status_Code>>& all_statuses() const
         { return m_all_status; }

      /**
      * @return string representation of the validation result
      */
      std::string result_string() const;

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
      Path_Validation_Result(std::vector<std::set<Certificate_Status_Code>> status,
                             std::vector<std::shared_ptr<const X509_Certificate>>&& cert_chain);

      /**
      * Create a Path_Validation_Result
      * @param status validation status code
      */
      explicit Path_Validation_Result(Certificate_Status_Code status) : m_overall(status) {}

   private:
      Certificate_Status_Code m_overall;
      std::vector<std::set<Certificate_Status_Code>> m_all_status;
      std::vector<std::shared_ptr<const X509_Certificate>> m_cert_path;
   };

namespace PKIX {

/**
* Build certificate path
* @param cert_path_out output parameter, cert_path will be appended to this vector
* @param trusted_certstores list of certificate stores that contain trusted certificates
* @param end_entity the cert to be validated
* @param end_entity_extra optional list of additional untrusted certs for path building
* @return result of the path building operation (OK or error)
*/
Certificate_Status_Code
BOTAN_DLL build_certificate_path(std::vector<std::shared_ptr<const X509_Certificate>>& cert_path_out,
                                 const std::vector<Certificate_Store*>& trusted_certstores,
                                 const std::shared_ptr<const X509_Certificate>& end_entity,
                                 const std::vector<std::shared_ptr<const X509_Certificate>>& end_entity_extra);

/**
* Perform certificate validation
* @param cert_path path built by build_certificate_path with OK result
* @param ref_time whatever time you want to perform the validation
* against (normally current system clock)
* @param hostname the hostname
* @param usage end entity usage checks
* @param min_signature_algo_strength 80 or 128 typically
* @param trusted_hashes set of trusted hash functions,
* empty means accept any hash we have an OID for
*/
std::vector<std::set<Certificate_Status_Code>>
BOTAN_DLL check_chain(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                      std::chrono::system_clock::time_point ref_time,
                      const std::string& hostname,
                      Usage_Type usage,
                      size_t min_signature_algo_strength,
                      const std::set<std::string>& trusted_hashes);

std::vector<std::set<Certificate_Status_Code>>
BOTAN_DLL check_ocsp(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                     const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_responses,
                     const std::vector<Certificate_Store*>& certstores,
                     std::chrono::system_clock::time_point ref_time);

std::vector<std::set<Certificate_Status_Code>>
BOTAN_DLL check_crl(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                    const std::vector<std::shared_ptr<const X509_CRL>>& crls,
                    std::chrono::system_clock::time_point ref_time);

std::vector<std::set<Certificate_Status_Code>>
BOTAN_DLL check_crl(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                    const std::vector<Certificate_Store*>& certstores,
                    std::chrono::system_clock::time_point ref_time);

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)

std::vector<std::set<Certificate_Status_Code>>
BOTAN_DLL check_ocsp_online(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                            const std::vector<Certificate_Store*>& trusted_certstores,
                            std::chrono::system_clock::time_point ref_time,
                            std::chrono::milliseconds timeout,
                            bool ocsp_check_intermediate_CAs);

std::vector<std::set<Certificate_Status_Code>>
BOTAN_DLL check_crl_online(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                           const std::vector<Certificate_Store*>& trusted_certstores,
                           std::chrono::system_clock::time_point ref_time,
                           std::chrono::milliseconds timeout);

#endif

}


/**
* PKIX Path Validation
* @param end_certs certificate chain to validate
* @param restrictions path validation restrictions
* @param trusted_roots list of certificate stores that contain trusted certificates
* @param hostname if not empty, compared against the DNS name in end_certs[0]
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_certs[0]
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeoutput for OCSP operations, 0 disables OCSP check
* @return result of the path validation
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& trusted_roots,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0));

/**
* PKIX Path Validation
* @param end_cert certificate to validate
* @param restrictions path validation restrictions
* @param trusted_roots list of stores that contain trusted certificates
* @param hostname if not empty, compared against the DNS name in end_cert
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_cert
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeoutput for OCSP operations, 0 disables OCSP check
* @return result of the path validation
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& trusted_roots,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0));

/**
* PKIX Path Validation
* @param end_cert certificate to validate
* @param restrictions path validation restrictions
* @param store store that contains trusted certificates
* @param hostname if not empty, compared against the DNS name in end_cert
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_cert
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeoutput for OCSP operations, 0 disables OCSP check
* @return result of the path validation
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0));

/**
* PKIX Path Validation
* @param end_certs certificate chain to validate
* @param restrictions path validation restrictions
* @param store store that contains trusted certificates
* @param hostname if not empty, compared against the DNS name in end_certs[0]
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_certs[0]
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeoutput for OCSP operations, 0 disables OCSP check
* @return result of the path validation
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0));

}

#endif

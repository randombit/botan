/*
* X.509 Cert Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_CERT_PATH_VALIDATION_H__
#define BOTAN_X509_CERT_PATH_VALIDATION_H__

#include <botan/x509cert.h>
#include <botan/certstor.h>
#include <set>

namespace Botan {

/**
* X.509 Certificate Validation Result
*/
enum X509_Path_Validation_Code {
   VERIFIED,
   UNKNOWN_X509_ERROR,
   CANNOT_ESTABLISH_TRUST,
   CERT_CHAIN_TOO_LONG,
   SIGNATURE_ERROR,
   POLICY_ERROR,
   INVALID_USAGE,

   CERT_MULTIPLE_ISSUERS_FOUND,

   CERT_FORMAT_ERROR,
   CERT_ISSUER_NOT_FOUND,
   CERT_NOT_YET_VALID,
   CERT_HAS_EXPIRED,
   CERT_IS_REVOKED,

   CRL_NOT_FOUND,
   CRL_FORMAT_ERROR,
   CRL_ISSUER_NOT_FOUND,
   CRL_NOT_YET_VALID,
   CRL_HAS_EXPIRED,

   CA_CERT_CANNOT_SIGN,
   CA_CERT_NOT_FOR_CERT_ISSUER,
   CA_CERT_NOT_FOR_CRL_ISSUER
};

      enum Usage_Restrictions {
         NO_RESTRICTIONS  = 0x00,
         TLS_SERVER       = 0x01,
         TLS_CLIENT       = 0x02,
         CODE_SIGNING     = 0x04,
         EMAIL_PROTECTION = 0x08,
         TIME_STAMPING    = 0x10,
         CRL_SIGNING      = 0x20
      };

class Path_Validation_Result
   {
   public:
      Path_Validation_Result() :
         validation_result(UNKNOWN_X509_ERROR),
         allowed_usages(NO_RESTRICTIONS)
         {}

      X509_Path_Validation_Code validation_result;
      Usage_Restrictions allowed_usages;

      std::vector<X509_Certificate> cert_path;

      /**
      * Returns the set of hash functions you are implicitly
      * trusting by trusting this result.
      */
      std::set<std::string> trusted_hashes() const;
   };

Path_Validation_Result BOTAN_DLL x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const std::vector<Certificate_Store*>& certstores);

Path_Validation_Result BOTAN_DLL x509_path_validate(
   const X509_Certificate& end_cert,
   const std::vector<Certificate_Store*>& certstores);

Path_Validation_Result BOTAN_DLL x509_path_validate(
   const X509_Certificate& end_cert,
   Certificate_Store& store);

Path_Validation_Result BOTAN_DLL x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   Certificate_Store& store);

}

#endif

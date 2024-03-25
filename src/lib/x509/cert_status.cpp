/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_enums.h>

namespace Botan {

const char* to_string(Certificate_Status_Code code) {
   switch(code) {
      case Certificate_Status_Code::VERIFIED:
         return "Verified";
      case Certificate_Status_Code::OCSP_RESPONSE_GOOD:
         return "OCSP response accepted as affirming unrevoked status for certificate";
      case Certificate_Status_Code::OCSP_SIGNATURE_OK:
         return "Signature on OCSP response was found valid";
      case Certificate_Status_Code::VALID_CRL_CHECKED:
         return "Valid CRL examined";

      case Certificate_Status_Code::CERT_SERIAL_NEGATIVE:
         return "Certificate serial number is negative";
      case Certificate_Status_Code::DN_TOO_LONG:
         return "Distinguished name too long";
      case Certificate_Status_Code::OCSP_NO_REVOCATION_URL:
         return "OCSP URL not available";
      case Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE:
         return "OCSP server not available";
      case Certificate_Status_Code::TRUSTED_CERT_NOT_YET_VALID:
         return "Trusted certificate is not yet valid";
      case Certificate_Status_Code::TRUSTED_CERT_HAS_EXPIRED:
         return "Trusted certificate has expired";
      case Certificate_Status_Code::OCSP_ISSUER_NOT_TRUSTED:
         return "OCSP issuer is not trustworthy";

      case Certificate_Status_Code::NO_REVOCATION_DATA:
         return "No revocation data";
      case Certificate_Status_Code::SIGNATURE_METHOD_TOO_WEAK:
         return "Signature method too weak";
      case Certificate_Status_Code::UNTRUSTED_HASH:
         return "Hash function used is considered too weak for security";

      case Certificate_Status_Code::CERT_NOT_YET_VALID:
         return "Certificate is not yet valid";
      case Certificate_Status_Code::CERT_HAS_EXPIRED:
         return "Certificate has expired";
      case Certificate_Status_Code::OCSP_NOT_YET_VALID:
         return "OCSP is not yet valid";
      case Certificate_Status_Code::OCSP_HAS_EXPIRED:
         return "OCSP response has expired";
      case Certificate_Status_Code::OCSP_IS_TOO_OLD:
         return "OCSP response is too old";
      case Certificate_Status_Code::CRL_NOT_YET_VALID:
         return "CRL response is not yet valid";
      case Certificate_Status_Code::CRL_HAS_EXPIRED:
         return "CRL has expired";

      case Certificate_Status_Code::CERT_ISSUER_NOT_FOUND:
         return "Certificate issuer not found";
      case Certificate_Status_Code::CANNOT_ESTABLISH_TRUST:
         return "Cannot establish trust";
      case Certificate_Status_Code::CERT_CHAIN_LOOP:
         return "Loop in certificate chain";
      case Certificate_Status_Code::CHAIN_LACKS_TRUST_ROOT:
         return "Certificate chain does not end in a CA certificate";
      case Certificate_Status_Code::CHAIN_NAME_MISMATCH:
         return "Certificate issuer does not match subject of issuing cert";

      case Certificate_Status_Code::POLICY_ERROR:
         return "Certificate policy error";
      case Certificate_Status_Code::DUPLICATE_CERT_POLICY:
         return "Certificate contains duplicate policy";
      case Certificate_Status_Code::INVALID_USAGE:
         return "Certificate does not allow the requested usage";
      case Certificate_Status_Code::CERT_CHAIN_TOO_LONG:
         return "Certificate chain too long";
      case Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER:
         return "CA certificate not allowed to issue certs";
      case Certificate_Status_Code::CA_CERT_NOT_FOR_CRL_ISSUER:
         return "CA certificate not allowed to issue CRLs";
      case Certificate_Status_Code::NO_MATCHING_CRLDP:
         return "No CRL with matching distribution point for certificate";
      case Certificate_Status_Code::OCSP_CERT_NOT_LISTED:
         return "OCSP cert not listed";
      case Certificate_Status_Code::OCSP_BAD_STATUS:
         return "OCSP bad status";
      case Certificate_Status_Code::CERT_NAME_NOMATCH:
         return "Certificate does not match provided name";
      case Certificate_Status_Code::NAME_CONSTRAINT_ERROR:
         return "Certificate does not pass name constraint";
      case Certificate_Status_Code::UNKNOWN_CRITICAL_EXTENSION:
         return "Unknown critical extension encountered";
      case Certificate_Status_Code::DUPLICATE_CERT_EXTENSION:
         return "Duplicate certificate extension encountered";
      case Certificate_Status_Code::EXT_IN_V1_V2_CERT:
         return "Encountered extension in certificate with version that does not allow it";
      case Certificate_Status_Code::V2_IDENTIFIERS_IN_V1_CERT:
         return "Encountered v2 identifiers in v1 certificate";
      case Certificate_Status_Code::OCSP_SIGNATURE_ERROR:
         return "OCSP signature error";
      case Certificate_Status_Code::OCSP_ISSUER_NOT_FOUND:
         return "Unable to find certificate issusing OCSP response";
      case Certificate_Status_Code::OCSP_RESPONSE_MISSING_KEYUSAGE:
         return "OCSP issuer's keyusage prohibits OCSP";
      case Certificate_Status_Code::OCSP_RESPONSE_INVALID:
         return "OCSP parsing valid";
      case Certificate_Status_Code::OCSP_NO_HTTP:
         return "OCSP requests not available, no HTTP support compiled in";
      case Certificate_Status_Code::CERT_IS_REVOKED:
         return "Certificate is revoked";
      case Certificate_Status_Code::CRL_BAD_SIGNATURE:
         return "CRL bad signature";
      case Certificate_Status_Code::SIGNATURE_ERROR:
         return "Signature error";
      case Certificate_Status_Code::CERT_PUBKEY_INVALID:
         return "Certificate public key invalid";
      case Certificate_Status_Code::SIGNATURE_ALGO_UNKNOWN:
         return "Certificate signed with unknown/unavailable algorithm";
      case Certificate_Status_Code::SIGNATURE_ALGO_BAD_PARAMS:
         return "Certificate signature has invalid parameters";

         // intentionally no default so we are warned if new enum values are added
   }

   return nullptr;
}

}  // namespace Botan

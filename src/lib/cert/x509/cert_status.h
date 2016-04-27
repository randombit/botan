/*
* Result enums
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_PATH_RESULT_H__
#define BOTAN_X509_PATH_RESULT_H__

namespace Botan {

enum class Certificate_Status_Code {
   VERIFIED = 0x00000000,
   OCSP_RESPONSE_GOOD,
   NO_REVOCATION_DATA,

   // Local policy failures
   SIGNATURE_METHOD_TOO_WEAK = 1000,
   UNTRUSTED_HASH,

   // Time problems
   CERT_NOT_YET_VALID = 2000,
   CERT_HAS_EXPIRED,
   OCSP_NOT_YET_VALID,
   OCSP_HAS_EXPIRED,
   CRL_NOT_YET_VALID,
   CRL_HAS_EXPIRED,

   // Chain generation problems
   CERT_ISSUER_NOT_FOUND = 3000,
   CANNOT_ESTABLISH_TRUST,

   CERT_CHAIN_LOOP,

   // Validation errors
   POLICY_ERROR = 4000,
   INVALID_USAGE,
   CERT_CHAIN_TOO_LONG,
   CA_CERT_NOT_FOR_CERT_ISSUER,
   NAME_CONSTRAINT_ERROR,

   // Revocation errors
   CA_CERT_NOT_FOR_CRL_ISSUER,
   OCSP_CERT_NOT_LISTED,
   OCSP_BAD_STATUS,

   CERT_NAME_NOMATCH,

   UNKNOWN_CRITICAL_EXTENSION,

   // Hard failures
   CERT_IS_REVOKED = 5000,
   CRL_BAD_SIGNATURE,
   SIGNATURE_ERROR,
};

}

#endif

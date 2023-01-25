/*
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_PKIX_ENUMS_H_
#define BOTAN_X509_PKIX_ENUMS_H_

#include <botan/types.h>

namespace Botan {

class Public_Key;

/**
* Certificate validation status code
*/
enum class Certificate_Status_Code {
   OK = 0,
   VERIFIED = 0,

   // Revocation status
   OCSP_RESPONSE_GOOD = 1,
   OCSP_SIGNATURE_OK = 2,
   VALID_CRL_CHECKED = 3,
   OCSP_NO_HTTP = 4,

   // Warnings
   FIRST_WARNING_STATUS = 500,
   CERT_SERIAL_NEGATIVE = 500,
   DN_TOO_LONG = 501,
   OCSP_NO_REVOCATION_URL = 502,
   OCSP_SERVER_NOT_AVAILABLE = 503,

   // Errors
   FIRST_ERROR_STATUS = 1000,

   SIGNATURE_METHOD_TOO_WEAK = 1000,
   UNTRUSTED_HASH = 1001,
   NO_REVOCATION_DATA = 1002,
   NO_MATCHING_CRLDP = 1003,
   OCSP_ISSUER_NOT_TRUSTED = 1004,

   // Time problems
   CERT_NOT_YET_VALID = 2000,
   CERT_HAS_EXPIRED = 2001,
   OCSP_NOT_YET_VALID = 2002,
   OCSP_HAS_EXPIRED = 2003,
   CRL_NOT_YET_VALID = 2004,
   CRL_HAS_EXPIRED = 2005,
   OCSP_IS_TOO_OLD = 2006,

   // Chain generation problems
   CERT_ISSUER_NOT_FOUND = 3000,
   CANNOT_ESTABLISH_TRUST = 3001,
   CERT_CHAIN_LOOP = 3002,
   CHAIN_LACKS_TRUST_ROOT = 3003,
   CHAIN_NAME_MISMATCH = 3004,

   // Validation errors
   POLICY_ERROR = 4000,
   INVALID_USAGE = 4001,
   CERT_CHAIN_TOO_LONG = 4002,
   CA_CERT_NOT_FOR_CERT_ISSUER = 4003,
   NAME_CONSTRAINT_ERROR = 4004,

   // Revocation errors
   CA_CERT_NOT_FOR_CRL_ISSUER = 4005,
   OCSP_CERT_NOT_LISTED = 4006,
   OCSP_BAD_STATUS = 4007,

   // Other problems
   CERT_NAME_NOMATCH = 4008,
   UNKNOWN_CRITICAL_EXTENSION = 4009,
   DUPLICATE_CERT_EXTENSION = 4010,
   OCSP_SIGNATURE_ERROR = 4501,
   OCSP_ISSUER_NOT_FOUND = 4502,
   OCSP_RESPONSE_MISSING_KEYUSAGE = 4503,
   OCSP_RESPONSE_INVALID = 4504,
   EXT_IN_V1_V2_CERT = 4505,
   DUPLICATE_CERT_POLICY = 4506,
   V2_IDENTIFIERS_IN_V1_CERT = 4507,

   // Hard failures
   CERT_IS_REVOKED = 5000,
   CRL_BAD_SIGNATURE = 5001,
   SIGNATURE_ERROR = 5002,
   CERT_PUBKEY_INVALID = 5003,
   SIGNATURE_ALGO_UNKNOWN = 5004,
   SIGNATURE_ALGO_BAD_PARAMS = 5005
};

/**
* Convert a status code to a human readable diagnostic message
* @param code the certifcate status
* @return string literal constant, or nullptr if code unknown
*/
BOTAN_PUBLIC_API(2,0) const char* to_string(Certificate_Status_Code code);

/**
* X.509v3 Key Constraints.
* If updating update copy in ffi.h
*/
class BOTAN_PUBLIC_API(3,0) Key_Constraints
   {
   public:
      enum Key_Constraints_Bits : uint32_t {
         None              = 0,
         DigitalSignature  = 1 << 15,
         NonRepudiation    = 1 << 14,
         KeyEncipherment   = 1 << 13,
         DataEncipherment  = 1 << 12,
         KeyAgreement      = 1 << 11,
         KeyCertSign       = 1 << 10,
         CrlSign           = 1 << 9,
         EncipherOnly      = 1 << 8,
         DecipherOnly      = 1 << 7,

         // Deprecated SHOUTING_CASE names for Key_Constraints
         // will be removed in a future major release
         NO_CONSTRAINTS    = None,
         DIGITAL_SIGNATURE = DigitalSignature,
         NON_REPUDIATION   = NonRepudiation,
         KEY_ENCIPHERMENT  = KeyEncipherment,
         DATA_ENCIPHERMENT = DataEncipherment,
         KEY_AGREEMENT     = KeyAgreement,
         KEY_CERT_SIGN     = KeyCertSign,
         CRL_SIGN          = CrlSign,
         ENCIPHER_ONLY     = EncipherOnly,
         DECIPHER_ONLY     = DecipherOnly,
      };

      Key_Constraints(const Key_Constraints& other) = default;
      Key_Constraints(Key_Constraints&& other) = default;
      Key_Constraints& operator=(const Key_Constraints& other) = default;
      Key_Constraints& operator=(Key_Constraints&& other) = default;

      Key_Constraints(Key_Constraints_Bits bits) : m_value(bits) {}

      explicit Key_Constraints(uint32_t bits) : m_value(bits) {}

      Key_Constraints() : m_value(0) {}

      bool operator==(const Key_Constraints& other) const { return m_value == other.m_value; }
      bool operator!=(const Key_Constraints& other) const { return m_value != other.m_value; }

      bool operator==(Key_Constraints_Bits other) const { return m_value == other; }
      bool operator!=(Key_Constraints_Bits other) const { return m_value != other; }

      void operator|=(Key_Constraints_Bits other)
         {
         m_value |= other;
         }

      // Return true if all bits in mask are set
      bool includes(Key_Constraints_Bits other) const { return (m_value & other) == other; }
      bool includes(Key_Constraints other) const { return (m_value & other.m_value) == other.m_value; }

      bool empty() const { return m_value == 0; }

      uint32_t value() const { return m_value; }

      std::string to_string() const;

      /**
      * Check that key constraints are permitted for a specific public key.
      * @param pub_key the public key on which the constraints shall be enforced on
      * @return false if the constraints are not permitted for this key
      */
      bool compatible_with(const Public_Key& key) const;
   private:
      uint32_t m_value;
   };

/**
* X.509v2 CRL Reason Code.
*/
enum class CRL_Code : uint32_t {
   UNSPECIFIED            = 0,
   KEY_COMPROMISE         = 1,
   CA_COMPROMISE          = 2,
   AFFILIATION_CHANGED    = 3,
   SUPERSEDED             = 4,
   CESSATION_OF_OPERATION = 5,
   CERTIFICATE_HOLD       = 6,
   REMOVE_FROM_CRL        = 8,
   PRIVLEDGE_WITHDRAWN    = 9,
   PRIVILEGE_WITHDRAWN    = 9,
   AA_COMPROMISE          = 10,

   DELETE_CRL_ENTRY       = 0xFF00,
   OCSP_GOOD              = 0xFF01,
   OCSP_UNKNOWN           = 0xFF02
};

}

#endif

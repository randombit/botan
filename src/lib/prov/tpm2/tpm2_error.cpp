/*
* TPM 2 error handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_error.h>

#include <botan/internal/fmt.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_rc.h>

namespace Botan::TPM2 {

TSS2_RC get_raw_rc(TSS2_RC rc) {
#if defined(BOTAN_TSS2_SUPPORTS_ERROR_DECODING)
   TSS2_RC_INFO info;
   const TSS2_RC decoding_rc = Tss2_RC_DecodeInfo(rc, &info);
   if(decoding_rc != TSS2_RC_SUCCESS) [[unlikely]] {
      throw Error(fmt("Decoding RC failed (was: {})", rc), decoding_rc);
   }
   return info.error;
#else
   // This fallback implementation is derived from the implementation of
   // Tss2_RC_DecodeInfo in tpm2-tss 4.0.0.
   const bool formatted = (rc & (1 << 7)) != 0;
   if(formatted) {
      return (rc & 0x3F) | TPM2_RC_FMT1;
   } else {
      return rc & 0xFFFF;
   }
#endif
}

namespace {

std::string raw_rc_to_string(TSS2_RC rc) noexcept {
   switch(rc) {
      case TPM2_RC_SUCCESS:
         return "TPM2_RC_SUCCESS";
      case TPM2_RC_BAD_TAG:
         return "TPM2_RC_BAD_TAG";
      case TPM2_RC_INITIALIZE:
         return "TPM2_RC_INITIALIZE";
      case TPM2_RC_FAILURE:
         return "TPM2_RC_FAILURE";
      case TPM2_RC_SEQUENCE:
         return "TPM2_RC_SEQUENCE";
      case TPM2_RC_PRIVATE:
         return "TPM2_RC_PRIVATE";
      case TPM2_RC_HMAC:
         return "TPM2_RC_HMAC";
      case TPM2_RC_DISABLED:
         return "TPM2_RC_DISABLED";
      case TPM2_RC_EXCLUSIVE:
         return "TPM2_RC_EXCLUSIVE";
      case TPM2_RC_AUTH_TYPE:
         return "TPM2_RC_AUTH_TYPE";
      case TPM2_RC_AUTH_MISSING:
         return "TPM2_RC_AUTH_MISSING";
      case TPM2_RC_POLICY:
         return "TPM2_RC_POLICY";
      case TPM2_RC_PCR:
         return "TPM2_RC_PCR";
      case TPM2_RC_PCR_CHANGED:
         return "TPM2_RC_PCR_CHANGED";
      case TPM2_RC_UPGRADE:
         return "TPM2_RC_UPGRADE";
      case TPM2_RC_TOO_MANY_CONTEXTS:
         return "TPM2_RC_TOO_MANY_CONTEXTS";
      case TPM2_RC_AUTH_UNAVAILABLE:
         return "TPM2_RC_AUTH_UNAVAILABLE";
      case TPM2_RC_REBOOT:
         return "TPM2_RC_REBOOT";
      case TPM2_RC_UNBALANCED:
         return "TPM2_RC_UNBALANCED";
      case TPM2_RC_COMMAND_SIZE:
         return "TPM2_RC_COMMAND_SIZE";
      case TPM2_RC_COMMAND_CODE:
         return "TPM2_RC_COMMAND_CODE";
      case TPM2_RC_AUTHSIZE:
         return "TPM2_RC_AUTHSIZE";
      case TPM2_RC_AUTH_CONTEXT:
         return "TPM2_RC_AUTH_CONTEXT";
      case TPM2_RC_NV_RANGE:
         return "TPM2_RC_NV_RANGE";
      case TPM2_RC_NV_SIZE:
         return "TPM2_RC_NV_SIZE";
      case TPM2_RC_NV_LOCKED:
         return "TPM2_RC_NV_LOCKED";
      case TPM2_RC_NV_AUTHORIZATION:
         return "TPM2_RC_NV_AUTHORIZATION";
      case TPM2_RC_NV_UNINITIALIZED:
         return "TPM2_RC_NV_UNINITIALIZED";
      case TPM2_RC_NV_SPACE:
         return "TPM2_RC_NV_SPACE";
      case TPM2_RC_NV_DEFINED:
         return "TPM2_RC_NV_DEFINED";
      case TPM2_RC_BAD_CONTEXT:
         return "TPM2_RC_BAD_CONTEXT";
      case TPM2_RC_CPHASH:
         return "TPM2_RC_CPHASH";
      case TPM2_RC_PARENT:
         return "TPM2_RC_PARENT";
      case TPM2_RC_NEEDS_TEST:
         return "TPM2_RC_NEEDS_TEST";
      case TPM2_RC_NO_RESULT:
         return "TPM2_RC_NO_RESULT";
      case TPM2_RC_SENSITIVE:
         return "TPM2_RC_SENSITIVE";
      case TPM2_RC_MAX_FM0:
         return "TPM2_RC_MAX_FM0";
      case TPM2_RC_FMT1:
         return "TPM2_RC_FMT1";
      case TPM2_RC_ASYMMETRIC:
         return "TPM2_RC_ASYMMETRIC";
      case TPM2_RC_ATTRIBUTES:
         return "TPM2_RC_ATTRIBUTES";
      case TPM2_RC_HASH:
         return "TPM2_RC_HASH";
      case TPM2_RC_VALUE:
         return "TPM2_RC_VALUE";
      case TPM2_RC_HIERARCHY:
         return "TPM2_RC_HIERARCHY";
      case TPM2_RC_KEY_SIZE:
         return "TPM2_RC_KEY_SIZE";
      case TPM2_RC_MGF:
         return "TPM2_RC_MGF";
      case TPM2_RC_MODE:
         return "TPM2_RC_MODE";
      case TPM2_RC_TYPE:
         return "TPM2_RC_TYPE";
      case TPM2_RC_HANDLE:
         return "TPM2_RC_HANDLE";
      case TPM2_RC_KDF:
         return "TPM2_RC_KDF";
      case TPM2_RC_RANGE:
         return "TPM2_RC_RANGE";
      case TPM2_RC_AUTH_FAIL:
         return "TPM2_RC_AUTH_FAIL";
      case TPM2_RC_NONCE:
         return "TPM2_RC_NONCE";
      case TPM2_RC_PP:
         return "TPM2_RC_PP";
      case TPM2_RC_SCHEME:
         return "TPM2_RC_SCHEME";
      case TPM2_RC_SIZE:
         return "TPM2_RC_SIZE";
      case TPM2_RC_SYMMETRIC:
         return "TPM2_RC_SYMMETRIC";
      case TPM2_RC_TAG:
         return "TPM2_RC_TAG";
      case TPM2_RC_SELECTOR:
         return "TPM2_RC_SELECTOR";
      case TPM2_RC_INSUFFICIENT:
         return "TPM2_RC_INSUFFICIENT";
      case TPM2_RC_SIGNATURE:
         return "TPM2_RC_SIGNATURE";
      case TPM2_RC_KEY:
         return "TPM2_RC_KEY";
      case TPM2_RC_POLICY_FAIL:
         return "TPM2_RC_POLICY_FAIL";
      case TPM2_RC_INTEGRITY:
         return "TPM2_RC_INTEGRITY";
      case TPM2_RC_TICKET:
         return "TPM2_RC_TICKET";
      case TPM2_RC_RESERVED_BITS:
         return "TPM2_RC_RESERVED_BITS";
      case TPM2_RC_BAD_AUTH:
         return "TPM2_RC_BAD_AUTH";
      case TPM2_RC_EXPIRED:
         return "TPM2_RC_EXPIRED";
      case TPM2_RC_POLICY_CC:
         return "TPM2_RC_POLICY_CC";
      case TPM2_RC_BINDING:
         return "TPM2_RC_BINDING";
      case TPM2_RC_CURVE:
         return "TPM2_RC_CURVE";
      case TPM2_RC_ECC_POINT:
         return "TPM2_RC_ECC_POINT";
      case TPM2_RC_WARN:
         return "TPM2_RC_WARN";
      case TPM2_RC_CONTEXT_GAP:
         return "TPM2_RC_CONTEXT_GAP";
      case TPM2_RC_OBJECT_MEMORY:
         return "TPM2_RC_OBJECT_MEMORY";
      case TPM2_RC_SESSION_MEMORY:
         return "TPM2_RC_SESSION_MEMORY";
      case TPM2_RC_MEMORY:
         return "TPM2_RC_MEMORY";
      case TPM2_RC_SESSION_HANDLES:
         return "TPM2_RC_SESSION_HANDLES";
      case TPM2_RC_OBJECT_HANDLES:
         return "TPM2_RC_OBJECT_HANDLES";
      case TPM2_RC_LOCALITY:
         return "TPM2_RC_LOCALITY";
      case TPM2_RC_YIELDED:
         return "TPM2_RC_YIELDED";
      case TPM2_RC_CANCELED:
         return "TPM2_RC_CANCELED";
      case TPM2_RC_TESTING:
         return "TPM2_RC_TESTING";
      case TPM2_RC_REFERENCE_H0:
         return "TPM2_RC_REFERENCE_H0";
      case TPM2_RC_REFERENCE_H1:
         return "TPM2_RC_REFERENCE_H1";
      case TPM2_RC_REFERENCE_H2:
         return "TPM2_RC_REFERENCE_H2";
      case TPM2_RC_REFERENCE_H3:
         return "TPM2_RC_REFERENCE_H3";
      case TPM2_RC_REFERENCE_H4:
         return "TPM2_RC_REFERENCE_H4";
      case TPM2_RC_REFERENCE_H5:
         return "TPM2_RC_REFERENCE_H5";
      case TPM2_RC_REFERENCE_H6:
         return "TPM2_RC_REFERENCE_H6";
      case TPM2_RC_REFERENCE_S0:
         return "TPM2_RC_REFERENCE_S0";
      case TPM2_RC_REFERENCE_S1:
         return "TPM2_RC_REFERENCE_S1";
      case TPM2_RC_REFERENCE_S2:
         return "TPM2_RC_REFERENCE_S2";
      case TPM2_RC_REFERENCE_S3:
         return "TPM2_RC_REFERENCE_S3";
      case TPM2_RC_REFERENCE_S4:
         return "TPM2_RC_REFERENCE_S4";
      case TPM2_RC_REFERENCE_S5:
         return "TPM2_RC_REFERENCE_S5";
      case TPM2_RC_REFERENCE_S6:
         return "TPM2_RC_REFERENCE_S6";
      case TPM2_RC_NV_RATE:
         return "TPM2_RC_NV_RATE";
      case TPM2_RC_LOCKOUT:
         return "TPM2_RC_LOCKOUT";
      case TPM2_RC_RETRY:
         return "TPM2_RC_RETRY";
      case TPM2_RC_NV_UNAVAILABLE:
         return "TPM2_RC_NV_UNAVAILABLE";

      default:
         return Botan::fmt("Unknown TSS2_RC: {}", rc);
   }
}

}  // namespace

Error::Error(std::string_view location, TSS2_RC rc) :
      Exception(fmt("TPM2 Exception in {}: Code {} - {} ({})",
                    location,
                    raw_rc_to_string(get_raw_rc(rc)),
                    rc,
                    Tss2_RC_Decode(rc))),
      m_rc(rc) {}

std::string Error::error_message() const {
   return Tss2_RC_Decode(m_rc);
}

}  // namespace Botan::TPM2

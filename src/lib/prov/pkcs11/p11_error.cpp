/*
* PKCS #11 Error Information
* (C) 2025 Jack Lloyd
* (C) 2025 Fabian Albert - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11.h>
#include <botan/internal/fmt.h>

namespace Botan::PKCS11 {

namespace {
std::string to_string(ReturnValue return_val) {
   switch(return_val) {
      case ReturnValue::OK:
         return "function executed successfully";
      case ReturnValue::Cancel:
         return "function aborted by application";
      case ReturnValue::HostMemory:
         return "insufficient memory to perform function";
      case ReturnValue::SlotIdInvalid:
         return "invalid slot id";
      case ReturnValue::GeneralError:
         return "unrecoverable error occurred";
      case ReturnValue::FunctionFailed:
         return "function failed without detailed information";
      case ReturnValue::ArgumentsBad:
         return "invalid arguments supplied";
      case ReturnValue::NoEvent:
         return "no new slot events";
      case ReturnValue::NeedToCreateThreads:
         return "library needs to create threads";
      case ReturnValue::CantLock:
         return "requested locking not available";
      case ReturnValue::AttributeReadOnly:
         return "attribute cannot be modified";
      case ReturnValue::AttributeSensitive:
         return "attribute is sensitive and cannot be revealed";
      case ReturnValue::AttributeTypeInvalid:
         return "invalid attribute type";
      case ReturnValue::AttributeValueInvalid:
         return "invalid attribute value";
      case ReturnValue::ActionProhibited:
         return "action not allowed by policy";
      case ReturnValue::DataInvalid:
         return "invalid plaintext input data";
      case ReturnValue::DataLenRange:
         return "plaintext data length out of range";
      case ReturnValue::DeviceError:
         return "problem with token or slot";
      case ReturnValue::DeviceMemory:
         return "insufficient token memory";
      case ReturnValue::DeviceRemoved:
         return "token removed during function execution";
      case ReturnValue::EncryptedDataInvalid:
         return "invalid ciphertext input";
      case ReturnValue::EncryptedDataLenRange:
         return "ciphertext length out of range";
      case ReturnValue::AeadDecryptFailed:
         return "AEAD decrypt failed";
      case ReturnValue::FunctionCanceled:
         return "function canceled mid-execution";
      case ReturnValue::FunctionNotParallel:
         return "no function executing in parallel";
      case ReturnValue::FunctionNotSupported:
         return "function not supported";
      case ReturnValue::KeyHandleInvalid:
         return "invalid key handle";
      case ReturnValue::KeySizeRange:
         return "key size out of range";
      case ReturnValue::KeyTypeInconsistent:
         return "key type inconsistent with mechanism";
      case ReturnValue::KeyNotNeeded:
         return "extraneous key supplied";
      case ReturnValue::KeyChanged:
         return "key changed";
      case ReturnValue::KeyNeeded:
         return "key needed to restore session state";
      case ReturnValue::KeyIndigestible:
         return "key cannot be digested";
      case ReturnValue::KeyFunctionNotPermitted:
         return "key use not permitted";
      case ReturnValue::KeyNotWrappable:
         return "key cannot be wrapped";
      case ReturnValue::KeyUnextractable:
         return "key cannot be extracted";
      case ReturnValue::MechanismInvalid:
         return "invalid mechanism specified";
      case ReturnValue::MechanismParamInvalid:
         return "invalid mechanism parameters";
      case ReturnValue::ObjectHandleInvalid:
         return "invalid object handle";
      case ReturnValue::OperationActive:
         return "conflicting active operation";
      case ReturnValue::OperationNotInitialized:
         return "operation not initialized";
      case ReturnValue::PinIncorrect:
         return "incorrect PIN";
      case ReturnValue::PinInvalid:
         return "invalid PIN characters";
      case ReturnValue::PinLenRange:
         return "PIN length out of range";
      case ReturnValue::PinExpired:
         return "PIN expired";
      case ReturnValue::PinLocked:
         return "PIN locked due to failed attempts";
      case ReturnValue::SessionClosed:
         return "session closed during function execution";
      case ReturnValue::SessionCount:
         return "too many sessions open";
      case ReturnValue::SessionHandleInvalid:
         return "invalid session handle";
      case ReturnValue::SessionParallelNotSupported:
         return "parallel sessions not supported";
      case ReturnValue::SessionReadOnly:
         return "read-only session";
      case ReturnValue::SessionExists:
         return "session already open";
      case ReturnValue::SessionReadOnlyExists:
         return "read-only session already exists";
      case ReturnValue::SessionReadWriteSoExists:
         return "read/write SO session exists";
      case ReturnValue::SignatureInvalid:
         return "invalid signature";
      case ReturnValue::SignatureLenRange:
         return "invalid signature length";
      case ReturnValue::TemplateIncomplete:
         return "incomplete template";
      case ReturnValue::TemplateInconsistent:
         return "conflicting template attributes";
      case ReturnValue::TokenNotPresent:
         return "token not present in slot";
      case ReturnValue::TokenNotRecognized:
         return "token not recognized";
      case ReturnValue::TokenWriteProtected:
         return "token is write-protected";
      case ReturnValue::UnwrappingKeyHandleInvalid:
         return "invalid unwrapping key handle";
      case ReturnValue::UnwrappingKeySizeRange:
         return "unwrapping key size out of range";
      case ReturnValue::UnwrappingKeyTypeInconsistent:
         return "unwrapping key type inconsistent";
      case ReturnValue::UserAlreadyLoggedIn:
         return "user already logged in";
      case ReturnValue::UserNotLoggedIn:
         return "user not logged in";
      case ReturnValue::UserPinNotInitialized:
         return "user PIN not initialized";
      case ReturnValue::UserTypeInvalid:
         return "invalid user type";
      case ReturnValue::UserAnotherAlreadyLoggedIn:
         return "another user already logged in";
      case ReturnValue::UserTooManyTypes:
         return "too many distinct users logged in";
      case ReturnValue::WrappedKeyInvalid:
         return "invalid wrapped key";
      case ReturnValue::WrappedKeyLenRange:
         return "wrapped key length out of range";
      case ReturnValue::WrappingKeyHandleInvalid:
         return "invalid wrapping key handle";
      case ReturnValue::WrappingKeySizeRange:
         return "wrapping key size out of range";
      case ReturnValue::WrappingKeyTypeInconsistent:
         return "wrapping key type inconsistent";
      case ReturnValue::RandomSeedNotSupported:
         return "RNG does not accept seeding";
      case ReturnValue::RandomNoRng:
         return "no random number generator";
      case ReturnValue::DomainParamsInvalid:
         return "invalid domain parameters";
      case ReturnValue::CurveNotSupported:
         return "curve not supported by token";
      case ReturnValue::BufferTooSmall:
         return "output buffer too small";
      case ReturnValue::SavedStateInvalid:
         return "invalid saved state";
      case ReturnValue::InformationSensitive:
         return "information is sensitive";
      case ReturnValue::StateUnsaveable:
         return "state cannot be saved";
      case ReturnValue::CryptokiNotInitialized:
         return "library not initialized";
      case ReturnValue::CryptokiAlreadyInitialized:
         return "library already initialized";
      case ReturnValue::MutexBad:
         return "bad mutex object";
      case ReturnValue::MutexNotLocked:
         return "mutex not locked";
      case ReturnValue::NewPinMode:
         return "new PIN mode";
      case ReturnValue::NextOtp:
         return "next OTP";
      case ReturnValue::ExceededMaxIterations:
         return "exceeded max iterations";
      case ReturnValue::FipsSelfTestFailed:
         return "FIPS self-test failed";
      case ReturnValue::LibraryLoadFailed:
         return "failed to load dependent library";
      case ReturnValue::PinTooWeak:
         return "PIN too weak";
      case ReturnValue::PublicKeyInvalid:
         return "invalid public key";
      case ReturnValue::FunctionRejected:
         return "signature request rejected by user";
      case ReturnValue::TokenResourceExceeded:
         return "token resource exceeded";
      case ReturnValue::OperationCancelFailed:
         return "operation cancel failed";
      case ReturnValue::KeyExhausted:
         return "key exhausted";
      case ReturnValue::Pending:
         return "operation running asynchronously";
      case ReturnValue::SessionAsyncNotSupported:
         return "async operations not supported";
      case ReturnValue::SeedRandomRequired:
         return "RNG needs seeding";
      case ReturnValue::OperationNotValidated:
         return "operation violates token validation policies";
      case ReturnValue::TokenNotInitialized:
         return "token needs initialization";
      case ReturnValue::VendorDefined:
         return "vendor defined error";
   }
   return "unknown error";
}
}  // namespace

PKCS11_ReturnError::PKCS11_ReturnError(ReturnValue return_val) :
      PKCS11_Error(Botan::fmt("{} ({})", static_cast<uint32_t>(return_val), to_string(return_val))),
      m_return_val(return_val) {}

}  // namespace Botan::PKCS11

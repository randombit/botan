/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/exceptn.h>

#include <botan/internal/fmt.h>

namespace Botan {

std::string to_string(ErrorType type) {
   switch(type) {
      case ErrorType::Unknown:
         return "Unknown";
      case ErrorType::SystemError:
         return "SystemError";
      case ErrorType::NotImplemented:
         return "NotImplemented";
      case ErrorType::OutOfMemory:
         return "OutOfMemory";
      case ErrorType::InternalError:
         return "InternalError";
      case ErrorType::IoError:
         return "IoError";
      case ErrorType::InvalidObjectState:
         return "InvalidObjectState";
      case ErrorType::KeyNotSet:
         return "KeyNotSet";
      case ErrorType::InvalidArgument:
         return "InvalidArgument";
      case ErrorType::InvalidKeyLength:
         return "InvalidKeyLength";
      case ErrorType::InvalidNonceLength:
         return "InvalidNonceLength";
      case ErrorType::LookupError:
         return "LookupError";
      case ErrorType::EncodingFailure:
         return "EncodingFailure";
      case ErrorType::DecodingFailure:
         return "DecodingFailure";
      case ErrorType::TLSError:
         return "TLSError";
      case ErrorType::HttpError:
         return "HttpError";
      case ErrorType::InvalidTag:
         return "InvalidTag";
      case ErrorType::RoughtimeError:
         return "RoughtimeError";
      case ErrorType::CommonCryptoError:
         return "CommonCryptoError";
      case ErrorType::Pkcs11Error:
         return "Pkcs11Error";
      case ErrorType::TPMError:
         return "TPMError";
      case ErrorType::DatabaseError:
         return "DatabaseError";
      case ErrorType::ZlibError:
         return "ZlibError";
      case ErrorType::Bzip2Error:
         return "Bzip2Error";
      case ErrorType::LzmaError:
         return "LzmaError";
   }

   // No default case in above switch so compiler warns
   return "Unrecognized Botan error";
}

Exception::Exception(std::string_view msg) : m_msg(msg) {}

Exception::Exception(std::string_view msg, const std::exception& e) : m_msg(fmt("{} failed with {}", msg, e.what())) {}

Exception::Exception(const char* prefix, std::string_view msg) : m_msg(fmt("{} {}", prefix, msg)) {}

Invalid_Argument::Invalid_Argument(std::string_view msg) : Exception(msg) {}

Invalid_Argument::Invalid_Argument(std::string_view msg, std::string_view where) :
      Exception(fmt("{} in {}", msg, where)) {}

Invalid_Argument::Invalid_Argument(std::string_view msg, const std::exception& e) : Exception(msg, e) {}

namespace {

std::string format_lookup_error(std::string_view type, std::string_view algo, std::string_view provider) {
   if(provider.empty()) {
      return fmt("Unavailable {} {}", type, algo);
   } else {
      return fmt("Unavailable {} {} for provider {}", type, algo, provider);
   }
}

}  // namespace

Lookup_Error::Lookup_Error(std::string_view type, std::string_view algo, std::string_view provider) :
      Exception(format_lookup_error(type, algo, provider)) {}

Internal_Error::Internal_Error(std::string_view err) : Exception("Internal error:", err) {}

Unknown_PK_Field_Name::Unknown_PK_Field_Name(std::string_view algo_name, std::string_view field_name) :
      Invalid_Argument(fmt("Unknown field '{}' for algorithm {}", field_name, algo_name)) {}

Invalid_Key_Length::Invalid_Key_Length(std::string_view name, size_t length) :
      Invalid_Argument(fmt("{} cannot accept a key of length {}", name, length)) {}

Invalid_IV_Length::Invalid_IV_Length(std::string_view mode, size_t bad_len) :
      Invalid_Argument(fmt("IV length {} is invalid for {}", bad_len, mode)) {}

Key_Not_Set::Key_Not_Set(std::string_view algo) : Invalid_State(fmt("Key not set in {}", algo)) {}

PRNG_Unseeded::PRNG_Unseeded(std::string_view algo) : Invalid_State(fmt("PRNG {} not seeded", algo)) {}

Algorithm_Not_Found::Algorithm_Not_Found(std::string_view name) :
      Lookup_Error(fmt("Could not find any algorithm named '{}'", name)) {}

Provider_Not_Found::Provider_Not_Found(std::string_view algo, std::string_view provider) :
      Lookup_Error(fmt("Could not find provider '{}' for algorithm '{}'", provider, algo)) {}

Invalid_Algorithm_Name::Invalid_Algorithm_Name(std::string_view name) :
      Invalid_Argument(fmt("Invalid algorithm name: '{}'", name)) {}

Encoding_Error::Encoding_Error(std::string_view name) : Exception("Encoding error:", name) {}

Decoding_Error::Decoding_Error(std::string_view name) : Exception(name) {}

Decoding_Error::Decoding_Error(std::string_view category, std::string_view err) :
      Exception(fmt("{}: {}", category, err)) {}

Decoding_Error::Decoding_Error(std::string_view msg, const std::exception& e) : Exception(msg, e) {}

Invalid_Authentication_Tag::Invalid_Authentication_Tag(std::string_view msg) :
      Exception("Invalid authentication tag:", msg) {}

Stream_IO_Error::Stream_IO_Error(std::string_view err) : Exception("I/O error:", err) {}

System_Error::System_Error(std::string_view msg, int err_code) :
      Exception(fmt("{} error code {}", msg, err_code)), m_error_code(err_code) {}

Not_Implemented::Not_Implemented(std::string_view err) : Exception("Not implemented", err) {}

}  // namespace Botan

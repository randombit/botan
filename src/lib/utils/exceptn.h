/*
* Exceptions
* (C) 1999-2009,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EXCEPTION_H_
#define BOTAN_EXCEPTION_H_

#include <botan/types.h>
#include <exception>
#include <string>
#include <string_view>

namespace Botan {

/**
* Different types of errors that might occur
*/
enum class ErrorType : uint16_t {
   /** Some unknown error */
   Unknown = 1,
   /** An error while calling a system interface */
   SystemError = 2,
   /** An operation seems valid, but not supported by the current version */
   NotImplemented = 3,
   /** Memory allocation failure */
   OutOfMemory = 4,
   /** An internal error occurred */
   InternalError = 5,
   /** An I/O error occurred */
   IoError = 6,

   /** Invalid object state */
   InvalidObjectState = 100,
   /** A key was not set on an object when this is required */
   KeyNotSet = 101,
   /** The application provided an argument which is invalid */
   InvalidArgument = 102,
   /** A key with invalid length was provided */
   InvalidKeyLength = 103,
   /** A nonce with invalid length was provided */
   InvalidNonceLength = 104,
   /** An object type was requested but cannot be found */
   LookupError = 105,
   /** Encoding a message or datum failed */
   EncodingFailure = 106,
   /** Decoding a message or datum failed */
   DecodingFailure = 107,
   /** A TLS error (error_code will be the alert type) */
   TLSError = 108,
   /** An error during an HTTP operation */
   HttpError = 109,
   /** A message with an invalid authentication tag was detected */
   InvalidTag = 110,
   /** An error during Roughtime validation */
   RoughtimeError = 111,

   /** An error when interacting with CommonCrypto API */
   CommonCryptoError = 201,
   /** An error when interacting with a PKCS11 device */
   Pkcs11Error = 202,
   /** An error when interacting with a TPM device */
   TPMError = 203,
   /** An error when interacting with a database */
   DatabaseError = 204,

   /** An error when interacting with zlib */
   ZlibError = 300,
   /** An error when interacting with bzip2 */
   Bzip2Error = 301,
   /** An error when interacting with lzma */
   LzmaError = 302,

};

//! \brief Convert an ErrorType to string
std::string BOTAN_PUBLIC_API(2, 11) to_string(ErrorType type);

/**
* Base class for all exceptions thrown by the library
*/
class BOTAN_PUBLIC_API(2, 0) Exception : public std::exception {
   public:
      /**
      * Return a descriptive string which is hopefully comprehensible to
      * a developer. It will likely not be useful for an end user.
      *
      * The string has no particular format, and the content of exception
      * messages may change from release to release. Thus the main use of this
      * function is for logging or debugging.
      */
      const char* what() const noexcept override { return m_msg.c_str(); }

      /**
      * Return the "type" of error which occurred.
      */
      virtual ErrorType error_type() const noexcept { return ErrorType::Unknown; }

      /**
      * Return an error code associated with this exception, or otherwise 0.
      *
      * The domain of this error varies depending on the source, for example on
      * POSIX systems it might be errno, while on a Windows system it might be
      * the result of GetLastError or WSAGetLastError.
      */
      virtual int error_code() const noexcept { return 0; }

      /**
      * Avoid throwing base Exception, use a subclass
      */
      explicit Exception(std::string_view msg);

      /**
      * Avoid throwing base Exception, use a subclass
      */
      Exception(const char* prefix, std::string_view msg);

      /**
      * Avoid throwing base Exception, use a subclass
      */
      Exception(std::string_view msg, const std::exception& e);

   private:
      std::string m_msg;
};

/**
* An invalid argument was provided to an API call.
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_Argument : public Exception {
   public:
      /**
      * Create a Invalid_Argument exception
      * @param msg a description of the problem
      */
      explicit Invalid_Argument(std::string_view msg);

      /**
      * Create a Invalid_Argument exception
      * @param msg a description of the problem
      * @param where the API call which received the invalid argument
      */
      explicit Invalid_Argument(std::string_view msg, std::string_view where);

      /**
      * Create a Invalid_Argument exception
      * @param msg a description of the problem
      * @param e the exception which caused this one
      */
      Invalid_Argument(std::string_view msg, const std::exception& e);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::InvalidArgument; }
};

/**
* An invalid/unknown field name was passed to Public_Key::get_int_field
*/
class BOTAN_PUBLIC_API(3, 0) Unknown_PK_Field_Name final : public Invalid_Argument {
   public:
      /**
      * Create a Unknown_PK_Field_Name exception
      * @param algo_name the name of the key algorithm
      * @param field_name the unknown field which was requested
      */
      Unknown_PK_Field_Name(std::string_view algo_name, std::string_view field_name);
};

/**
* An invalid key length was used
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_Key_Length final : public Invalid_Argument {
   public:
      /**
      * Create a Invalid_Key_Length exception
      * @param name the name of the algorithm which rejected the key
      * @param length the invalid key length in bytes
      */
      Invalid_Key_Length(std::string_view name, size_t length);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::InvalidKeyLength; }
};

/**
* An invalid nonce length was used
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_IV_Length final : public Invalid_Argument {
   public:
      /**
      * Create a Invalid_IV_Length exception
      * @param mode the name of the mode which rejected the nonce
      * @param bad_len the invalid nonce length in bytes
      */
      Invalid_IV_Length(std::string_view mode, size_t bad_len);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::InvalidNonceLength; }
};

/**
* Invalid_Algorithm_Name Exception
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_Algorithm_Name final : public Invalid_Argument {
   public:
      /**
      * Create a Invalid_Algorithm_Name exception
      * @param name the algorithm name which could not be parsed
      */
      explicit Invalid_Algorithm_Name(std::string_view name);
};

/**
* Encoding_Error Exception
*/
class BOTAN_PUBLIC_API(2, 0) Encoding_Error final : public Exception {
   public:
      /**
      * Create a Encoding_Error exception
      * @param name a description of the encoding which failed
      */
      explicit Encoding_Error(std::string_view name);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::EncodingFailure; }
};

/**
* A decoding error occurred.
*/
class BOTAN_PUBLIC_API(2, 0) Decoding_Error : public Exception {
   public:
      /**
      * Create a Decoding_Error exception
      * @param name a description of the decoding which failed
      */
      explicit Decoding_Error(std::string_view name);

      /**
      * Create a Decoding_Error exception
      * @param category the kind of object being decoded
      * @param err a description of the problem
      */
      Decoding_Error(std::string_view category, std::string_view err);

      /**
      * Create a Decoding_Error exception
      * @param msg a description of the problem
      * @param e the exception which caused this one
      */
      Decoding_Error(std::string_view msg, const std::exception& e);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::DecodingFailure; }
};

/**
* Invalid state was encountered. A request was made on an object while the
* object was in a state where the operation cannot be performed.
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_State : public Exception {
   public:
      /**
      * Create a Invalid_State exception
      * @param err a description of the invalid state
      */
      explicit Invalid_State(std::string_view err) : Exception(err) {}

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::InvalidObjectState; }
};

/**
* A PRNG was called on to produce output while still unseeded
*/
class BOTAN_PUBLIC_API(2, 0) PRNG_Unseeded final : public Invalid_State {
   public:
      /**
      * Create a PRNG_Unseeded exception
      * @param algo the name of the unseeded PRNG
      */
      explicit PRNG_Unseeded(std::string_view algo);
};

/**
* The key was not set on an object. This occurs with symmetric objects where
* an operation which requires the key is called prior to set_key being called.
*/
class BOTAN_PUBLIC_API(2, 4) Key_Not_Set : public Invalid_State {
   public:
      /**
      * Create a Key_Not_Set exception
      * @param algo the name of the algorithm whose key was not set
      */
      explicit Key_Not_Set(std::string_view algo);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::KeyNotSet; }
};

/**
* A request was made for some kind of object which could not be located
*/
class BOTAN_PUBLIC_API(2, 0) Lookup_Error : public Exception {
   public:
      /**
      * Create a Lookup_Error exception
      * @param err a description of the object which was not found
      */
      explicit Lookup_Error(std::string_view err) : Exception(err) {}

      /**
      * Create a Lookup_Error exception
      * @param type the kind of object which was requested
      * @param algo the algorithm name which was requested
      * @param provider the provider which was requested, if any
      */
      Lookup_Error(std::string_view type, std::string_view algo, std::string_view provider = "");

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::LookupError; }
};

/**
* Algorithm_Not_Found Exception
*
* @warning This exception type will be removed in the future. Instead
* just catch Lookup_Error.
*/
class BOTAN_PUBLIC_API(2, 0) Algorithm_Not_Found final : public Lookup_Error {
   public:
      /**
      * Create a Algorithm_Not_Found exception
      * @param name the algorithm which was not found
      */
      explicit Algorithm_Not_Found(std::string_view name);
};

/**
* Provider_Not_Found is thrown when a specific provider was requested
* but that provider is not available.
*
* @warning This exception type will be removed in the future. Instead
* just catch Lookup_Error.
*/
class BOTAN_PUBLIC_API(2, 0) Provider_Not_Found final : public Lookup_Error {
   public:
      /**
      * Create a Provider_Not_Found exception
      * @param algo the algorithm which was requested
      * @param provider the provider which was not available
      */
      Provider_Not_Found(std::string_view algo, std::string_view provider);
};

/**
* An AEAD or MAC check detected a message modification
*
* In versions before 2.10, Invalid_Authentication_Tag was named
* Integrity_Failure, it was renamed to make its usage more clear.
*/
class BOTAN_PUBLIC_API(2, 0) Invalid_Authentication_Tag final : public Exception {
   public:
      /**
      * Create a Invalid_Authentication_Tag exception
      * @param msg a description of the failure
      */
      explicit Invalid_Authentication_Tag(std::string_view msg);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::InvalidTag; }
};

/**
* For compatibility with older versions
*/
typedef Invalid_Authentication_Tag Integrity_Failure;

/**
* An error occurred while operating on an IO stream
*/
class BOTAN_PUBLIC_API(2, 0) Stream_IO_Error final : public Exception {
   public:
      /**
      * Create a Stream_IO_Error exception
      * @param err a description of the IO failure
      */
      explicit Stream_IO_Error(std::string_view err);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::IoError; }
};

/**
* System_Error
*
* This exception is thrown in the event of an error related to interacting
* with the operating system.
*
* This exception type also (optionally) captures an integer error code eg
* POSIX errno or Windows GetLastError.
*/
class BOTAN_PUBLIC_API(2, 9) System_Error : public Exception {
   public:
      /**
      * Create a System_Error exception
      * @param msg a description of the problem
      */
      explicit System_Error(std::string_view msg) : Exception(msg), m_error_code(0) {}

      /**
      * Create a System_Error exception
      * @param msg a description of the problem
      * @param err_code the operating system error code
      */
      System_Error(std::string_view msg, int err_code);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::SystemError; }

      /**
      * Return the operating system error code associated with this exception
      * @return the operating system error code captured at construction
      */
      int error_code() const noexcept override { return m_error_code; }

   private:
      int m_error_code;
};

/**
* An internal error occurred. If observed, please file a bug.
*/
class BOTAN_PUBLIC_API(2, 0) Internal_Error : public Exception {
   public:
      /**
      * Create a Internal_Error exception
      * @param err a description of the internal error
      */
      explicit Internal_Error(std::string_view err);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::InternalError; }
};

/**
* Not Implemented Exception
*
* This is thrown in the situation where a requested operation is
* logically valid but is not implemented by this version of the library.
*/
class BOTAN_PUBLIC_API(2, 0) Not_Implemented final : public Exception {
   public:
      /**
      * Create a Not_Implemented exception
      * @param err a description of the unimplemented operation
      */
      explicit Not_Implemented(std::string_view err);

      /**
      * Return the error type of this exception
      * @return the error type of this exception
      */
      ErrorType error_type() const noexcept override { return ErrorType::NotImplemented; }
};

/**
* Throw an exception of type E, prefixing the message with the source location
*
* @param file the source file name
* @param line the source line number
* @param func the enclosing function name
* @param args the remaining arguments forwarded to E's constructor
*/
template <typename E, typename... Args>
inline void do_throw_error(const char* file, int line, const char* func, Args... args) {
   throw E(file, line, func, args...);
}

}  // namespace Botan

#endif

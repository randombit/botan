/*
* Exceptions
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EXCEPTION_H_
#define BOTAN_EXCEPTION_H_

#include <botan/types.h>
#include <exception>
#include <string>

namespace Botan {

/**
* Base class for all exceptions thrown by the library
*/
class BOTAN_PUBLIC_API(2,0) Exception : public std::exception
   {
   public:
      Exception(const char* prefix, const std::string& msg);
      explicit Exception(const std::string& msg);
      const char* what() const BOTAN_NOEXCEPT override { return m_msg.c_str(); }
   protected:
      Exception(const std::string& msg, const std::exception& e);
   private:
      std::string m_msg;
   };

/**
* An invalid argument
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Argument : public Exception
   {
   public:
      explicit Invalid_Argument(const std::string& msg);

      explicit Invalid_Argument(const std::string& msg, const std::string& where);

      Invalid_Argument(const std::string& msg, const std::exception& e);
   };

/**
* Unsupported_Argument Exception
*
* An argument that is invalid because it is not supported by Botan.
* It might or might not be valid in another context like a standard.
*/
class BOTAN_PUBLIC_API(2,0) Unsupported_Argument final : public Invalid_Argument
   {
   public:
      explicit Unsupported_Argument(const std::string& msg) : Invalid_Argument(msg) {}
   };

/**
* Invalid_State Exception
*/
class BOTAN_PUBLIC_API(2,0) Invalid_State : public Exception
   {
   public:
      explicit Invalid_State(const std::string& err) : Exception(err) {}
   };

class BOTAN_PUBLIC_API(2,4) Key_Not_Set : public Invalid_State
   {
   public:
      explicit Key_Not_Set(const std::string& algo);
   };

/**
* Lookup_Error Exception
*/
class BOTAN_PUBLIC_API(2,0) Lookup_Error : public Exception
   {
   public:
      explicit Lookup_Error(const std::string& err) : Exception(err) {}

      Lookup_Error(const std::string& type,
                   const std::string& algo,
                   const std::string& provider);
   };

/**
* Internal_Error Exception
*/
class BOTAN_PUBLIC_API(2,0) Internal_Error : public Exception
   {
   public:
      explicit Internal_Error(const std::string& err);
   };

/**
* Invalid_Key_Length Exception
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Key_Length final : public Invalid_Argument
   {
   public:
      Invalid_Key_Length(const std::string& name, size_t length);
   };

/**
* Invalid_IV_Length Exception
*/
class BOTAN_PUBLIC_API(2,0) Invalid_IV_Length final : public Invalid_Argument
   {
   public:
      Invalid_IV_Length(const std::string& mode, size_t bad_len);
   };

/**
* PRNG_Unseeded Exception
*/
class BOTAN_PUBLIC_API(2,0) PRNG_Unseeded final : public Invalid_State
   {
   public:
      explicit PRNG_Unseeded(const std::string& algo);
   };

/**
* Policy_Violation Exception
*/
class BOTAN_PUBLIC_API(2,0) Policy_Violation final : public Invalid_State
   {
   public:
      BOTAN_DEPRECATED("deprecated") explicit Policy_Violation(const std::string& err);
   };

/**
* Algorithm_Not_Found Exception
*/
class BOTAN_PUBLIC_API(2,0) Algorithm_Not_Found final : public Lookup_Error
   {
   public:
      explicit Algorithm_Not_Found(const std::string& name);
   };

/**
* No_Provider_Found Exception
*/
class BOTAN_PUBLIC_API(2,0) No_Provider_Found final : public Exception
   {
   public:
      BOTAN_DEPRECATED("deprecated") explicit No_Provider_Found(const std::string& name);
   };

/**
* Provider_Not_Found is thrown when a specific provider was requested
* but that provider is not available.
*/
class BOTAN_PUBLIC_API(2,0) Provider_Not_Found final : public Lookup_Error
   {
   public:
      Provider_Not_Found(const std::string& algo, const std::string& provider);
   };

/**
* Invalid_Algorithm_Name Exception
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Algorithm_Name final : public Invalid_Argument
   {
   public:
      explicit Invalid_Algorithm_Name(const std::string& name);
   };

/**
* Encoding_Error Exception
*/
class BOTAN_PUBLIC_API(2,0) Encoding_Error final : public Invalid_Argument
   {
   public:
      explicit Encoding_Error(const std::string& name);
   };

/**
* Decoding_Error Exception
*/
class BOTAN_PUBLIC_API(2,0) Decoding_Error : public Invalid_Argument
   {
   public:
      explicit Decoding_Error(const std::string& name);

      Decoding_Error(const std::string& name, const char* exception_message);

      Decoding_Error(const std::string& msg, const std::exception& e);
   };

/**
* Integrity_Failure Exception
*/
class BOTAN_PUBLIC_API(2,0) Integrity_Failure final : public Exception
   {
   public:
      explicit Integrity_Failure(const std::string& msg);
   };

/**
* Invalid_OID Exception
*/
class BOTAN_PUBLIC_API(2,0) Invalid_OID final : public Decoding_Error
   {
   public:
      explicit Invalid_OID(const std::string& oid);
   };

/**
* Stream_IO_Error Exception
*/
class BOTAN_PUBLIC_API(2,0) Stream_IO_Error final : public Exception
   {
   public:
      explicit Stream_IO_Error(const std::string& err);
   };

/**
* Self Test Failure Exception
*/
class BOTAN_PUBLIC_API(2,0) Self_Test_Failure final : public Internal_Error
   {
   public:
      BOTAN_DEPRECATED("deprecated") explicit Self_Test_Failure(const std::string& err);
   };

/**
* Not Implemented Exception
*/
class BOTAN_PUBLIC_API(2,0) Not_Implemented final : public Exception
   {
   public:
      explicit Not_Implemented(const std::string& err);
   };

}

#endif

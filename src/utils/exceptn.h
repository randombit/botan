/*
* Exceptions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EXCEPTION_H__
#define BOTAN_EXCEPTION_H__

#include <botan/types.h>
#include <botan/parsing.h>
#include <exception>
#include <stdexcept>
#include <string>

namespace Botan {

/*
* Exception Base Class
*/
class BOTAN_DLL Exception : public std::exception
   {
   public:
      Exception(const std::string& m = "Unknown error") :
         msg("Botan: " + m)
         {}

      const char* what() const throw() { return msg.c_str(); }

      virtual ~Exception() throw() {}
   private:
      std::string msg;
   };

/*
* Invalid_Argument Exception
*/
struct BOTAN_DLL Invalid_Argument : public Exception
   {
   Invalid_Argument(const std::string& err = "") :
      Exception(err)
      {}
   };

/*
* Invalid_State Exception
*/
struct BOTAN_DLL Invalid_State : public Exception
   {
   Invalid_State(const std::string& err) :
      Exception(err)
      {}
   };

/*
* Format_Error Exception
*/
struct BOTAN_DLL Format_Error : public Exception
   {
   Format_Error(const std::string& err = "") :
      Exception(err)
      {}
   };

/*
* Lookup_Error Exception
*/
struct BOTAN_DLL Lookup_Error : public Exception
   {
   Lookup_Error(const std::string& err) :
      Exception(err)
      {}
   };

/*
* Internal_Error Exception
*/
struct BOTAN_DLL Internal_Error : public Exception
   {
   Internal_Error(const std::string& err) :
      Exception("Internal error: " + err)
      {}
   };

/*
* Invalid_Key_Length Exception
*/
struct BOTAN_DLL Invalid_Key_Length : public Invalid_Argument
   {
   Invalid_Key_Length(const std::string& name, u32bit length) :
      Invalid_Argument(name + " cannot accept a key of length " +
                       to_string(length))
      {}
   };

/*
* Invalid_Block_Size Exception
*/
struct BOTAN_DLL Invalid_Block_Size : public Invalid_Argument
   {
   Invalid_Block_Size(const std::string& mode,
                      const std::string& pad) :
      Invalid_Argument("Padding method " + pad +
                       " cannot be used with " + mode)
      {}
   };

/*
* Invalid_IV_Length Exception
*/
struct BOTAN_DLL Invalid_IV_Length : public Invalid_Argument
   {
   Invalid_IV_Length(const std::string& mode, u32bit bad_len) :
      Invalid_Argument("IV length " + to_string(bad_len) +
                       " is invalid for " + mode)
      {}
   };

/*
* PRNG_Unseeded Exception
*/
struct BOTAN_DLL PRNG_Unseeded : public Invalid_State
   {
   PRNG_Unseeded(const std::string& algo) :
      Invalid_State("PRNG not seeded: " + algo)
      {}
   };

/*
* Policy_Violation Exception
*/
struct BOTAN_DLL Policy_Violation : public Invalid_State
   {
   Policy_Violation(const std::string& err) :
      Invalid_State("Policy violation: " + err)
      {}
   };

/*
* Algorithm_Not_Found Exception
*/
struct BOTAN_DLL Algorithm_Not_Found : public Lookup_Error
   {
   Algorithm_Not_Found(const std::string& name) :
      Lookup_Error("Could not find any algorithm named \"" + name + "\"")
      {}
   };

/*
* Invalid_Algorithm_Name Exception
*/
struct BOTAN_DLL Invalid_Algorithm_Name : public Format_Error
   {
   Invalid_Algorithm_Name(const std::string& name):
      Format_Error("Invalid algorithm name: " + name)
      {}
   };

/*
* Encoding_Error Exception
*/
struct BOTAN_DLL Encoding_Error : public Format_Error
   {
   Encoding_Error(const std::string& name) :
      Format_Error("Encoding error: " + name) {}
   };

/*
* Decoding_Error Exception
*/
struct BOTAN_DLL Decoding_Error : public Format_Error
   {
   Decoding_Error(const std::string& name) :
      Format_Error("Decoding error: " + name) {}
   };

/*
* Invalid_OID Exception
*/
struct BOTAN_DLL Invalid_OID : public Decoding_Error
   {
   Invalid_OID(const std::string& oid) :
      Decoding_Error("Invalid ASN.1 OID: " + oid) {}
   };

/*
* Stream_IO_Error Exception
*/
struct BOTAN_DLL Stream_IO_Error : public Exception
   {
   Stream_IO_Error(const std::string& err) :
      Exception("I/O error: " + err)
      {}
   };

/*
* Configuration Error Exception
*/
struct BOTAN_DLL Config_Error : public Format_Error
   {
   Config_Error(const std::string& err) :
      Format_Error("Config error: " + err)
      {}

   Config_Error(const std::string& err, u32bit line) :
      Format_Error("Config error at line " + to_string(line) + ": " + err)
      {}
   };

/*
* Integrity Failure Exception
*/
struct BOTAN_DLL Integrity_Failure : public Internal_Error
   {
   Integrity_Failure(const std::string& err) :
      Internal_Error("Integrity failure: " + err)
      {}
   };

/*
* Self Test Failure Exception
*/
struct BOTAN_DLL Self_Test_Failure : public Internal_Error
   {
   Self_Test_Failure(const std::string& err) :
      Internal_Error("Self test failed: " + err)
      {}
   };

}

#endif

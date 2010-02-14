/*
* SSL Exceptions
* (C) 2004-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SSL_EXCEPTION_H__
#define BOTAN_SSL_EXCEPTION_H__

#include <botan/tls_magic.h>
#include <botan/exceptn.h>

namespace Botan {

struct BOTAN_DLL TLS_Exception : public Exception
   {
   public:
      Alert_Type type() const { return alert_type; }

      TLS_Exception(Alert_Type type, const std::string& msg) :
         Exception("SSL/TLS error: " + msg), alert_type(type)
         {}

   private:
      Alert_Type alert_type;
   };

struct BOTAN_DLL Unexpected_Message : public TLS_Exception
   {
   Unexpected_Message(const std::string& err) :
      TLS_Exception(UNEXPECTED_MESSAGE, err) {}
   };

}

#endif

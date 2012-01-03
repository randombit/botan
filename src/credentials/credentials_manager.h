/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CREDENTIALS_MANAGER_H__
#define BOTAN_CREDENTIALS_MANAGER_H__

#include <botan/x509cert.h>
#include <botan/secmem.h>
#include <string>

namespace Botan {

class BigInt;

/**
* Interface for a credentials manager.
*
* A type is a fairly static value that represents the general nature
* of the transaction occuring. Currently defined are "tls-client" and
* "tls-server". Context represents a hostname, email address,
* username, or other identifier.
*/
class BOTAN_DLL Credentials_Manager
   {
   public:
      virtual ~Credentials_Manager() {}

      /**
      * @return identifier for client-side SRP auth, if available
                for this type/context
      */
      virtual std::string srp_identifier(const std::string& type,
                                         const std::string& context);

      /**
      * @return password for client-side SRP auth, if available
                for this identifier/type/context
      */
      virtual std::string srp_password(const std::string& identifier,
                                       const std::string& type,
                                       const std::string& context);

      /**
      * @todo add option for faking verifier if identifier is unknown
      */
      virtual bool srp_verifier(const std::string& identifier,
                                const std::string& type,
                                const std::string& context,
                                BigInt& group_prime,
                                BigInt& group_generator,
                                BigInt& verifier,
                                MemoryRegion<byte>& salt);

      /**
      * @param cert_key_type is a string representing the key type
      * ("RSA", "DSA", "ECDSA") or empty if no preference.
      */
      virtual std::vector<X509_Certificate> cert_chain(
         const std::string& cert_key_type,
         const std::string& type,
         const std::string& context);

      /**
      * @return private key associated with this certificate if we should
      *         use it with this context
      */
      virtual Private_Key* private_key_for(const X509_Certificate& cert,
                                           const std::string& type,
                                           const std::string& context);
   };

}

#endif

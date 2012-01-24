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
* of the transaction occuring. Currently used values are "tls-client"
* and "tls-server". Context represents a hostname, email address,
* username, or other identifier.

*/
class BOTAN_DLL Credentials_Manager
   {
   public:
      virtual ~Credentials_Manager() {}

      /**
      * @return identifier for client-side SRP auth, if available
                for this type/context. Should return empty string
                if password auth not desired/available.
      */
      virtual std::string srp_identifier(const std::string& type,
                                         const std::string& context);

      /**
      * @param identifier specifies what identifier we want the
      *        password for. This will be a value previously returned
      *        by srp_identifier.
      * @return password for client-side SRP auth, if available
                for this identifier/type/context.
      */
      virtual std::string srp_password(const std::string& identifier,
                                       const std::string& type,
                                       const std::string& context);

      /**
      * Retrieve SRP verifier parameters
      */
      virtual bool srp_verifier(const std::string& identifier,
                                const std::string& type,
                                const std::string& context,
                                BigInt& group_prime,
                                BigInt& group_generator,
                                BigInt& verifier,
                                MemoryRegion<byte>& salt,
                                bool generate_fake_on_unknown);

      /**
      * Return a cert chain we can use, ordered from leaf to root.
      * Assumed that we can get the private key of the leaf with
      * private_key_for
      *
      * @param cert_key_type is a set string representing the allowed
      * key type ("RSA", "DSA", "ECDSA", etc) or empty if no
      * preference.
      */
      virtual std::vector<X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string& context);

      /**
      * Return a cert chain we can use, ordered from leaf to root.
      * Assumed that we can get the private key of the leaf with
      * private_key_for
      *
      * @param cert_key_type is a set string representing the allowed
      * key type ("RSA", "DSA", "ECDSA", etc) or empty if no
      * preference.
      */
      std::vector<X509_Certificate> cert_chain_single_type(
         const std::string& cert_key_type,
         const std::string& type,
         const std::string& context);

      /**
      * Return a list of the certificates of CAs that we trust in this
      * type/context.
      */
      virtual std::vector<X509_Certificate> trusted_certificate_authorities(
         const std::string& type,
         const std::string& context);

      /**
      * Check the certificate chain is valid up to a trusted root, and
      * optionally (if hostname != "") that the hostname given is
      * consistent with the leaf certificate.
      *
      * This function should throw an exception derived from
      * std::exception with an informative what() result if the
      * certificate chain cannot be verified.
      */
      virtual void verify_certificate_chain(
         const std::vector<X509_Certificate>& cert_chain,
         const std::string& hostname = "");

      /**
      * @return private key associated with this certificate if we should
      *         use it with this context. cert was returned by cert_chain
      */
      virtual Private_Key* private_key_for(const X509_Certificate& cert,
                                           const std::string& type,
                                           const std::string& context);
   };

}

#endif

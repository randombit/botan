/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CREDENTIALS_MANAGER_H_
#define BOTAN_CREDENTIALS_MANAGER_H_

#include <botan/asn1_obj.h>
#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/strong_type.h>
#include <botan/symkey.h>
#include <botan/x509cert.h>
#include <string>

namespace Botan {

class X509_DN;
class BigInt;

/// @brief holds a PSK identity as used in TLS 1.3
using PresharedKeyID = Strong<std::vector<uint8_t>, struct PresharedKeyID_>;

/**
* Interface for a credentials manager.
*
* A type is a fairly static value that represents the general nature
* of the transaction occurring. Currently used values are "tls-client"
* and "tls-server". Context represents a hostname, email address,
* username, or other identifier.
*/
class BOTAN_PUBLIC_API(2, 0) Credentials_Manager {
   public:
      virtual ~Credentials_Manager() = default;

      /**
      * Return a list of the certificates of CAs that we trust in this
      * type/context.
      *
      * @param type specifies the type of operation occurring
      *
      * @param context specifies a context relative to type. For instance
      *        for type "tls-client", context specifies the servers name.
      */
      virtual std::vector<Certificate_Store*> trusted_certificate_authorities(const std::string& type,
                                                                              const std::string& context);

      /**
      * Return a cert chain we can use, ordered from leaf to root,
      * or else an empty vector.
      *
      * It is assumed that the caller can get the private key of the
      * leaf with private_key_for
      *
      * For a comprehensive write-up of how to select certificates for TLS
      * CertificateVerify messages, see RFC 8446 Sections 4.4.2.2 and 4.4.2.3.
      *
      * @param cert_key_types specifies the key types desired ("RSA",
      *                       "DSA", "ECDSA", etc), or empty if there
      *                       is no preference by the caller.
      * @param cert_signature_schemes specifies the signature types desired
      *                               as signatures in the certificate(s) itself,
      *                               or empty for no preference by the caller.
      *
      * @param acceptable_CAs the CAs the requestor will accept (possibly empty)
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      */
      virtual std::vector<X509_Certificate> find_cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
         const std::vector<X509_DN>& acceptable_CAs,
         const std::string& type,
         const std::string& context);

      /**
      * Return a cert chain we can use, ordered from leaf to root,
      * or else an empty vector.
      *
      * This virtual function is deprecated, and will be removed in a
      * future release. Use (and override) find_cert_chain instead.
      *
      * It is assumed that the caller can get the private key of the
      * leaf with private_key_for
      *
      * @param cert_key_types specifies the key types desired ("RSA",
      *                       "DSA", "ECDSA", etc), or empty if there
      *                       is no preference by the caller.
      * @param cert_signature_schemes specifies the signature types desired
      *                               as signatures in the certificate(s) itself,
      *                               or empty for no preference by the caller.
      *
      * @param type specifies the type of operation occurring
      *
      * @param context specifies a context relative to type.
      */
      virtual std::vector<X509_Certificate> cert_chain(const std::vector<std::string>& cert_key_types,
                                                       const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
                                                       const std::string& type,
                                                       const std::string& context);

      /**
      * Return a cert chain we can use, ordered from leaf to root,
      * or else an empty vector.
      *
      * It is assumed that the caller can get the private key of the
      * leaf with private_key_for
      *
      * @param cert_key_type specifies the type of key requested
      *                      ("RSA", "DSA", "ECDSA", etc)
      * @param cert_signature_schemes specifies the signature types desired
      *                               as signatures in the certificate(s) itself,
      *                               or empty for no preference by the caller.
      *
      * @param type specifies the type of operation occurring
      *
      * @param context specifies a context relative to type.
      */
      std::vector<X509_Certificate> cert_chain_single_type(
         const std::string& cert_key_type,
         const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
         const std::string& type,
         const std::string& context);

      /**
      * @return private key associated with this certificate if we should
      *         use it with this context. cert was returned by cert_chain
      * This function should either return null or throw an exception if
      * the key is unavailable.
      */
      virtual std::shared_ptr<Private_Key> private_key_for(const X509_Certificate& cert,
                                                           const std::string& type,
                                                           const std::string& context);

      /**
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      * @return the PSK identity hint for this type/context
      */
      virtual std::string psk_identity_hint(const std::string& type, const std::string& context);

      /**
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      * @param identity_hint was passed by the server (but may be empty)
      * @return the PSK identity we want to use
      */
      virtual std::string psk_identity(const std::string& type,
                                       const std::string& context,
                                       const std::string& identity_hint);

      /**
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      * @param identity is a PSK identity previously returned by
               psk_identity for the same type and context.
      * @return the PSK used for identity, or throw an exception if no
      * key exists
      */
      virtual SymmetricKey psk(const std::string& type, const std::string& context, const std::string& identity);
};

}  // namespace Botan

#endif

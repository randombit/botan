/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CREDENTIALS_MANAGER_H_
#define BOTAN_CREDENTIALS_MANAGER_H_

#include <botan/pk_keys.h>
#include <botan/x509cert.h>
#include <botan/asn1_obj.h>
#include <botan/certstor.h>
#include <botan/symkey.h>
#include <string>

namespace Botan {

class X509_DN;
class BigInt;

/**
* Interface for a credentials manager.
*
* A type is a fairly static value that represents the general nature
* of the transaction occurring. Currently used values are "tls-client"
* and "tls-server". Context represents a hostname, email address,
* username, or other identifier.
*/
class BOTAN_PUBLIC_API(2,0) Credentials_Manager
   {
   public:
      virtual ~Credentials_Manager() = default;

      /**
      * Return a list of the certificates of CAs that we trust in this
      * type/context. The ``Credentials_Manager`` retains ownership of the
      * Certificate_Store pointers.
      *
      * @note It would have been a better API to return a vector of `shared_ptr`
      *       here.  This may change in a future major release.
      *
      * When @p type is "tls-client", @p context will be the hostname of the
      * server, or empty if the hostname is not known. This allows using a
      * different set of certificate stores in different contexts, for example
      * using the system certificate store unless contacting one particular
      * server which uses a cert issued by an internal CA.
      *
      * When @p type is "tls-server", the @p context will again be the hostname
      * of the server, or empty if the client did not send a server name
      * indicator. For TLS servers, these CAs are the ones trusted for signing
      * of client certificates. If you do not want the TLS server to ask for a
      * client cert, trusted_certificate_authorities() should return an empty
      * list for @p type "tls-server".
      *
      * The default implementation returns an empty list.
      *
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type. For instance for
      *        type "tls-client", context specifies the servers name.
      */
      virtual std::vector<Certificate_Store*> trusted_certificate_authorities(
         const std::string& type,
         const std::string& context);

      /**
      * Return a certificate chain we can use to identify ourselves, ordered
      * from leaf to root, or else an empty vector.
      *
      * It is assumed that the caller can get the private key of the leaf with
      * private_key_for()
      *
      * @warning  If this function returns a certificate that is not one of the
      *           types given in @p cert_key_types confusing handshake failures
      *           will result.
      *
      * For a comprehensive write-up of how to select certificates for TLS
      * CertificateVerify messages, see RFC 8446 Sections 4.4.2.2 and 4.4.2.3.
      *
      * @param cert_key_types specifies the key types desired ("RSA", "DSA",
      *                       "ECDSA", etc), or empty if there is no preference
      *                       by the caller.
      * @param cert_signature_schemes specifies the signature types desired as
      *                               signatures in the certificate(s) itself,
      *                               or empty for no preference by the caller.
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
      * Return a certificate chain we can use to identify ourselves, ordered
      * from leaf to root, or else an empty vector.
      *
      * @deprecated This virtual function is deprecated, and will be removed in
      *             a future release. Use (and override) find_cert_chain()
      *             instead.
      *
      * It is assumed that the caller can get the private key of the leaf with
      * private_key_for()
      *
      * @param cert_key_types specifies the key types desired ("RSA", "DSA",
      *                       "ECDSA", etc), or empty if there is no preference
      *                       by the caller.
      * @param cert_signature_schemes specifies the signature types desired as
      *                               signatures in the certificate(s) itself,
      *                               or empty for no preference by the caller.
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      */
      virtual std::vector<X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
         const std::string& type,
         const std::string& context);

      /**
      * Return a certificate chain we can use to identify ourselves, ordered
      * from leaf to root, or else an empty vector. Override this if we have one
      * certificate of type @p cert_key_type and we would like to use a
      * certificate in this type and context.
      *
      * For servers @p type will be "tls-server" and the @p context will be the
      * server name that the client requested via SNI (or empty, if the client
      * did not send SNI).
      *
      * @warning To avoid cross-protocol attacks it is recommended that if a
      *          server receives an SNI request for a name it does not expect,
      *          it should close the connection with an alert. This can be done
      *          by throwing an exception from the implementation of this
      *          function.
      *
      * It is assumed that the caller can get the private key of the leaf with
      * private_key_for()
      *
      * @param cert_key_type specifies the type of key requested ("RSA", "DSA",
      *                      "ECDSA", etc)
      * @param cert_signature_schemes specifies the signature types desired as
      *                               signatures in the certificate(s) itself,
      *                               or empty for no preference by the caller.
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      */
      std::vector<X509_Certificate> cert_chain_single_type(
         const std::string& cert_key_type,
         const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
         const std::string& type,
         const std::string& context);

      /**
      * Return a `shared_ptr` to the private key for this certificate. The
      * @p cert will be the leaf cert of a chain returned previously by
      * find_cert_chain() or cert_chain_single_type().
      *
      * @return private key associated with this certificate if we should use it
      *         with this context. cert was returned by cert_chain This function
      *         should either return null or throw an exception if the key is
      *         unavailable.
      */
      virtual std::shared_ptr<Private_Key>
         private_key_for(const X509_Certificate& cert,
                         const std::string& type,
                         const std::string& context);

      /**
      * Returns an identity hint which may be provided to the client. This can
      * help a client understand what PSK to use.
      *
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      * @return the PSK identity hint for this type/context
      */
      virtual std::string psk_identity_hint(const std::string& type,
                                            const std::string& context);

      /**
      * Returns the identity we would like to use given this @p type and
      * @p context and the optional @p identity_hint. Not all servers or
      * protocols will provide a hint.
      *
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      * @param identity_hint was passed by the server (but may be empty)
      * @return the PSK identity we want to use
      */
      virtual std::string psk_identity(const std::string& type,
                                       const std::string& context,
                                       const std::string& identity_hint);

      /**
      * Return a symmetric key for use with @p identity
      *
      * One important special case for this method is where @p type is
      * "tls-server", @p context is "session-ticket" and @p identity is an empty
      * string. If a key is returned for this case, a TLS server will offer
      * session tickets to clients who can use them, and the returned key will
      * be used to encrypt the ticket. The server is allowed to change the key
      * at any time (though changing the key means old session tickets can no
      * longer be used for resumption, forcing a full re-handshake when the
      * client next connects). One simple approach to add support for session
      * tickets in your server is to generate a random key the first time psk()
      * is called to retrieve the session ticket key, cache it for later use in
      * the Credentials_Manager, and simply let it be thrown away when the
      * process terminates. See RFC 4507 or RFC 8446 for more information about
      * TLS session tickets.
      *
      * A similar special case exists for DTLS cookie verification. In this case
      * @p type will be "tls-server" and @p context is "dtls-cookie-secret". If
      * no key is returned, then DTLS cookies are not used. Similar to the
      * session ticket key, the DTLS cookie secret can be chosen during server
      * startup and rotated at any time with no ill effect.
      *
      * @warning If DTLS cookies are not used then the server is prone to be
      *          abused as a DoS amplifier, where the attacker sends a
      *          relatively small client hello in a UDP packet with a forged
      *          return address, and then the server replies to the victim with
      *          several messages that are larger. This not only hides the
      *          attackers address from the victim, but increases their
      *          effective bandwidth. This is not an issue when using DTLS over
      *          SCTP or TCP.
      *
      * @param type specifies the type of operation occurring
      * @param context specifies a context relative to type.
      * @param identity is a PSK identity previously returned by psk_identity
      *                 for the same type and context.
      * @return the PSK used for identity, or throw an exception if no key
      *         exists
      */
      virtual SymmetricKey psk(const std::string& type,
                               const std::string& context,
                               const std::string& identity);
   };

}

#endif

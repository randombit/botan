
Credentials Manager
==================================================

A ``Credentials_Manager`` is a way to abstract how the application
stores credentials. The main user is the :doc:`tls` implementation.

.. cpp:class:: Credentials_Manager

   .. cpp:function:: std::vector<Certificate_Store*> \
         trusted_certificate_authorities( \
         const std::string& type, \
         const std::string& context)

      Return the list of certificate stores, each of which is assumed
      to contain (only) trusted certificate authorities. The
      ``Credentials_Manager`` retains ownership of the
      Certificate_Store pointers.

      .. note::

         It would have been a better API to return a vector of
         ``shared_ptr`` here.  This may change in a future major release.

      When *type* is "tls-client", *context* will be the hostname of
      the server, or empty if the hostname is not known. This allows
      using a different set of certificate stores in different contexts,
      for example using the system certificate store unless contacting
      one particular server which uses a cert issued by an internal CA.

      When *type* is "tls-server", the *context* will again be the
      hostname of the server, or empty if the client did not send a
      server name indicator. For TLS servers, these CAs are the ones
      trusted for signing of client certificates. If you do not want
      the TLS server to ask for a client cert,
      ``trusted_certificate_authorities`` should return an empty list
      for *type* "tls-server".

      The default implementation returns an empty list.

   .. cpp:function:: std::vector<X509_Certificate> find_cert_chain( \
                     const std::vector<std::string>& cert_key_types, \
                     const std::vector<X509_DN>& acceptable_CAs, \
                     const std::string& type, \
                     const std::string& context)

      Return the certificate chain to use to identify ourselves. The
      ``acceptable_CAs`` parameter gives a list of CAs the peer trusts.
      This may be empty.

      .. warning::
         If this function returns a certificate that is not one of the
         types given in ``cert_key_types`` confusing handshake
         failures will result.

   .. cpp:function:: std::vector<X509_Certificate> cert_chain( \
         const std::vector<std::string>& cert_key_types, \
         const std::string& type, \
         const std::string& context)

      Return the certificate chain to use to identify ourselves. Starting in
      2.5, prefer ``find_cert_chain`` which additionally provides the CA list.

   .. cpp:function:: std::vector<X509_Certificate> cert_chain_single_type( \
         const std::string& cert_key_type, \
         const std::string& type, \
         const std::string& context)

      Return the certificate chain to use to identifier ourselves, if
      we have one of type *cert_key_type* and we would like to use a
      certificate in this *type*/*context*.

      For servers *type* will be "tls-server" and the *context* will
      be the server name that the client requested via SNI (or empty,
      if the client did not send SNI).

      .. warning::

         To avoid cross-protocol attacks it is recommended that if a server
         receives an SNI request for a name it does not expect, it should close
         the connection with an alert. This can be done by throwing an exception
         from the implementation of this function.

   .. cpp:function:: std::shared_ptr<Private_Key> private_key_for(const X509_Certificate& cert, \
                                                  const std::string& type, \
                                                  const std::string& context)

      Return a shared pointer to the private key for this certificate. The
      *cert* will be the leaf cert of a chain returned previously by
      ``cert_chain`` or ``cert_chain_single_type``.

In versions before 1.11.34, there was an additional function on `Credentials_Manager`

   .. cpp::function:: void verify_certificate_chain( \
         const std::string& type, \
         const std::string& hostname, \
         const std::vector<X509_Certificate>& cert_chain)

This function has been replaced by `TLS::Callbacks::tls_verify_cert_chain`.

SRP Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``Credentials_Manager`` contains the hooks used by TLS clients and
servers for SRP authentication.

.. note::

   Support for TLS-SRP is deprecated, and will be removed in a future
   major release. When that occurs these APIs will be removed. Prefer
   instead performing a standard TLS handshake, then perform a PAKE
   authentication inside of (and cryptographically bound to) the TLS
   channel.

.. cpp:function:: bool attempt_srp(const std::string& type, \
                                   const std::string& context)

   Returns if we should consider using SRP for authentication

.. cpp:function:: std::string srp_identifier(const std::string& type, \
                                             const std::string& context)

   Returns the SRP identifier we'd like to use (used by client)

.. cpp:function:: std::string srp_password(const std::string& type, \
                                           const std::string& context, \
                                           const std::string& identifier)

   Returns the password for *identifier* (used by client)

.. cpp:function:: bool srp_verifier(const std::string& type, \
                                    const std::string& context, \
                                    const std::string& identifier, \
                                    std::string& group_name, \
                                    BigInt& verifier, \
                                    std::vector<uint8_t>& salt, \
                                    bool generate_fake_on_unknown)

    Returns the SRP verifier information for *identifier* (used by server)

Preshared Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TLS supports the use of pre shared keys for authentication.

.. cpp:function:: SymmetricKey psk(const std::string& type, \
                                   const std::string& context, \
                                   const std::string& identity)

    Return a symmetric key for use with *identity*

    One important special case for ``psk`` is where *type* is
    "tls-server", *context* is "session-ticket" and *identity* is an
    empty string. If a key is returned for this case, a TLS server
    will offer session tickets to clients who can use them, and the
    returned key will be used to encrypt the ticket. The server is
    allowed to change the key at any time (though changing the key
    means old session tickets can no longer be used for resumption,
    forcing a full re-handshake when the client next connects). One
    simple approach to add support for session tickets in your server
    is to generate a random key the first time ``psk`` is called to
    retrieve the session ticket key, cache it for later use in the
    ``Credentials_Manager``, and simply let it be thrown away when the
    process terminates. See :rfc:`4507` for more information about TLS
    session tickets.

    A similar special case exists for DTLS cookie verification. In
    this case *type* will be "tls-server" and *context* is
    "dtls-cookie-secret". If no key is returned, then DTLS cookies are
    not used. Similar to the session ticket key, the DTLS cookie
    secret can be chosen during server startup and rotated at any time
    with no ill effect.

    .. warning::

       If DTLS cookies are not used then the server is prone to be
       abused as a DoS amplifier, where the attacker sends a
       relatively small client hello in a UDP packet with a forged
       return address, and then the server replies to the victim with
       several messages that are larger. This not only hides the
       attackers address from the victim, but increases their
       effective bandwidth. This is not an issue when using DTLS over
       SCTP or TCP.

.. cpp:function:: std::string psk_identity_hint(const std::string& type, \
                                                const std::string& context)

    Returns an identity hint which may be provided to the client. This
    can help a client understand what PSK to use.

.. cpp:function:: std::string psk_identity(const std::string& type, \
                                           const std::string& context, \
                                           const std::string& identity_hint)

    Returns the identity we would like to use given this *type* and
    *context* and the optional *identity_hint*. Not all servers or
    protocols will provide a hint.

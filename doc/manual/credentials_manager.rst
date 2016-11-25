
Credentials Manager
==================================================

A ``Credentials_Manager`` is a way to abstract how the application
stores credentials in a way that is usable by protocol
implementations. Currently the main user is the :doc:`tls`
implementation.

.. cpp:class:: Credentials_Manager

   .. cpp:function:: std::vector<X509_Certificate> \
         trusted_certificate_authorities( \
         const std::string& type, \
         const std::string& context)

      Return the list of trusted certificate authorities.

      When *type* is "tls-client", *context* will be the hostname of
      the server, or empty if the hostname is not known.

      When *type* is "tls-server", the *context* will again be the
      hostname of the server, or empty if the client did not send a
      server name indicator. For TLS servers, these CAs are the ones
      trusted for signing of client certificates. If you do not want
      the TLS server to ask for a client cert,
      ``trusted_certificate_authorities`` should return an empty list
      for *type* "tls-server".

      The default implementation returns an empty list.

   .. cpp:function:: std::vector<X509_Certificate> cert_chain( \
         const std::vector<std::string>& cert_key_types, \
         const std::string& type, \
         const std::string& context)

      Return the certificate chain to use to identify ourselves

   .. cpp:function:: std::vector<X509_Certificate> cert_chain_single_type( \
         const std::string& cert_key_type, \
         const std::string& type, \
         const std::string& context)

      Return the certificate chain to use to identifier ourselves, if
      we have one of type *cert_key_tye* and we would like to use a
      certificate in this *type*/*context*.

   .. cpp:function:: Private_Key* private_key_for(const X509_Certificate& cert, \
                                                  const std::string& type, \
                                                  const std::string& context)

      Return the private key for this certificate. The *cert* will be
      the leaf cert of a chain returned previously by ``cert_chain``
      or ``cert_chain_single_type``.

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
                                    std::vector<byte>& salt, \
                                    bool generate_fake_on_unknown)

    Returns the SRP verifier information for *identifier* (used by server)

Preshared Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TLS and some other protocols support the use of pre shared keys for
authentication.

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
    process terminates.

    See :rfc:`4507` for more information about TLS session tickets.

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

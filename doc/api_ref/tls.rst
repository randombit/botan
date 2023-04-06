Transport Layer Security (TLS)
========================================

Botan has client and server implementations of the TLS protocol version 1.2 and
1.3. There is also support for DTLS (v1.2), a variant of TLS adapted for
operation on datagram transports such as UDP and SCTP. DTLS support should be
considered as beta quality and further testing is invited.

As of version 1.11.13, support for the insecure SSLv3 protocol has been removed.
Additionally, with Botan 3.0.0 support for (D)TLS 1.0 and 1.1 was also removed.

The TLS implementation does not know anything about sockets or the
network layer. Instead, it calls a user provided callback (hereafter
``output_fn``) whenever it has data that it would want to send to the
other party (for instance, by writing it to a network socket), and
whenever the application receives some data from the counterparty (for
instance, by reading from a network socket) it passes that information
to TLS using :cpp:func:`TLS::Channel::received_data`. If the data
passed in results in some change in the state, such as a handshake
completing, or some data or an alert being received from the other
side, then the appropriate user provided callback will be invoked.

If the reader is familiar with OpenSSL's BIO layer, it might be analogous
to saying the only way of interacting with Botan's TLS is via a `BIO_mem` I/O
abstraction. This makes the library completely agnostic to how you
write your network layer, be it blocking sockets, libevent, asio, a
message queue, lwIP on RTOS, some carrier pigeons, etc.

Additionally, Botan offers a :ref:`higher-level TLS stream abstraction
<tls_stream>` that is designed as a de-facto drop-in replacement for ASIO's
``ssl_stream``.

Application Callbacks
---------------------

The application callbacks are encapsulated as the class ``TLS::Callbacks``.
Below is an overview of the most important and mandatory callbacks. Others are
optional and provide hooks for applications to gather information of the
established connection or even customize the TLS stack's behavior.

.. container:: toggle

    .. doxygenclass:: Botan::TLS::Callbacks
       :members:
       :membergroups: Mandatory Informational

TLS Channels
----------------------------------------

TLS servers and clients share an interface called `TLS::Channel`. A
TLS channel (either client or server object) has these methods
available:

.. doxygenclass:: Botan::TLS::Channel
    :members: received_data,send,close,is_active,is_closed,is_closed_for_reading,is_closed_for_writing,timeout_check,peer_cert_chain,key_material_export,update_traffic_keys,renegotiate

.. _tls_client:

TLS Clients
----------------------------------------

.. doxygenclass:: Botan::TLS::Client
    :members: Client

Code Example
^^^^^^^^^^^^

A minimal example of a TLS client is provided below.
The full code for a TLS client using BSD sockets is in `src/cli/tls_client.cpp`

.. literalinclude:: /../src/examples/tls_client.cpp
   :language: cpp

.. _tls_server:

TLS Servers
----------------------------------------

.. doxygenclass:: Botan::TLS::Server
    :members: Server

Code Example
^^^^^^^^^^^^

A minimal example of a TLS server is provided below.
The full code for a TLS server using asio is in `src/cli/tls_proxy.cpp`.

.. literalinclude:: /../src/examples/tls_proxy.cpp
   :language: cpp

.. _tls_sessions:

TLS Sessions
----------------------------------------

TLS allows clients and servers to support *session resumption*, where
the end point retains some information about an established session
and then reuse that information to bootstrap a new session in way that
is much cheaper computationally than a full handshake.

Every time the
``TLS::Callbacks::tls_should_persist_resumption_information()`` is
called, a new session has been established, and a ``TLS::Session_Summary`` is
included that provides information about that session:

.. note::

   The serialization format of Session is not considered stable and is allowed
   to change even across minor releases. In the event of such a change, old
   sessions will no longer be able to be resumed.

API Overview
^^^^^^^^^^^^

.. container:: toggle

    .. doxygenclass:: Botan::TLS::Session
        :members: version,ciphersuite,server_info,peer_certs,encrypt,decrypt

.. _tls_session_managers:

TLS Session Managers
----------------------------------------

Session managers keep track of sessions for later resumption. Botan provides a
number of implementations that should suffice for most typical applications.
When used in a TLS server, the manager may keep sessions as persistent state
(e.g. in a database) or pass the entire encrypted session information to the
client as a ticket.

Though, you may want sessions stored in a specific format or storage type. To do
so, implement the at least the pure-virtual methods ``TLS::Session_Manager`` and
pass your implementation to the ``TLS::Client`` or ``TLS::Server`` constructor.
Some methods in the base class have default implementations that your derived
class will most likely take advantage of.

Note that the ``TLS::Session_Manager`` faced a major overhaul to properly
accomodate the fairly different needs of TLS 1.2 and TLS 1.3. See the
:ref:`migration guide <session_handling_with_tls_13>` for further info.

Below is an overview of the pure-virtual methods that a custom implementation
will need to provide:

.. container:: toggle

    .. doxygenclass:: Botan::TLS::Session_Manager
        :members: store,remove,remove_all,retrieve_one,find_some

.. _tls_session_manager_inmem:

In Memory Session Manager
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``TLS::Session_Manager_In_Memory`` implementation saves sessions
in memory, with an upper bound on the maximum number of sessions and
the lifetime of a session.

For TLS clients that don't require sessions to outlive their process, this
manager is a good choice. Note, however, that this implementation will never
emit stateless session tickets. When used in a TLS server, sessions will have to
be kept in the server's memory. Consider using it as part of a
:ref:`hybrid session manager <tls_session_mgr_hybrid>` in this case.

It is safe to share a single object across many threads as it uses a
lock internally.

.. doxygenclass:: Botan::TLS::Session_Manager_In_Memory
    :members: Session_Manager_In_Memory

SQLite3 Session Manager
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This session manager is only available if support for SQLite3 was
enabled at build time. If the macro
``BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER`` is defined, then
``botan/tls_session_manager_sqlite.h`` contains
``TLS::Session_Manager_SQLite`` which stores sessions persistently to
a sqlite3 database. The session data is encrypted using a passphrase,
and stored in two tables, named ``tls_sessions`` (which holds the
actual session information) and ``tls_sessions_metadata`` (which holds
the PBKDF information).

For TLS clients that want to persist sessions to disk so that they outlive a
single process runtime, this manager is a good choice. Note, however, that this
implementation will never emit stateless session tickets. When used in a TLS
server, sessions will have to be kept on the server's disk. Consider using it
as part of a :ref:`hybrid session manager <tls_session_mgr_hybrid>` in this
case.

.. warning:: The hostnames associated with the saved sessions are
             stored in the database in plaintext. This may be a
             serious privacy risk in some applications.

.. doxygenclass:: Botan::TLS::Session_Manager_SQLite
    :members: Session_Manager_SQLite

Stateless Session Manager
^^^^^^^^^^^^^^^^^^^^^^^^^

This session manager will never persist any sessions. Instead it will always
symmetrically encrypt the session information to create a session ticket that
may be passed to a client.

This manager should be used in TLS servers only. It will never produce any state
that would need to be managed on the server.

.. doxygenclass:: Botan::TLS::Session_Manager_Stateless
    :members: Session_Manager_Stateless

.. _tls_session_mgr_hybrid:

Hybrid Session Manager
^^^^^^^^^^^^^^^^^^^^^^

The hybrid session manager combines the stateless session manager with a
stateful fallback. If a client signals no support for stateless session tickets,
the hybrid manager will keep state on the server. Note that TLS clients don't
benefit from this extra complexity: They must always persist sessions if they
wish to resume later. Note that TLS 1.3 clients support stateless session
tickets by default.

.. doxygenclass:: Botan::TLS::Session_Manager_Hybrid
    :members: Session_Manager_Hybrid

Noop Session Mananger
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``TLS::Session_Manager_Noop`` implementation does not save
sessions at all, and thus session resumption always fails. Its
constructor has no arguments.


TLS Policies
----------------------------------------

``TLS::Policy`` is how an application can control details of what will
be negotiated during a handshake. The base class acts as the default
policy. There is also a ``Strict_Policy`` (which forces only secure
options, reducing compatibility) and ``Text_Policy`` which reads
policy settings from a file.

.. cpp:class:: TLS::Policy

 .. cpp:function:: std::vector<std::string> allowed_ciphers() const

     Returns the list of ciphers we are willing to negotiate, in order
     of preference.

     Clients send a list of ciphersuites in order of preference,
     servers are free to choose any of them. Some servers will use the
     clients preferences, others choose from the clients list
     prioritizing based on its preferences.

     No export key exchange mechanisms or ciphersuites are supported
     by botan. The null encryption ciphersuites (which provide only
     authentication, sending data in cleartext) are also not supported
     by the implementation and cannot be negotiated.

     Cipher names without an explicit mode refers to CBC+HMAC ciphersuites.

     Default value: "ChaCha20Poly1305", "AES-256/GCM", "AES-128/GCM"

     Also allowed: "AES-256", "AES-128",
     "AES-256/CCM", "AES-128/CCM", "AES-256/CCM(8)", "AES-128/CCM(8)",
     "Camellia-256/GCM", "Camellia-128/GCM", "ARIA-256/GCM", "ARIA-128/GCM"

     Also allowed (though currently experimental): "AES-128/OCB(12)",
     "AES-256/OCB(12)"

     In versions up to 2.8.0, the CBC and CCM ciphersuites "AES-256",
     "AES-128", "AES-256/CCM" and "AES-128/CCM" were enabled by default.

     Also allowed (although **not recommended**): "3DES"

     .. note::

        Before 1.11.30 only the non-standard ChaCha20Poly1305 ciphersuite
        was implemented. The RFC 7905 ciphersuites are supported in 1.11.30
        onwards.

     .. note::

        Support for the broken RC4 cipher was removed in 1.11.17

     .. note::

        All CBC ciphersuites are deprecated and will be removed in a future release.

 .. cpp:function:: std::vector<std::string> allowed_macs() const

     Returns the list of algorithms we are willing to use for
     message authentication, in order of preference.

     Default: "AEAD", "SHA-256", "SHA-384", "SHA-1"

     A plain hash function indicates HMAC

     .. note::

        SHA-256 is preferred over SHA-384 in CBC mode because the
        protections against the Lucky13 attack are somewhat more
        effective for SHA-256 than SHA-384.

 .. cpp:function:: std::vector<std::string> allowed_key_exchange_methods() const

     Returns the list of key exchange methods we are willing to use,
     in order of preference.

     Default: "ECDH", "DH"

     Also allowed: "RSA", "ECDHE_PSK", "PSK"

     .. note::

        Static RSA ciphersuites are disabled by default since 1.11.34.
        In addition to not providing forward security, any server which is
        willing to negotiate these ciphersuites exposes themselves to a variety
        of chosen ciphertext oracle attacks which are all easily avoided by
        signing (as in PFS) instead of decrypting.

     .. note::

        In order to enable RSA or PSK ciphersuites one must also enable
        authentication method "IMPLICIT", see :cpp:func:`allowed_signature_methods`.

 .. cpp:function:: std::vector<std::string> allowed_signature_hashes() const

     Returns the list of hash algorithms we are willing to use for
     public key signatures, in order of preference.

     Default: "SHA-512", "SHA-384", "SHA-256"

     Also allowed (although **not recommended**): "SHA-1"

     .. note::

        This is only used with TLS v1.2. In earlier versions of the
        protocol, signatures are fixed to using only SHA-1 (for
        DSA/ECDSA) or a MD5/SHA-1 pair (for RSA).

 .. cpp:function:: std::vector<std::string> allowed_signature_methods() const

     Default: "ECDSA", "RSA"

     Also allowed (disabled by default): "IMPLICIT"

     "IMPLICIT" enables ciphersuites which are authenticated not by a signature
     but through a side-effect of the key exchange. In particular this setting
     is required to enable PSK and static RSA ciphersuites.

 .. cpp:function:: std::vector<Group_Params> key_exchange_groups() const

     Return a list of ECC curve and DH group TLS identifiers we are willing to use, in order of preference.
     The default ordering puts the best performing ECC first.

     Default:
     Group_Params::X25519,
     Group_Params::SECP256R1, Group_Params::BRAINPOOL256R1,
     Group_Params::SECP384R1, Group_Params::BRAINPOOL384R1,
     Group_Params::SECP521R1, Group_Params::BRAINPOOL512R1,
     Group_Params::FFDHE_2048, Group_Params::FFDHE_3072, Group_Params::FFDHE_4096,
     Group_Params::FFDHE_6144, Group_Params::FFDHE_8192

     No other values are currently defined.

 .. cpp:function:: bool use_ecc_point_compression() const

     Prefer ECC point compression.

     Signals that we prefer ECC points to be compressed when transmitted to us.
     The other party may not support ECC point compression and therefore may still
     send points uncompressed.

     Note that the certificate used during authentication must also follow the other
     party's preference.

     Default: false

     .. note::

        Support for EC point compression is deprecated and will be removed in a
        future major release.

 .. cpp:function:: bool acceptable_protocol_version(Protocol_Version version)

     Return true if this version of the protocol is one that we are
     willing to negotiate.

     Default: Accepts TLS v1.2 and DTLS v1.2, and rejects all older versions.

 .. cpp:function:: bool server_uses_own_ciphersuite_preferences() const

     If this returns true, a server will pick the cipher it prefers the
     most out of the client's list. Otherwise, it will negotiate the
     first cipher in the client's ciphersuite list that it supports.

     Default: true

 .. cpp:function:: bool allow_client_initiated_renegotiation() const

     If this function returns true, a server will accept a
     client-initiated renegotiation attempt. Otherwise it will send
     the client a non-fatal ``no_renegotiation`` alert.

     Default: false

 .. cpp:function:: bool allow_server_initiated_renegotiation() const

     If this function returns true, a client will accept a
     server-initiated renegotiation attempt. Otherwise it will send
     the server a non-fatal ``no_renegotiation`` alert.

     Default: false

 .. cpp:function:: bool abort_connection_on_undesired_renegotiation() const

     If a renegotiation attempt is being rejected due to the configuration of
     :cpp:func:`TLS::Policy::allow_client_initiated_renegotiation` or
     :cpp:func:`TLS::Policy::allow_server_initiated_renegotiation`, and
     this function returns true then the connection is closed with a fatal
     alert instead of the default warning alert.

     Default: false

 .. cpp:function:: bool allow_insecure_renegotiation() const

     If this function returns true, we will allow renegotiation attempts
     even if the counterparty does not support the RFC 5746 extensions.

     .. warning:: Returning true here could expose you to attacks

     Default: false

 .. cpp:function:: size_t minimum_signature_strength() const

     Return the minimum strength (as ``n``, representing ``2**n`` work)
     we will accept for a signature algorithm on any certificate.

     Use 80 to enable RSA-1024 (*not recommended*), or 128 to require
     either ECC or large (~3000 bit) RSA keys.

     Default: 110 (allowing 2048 bit RSA)

 .. cpp:function:: bool require_cert_revocation_info() const

     If this function returns true, and a ciphersuite using certificates was
     negotiated, then we must have access to a valid CRL or OCSP response in
     order to trust the certificate.

     .. warning:: Returning false here could expose you to attacks

     Default: true

 .. cpp:function:: Group_Params default_dh_group() const

     For ephemeral Diffie-Hellman key exchange, the server sends a
     group parameter. Return the 2 Byte TLS group identifier specifying the group parameter a
     server should use.

     Default: 2048 bit IETF IPsec group ("modp/ietf/2048")

 .. cpp:function:: size_t minimum_dh_group_size() const

     Return the minimum size in bits for a Diffie-Hellman group that a
     client will accept. Due to the design of the protocol the client
     has only two options - accept the group, or reject it with a
     fatal alert then attempt to reconnect after disabling ephemeral
     Diffie-Hellman.

     Default: 2048 bits

 .. cpp:function:: bool allow_tls10() const

      Return true from here to allow TLS v1.0. Since 2.8.0, returns
      ``false`` by default.

 .. cpp:function:: bool allow_tls11() const

      Return true from here to allow TLS v1.1. Since 2.8.0, returns
      ``false`` by default.

 .. cpp:function:: bool allow_tls12() const

      Return true from here to allow TLS v1.2. Returns ``true`` by default.

 .. cpp:function:: size_t minimum_rsa_bits() const

     Minimum accepted RSA key size. Default 2048 bits.

 .. cpp:function:: size_t minimum_dsa_group_size() const

     Minimum accepted DSA key size. Default 2048 bits.

 .. cpp:function:: size_t minimum_ecdsa_group_size() const

     Minimum size for ECDSA keys (256 bits).

 .. cpp:function:: size_t minimum_ecdh_group_size() const

     Minimum size for ECDH keys (255 bits).

 .. cpp:function:: void check_peer_key_acceptable(const Public_Key& public_key) const

     Allows the policy to examine peer public keys. Throw an exception
     if the key should be rejected. Default implementation checks
     against policy values `minimum_dh_group_size`, `minimum_rsa_bits`,
     `minimum_ecdsa_group_size`, and `minimum_ecdh_group_size`.

 .. cpp:function:: bool hide_unknown_users() const

     The PSK suites work using an identifier along with a
     shared secret. If this function returns true, when an identifier
     that the server does not recognize is provided by a client, a
     random shared secret will be generated in such a way that a
     client should not be able to tell the difference between the
     identifier not being known and the secret being wrong.  This can
     help protect against some username probing attacks.  If it
     returns false, the server will instead send an
     ``unknown_psk_identity`` alert when an unknown identifier is
     used.

     Default: false

 .. cpp:function:: u32bit session_ticket_lifetime() const

     Return the lifetime of session tickets. Each session includes the
     start time. Sessions resumptions using tickets older than
     ``session_ticket_lifetime`` seconds will fail, forcing a full
     renegotiation.

     Default: 86400 seconds (1 day)

TLS Ciphersuites
----------------------------------------

.. cpp:class:: TLS::Ciphersuite

 .. cpp:function:: uint16_t ciphersuite_code() const

     Return the numerical code for this ciphersuite

 .. cpp:function:: std::string to_string() const

     Return the full name of ciphersuite (for example
     "RSA_WITH_RC4_128_SHA" or "ECDHE_RSA_WITH_AES_128_GCM_SHA256")

 .. cpp:function:: std::string kex_algo() const

     Return the key exchange algorithm of this ciphersuite

 .. cpp:function:: std::string sig_algo() const

     Return the signature algorithm of this ciphersuite

 .. cpp:function:: std::string cipher_algo() const

     Return the cipher algorithm of this ciphersuite

 .. cpp:function:: std::string mac_algo() const

     Return the authentication algorithm of this ciphersuite

 .. cpp:function:: bool acceptable_ciphersuite(const Ciphersuite& suite) const

     Return true if ciphersuite is accepted by the policy.

     Allows an application to reject any ciphersuites, which are
     undesirable for whatever reason without having to reimplement
     :cpp:func:`TLS::Ciphersuite::ciphersuite_list`

 .. cpp:function:: std::vector<uint16_t> ciphersuite_list(Protocol_Version version, bool have_srp) const

     Return allowed ciphersuites in order of preference

     Allows an application to have full control over ciphersuites
     by returning desired ciphersuites in preference order.

.. _tls_alerts:

TLS Alerts
----------------------------------------

A ``TLS::Alert`` is passed to every invocation of a channel's *alert_cb*.

.. cpp:class:: TLS::Alert

  .. cpp:function:: is_valid() const

       Return true if this alert is not a null alert

  .. cpp:function:: is_fatal() const

       Return true if this alert is fatal. A fatal alert causes the
       connection to be immediately disconnected. Otherwise, the alert
       is a warning and the connection remains valid.

  .. cpp:function:: Type type() const

       Returns the type of the alert as an enum

  .. cpp:function:: std::string type_string()

       Returns the type of the alert as a string

TLS Protocol Version
----------------------------------------

TLS has several different versions with slightly different behaviors.
The ``TLS::Protocol_Version`` class represents a specific version:

.. cpp:class:: TLS::Protocol_Version

 .. cpp:enum:: Version_Code

     ``TLS_V10``, ``TLS_V11``, ``TLS_V12``, ``DTLS_V10``, ``DTLS_V12``

 .. cpp:function:: Protocol_Version(Version_Code named_version)

      Create a specific version

 .. cpp:function:: uint8_t major_version() const

      Returns major number of the protocol version

 .. cpp:function:: uint8_t minor_version() const

      Returns minor number of the protocol version

 .. cpp:function:: std::string to_string() const

      Returns string description of the version, for instance "TLS
      v1.1" or "DTLS v1.0".

 .. cpp:function:: static Protocol_Version latest_tls_version()

      Returns the latest version of the TLS protocol known to the library
      (currently TLS v1.2)

 .. cpp:function:: static Protocol_Version latest_dtls_version()

      Returns the latest version of the DTLS protocol known to the
      library (currently DTLS v1.2)

TLS Custom Key Exchange Mechanisms
----------------------------------------

Applications can override the ephemeral key exchange mechanism used in TLS.
This is not necessary for typical applications and might pose a serious security risk.
Though, it allows the usage of custom groups or curves, offloading of cryptographic calculations to
special hardware or the addition of entirely different algorithms (e.g. for post-quantum resilience).

From a technical point of view, the supported_groups TLS extension is used in the client hello to
advertise a list of supported elliptic curves and DH groups. The server subsequently selects one of
the groups, which is supported by both endpoints. Groups are represented by their TLS identifier.
This two-byte identifier is standardized for commonly used groups and curves. In addition, the standard
reserves the identifiers 0xFE00 to 0xFEFF for custom groups, curves or other algorithms.

To use custom curves with the Botan :cpp:class:`TLS::Client` or :cpp:class:`TLS::Server` the following
additional adjustments have to be implemented as shown in the following code examples.

1. Registration of the custom curve
2. Implementation TLS callbacks ``tls_generate_ephemeral_key`` and ``tls_ephemeral_key_agreement``
3. Adjustment of the TLS policy by allowing the custom curve

Below is a code example for a TLS client using a custom curve.
For servers, it works exactly the same.

Client Code Example
^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: /../src/examples/tls_custom_curves_client.cpp
   :language: cpp

.. _tls_stream:

TLS Stream
----------------------------------------

:cpp:class:`TLS::Stream` offers a Boost.Asio compatible wrapper around :cpp:class:`TLS::Client` and :cpp:class:`TLS::Server`.
It can be used as an alternative to Boost.Asio's `ssl::stream <https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ssl__stream.html>`_ with minor adjustments to the using code.
It offers the following interface:

.. cpp:class:: template <class StreamLayer, class ChannelT> TLS::Stream

   *StreamLayer* specifies the type of the stream's *next layer*, for example a `Boost.Asio TCP socket <https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ip__tcp/socket.html>`_.
   *ChannelT* is the type of the stream's *native handle*; it defaults to :cpp:class:`TLS::Channel` and should not be specified manually.

   .. cpp:function:: template <typename... Args> \
                     explicit Stream(Context& context, Args&& ... args)

   Construct a new TLS stream.
   The *context* parameter will be used to initialize the underlying *native handle*, i.e. the :ref:`TLS::Client <tls_client>` or :ref:`TLS::Server <tls_server>`, when :cpp:func:`handshake` is called.
   Using code must ensure the context is kept alive for the lifetime of the stream.
   The further *args* will be forwarded to the *next layer*'s constructor.

   .. cpp:function:: template <typename... Args> \
                     explicit Stream(Arg&& arg, Context& context)

   Convenience constructor for :cpp:class:`boost::asio::ssl::stream` compatibility.
   The parameters have the same meaning as for the first constructor, but their order is changed and only one argument can be passed to the *next layer* constructor.


   .. cpp:function:: void handshake(Connection_Side side, boost::system::error_code& ec)

   Set up the *native handle* and perform the TLS handshake.

   .. cpp:function:: void handshake(Connection_Side side)

   Overload of :cpp:func:`handshake` that throws an exception if an error occurs.

   .. cpp:function:: template <typename HandshakeHandler> \
                     DEDUCED async_handshake(Connection_Side side, HandshakeHandler&& handler)

   Asynchronous variant of :cpp:func:`handshake`.
   The function returns immediately and calls the *handler* callback function after performing asynchronous I/O to complete the TLS handshake.
   The return type is an automatically deduced specialization of :cpp:class:`boost::asio::async_result`, depending on the *HandshakeHandler* type.


   .. cpp:function:: void shutdown(boost::system::error_code& ec)

   Calls :cpp:func:`TLS::Channel::close` on the native handle and writes the TLS alert to the *next layer*.

   .. cpp:function:: void shutdown()

   Overload of :cpp:func:`shutdown` that throws an exception if an error occurs.

   .. cpp:function:: template <typename ShutdownHandler> \
                     void async_shutdown(ShutdownHandler&& handler)

   Asynchronous variant of :cpp:func:`shutdown`.
   The function returns immediately and calls the *handler* callback function after performing asynchronous I/O to complete the TLS shutdown.


   .. cpp:function:: template <typename MutableBufferSequence> \
                     std::size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec)

   Reads encrypted data from the *next layer*, decrypts it, and writes it into the provided *buffers*.
   If an error occurs, *error_code* is set.
   Returns the number of bytes read.

   .. cpp:function:: template <typename MutableBufferSequence> \
                     std::size_t read_some(const MutableBufferSequence& buffers)

   Overload of :cpp:func:`read_some` that throws an exception if an error occurs.

   .. cpp:function:: template <typename MutableBufferSequence, typename ReadHandler> \
                     DEDUCED async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)

   Asynchronous variant of :cpp:func:`read_some`.
   The function returns immediately and calls the *handler* callback function after writing the decrypted data into the provided *buffers*.
   The return type is an automatically deduced specialization of :cpp:class:`boost::asio::async_result`, depending on the *ReadHandler* type.
   *ReadHandler* should suffice the `requirements to a Boost.Asio read handler <https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ReadHandler.html>`_.


   .. cpp:function:: template <typename ConstBufferSequence> \
                     std::size_t write_some(const ConstBufferSequence& buffers, boost::system::error_code& ec)

   Encrypts data from the provided *buffers* and writes it to the *next layer*.
   If an error occurs, *error_code* is set.
   Returns the number of bytes written.

   .. cpp:function:: template <typename ConstBufferSequence> \
                     std::size_t write_some(const ConstBufferSequence& buffers)

   Overload of :cpp:func:`write_some` that throws an exception rather than setting an error code.

   .. cpp:function:: template <typename ConstBufferSequence, typename WriteHandler> \
                     DEDUCED async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)

   Asynchronous variant of :cpp:func:`write_some`.
   The function returns immediately and calls the *handler* callback function after writing the encrypted data to the *next layer*.
   The return type is an automatically deduced specialization of :cpp:class:`boost::asio::async_result`, depending on the *WriteHandler* type.
   *WriteHandler* should suffice the `requirements to a Boost.Asio write handler <https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/WriteHandler.html>`_.

.. cpp:class:: TLS::Context

   A helper class to initialize and configure the Stream's underlying *native handle* (see :cpp:class:`TLS::Client` and :cpp:class:`TLS::Server`).

   .. cpp:function:: Context(Credentials_Manager&   credentialsManager, \
                             RandomNumberGenerator& randomNumberGenerator, \
                             Session_Manager&       sessionManager, \
                             Policy&                policy, \
                             Server_Information     serverInfo = Server_Information())

   Constructor for TLS::Context.

   .. cpp:function:: void set_verify_callback(Verify_Callback_T callback)

   Set a user-defined callback function for certificate chain verification. This
   will cause the stream to override the default implementation of the
   :cpp:func:`tls_verify_cert_chain` callback.

TLS Stream Client Code Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The code below illustrates how to build a simple HTTPS client based on the TLS Stream and Boost.Beast. When run, it fetches the content of `https://botan.randombit.net/news.html` and prints it to stdout.

.. literalinclude:: /../src/examples/tls_stream_client.cpp
   :language: cpp

.. _tls_session_encryption:

TLS Session Encryption
-------------------------

A unified format is used for encrypting TLS sessions either for durable storage
(on client or server) or when creating TLS session tickets. This format is *not
stable* even across the same major version.

The current session encryption scheme was introduced in 2.13.0, replacing the
format previously used since 1.11.13.

Session encryption accepts a key of any length, though for best security a key
of 256 bits should be used. This master key is used to key an instance of HMAC
using the SHA-512/256 hash.

First a "key name" or identifier is created, by HMAC'ing the fixed string "BOTAN
TLS SESSION KEY NAME" and truncating to 4 bytes. This is the initial prefix of
the encrypted session, and will remain fixed as long as the same ticket key is
used. This allows quickly rejecting sessions which are encrypted using an
unknown or incorrect key.

Then a key used for AES-256 in GCM mode is created by first choosing a 128 bit
random seed, and HMAC'ing it to produce a 256-bit value. This means for any one
master key as many as 2\ :sup:`128` GCM keys can be created. This is done
because NIST recommends that when using random nonces no one GCM key be used to
encrypt more than 2\ :sup:`32` messages (to avoid the possiblity of nonce
reuse).

A random 96-bit nonce is created and included in the header.

AES in GCM is used to encrypt and authenticate the serialized session. The
key name, key seed, and AEAD nonce are all included as additional data.

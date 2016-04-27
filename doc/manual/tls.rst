Transport Layer Security (TLS)
========================================

.. versionadded:: 1.11.0

Botan has client and server implementations of various versions of the
TLS protocol, including TLS v1.0, TLS v1.1, and TLS v1.2. As of
version 1.11.13, support for the insecure SSLv3 protocol has been
removed.

There is also support for DTLS (v1.0 and v1.2), a variant of TLS
adapted for operation on datagram transports such as UDP and
SCTP. DTLS support should be considered as beta quality and further
testing is invited.

The TLS implementation does not know anything about sockets or the
network layer. Instead, it calls a user provided callback (hereafter
``output_fn``) whenever it has data that it would want to send to the
other party (for instance, by writing it to a network socket), and
whenever the application receives some data from the counterparty (for
instance, by reading from a network socket) it passes that information
to TLS using :cpp:func:`TLS::Channel::received_data`. If the data
passed in results in some change in the state, such as a handshake
completing, or some data or an alert being received from the other
side, then a user provided callback will be invoked. If the reader is
familiar with OpenSSL's BIO layer, it might be analagous to saying the
only way of interacting with Botan's TLS is via a `BIO_mem` I/O
abstraction. This makes the library completely agnostic to how you
write your network layer, be it blocking sockets, libevent, asio, a
message queue, etc.

The callbacks for TLS have the signatures

 .. cpp:function:: void output_fn(const byte data[], size_t data_len)

    TLS requests that all bytes of *data* be queued up to send to the
    counterparty. After this function returns, *data* will be
    overwritten, so a copy of the input must be made if the callback
    cannot send the data immediately.

 .. cpp:function:: void data_cb(const byte data[], size_t data_len)

     Called whenever application data is received from the other side
     of the connection, in which case *data* and *data_len* specify
     the data received. This array will be overwritten sometime after
     the callback returns, so again a copy should be made if need be.

 .. cpp:function:: void alert_cb(Alert alert, const byte data[], size_t data_len)

     Called when an alert is received. Normally, data is null and
     data_len is 0, as most alerts have no associated data. However,
     if TLS heartbeats (see :rfc:`6520`) were negotiated, and we
     initiated a heartbeat, then if/when the other party responds,
     ``alert_cb`` will be called with whatever data was included in
     the heartbeat response (if any) along with a psuedo-alert value
     of ``HEARTBEAT_PAYLOAD``.

 .. cpp:function:: bool handshake_cb(const TLS::Session& session)

     Called whenever a negotiation completes. This can happen more
     than once on any connection. The *session* parameter provides
     information about the session which was established.

     If this function returns false, the session will not be cached
     for later resumption.

     If this function wishes to cancel the handshake, it can throw an
     exception which will send a close message to the counterparty and
     reset the connection state.

You can of course use tools like ``std::bind`` to bind additional
parameters to your callback functions.

TLS Channels
----------------------------------------

TLS servers and clients share an interface called `TLS::Channel`. A
TLS channel (either client or server object) has these methods
available:

.. cpp:class:: TLS::Channel

   .. cpp:type:: std::function<void (const byte[], size_t)> output_fn

   .. cpp:type:: std::function<void (const byte[], size_t)> data_cb

   .. cpp:type:: std::function<void (Alert, const byte[], size_t)> alert_cb

   .. cpp:type:: std::function<bool (const Session&)> handshake_cb

     Typedefs used in the code for the functions described above

   .. cpp:function:: size_t received_data(const byte buf[], size_t buf_size)
   .. cpp:function:: size_t received_data(const std::vector<byte>& buf)

     This function is used to provide data sent by the counterparty
     (eg data that you read off the socket layer). Depending on the
     current protocol state and the amount of data provided this may
     result in one or more callback functions that were provided to
     the constructor being called.

     The return value of ``received_data`` specifies how many more
     bytes of input are needed to make any progress, unless the end of
     the data fell exactly on a message boundary, in which case it
     will return 0 instead.

   .. cpp:function:: void send(const byte buf[], size_t buf_size)
   .. cpp:function:: void send(const std::string& str)
   .. cpp:function:: void send(const std::vector<byte>& vec)

     Create one or more new TLS application records containing the
     provided data and send them. This will eventually result in at
     least one call to the ``output_fn`` callback before ``send``
     returns.

     If the current TLS connection state is unable to transmit new
     application records (for example because a handshake has not
     yet completed or the connnection has already ended due to an
     error) an exception will be thrown.

   .. cpp:function:: void close()

     A close notification is sent to the counterparty, and the
     internal state is cleared.

   .. cpp:function:: void send_alert(const Alert& alert)

     Some other alert is sent to the counterparty. If the alert is
     fatal, the internal state is cleared.

   .. cpp:function:: bool is_active()

     Returns true if and only if a handshake has been completed on
     this connection and the connection has not been subsequently
     closed.

   .. cpp:function:: bool is_closed()

      Returns true if and only if either a close notification or a
      fatal alert message have been either sent or received.

   .. cpp:function:: bool timeout_check()

      This function does nothing unless the channel represents a DTLS
      connection and a handshake is actively in progress. In this case
      it will check the current timeout state and potentially initiate
      retransmission of handshake packets. Returns true if a timeout
      condition occurred.

   .. cpp:function:: void renegotiate(bool force_full_renegotiation = false)

      Initiates a renegotiation. The counterparty is allowed by the
      protocol to ignore this request. If a successful renegotiation
      occurs, the *handshake_cb* callback will be called again.

      If *force_full_renegotiation* is false, then the client will
      attempt to simply renew the current session - this will refresh
      the symmetric keys but will not change the session master
      secret. Otherwise it will initiate a completely new session.

      For a server, if *force_full_renegotiation* is false, then a
      session resumption will be allowed if the client attempts
      it. Otherwise the server will prevent resumption and force the
      creation of a new session.

   .. cpp:function:: std::vector<X509_Certificate> peer_cert_chain()

      Returns the certificate chain of the counterparty. When acting
      as a client, this value will be non-empty unless the client's
      policy allowed anonymous connections and the server then chose
      an anonymous ciphersuite. Acting as a server, this value will
      ordinarily be empty, unless the server requested a certificate
      and the client responded with one.

   .. cpp:function:: SymmetricKey key_material_export( \
          const std::string& label, \
          const std::string& context, \
          size_t length)

      Returns an exported key of *length* bytes derived from *label*,
      *context*, and the session's master secret and client and server
      random values. This key will be unique to this connection, and
      as long as the session master secret remains secure an attacker
      should not be able to guess the key.

      Per :rfc:`5705`, *label* should begin with "EXPERIMENTAL" unless
      the label has been standardized in an RFC.

.. _tls_client:

TLS Clients
----------------------------------------

.. cpp:class:: TLS::Client

   .. cpp:function:: Client( \
         output_fn out, \
         data_cb app_data_cb, \
         alert_cb alert_cb, \
         handshake_cb hs_cb, \
         Session_Manager& session_manager, \
         Credentials_Manager& creds, \
         const Policy& policy, \
         RandomNumberGenerator& rng, \
         const Server_Information& server_info = Server_Information(), \
         const Protocol_Version offer_version = Protocol_Version::latest_tls_version(), \
         const std::vector<std::string>& next_protocols = {}, \
         size_t reserved_io_buffer_size = 16*1024 \
         )

   Initialize a new TLS client. The constructor will immediately
   initiate a new session.

   The *output_fn* callback will be called with output that
   should be sent to the counterparty. For instance this will be
   called immediately from the constructor after the client hello
   message is constructed. An implementation of *output_fn* is
   allowed to defer the write (for instance if writing when the
   callback occurs would block), but should eventually write the data
   to the counterparty *in order*.

   The *data_cb* will be called with data sent by the counterparty
   after it has been processed. The byte array and size_t represent
   the plaintext value and size.

   The *alert_cb* will be called when a protocol alert is received,
   commonly with a close alert during connection teardown.

   The *handshake_cb* function is called when a handshake
   (either initial or renegotiation) is completed. The return value of
   the callback specifies if the session should be cached for later
   resumption. If the function for some reason desires to prevent the
   connection from completing, it should throw an exception
   (preferably a TLS::Exception, which can provide more specific alert
   information to the counterparty). The :cpp:class:`TLS::Session`
   provides information about the session that was just established.

   The *session_manager* is an interface for storing TLS sessions,
   which allows for session resumption upon reconnecting to a server.
   In the absence of a need for persistent sessions, use
   :cpp:class:`TLS::Session_Manager_In_Memory` which caches
   connections for the lifetime of a single process. See
   :ref:`tls_session_managers` for more about session managers.

   The *credentials_manager* is an interface that will be called to
   retrieve any certificates, secret keys, pre-shared keys, or SRP
   information; see :doc:`credentials_manager` for more information.

   Use the optional *server_info* to specify the DNS name of the
   server you are attempting to connect to, if you know it. This helps
   the server select what certificate to use and helps the client
   validate the connection.

   Use the optional *offer_version* to control the version of TLS you
   wish the client to offer. Normally, you'll want to offer the most
   recent version of (D)TLS that is available, however some broken
   servers are intolerant of certain versions being offered, and for
   classes of applications that have to deal with such servers
   (typically web browsers) it may be necessary to implement a version
   backdown strategy if the initial attempt fails.

   .. warning::

     Implementing such a backdown strategy allows an attacker to
     downgrade your connection to the weakest protocol that both you
     and the server support.

   Setting *offer_version* is also used to offer DTLS instead of TLS;
   use :cpp:func:`TLS::Protocol_Version::latest_dtls_version`.

   Optionally, the client will advertise *app_protocols* to the
   server using the ALPN extension.

   The optional *reserved_io_buffer_size* specifies how many bytes to
   pre-allocate in the I/O buffers. Use this if you want to control
   how much memory the channel uses initially (the buffers will be
   resized as needed to process inputs). Otherwise some reasonable
   default is used.

Code for a TLS client using BSD sockets is in `src/cli/tls_client.cpp`

TLS Servers
----------------------------------------

.. cpp:class:: TLS::Server

   .. cpp:function:: Server( \
         output_fn output, \
         data_cb data_cb, \
         alert_cb alert_cb, \
         handshake_cb handshake_cb, \
         Session_Manager& session_manager, \
         Credentials_Manager& creds, \
         const Policy& policy, \
         RandomNumberGenerator& rng, \
         next_protocol_fn next_proto = next_protocol_fn(), \
         bool is_datagram = false, \
         size_t reserved_io_buffer_size = 16*1024 \
         )

The first 8 arguments as well as the final argument
*reserved_io_buffer_size*, are treated similiarly to the :ref:`client
<tls_client>`.

The (optional) argument, *proto_chooser*, is a function called if the
client sent the ALPN extension to negotiate an application
protocol. In that case, the function should choose a protocol to use
and return it. Alternately it can throw an exception to abort the
exchange; the ALPN specification says that if this occurs the alert
should be of type `NO_APPLICATION_PROTOCOL`.

The optional argument *is_datagram* specifies if this is a TLS or DTLS
server; unlike clients, which know what type of protocol (TLS vs DTLS)
they are negotiating from the start via the *offer_version*, servers
would not until they actually received a hello without this parameter.

Code for a TLS server using asio is in `src/cli/tls_proxy.cpp`.

.. _tls_sessions:

TLS Sessions
----------------------------------------

TLS allows clients and servers to support *session resumption*, where
the end point retains some information about an established session
and then reuse that information to bootstrap a new session in way that
is much cheaper computationally than a full handshake.

Every time your handshake callback is called, a new session has been
established, and a ``TLS::Session`` is included that provides
information about that session:

.. cpp:class:: TLS::Session

   .. cpp:function:: Protocol_Version version() const

       Returns the :cpp:class:`protocol version <TLS::Protocol_Version>`
       that was negotiated

   .. cpp:function:: Ciphersuite ciphersite() const

       Returns the :cpp:class:`ciphersuite <TLS::Ciphersuite>` that
       was negotiated.

   .. cpp:function:: Server_Information server_info() const

       Returns information that identifies the server side of the
       connection.  This is useful for the client in that it
       identifies what was originally passed to the constructor. For
       the server, it includes the name the client specified in the
       server name indicator extension.

   .. cpp:function:: std::vector<X509_Certificate> peer_certs() const

       Returns the certificate chain of the peer

   .. cpp:function:: std::string srp_identifier() const

       If an SRP ciphersuite was used, then this is the identifier
       that was used for authentication.

   .. cpp:function:: bool secure_renegotiation() const

      Returns ``true`` if the connection was negotiated with the
      correct extensions to prevent the renegotiation attack.

   .. cpp:function:: std::vector<byte> encrypt(const SymmetricKey& key, \
                                               RandomNumberGenerator& rng)

      Encrypts a session using a symmetric key *key* and returns a raw
      binary value that can later be passed to ``decrypt``. The key
      may be of any length.

      Currently the implementation encrypts the session using AES-256
      in GCM mode with a random nonce.

   .. cpp:function:: static Session decrypt(const byte ciphertext[], \
                                            size_t length, \
                                            const SymmetricKey& key)

      Decrypts a session that was encrypted previously with ``encrypt`` and
      ``key``, or throws an exception if decryption fails.

   .. cpp:function:: secure_vector<byte> DER_encode() const

       Returns a serialized version of the session.

       .. warning:: The return value of ``DER_encode`` contains the
                    master secret for the session, and an attacker who
                    recovers it could recover plaintext of previous
                    sessions or impersonate one side to the other.

.. _tls_session_managers:

TLS Session Managers
----------------------------------------

You may want sessions stored in a specific format or storage type. To
do so, implement the ``TLS::Session_Manager`` interface and pass your
implementation to the ``TLS::Client`` or ``TLS::Server`` constructor.

.. cpp:class:: TLS::Session_Mananger

 .. cpp:function:: void save(const Session& session)

     Save a new *session*. It is possible that this sessions session
     ID will replicate a session ID already stored, in which case the
     new session information should overwrite the previous information.

 .. cpp:function:: void remove_entry(const std::vector<byte>& session_id)

      Remove the session identified by *session_id*. Future attempts
      at resumption should fail for this session.

 .. cpp:function:: bool load_from_session_id(const std::vector<byte>& session_id, \
                                             Session& session)

      Attempt to resume a session identified by *session_id*. If
      located, *session* is set to the session data previously passed
      to *save*, and ``true`` is returned. Otherwise *session* is not
      modified and ``false`` is returned.

 .. cpp:function:: bool load_from_server_info(const Server_Information& server, \
                                              Session& session)

      Attempt to resume a session with a known server.

 .. cpp:function:: std::chrono::seconds session_lifetime() const

      Returns the expected maximum lifetime of a session when using
      this session manager. Will return 0 if the lifetime is unknown
      or has no explicit expiration policy.

.. _tls_session_manager_inmem:

In Memory Session Manager
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``TLS::Session_Manager_In_Memory`` implementation saves sessions
in memory, with an upper bound on the maximum number of sessions and
the lifetime of a session.

It is safe to share a single object across many threads as it uses a
lock internally.

.. cpp:class:: TLS::Session_Managers_In_Memory

 .. cpp:function:: Session_Manager_In_Memory(RandomNumberGenerator& rng, \
                                             size_t max_sessions = 1000, \
                                             std::chrono::seconds session_lifetime = 7200)

    Limits the maximum number of saved sessions to *max_sessions*, and
    expires all sessions older than *session_lifetime*.

Noop Session Mananger
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``TLS::Session_Manager_Noop`` implementation does not save
sessions at all, and thus session resumption always fails. Its
constructor has no arguments.

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

.. warning:: The hostnames associated with the saved sessions are
             stored in the database in plaintext. This may be a
             serious privacy risk in some applications.

.. cpp:class:: TLS::Session_Manager_SQLite

 .. cpp:function:: Session_Manager_SQLite( \
       const std::string& passphrase, \
       RandomNumberGenerator& rng, \
       const std::string& db_filename, \
       size_t max_sessions = 1000, \
       std::chrono::seconds session_lifetime = 7200)

   Uses the sqlite3 database named by *db_filename*.

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

     Values without an explicit mode use old-style CBC with HMAC encryption.

     Default value: "AES-256/GCM", "AES-128/GCM", "ChaCha20Poly1305",
     "AES-256/CCM", "AES-128/CCM", "AES-256/CCM-8", "AES-128/CCM-8",
     "AES-256", "AES-128"

     Also allowed: "Camellia-256/GCM", "Camellia-128/GCM",
     "Camellia-256", "Camellia-128"

     Also allowed (though currently experimental): "AES-128/OCB(12)",
     "AES-256/OCB(12)"

     Also allowed (although **not recommended**): "SEED", "3DES"

     .. note::

        The current ChaCha20Poly1305 ciphersuites are non-standard but
        as of 2015 were implemented and deployed by Google and
        elsewhere. Support will be changed to using IETF standard
        ChaCha20Poly1305 ciphersuites when those are defined.

     .. note::

        Support for the broken RC4 cipher was removed in 1.11.17

 .. cpp:function:: std::vector<std::string> allowed_macs() const

     Returns the list of algorithms we are willing to use for
     message authentication, in order of preference.

     Default: "AEAD", "SHA-384", "SHA-256", "SHA-1"

     A plain hash function indicates HMAC

 .. cpp:function:: std::vector<std::string> allowed_key_exchange_methods() const

     Returns the list of key exchange methods we are willing to use,
     in order of preference.

     Default: "ECDH", "DH", "RSA"

     Also allowed: "SRP_SHA", "ECDHE_PSK", "DHE_PSK", "PSK"

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

     Default: "ECDSA", "RSA", "DSA"

     Also allowed (disabled by default): "" (meaning anonymous)

 .. cpp:function:: std::vector<std::string> allowed_ecc_curves() const

     Return a list of ECC curves we are willing to use, in order of preference.

     Default: "brainpool512r1", "secp521r1", "brainpool384r1",
     "secp384r1", "brainpool256r1", "secp256r1"

     No other values are currently defined.

 .. cpp:function:: std::vector<byte> compression() const

     Return the list of compression methods we are willing to use, in order of
     preference. Default is null compression only.

     .. note::

        TLS compression is not currently supported.

 .. cpp:function:: bool acceptable_protocol_version(Protocol_Version version)

     Return true if this version of the protocol is one that we are
     willing to negotiate.

     Default: Accepts TLS v1.0 or higher and DTLS v1.2 or higher.

 .. cpp:function:: bool server_uses_own_ciphersuite_preferences() const

     If this returns true, a server will pick the cipher it prefers the
     most out of the client's list. Otherwise, it will negotiate the
     first cipher in the client's ciphersuite list that it supports.

 .. cpp:function:: bool negotiate_heartbeat_support() const

     If this function returns true, clients will offer the heartbeat
     support extension, and servers will respond to clients offering
     the extension. Otherwise, clients will not offer heartbeat
     support and servers will ignore clients offering heartbeat
     support.

     If this returns true, callers should expect to handle heartbeat
     data in their ``alert_cb``.

     Default: false

 .. cpp:function:: bool allow_server_initiated_renegotiation() const

     If this function returns true, a client will accept a
     server-initiated renegotiation attempt. Otherwise it will send
     the server a non-fatal ``no_renegotiation`` alert.

     Default: false

 .. cpp:function:: bool allow_insecure_renegotiation() const

     If this function returns true, we will allow renegotiation attempts
     even if the counterparty does not support the RFC 5746 extensions.

     .. warning:: Returning true here could expose you to attacks

     Default: false

 .. cpp:function:: std::string dh_group() const

     For ephemeral Diffie-Hellman key exchange, the server sends a
     group parameter. Return a string specifying the group parameter a
     server should use.

     Default: 2048 bit IETF IPsec group ("modp/ietf/2048")

 .. cpp:function:: size_t minimum_dh_group_size() const

     Return the minimum size in bits for a Diffie-Hellman group that a
     client will accept. Due to the design of the protocol the client
     has only two options - accept the group, or reject it with a
     fatal alert then attempt to reconnect after disabling ephemeral
     Diffie-Hellman.

     Default: 1024 bits

 .. cpp:function:: bool hide_unknown_users() const

     The SRP and PSK suites work using an identifier along with a
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

 .. cpp:function:: u16bit ciphersuite_code() const

     Return the numerical code for this ciphersuite

 .. cpp:function:: std::string to_string() const

     Return the ful name of ciphersuite (for example
     "RSA_WITH_RC4_128_SHA" or "ECDHE_RSA_WITH_AES_128_GCM_SHA256")

 .. cpp:function:: std::string kex_algo() const

     Return the key exchange algorithm of this ciphersuite

 .. cpp:function:: std::string sig_algo() const

     Return the signature algorithm of this ciphersuite

 .. cpp:function:: std::string cipher_algo() const

     Return the cipher algorithm of this ciphersuite

 .. cpp:function:: std::string mac_algo() const

     Return the authentication algorithm of this ciphersuite

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

 .. cpp:function:: byte major_version() const

      Returns major number of the protocol version

 .. cpp:function:: byte minor_version() const

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

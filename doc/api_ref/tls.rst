Transport Layer Security (TLS)
========================================

Botan has client and server implementations of TLS 1.2 and 1.3. Support for
older versions of the protocol was removed with Botan 3.0.

There is also support for DTLS (currently v1.2 only), a variant of TLS
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
side, then the appropriate user provided callback will be invoked.

If the reader is familiar with OpenSSL's BIO layer, it might be analogous
to saying the only way of interacting with Botan's TLS is via a `BIO_mem` I/O
abstraction. This makes the library completely agnostic to how you
write your network layer, be it blocking sockets, libevent, asio, a
message queue, lwIP on RTOS, some carrier pigeons, etc.

Note that we support :ref:`an optional Boost ASIO stream <tls_asio_stream>`
that is a convenient way to use Botan's TLS implementation as an almost drop-in
replacement of ASIO's `ssl::stream`. Applications that build their network
layer on Boost ASIO are advised to use this wrapper of ``TLS::Client`` and
``TLS::Server``.

Application callbacks are encapsulated as the class ``TLS::Callbacks`` with the
following members. The first three (``tls_emit_data``, ``tls_record_received``,
``tls_alert``) are mandatory for using TLS, all others are optional and provide
additional information about the connection.

 .. cpp:function:: void tls_emit_data(std::span<const uint8_t> data)

    Mandatory. The TLS stack requests that all bytes of *data* be queued up to send to the
    counterparty. After this function returns, the buffer containing *data* will
    be overwritten, so a copy of the input must be made if the callback
    cannot send the data immediately.

    As an example you could ``send`` to perform a blocking write on a socket,
    or append the data to a queue managed by your application, and initiate
    an asynchronous write.

    For TLS all writes must occur *in the order requested*.
    For DTLS this ordering is not strictly required, but is still recommended.

 .. cpp:function:: void tls_record_received(uint64_t rec_no, std::span<const uint8_t> data)

    Mandatory. Called once for each application_data record which is received, with the
    matching (TLS level) record sequence number.

    Currently empty records are ignored and do not instigate a callback,
    but this may change in a future release.

     As with ``tls_emit_data``, the array will be overwritten sometime after
     the callback returns, so a copy should be made if needed.

     For TLS the record number will always increase.

     For DTLS, it is possible to receive records with the `rec_no` field out of
     order, or with gaps, corresponding to reordered or lost datagrams.

 .. cpp:function:: void tls_alert(Alert alert)

     Mandatory. Called when an alert is received from the peer. Note that alerts
     received before the handshake is complete are not authenticated and
     could have been inserted by a MITM attacker.

 .. cpp:function:: void tls_session_established(const Botan::TLS::Session_Summary& session)

     Optional - default implementation is a no-op
     Called whenever a negotiation completes. This can happen more than once on
     TLS 1.2 connections, if renegotiation occurs. The *session* parameter
     provides information about the session which was just established.

     If this function wishes to cancel the handshake, it can throw an
     exception which will send a close message to the counterparty and
     reset the connection state.

 .. cpp:function:: void tls_verify_cert_chain(const std::vector<X509_Certificate>& cert_chain, \
                   const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_responses, \
                   const std::vector<Certificate_Store*>& trusted_roots, \
                   Usage_Type usage, \
                   std::string_view hostname, \
                   const Policy& policy)

     Optional - default implementation should work for many users.
     It can be overridden for implementing extra validation routines
     such as public key pinning.

     Verifies the certificate chain in *cert_chain*, assuming the leaf
     certificate is the first element. Throws an exception if any
     error makes this certificate chain unacceptable.

     If usage is `Usage_Type::TLS_SERVER_AUTH`, then *hostname* should
     match the information in the server certificate. If usage is
     `TLS_CLIENT_AUTH`, then *hostname* specifies the host the client
     is authenticating against (from SNI); the callback can use this for
     any special site specific auth logic.

     The `ocsp_responses` is a possibly empty list of OCSP responses provided by
     the server. In the current implementation of TLS OCSP stapling, only a
     single OCSP response can be returned. A existing TLS extension allows the
     server to send multiple OCSP responses, this extension may be supported in
     the future in which case more than one OCSP response may be given during
     this callback.

     The `trusted_roots` parameter was returned by a call from the associated
     `Credentials_Manager`.

     The `policy` provided is the policy for the TLS session which is
     being authenticated using this certificate chain. It can be consulted
     for values such as allowable signature methods and key sizes.

 .. cpp:function:: std::chrono::milliseconds tls_verify_cert_chain_ocsp_timeout() const

     Called by default `tls_verify_cert_chain` to set timeout for online OCSP requests
     on the certificate chain. Return 0 to disable OCSP. Current default is 0.

 .. cpp:function:: std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos)

     Optional. Called by the server when a client includes a list of protocols in the ALPN extension.
     The server then choose which protocol to use, or "" to disable sending any ALPN response.
     The default implementation returns the empty string all of the time, effectively disabling
     ALPN responses. The server may also throw an exception to reject the connection; this is
     recommended when the client sends a list of protocols and the server does not understand
     any of them.

     .. warning::

        The ALPN RFC requires that if the server does not understand any of the
        protocols offered by the client, it should close the connection using an
        alert. Carrying on the connection (for example by ignoring ALPN when the
        server does not understand the protocol list) can expose applications to
        cross-protocol attacks.

 .. cpp:function:: void tls_session_activated()

    Optional. By default does nothing. This is called when the session is
    activated, that is once it is possible to send or receive data on the
    channel.  In particular it is possible for an implementation of this
    function to perform an initial write on the channel.

 .. cpp:function:: std::vector<uint8_t> tls_provide_cert_status(const std::vector<X509_Certificate>& chain, \
                                                           const Certificate_Status_Request& csr)

     Optional. This can return a cached OCSP response. This is only
     used on the server side, and only if the client requests OCSP
     stapling.

 .. cpp:function:: std::vector<std::vector<uint8_t>> tls_provide_cert_chain_status( \
                   const std::vector<X509_Certificate>& chain, \
                   const Certificate_Status_Request& csr)

     Optional. This may be called by TLS 1.3 clients or servers when OCSP
     stapling was negotiated. In contrast to ``tls_provide_cert_status``,
     this allows providing OCSP responses for each certificate in the chain.

     Note that the returned list of encoded OCSP responses must be of the same
     length as the input list of certificates in the chain. By default, this will
     call ``tls_provide_cert_status`` to obtain an OCSP response for the end-entity
     only.

 .. cpp:function:: std::string tls_peer_network_identity()

     Optional. Return a string that identifies the peer in some unique way
     (for example, by formatting the remote IP and port into a string).
     This is currently used to bind DTLS cookies to the network identity.

 .. cpp:function:: void tls_inspect_handshake_msg(const Handshake_Message&)

     This callback is optional, and can be used to inspect all handshake messages
     while the session establishment occurs.

 .. cpp:function:: void tls_modify_extensions(Extensions& extn, Connection_Side which_side)

     This callback is optional, and can be used to modify extensions before they
     are sent to the peer. For example this enables adding a custom extension,
     or replacing or removing an extension set by the library.

 .. cpp:function:: void tls_examine_extensions(const Extensions& extn, Connection_Side which_side)

     This callback is optional, and can be used to examine extensions sent by
     the peer.

 .. cpp:function:: void tls_log_error(const char* msg)

     Optional logging for an error message. (Not currently used)

 .. cpp:function:: void tls_log_debug(const char* msg)

     Optional logging for an debug message. (Not currently used)

 .. cpp:function:: void tls_log_debug_bin(const char* descr, const uint8_t val[], size_t len)

     Optional logging for an debug value. (Not currently used)

TLS Channels
----------------------------------------

TLS servers and clients share an interface called `TLS::Channel`. A
TLS channel (either client or server object) has these methods
available:

.. cpp:class:: TLS::Channel

   .. cpp:function:: size_t received_data(const uint8_t buf[], size_t buf_size)
   .. cpp:function:: size_t received_data(std::span<const uint8_t> buf)

     This function is used to provide data sent by the counterparty
     (eg data that you read off the socket layer). Depending on the
     current protocol state and the amount of data provided this may
     result in one or more callback functions that were provided to
     the constructor being called.

     The return value of ``received_data`` specifies how many more
     bytes of input are needed to make any progress, unless the end of
     the data fell exactly on a message boundary, in which case it
     will return 0 instead.

   .. cpp:function:: void send(const uint8_t buf[], size_t buf_size)
   .. cpp:function:: void send(std::string_view str)
   .. cpp:function:: void send(std::span<const uint8_t> vec)

     Create one or more new TLS application records containing the
     provided data and send them. This will eventually result in at
     least one call to the ``output_fn`` callback before ``send``
     returns.

     If the current TLS connection state is unable to transmit new
     application records (for example because a handshake has not
     yet completed or the connection has already ended due to an
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

   .. cpp:function:: bool is_closed_for_reading()

      TLS 1.3 supports half-open connections. If the peer notified a
      connection closure, this will return true. For TLS 1.2 this will
      always return the same ``is_closed``.

   .. cpp:function:: bool is_closed_for_writing()

      TLS 1.3 supports half-open connections. After calling ``close``
      on the channel, this will return true. For TLS 1.2 this will
      always return the same ``is_closed``.

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

      Note that TLS 1.3 does not support renegotiation. This method will
      throw when called on a channel that uses TLS 1.3.

      If *force_full_renegotiation* is false, then the client will
      attempt to simply renew the current session - this will refresh
      the symmetric keys but will not change the session master
      secret. Otherwise it will initiate a completely new session.

      For a server, if *force_full_renegotiation* is false, then a
      session resumption will be allowed if the client attempts
      it. Otherwise the server will prevent resumption and force the
      creation of a new session.

   .. cpp:function:: void update_traffic_keys(bool request_peer_update = false)

      After a successful handshake, this will update our traffic keys and
      may send a request to do the same to the peer.

      Note that this is a TLS 1.3 feature and invocations on a channel
      using TLS 1.2 will throw.

   .. cpp:function:: std::vector<X509_Certificate> peer_cert_chain()

      Returns the certificate chain of the counterparty. When acting
      as a client, this value will be non-empty. Acting as a server,
      this value will ordinarily be empty, unless the server requested
      a certificate and the client responded with one.

   .. cpp:function:: std::optional<std::string> external_psk_identity() const

      When this connection was established using a user-defined Preshared Key
      this will return the identity of the PSK used. If no PSK was used in
      the establishment of the connection this will return std::nullopt.

      Note that TLS 1.3 session resumption is based on PSKs internally.
      Neverthelees, connections that were established using a session resumption
      will return std::nullopt here.

   .. cpp:function:: SymmetricKey key_material_export( \
          std::string_view label, \
          std::string_view context, \
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
         const std::shared_ptr<Callbacks>& callbacks, \
         const std::shared_ptr<Session_Manager>& session_manager, \
         const std::shared_ptr<Credentials_Manager>& creds, \
         const std::shared_ptr<const Policy>& policy, \
         const std::shared_ptr<RandomNumberGenerator>& rng, \
         Server_Information server_info = Server_Information(), \
         Protocol_Version offer_version = Protocol_Version::latest_tls_version(), \
         const std::vector<std::string>& next_protocols = std::vector<std::string>(), \
         size_t reserved_io_buffer_size = 16*1024 \
         )

   Initialize a new TLS client. The constructor will immediately
   initiate a new session.

   The *callbacks* parameter specifies the various application callbacks
   which pertain to this particular client connection.

   The *session_manager* is an interface for storing TLS sessions,
   which allows for session resumption upon reconnecting to a server.
   In the absence of a need for persistent sessions, use
   :cpp:class:`TLS::Session_Manager_In_Memory` which caches
   connections for the lifetime of a single process. See
   :ref:`tls_session_managers` for more about session managers.

   The *credentials_manager* is an interface that will be called to
   retrieve any certificates, private keys, or pre-shared keys; see
   :doc:`credentials_manager` for more information.

   Use the optional *server_info* to specify the DNS name of the
   server you are attempting to connect to, if you know it. This helps
   the server select what certificate to use and helps the client
   validate the connection.

   Note that the server name indicator name must be a FQDN.  IP
   addresses are not allowed by RFC 6066 and may lead to interoperability
   problems.

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

.. _tls_client_example:

Code Example: TLS Client
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
A minimal example of a TLS client is provided below.
The full code for a TLS client using BSD sockets is in `src/cli/tls_client.cpp`

.. literalinclude:: /../src/examples/tls_client.cpp
   :language: cpp

.. _tls_server:

TLS Servers
----------------------------------------

.. cpp:class:: TLS::Server

   .. cpp:function:: Server( \
         const std::shared_ptr<Callbacks>& callbacks, \
         const std::shared_ptr<Session_Manager>& session_manager, \
         const std::shared_ptr<Credentials_Manager>& creds, \
         const std::shared_ptr<const Policy>& policy, \
         const std::shared_ptr<RandomNumberGenerator>& rng, \
         bool is_datagram = false, \
         size_t reserved_io_buffer_size = 16*1024 \
         )

The first 5 arguments as well as the final argument
*reserved_io_buffer_size*, are treated similarly to the :ref:`client
<tls_client>`.

If a client sends the ALPN extension, the ``callbacks`` function
``tls_server_choose_app_protocol`` will be called and the result
sent back to the client. If the empty string is returned, the server
will not send an ALPN response. The function can also throw an exception
to abort the handshake entirely, the ALPN specification says that if this
occurs the alert should be of type `NO_APPLICATION_PROTOCOL`.

The optional argument *is_datagram* specifies if this is a TLS or DTLS
server; unlike clients, which know what type of protocol (TLS vs DTLS)
they are negotiating from the start via the *offer_version*, servers
would not until they actually received a client hello.

.. _tls_server_example:

Code Example: TLS Server
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
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

Every time the handshake callback (``TLS::Callbacks::tls_session_established``)
is called, a new session has been established, and a ``TLS::Session_Summary`` is
included that provides information about that session:

.. cpp:class:: TLS::Session_Summary

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

   .. cpp:function:: bool was_resumption() const

       Returns true if the session resulted from a resumption of a previously
       established session.

   .. cpp:function:: std::vector<X509_Certificate> peer_certs() const

       Returns the certificate chain of the peer

   .. cpp:function:: std::optional<std::string> external_psk_identity() const

       If the session was established using a user-provided Preshared Key,
       its identity will be provided here. If no PSK was used, std::nullopt
       will be reported.

   .. cpp:function:: bool psk_used() const

       Returns true if the session was established using a user-provided
       Preshared Key.

.. _tls_session_managers:

TLS Session Managers
----------------------------------------

You may want sessions stored in a specific format or storage type. To
do so, implement the ``TLS::Session_Manager`` interface and pass your
implementation to the ``TLS::Client`` or ``TLS::Server`` constructor.

.. note::

   The serialization format of ``Session`` is not considered stable and is
   allowed to change even across minor releases. In the event of such a change,
   old sessions will no longer be able to be resumed.

The interface of the ``TLS::Session_Manager`` was completely redesigned
with Botan 3.0 to accommodate the new requirements of TLS 1.3. Please also see
:ref:`the migration guide <tls_session_manager_migration>` for an outline of
the differences between the Botan 2.x and 3.x API.

In Botan 3.0 the server-side ``TLS::Session_Manager`` gained the competency to
decide whether to store sessions in a stateful database and just return a
handle to it. Or to serialize the session into an encrypted ticket and pass it
back to the client. To distinguish those use cases, Botan 3.0 introduced a
``TLS::Session_Handle`` class that is used throughout this API.

Below is a brief overview of the most important methods that a custom
implementation must implement. There are more methods that provide applications
with full flexibility to handle session objects. More detail can be found in
the API documentation inline.

.. cpp:class:: TLS::Session_Mananger

 .. cpp:function:: void store(const Session& session, const Session_Handle& handle)

     Attempts to save a new *session*. Typical implementations will use
     ``TLS::Session::encrypt``, ``TLS::Session::DER_encode`` or
     ``TLS::Session::PEM_encode`` to obtain an opaque and serialized session
     object for storage. It is legal to simply drop an incoming session for
     whatever reason.

 .. cpp:function:: size_t remove(const Session_Handle& handle)

      Remove the session identified by *handle*. Future attempts
      at resumption should fail for this session. Returns the number of sessions
      actually removed.

 .. cpp:function:: size_t remove_all()

      Empties the session storage. Returns the number of sessions actually
      removed.

 .. cpp:function:: std::optional<Session> retrieve_one(const Session_Handle& handle)

      Attempts to retrieve a single session that corresponds to *handle* from
      storage. Typical implementations will use ``TLS::Session::decrypt`` or the
      ``TLS::Session`` constructors that deserialize a session from DER or PEM.
      If no session was found for the given *handle*, return std::nullopt. This
      method is called in TLS servers to find a specific session for a given
      handle.

 .. cpp:function:: std::vector<Session_with_Handle> find_some(const Server_Information& info, size_t max_sessions_hint)

      Try to find some saved sessions using information about the server. TLS
      1.3 clients may offer more than one session for resumption to the server.
      It is okay to ignore the *max_sessions_hint* and just return exactly one
      or no sessions at all.

 .. cpp:function:: recursive_mutex_type& mutex()

      Derived implementations may use this mutex to serialize concurrent requests.

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
                                             size_t max_sessions = 1000)

    Limits the maximum number of saved sessions to *max_sessions*.

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
       std::string_view passphrase, \
       const std::shared_ptr<RandomNumberGenerator>& rng, \
       std::string_view db_filename, \
       size_t max_sessions = 1000)

   Uses the sqlite3 database named by *db_filename*.

Stateless Session Manager
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This session manager is useful for servers that want to implement stateless
session resumption. If supported by the client, sessions are always encoded as
opaque and encrypted session tickets. Sessions are encrypted with a symmetric
secret obtained via ``TLS::Credentials_Manager::session_ticket_key()``.

 .. cpp:function:: Session_Manager_Stateless( \
       const std::shared_ptr<Credentials_Manager>& credentials_manager, \
       const std::shared_ptr<RandomNumberGenerator>& rng)

    Creates a stateless session manager.


Hybrid Session Manager
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a meta-manager that combines a ``TLS::Session_Manager_Stateless`` with
any (built-in or user-provided) stateful session manager. Typically, such a
hybrid manager is useful for TLS servers that want to support both stateless
session tickets and stateful session storage.

 .. cpp:function:: Session_Manager_Hybrid(std::unique_ptr<Session_Manager> stateful_manager, \
                   const std::shared_ptr<Credentials_Manager>& credentials_manager, \
                   const std::shared_ptr<RandomNumberGenerator>& rng, \
                   bool prefer_tickets = true)

    Creates a hybrid session manager that uses *stateful_manager* as its storage
    backend when session tickets are not supported or desired.

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

 .. cpp:function:: std::vector<Group_Param> key_exchange_groups_to_offer() const

     Return a list of groups to opportunistically offer key exchange information
     for in the initial ClientHello when offering TLS 1.3. This policy has no
     effect on TLS 1.2 connections.

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

 .. cpp:function:: bool allow_tls12() const

      Return true from here to allow TLS v1.2. Returns ``true`` by default.

 .. cpp:function:: bool allow_tls13() const

      Return true from here to allow TLS v1.3. Returns ``true`` by default.

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

 .. cpp:function:: std::chrono::seconds session_ticket_lifetime() const

     Return the lifetime of session tickets. Each session includes the
     start time. Sessions resumptions using tickets older than
     ``session_ticket_lifetime`` seconds will fail, forcing a full
     renegotiation.

     Default: 86400 seconds (1 day)

 .. cpp:function:: size_t new_session_tickets_upon_handshake_success() const

     Return the number of session tickets a TLS 1.3 server should issue
     automatically once a successful handshake was made. Alternatively, users
     may manually call ``TLS::Server::send_new_session_tickets()`` at any time
     after a successful handshake.

     Default: 1

 .. cpp:function:: std::optional<uint16_t> record_size_limit() const

     Defines the maximum TLS record length this peer is willing to receive or
     std::nullopt in case of no preference (will use the maximum allowed).

     This is currently implemented for TLS 1.3 only and will not be negotiated
     if TLS 1.2 is used or allowed.

     Default: no preference (use maximum allowed by the protocol)

 .. cpp:function:: bool tls_13_middlebox_compatibility_mode() const

     Enables middlebox compatibility mode as defined in RFC 8446 Appendix D.4.

     Default: true


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


Post-quantum-secure key exchange
--------------------------------

.. versionadded:: :: 3.2

Botan allows TLS 1.3 handshakes using both pure post-quantum secure algorithms
or a hybrid key exchange that combines a classical and a post-quantum secure
algorithm. For the latter it implements the recent IETF
`draft-ietf-tls-hybrid-design
<https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design>`_.

Note that post-quantum key exchanges in TLS 1.3 are not conclusively
standardized. Therefore, the key exchange group identifiers used by various TLS
1.3 implementations are not consistent. Applications that wish to enable hybrid
key exchanges must enable the hybrid algorithms in their TLS policy. Override
`TLS::Policy::key_exchange_groups()` and return a list of the desired exchange
groups. For text-based policy configurations use the identifiers in parenthesis.

Currently, Botan supports the following post-quantum secure key exchanges:

* ML-KEM plus ECC hybrid, as deployed by Google, Cloudflare, etc and likely
  to be in the future standardized by IETF

  * ``HYBRID_SECP256R1_ML_KEM_768`` ("secp256r1/ML-KEM-768")
  * ``HYBRID_X25519_ML_KEM_768`` ("x25519/ML-KEM-768")

* Pure ML-KEM as documented in IETF draft ``draft-connolly-tls-mlkem-key-agreement``

  * ``ML_KEM_512``
  * ``ML_KEM_768``
  * ``ML_KEM_1024``

.. _tls_hybrid_client_example:

Code Example: Hybrid TLS Client
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: /../src/examples/tls_13_hybrid_key_exchange_client.cpp
   :language: cpp

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
2. Implementation of TLS callbacks ``tls_generate_ephemeral_key`` and ``tls_deserialize_peer_public_key``
3. Adjustment of the TLS policy by allowing the custom curve

Below is a code example for a TLS client using a custom curve.
For servers, it works exactly the same.

Code Example: TLS Client using Custom Curve
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: /../src/examples/tls_custom_curves_client.cpp
   :language: cpp

.. _tls_asio_stream:

TLS Stream
----------------------------------------

:cpp:class:`TLS::Stream` offers a Boost.Asio compatible wrapper around :cpp:class:`TLS::Client` and :cpp:class:`TLS::Server`.
It can be used as an alternative to Boost.Asio's `ssl::stream <https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ssl__stream.html>`_ with minor adjustments to the using code.

To use the asio stream wrapper, a relatively recent version of boost is required.
Include ``botan/asio_compat.h`` and check that ``BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION``
is defined before including ``botan/asio_stream.h`` to be ensure compatibility at
compile time of your application.

The asio Stream offers the following interface:

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

.. _https_client_example:

Code Examples: HTTPS Client using Boost Beast
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Starting with Botan 3.3.0 (and assuming a recent version of Boost), one may use
Botan's TLS using C++20 coroutines. The following example implements a minimal
HTTPS client using Botan's default settings to fetch content from web servers.

To establish trust in the server's certificate, Botan attempts to use the
system's trust store (supported on macOS, Linux and Windows). If that does not
work, you might get an error indicating that the certificate is not trusted. In
that case, you can provide a custom trust store by subclassing the
:cpp:class:`Credentials_Manager` and passing it to the :cpp:class:`TLS::Stream`
as shown in :ref:`this example <asio_client_example>`.

Note that Botan's default TLS policy requires servers to provide a valid CRL or
OCSP response for their certificate. To disable this, derive the default policy
class :cpp:class:`TLS::Policy`, override
:cpp:func:`require_cert_revocation_info()` accordingly and pass an object of
your policy via the :cpp:class:`TLS::Context` to the :cpp:class:`TLS::Stream`.

.. literalinclude:: /../src/examples/tls_stream_coroutine_client.cpp
   :language: cpp

.. _asio_client_example:

Aside of the modern coroutines-based approach, the ASIO stream may also be used
in a more traditional way, using callback handler methods instead of coroutines.

Also, this example shows how to use a custom :cpp:class:`Credentials_Manager`
and pass it to the :cpp:class:`TLS::Stream` via a :cpp:class:`TLS::Context`
object.

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

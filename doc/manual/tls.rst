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
side, then the appropriate user provided callback will be invoked.

If the reader is familiar with OpenSSL's BIO layer, it might be analagous
to saying the only way of interacting with Botan's TLS is via a `BIO_mem` I/O
abstraction. This makes the library completely agnostic to how you
write your network layer, be it blocking sockets, libevent, asio, a
message queue, lwIP on RTOS, some carrier pidgeons, etc.

Starting in 1.11.31, the application callbacks are encapsulated as the class
``TLS::Callbacks`` with the following members. The first four (``tls_emit_data``,
``tls_record_received``, ``tls_alert``, and ``tls_session_established``) are
mandatory for using TLS, all others are optional and provide additional
information about the connection.

 .. cpp:function:: void tls_emit_data(const byte data[], size_t data_len)

    Mandatory. The TLS stack requests that all bytes of *data* be queued up to send to the
    counterparty. After this function returns, the buffer containing *data* will
    be overwritten, so a copy of the input must be made if the callback
    cannot send the data immediately.

    As an example you could ``send`` to perform a blocking write on a socket,
    or append the data to a queue managed by your application, and initiate
    an asyncronous write.

    For TLS all writes must occur *in the order requested*.
    For DTLS this ordering is not strictly required, but is still recommended.

 .. cpp:function:: void tls_record_received(uint64_t rec_no, const byte data[], size_t data_len)

    Mandatory. Called once for each application_data record which is received, with the
    matching (TLS level) record sequence number.

    Currently empty records are ignored and do not instigate a callback,
    but this may change in a future release.

     As with ``tls_emit_data``, the array will be overwritten sometime after
     the callback returns, so a copy should be made if needed.

     For TLS the record number will always increase.

     For DTLS, it is possible to receive records with the `rec_no` field out of
     order, or with gaps, cooresponding to reordered or lost datagrams.

 .. cpp:function:: void tls_alert(Alert alert)

     Mandatory. Called when an alert is received from the peer. Note that alerts
     received before the handshake is complete are not authenticated and
     could have been inserted by a MITM attacker.

 .. cpp:function:: bool tls_session_established(const TLS::Session& session)

     Mandatory. Called whenever a negotiation completes. This can happen more
     than once on any connection, if renegotiation occurs. The *session* parameter
     provides information about the session which was just established.

     If this function returns false, the session will not be cached
     for later resumption.

     If this function wishes to cancel the handshake, it can throw an
     exception which will send a close message to the counterparty and
     reset the connection state.

 .. cpp::function:: void tls_verify_cert_chain(const std::vector<X509_Certificate>& cert_chain, \
                   const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_responses, \
                   const std::vector<Certificate_Store*>& trusted_roots, \
                   Usage_Type usage, \
                   const std::string& hostname, \
                   const Policy& policy)

     Optional - default implementation should work for many users.
     It can be overrided for implementing extra validation routines
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

 .. cpp::function:: std::chrono::milliseconds tls_verify_cert_chain_ocsp_timeout() const

     Called by default `tls_verify_cert_chain` to set timeout for online OCSP requests
     on the certificate chain. Return 0 to disable OCSP. Current default is 0.

 .. cpp:function:: std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos)

     Optional. Called by the server when a client includes a list of protocols in the ALPN extension.
     The server then choose which protocol to use, or "" to disable sending any ALPN response.
     The default implementation returns the empty string all of the time, effectively disabling
     ALPN responses.

 .. cpp:function:: void tls_inspect_handshake_msg(const Handshake_Message&)

     This callback is optional, and can be used to inspect all handshake messages
     while the session establishment occurs.

 .. cpp:function:: void tls_log_error(const char* msg)

     Optional logging for an error message. (Not currently used)

 .. cpp:function:: void tls_log_debug(const char* msg)

     Optional logging for an debug message. (Not currently used)

 .. cpp:function:: void tls_log_debug_bin(const char* descr, const uint8_t val[], size_t len)

     Optional logging for an debug value. (Not currently used)

Versions from 1.11.0 to 1.11.30 did not have ``TLS::Callbacks`` and instead
used independent std::functions to pass the various callback functions.
This interface is currently still included but is deprecated and will be removed
in a future release. For the documentation for this interface, please check
the docs for 1.11.30. This version of the manual only documents the new interface
added in 1.11.31.

TLS Channels
----------------------------------------

TLS servers and clients share an interface called `TLS::Channel`. A
TLS channel (either client or server object) has these methods
available:

.. cpp:class:: TLS::Channel

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
         Callbacks& callbacks, \
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

   The *callbacks* parameter specifies the various application callbacks
   which pertain to this particular client connection.

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

Code Example
^^^^^^^^^^^^
A minimal example of a TLS client is provided below.
The full code for a TLS client using BSD sockets is in `src/cli/tls_client.cpp`

.. code-block:: cpp

    #include <botan/tls_client.h>
    #include <botan/tls_callbacks.h>
    #include <botan/tls_session_manager.h>
    #include <botan/tls_policy.h>
    #include <botan/auto_rng.h>
    #include <botan/certstor.h>

    /**
     * @brief Callbacks invoked by TLS::Channel.
     *
     * Botan::TLS::Callbacks is an abstract class.
     * For improved readability, only the functions that are mandatory
     * to implement are listed here. See src/lib/tls/tls_callbacks.h.
     */
    class Callbacks : public Botan::TLS::Callbacks
    {
       public:
          void tls_emit_data(const uint8_t data[], size_t size) override
             {
             // send data to tls server, e.g., using BSD sockets or boost asio
             }

          void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
             {
             // process full TLS record received by tls server, e.g.,
             // by passing it to the application
             }

          void tls_alert(Botan::TLS::Alert alert) override
             {
             // handle a tls alert received from the tls server
             }

          bool tls_session_established(const Botan::TLS::Session& session) override
             {
             // the session with the tls server was established
             // return false to prevent the session from being cached, true to
             // cache the session in the configured session manager
             return false;
             }
    };

    /**
     * @brief Credentials storage for the tls client.
     *
     * It returns a list of trusted CA certificates from a local directory.
     * TLS client authentication is disabled. See src/lib/tls/credentials_manager.h.
     */
    class Client_Credentials : public Botan::Credentials_Manager
    {
       public:
          std::vector<Certificate_Store*> trusted_certificate_authorities(
             const std::string& type,
             const std::string& context) override
             {
             // return a list of certificates of CAs we trust for tls server certificates,
             // e.g., all the certificates in the local directory "cas"
             return { new Botan::Certificate_Store_In_Memory("cas") };
             }

          std::vector<X509_Certificate> cert_chain(
             const std::vector<std::string>& cert_key_types,
             const std::string& type,
             const std::string& context) override
             {
             // when using tls client authentication (optional), return
             // a certificate chain being sent to the tls server,
             // else an empty list
             return std::vector<Botan::X509_Certificate>();
             }

          Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
             const std::string& type,
             const std::string& context) override
             {
             // when returning a chain in cert_chain(), return the private key
             // associated with the leaf certificate here
             return nullptr;
             }
    };

    int main()
       {
       // prepare all the parameters
       Callbacks callbacks;
       Botan::AutoSeeded_RNG rng;
       Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
       Botan::Client_Credentials creds;
       Botan::TLS::Strict_Policy policy;

       // open the tls connection
       Botan::TLS::Client client(callbacks,
                                 session_mgr,
                                 creds,
                                 policy,
                                 rng,
                                 Botan::TLS::Server_Information("botan.randombit.net", 443),
                                 Botan::TLS::Protocol_Version::TLS_V12);

       while(!client.is_closed())
          {
          // read data received from the tls server, e.g., using BSD sockets or boost asio
          // ...

          // send data to the tls server using client.send_data()
          }
       }

TLS Servers
----------------------------------------

.. cpp:class:: TLS::Server

   .. cpp:function:: Server( \
         Callbacks& callbacks, \
         Session_Manager& session_manager, \
         Credentials_Manager& creds, \
         const Policy& policy, \
         RandomNumberGenerator& rng, \
         bool is_datagram = false, \
         size_t reserved_io_buffer_size = 16*1024 \
         )

The first 5 arguments as well as the final argument
*reserved_io_buffer_size*, are treated similiarly to the :ref:`client
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

Code Example
^^^^^^^^^^^^
A minimal example of a TLS server is provided below.
The full code for a TLS server using asio is in `src/cli/tls_proxy.cpp`.

.. code-block:: cpp

    #include <botan/tls_client.h>
    #include <botan/tls_callbacks.h>
    #include <botan/tls_session_manager.h>
    #include <botan/tls_policy.h>
    #include <botan/auto_rng.h>
    #include <botan/certstor.h>
    #include <botan/pk_keys.h>

    #include <memory>

    /**
     * @brief Callbacks invoked by TLS::Channel.
     *
     * Botan::TLS::Callbacks is an abstract class.
     * For improved readability, only the functions that are mandatory
     * to implement are listed here. See src/lib/tls/tls_callbacks.h.
     */
    class Callbacks : public Botan::TLS::Callbacks
    {
       public:
          void tls_emit_data(const uint8_t data[], size_t size) override
             {
             // send data to tls client, e.g., using BSD sockets or boost asio
             }

          void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
             {
             // process full TLS record received by tls client, e.g.,
             // by passing it to the application
             }

          void tls_alert(Botan::TLS::Alert alert) override
             {
             // handle a tls alert received from the tls server
             }

          bool tls_session_established(const Botan::TLS::Session& session) override
             {
             // the session with the tls client was established
             // return false to prevent the session from being cached, true to
             // cache the session in the configured session manager
             return false;
             }
    };

    /**
     * @brief Credentials storage for the tls server.
     *
     * It returns a certificate and the associated private key to
     * authenticate the tls server to the client.
     * TLS client authentication is not requested.
     * See src/lib/tls/credentials_manager.h.
     */
    class Server_Credentials : public Botan::Credentials_Manager
    {
       public:
	  Server_Credentials() : m_key(Botan::X509::load_key("botan.randombit.net.key"))
             {
             }

          std::vector<Certificate_Store*> trusted_certificate_authorities(
             const std::string& type,
             const std::string& context) override
             {
             // if client authentication is required, this function
             // shall return a list of certificates of CAs we trust
             // for tls client certificates, otherwise return an empty list
             return std::vector<Certificate_Store*>();
             }

          std::vector<X509_Certificate> cert_chain(
             const std::vector<std::string>& cert_key_types,
             const std::string& type,
             const std::string& context) override
             {
             // return the certificate chain being sent to the tls client
             // e.g., the certificate file "botan.randombit.net.crt"
             return { Botan::X509_Certificate("botan.randombit.net.crt") };
             }

          Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
             const std::string& type,
             const std::string& context) override
             {
             // return the private key associated with the leaf certificate,
             // in this case the one associated with "botan.randombit.net.crt"
             return &m_key;
             }

          private:
             std::unique_ptr<Botan::Private_Key> m_key;
    };

    int main()
       {
       // prepare all the parameters
       Callbacks callbacks;
       Botan::AutoSeeded_RNG rng;
       Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
       Botan::Client_Credentials creds;
       Botan::TLS::Strict_Policy policy;

       // accept tls connection from client
       Botan::TLS::Server server(callbacks,
                                 session_mgr,
                                 creds,
                                 policy,
                                 rng);

       // read data received from the tls client, e.g., using BSD sockets or boost asio
       // and pass it to server.received_data().
       // ...

       // send data to the tls client using server.send_data()
       // ...
       }

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

     Cipher names without an explicit mode refers to CBC+HMAC ciphersuites.

     Default value: "ChaCha20Poly1305", "AES-256/GCM", "AES-128/GCM",
     "AES-256/CCM", "AES-128/CCM", "AES-256", "AES-128"

     Also allowed: "AES-256/CCM(8)", "AES-128/CCM(8)",
     "Camellia-256/GCM", "Camellia-128/GCM", "Camellia-256", "Camellia-128"

     Also allowed (though currently experimental): "AES-128/OCB(12)",
     "AES-256/OCB(12)"

     Also allowed (although **not recommended**): "SEED", "3DES"

     .. note::

        Before 1.11.30 only the non-standard ChaCha20Poly1305 ciphersuite
        was implemented. The RFC 7905 ciphersuites are supported in 1.11.30
        onwards.

     .. note::

        Support for the broken RC4 cipher was removed in 1.11.17

     .. note::

        SEED and 3DES are deprecated and will be removed in a future release.

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

     Default: "CECPQ1", "ECDH", "DH"

     .. note::

        CECPQ1 key exchange provides post-quantum security to the key exchange
        by combining NewHope with a standard x25519 ECDH exchange. This prevents
        an attacker, even one with a quantum computer, from later decrypting the
        contents of a recorded TLS transcript. The NewHope algorithm is very
        fast, but adds roughly 4 KiB of additional data transfer to every TLS
        handshake. And even if NewHope ends up completely broken, the 'extra'
        x25519 exchange secures the handshake.

        For applications where the additional data transfer size is unacceptable,
        simply allow only ECDH key exchange in the application policy. DH
        exchange also often involves transferring several additional Kb (without
        the benefit of post quantum security) so if CECPQ1 is being disabled for
        traffic overhread reasons, DH should also be avoid.

     Also allowed: "RSA", "SRP_SHA", "ECDHE_PSK", "DHE_PSK", "PSK"

     .. note::

        Static RSA ciphersuites are disabled by default since 1.11.34.
        In addition to not providing forward security, any server which is
        willing to negotiate these ciphersuites exposes themselves to a variety
        of chosen ciphertext oracle attacks which are all easily avoided by
        signing (as in PFS) instead of decrypting.

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

     Also allowed (disabled by default): "DSA", "" (empty string meaning anonymous)

     .. note::

        DSA authentication is deprecated and will be removed in a future release.

 .. cpp:function:: std::vector<std::string> allowed_ecc_curves() const

     Return a list of ECC curves we are willing to use, in order of preference.
     The default ordering puts the best performing ECC first.

     Default: "x25519", "secp256r1", "secp521r1", "secp384r1",
     "brainpool256r1", "brainpool384r1", "brainpool512r1"

     No other values are currently defined.

 .. cpp:function:: bool use_ecc_point_compression() const

     Prefer ECC point compression.

     Signals that we prefer ECC points to be compressed when transmitted to us.
     The other party may not support ECC point compression and therefore may still
     send points uncompressed.
    
     Note that the certificate used during authentication must also follow the other
     party's preference.

     Default: false

 .. cpp:function:: std::vector<byte> compression() const

     Return the list of compression methods we are willing to use, in order of
     preference. Default is null compression only.

     .. note::

        TLS data compression is not currently supported.

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

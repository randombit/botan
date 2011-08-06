
.. _ssl_api:

SSL and TLS
========================================

.. versionadded:: 1.9.4

Botan supports both client and server implementations of the SSL/TLS
protocols, including SSL v3, TLS v1.0, and TLS v1.1. The insecure and
obsolete SSL v2 is not supported.

The implementation uses ``std::tr1::function``, so it may not have
been compiled into the version you are using; you can test for the
feature macro ``BOTAN_HAS_SSL_TLS`` to check.

TLS Clients
----------------------------------------

.. cpp:class:: TLS_Client

   .. cpp:function:: TLS_Client( \
        std::tr1::function<size_t, byte*, size_t> input_fn, \
        std::tr1::function<void, const byte*, size_t> output_fn, \
        const TLS_Policy& policy, RandomNumberGenerator& rng)

   Creates a TLS client. It will call *input_fn* to read bytes from
   the network and call *output_fn* when bytes need to be written to
   the network.

   .. cpp:function:: size_t read(byte* buf, size_t buf_len)

   Reads up to *buf_len* bytes from the open connection into *buf*,
   returning the number of bytes actually written.

   .. cpp:function:: void write(const byte* buf, size_t buf_len)

   Writes *buf_len* bytes in *buf* to the remote side

   .. cpp:function:: void close()

   Closes the connection

   .. cpp:function:: std::vector<X509_Certificate> peer_cert_chain()

   Returns the certificate chain of the server

A simple TLS client example:

.. literalinclude:: examples/tls_client.cpp


TLS Servers
----------------------------------------

A simple TLS server

.. literalinclude:: examples/tls_server.cpp

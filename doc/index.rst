
Getting Started
========================================

If you need to build the library first, start with :doc:`building`.
Some Linux distributions include packages for Botan, so building from
source may not be required on your system.

.. only:: html

   The :ref:`genindex` and :ref:`search` may be useful to get started.

.. only:: html and website

   You can also download this manual as a `PDF <https://botan.randombit.net/handbook/botan.pdf>`_.

Examples
----------

Examples of usage are included in this documentation, some of which
are listed below:

* :ref:`Block Ciphers <block_cipher_example>`
* :ref:`Cipher Modes <cipher_modes_example>`
* :ref:`Hash Functions <hash_example>`
* :ref:`KDFs <key_derivation_function_example>`
* :ref:`MACs <mac_example>`
* :ref:`PBKDFs <pbkdf_example>`
* :ref:`Key Agreement <ecdh_example>`
* :ref:`ECDSA <ecdsa_example>`
* :ref:`Kyber <kyber_example>`
* :ref:`RSA <rsa_example>`
* :ref:`XMSS <xmss_example>`
* :ref:`Stream Ciphers <stream_ciphers_example>`
* :ref:`TLS Client <tls_client_example>`
* :ref:`TLS Client (PQC/hybrid) <tls_hybrid_client_example>`
* :ref:`HTTPS Client <https_client_example>`
* :ref:`TLS Server <tls_server_example>`
* :ref:`X.509 <x509_certificates_example>`

You'll find additional examples of usage in the
`src/examples <https://github.com/randombit/botan/tree/master/src/examples>`_ directory.

An additional source for example code is in the implementation of the
`command line interface <https://github.com/randombit/botan/tree/master/src/cli>`_,
which was intentionally written to act as practical examples of usage.

Books and other references
----------------------------

You should have some knowledge of cryptography *before* trying to use
the library. This is an area where it is very easy to make mistakes,
and where things are often subtle and/or counterintuitive. Obviously
the library tries to provide things at a high level precisely to
minimize the number of ways things can go wrong, but naive use will
almost certainly not result in a secure system.

Especially recommended are:

- *Cryptography Engineering*
  by Niels Ferguson, Bruce Schneier, and Tadayoshi Kohno

- `Security Engineering -- A Guide to Building Dependable Distributed Systems
  <https://www.cl.cam.ac.uk/~rja14/book.html>`_ by Ross Anderson

- `Handbook of Applied Cryptography <http://www.cacr.math.uwaterloo.ca/hac/>`_
  by Alfred J. Menezes, Paul C. Van Oorschot, and Scott A. Vanstone

If you're doing something non-trivial or unique, you might want to at
the very least ask for review/input at a place such as the
`cryptography stack exchange <https://crypto.stackexchange.com/>`_.
And (if possible) pay a professional cryptographer or security company
to review your design and code.


.. toctree::
   :maxdepth: 1
   :numbered:

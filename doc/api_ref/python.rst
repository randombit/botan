
Python Binding
========================================

.. versionadded:: 1.11.14

.. highlight:: python

.. py:module:: botan3

The Python binding is based on the `ffi` module of botan and the
`ctypes` module of the Python standard library.

The versioning of the Python module follows the major versioning of
the C++ library. So for Botan 2, the module is named ``botan2`` while
for Botan 3 it is ``botan3``.

Versioning
----------------------------------------
.. autofunction:: version_major

.. autofunction:: version_minor

.. autofunction:: version_patch

.. autofunction:: ffi_api_version

.. autofunction:: version_string


Utilities
----------------------------------------

.. autofunction:: const_time_compare

.. autodata:: MPILike

Random Number Generators
----------------------------------------

.. autoclass:: RandomNumberGenerator
   :members:

Hash Functions
----------------------------------------

.. autoclass:: HashFunction
   :members:

eXtensible Output Functions
----------------------------------------

.. autoclass:: XOF
   :members:

Message Authentication Codes
----------------------------------------

.. autoclass:: MsgAuthCode
   :members:

Ciphers
----------------------------------------

.. autoclass:: SymmetricCipher
   :members:

.. autoclass:: BlockCipher
   :members:

Bcrypt
----------------------------------------

.. autofunction:: bcrypt

.. autofunction:: check_bcrypt

PBKDF
----------------------------------------

.. autofunction:: pbkdf

.. autofunction:: pbkdf_timed

Scrypt
---------------

.. versionadded:: 2.8.0

.. autofunction:: scrypt

Argon2
----------------------------------------

.. autofunction:: argon2

KDF
----------------------------------------

.. autofunction:: kdf

Public Key
----------------------------------------

.. autoclass:: PublicKey
   :members:

Private Key
----------------------------------------

.. autoclass:: PrivateKey
   :members:

Public Key Operations
----------------------------------------

.. autoclass:: PKEncrypt
   :members:

.. autoclass:: PKDecrypt
   :members:

.. autoclass:: PKSign
   :members:

.. autoclass:: PKVerify
   :members:

.. autoclass:: PKKeyAgreement
   :members:

.. autoclass:: KemEncrypt
   :members:

.. autoclass:: KemDecrypt
   :members:

TPM 2.0 Bindings
-------------------------------------

.. versionadded:: 3.6.0

.. autoclass:: TPM2Context
   :members:

.. autoclass:: TPM2UnauthenticatedSession
   :members:

Multiple Precision Integers (MPI)
-------------------------------------
.. versionadded:: 2.8.0

.. autoclass:: MPI
   :members:

Object Identifiers (OID)
-------------------------------------
.. versionadded:: 3.8.0

.. autoclass:: OID
   :members:

EC Groups
-------------------------------------
.. versionadded:: 3.8.0

.. autoclass:: ECGroup
   :members:

Format Preserving Encryption (FE1 scheme)
-----------------------------------------
.. versionadded:: 2.8.0

.. autoclass:: FormatPreservingEncryptionFE1
   :members:

HOTP
-----------------------------------------
.. versionadded:: 2.8.0

.. autoclass:: HOTP
   :members:

TOTP
-----------------------------------------

.. autoclass:: TOTP
   :members:

Key Wrapping
-----------------------------------------

.. autofunction:: nist_key_wrap

.. autofunction:: nist_key_unwrap

Secure Remote Password protocol (SRP)
-----------------------------------------

.. autoclass:: Srp6ServerSession
   :members:

.. autofunction:: srp6_generate_verifier

.. autofunction:: srp6_client_agree

ZFEC
-----------------------------------------

.. autofunction:: zfec_encode

.. autofunction:: zfec_decode


X509Cert
-----------------------------------------

.. autoclass:: X509Cert
   :members:

X509CRL
-----------------------------------------

.. autoclass:: X509CRL
   :members:







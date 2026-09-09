
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

Library Version Compatibility
----------------------------------------

The module loads any Botan 3.x shared library, preferring the newest it can
find. It is written against the FFI API of the release it ships with, but the
library does not need to match: functionality which the loaded library
predates raises :class:`BotanFunctionUnavailable` when used, and everything
else works as usual. This means an application can bundle the newest
``botan3.py`` and run against whichever library the system provides.

The library in use can be identified with :func:`version_string` or
:func:`ffi_api_version`.

.. autodata:: BOTAN_FFI_VERSION

.. autodata:: BOTAN_MINIMUM_FFI_VERSION

.. autoclass:: BotanFunctionUnavailable
   :members:

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

.. autoclass:: BotanException
   :members:

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
----------------------------------------

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

.. autoclass:: ECScalar
   :members:

.. autoclass:: ECPoint
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

.. autofunction:: nist_key_wrap_padded

.. autofunction:: nist_key_unwrap_padded

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


SPAKE2+
-----------------------------------------
.. versionadded:: 3.13.0

.. autoclass:: Spake2pParams
   :members:

.. autofunction:: spake2p_derive_secret

.. autofunction:: spake2p_registration_record

.. autoclass:: Spake2pProver
   :members:

.. autoclass:: Spake2pVerifier
   :members:

X509Cert
-----------------------------------------

.. autoclass:: X509Cert
   :members:

.. autoclass:: X509GeneralNameType
   :members:

.. autoclass:: X509GeneralName
   :members:

X509CRL
-----------------------------------------

.. autoclass:: X509CRLReason
   :members:

.. autoclass:: X509CRLEntry
   :members:

.. autoclass:: X509CRL
   :members:







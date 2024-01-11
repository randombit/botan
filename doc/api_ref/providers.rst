External Providers
==============================

Botan ships with a variety of cryptographic algorithms in both pure software
as well as with support from :doc:`hardware acceleration <../hardware_acceleration>`.

Additionally, Botan allows to use external implementations to provide algorithms ("providers").

Integrated Providers
------------------------------

PKCS#11
^^^^^^^^^^^^^

PKCS#11 is a standard API for accessing cryptographic hardware. Botan
ships a :doc:`PKCS#11 provider <pkcs11>` for interacting with PKCS#11
devices which provide cryptographic algorithms. It is enabled by default.

TPM 1.2
^^^^^^^^^^^^^

The TPM 1.2 standard is a specification for a hardware device which provides
cryptographic algorithms. Botan ships a :doc:`TPM provider <tpm>` for interacting
with TPM devices. It is disabled by default.

CommonCrypto
^^^^^^^^^^^^^

CommonCrypto is a library provided by Apple for accessing cryptographic
algorithms. Botan ships a *CommonCrypto* provider for interacting with CommonCrypto.
It is disabled by default.

The CommonCrypto provider supports the following algorithms:

* SHA-1, SHA-256, SHA-384, SHA-512
* AES-128, AES-192, AES-256, DES, TDES, Blowfish, CAST-128
* CBC, CTR, OFB

Provider Interfaces
------------------------------

Symmetric Algorithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following interfaces can be used to implement providers
for symmetric algorithms:

* ``AEAD_Mode``
* ``BlockCipher``
* ``Cipher_Mode``
* ``Hash``
* ``KDF``
* ``MAC``
* ``PasswordHashFamily``
* ``PBKDF``
* ``StreamCipher``
* ``XOF``

Each of the interfaces provide a factory method which takes string arguments
and returns an object implementing the interface. The strings are the name of
the algorithm to be instantiated and the provider to be used.
For example, the following code creates a SHA-256 hash object using the
*CommonCrypto* provider:

.. code-block:: cpp

    #include <botan/hash.h>

    auto hash = Botan::HashFunction::create_or_throw("SHA-256", "CommonCrypto");

    hash->update("Hello");
    hash->update(" ");
    hash->update("World");
    auto digest = hash->final();

    // query the provider currently used
    std::string provider = hash->provider(); // "CommonCrypto"

Omitting the provider string or leaving it empty means the default provider
is used. The default provider is the first provider which supports the
requested algorithm. Depending on how Botan was configured at build time,
the default provider may be a pure software implementation, a hardware
accelerated implementation or an implementation using an integrated provider,
e.g., CommonCrypto.

The following rules apply:

1. If Botan was built with an integrated provider that is hooked into the
   ``T::create()``/``T::create_or_throw()`` factory methods (currently only *CommonCrypto* is),
   the default provider is the integrated provider.

2. If Botan was not built with an integrated provider as in (1), but
   with hardware acceleration support, e.g., AES-NI, and the hardware acceleration
   is available at runtime, the default provider is the hardware accelerated provider.

3. If Botan was not built with an integrated provider as in (1) and not built
   with hardware acceleration support, the default provider is the pure software
   implementation.

Regardless of the default provider, a specific provider can always be requested
by passing the provider name as the second argument to ``T::create()``/``T::create_or_throw()``.
Specifically, the special provider name ``"base"`` can always be used to
request the hardware accelerated (preferred, if available at runtime)
or pure software implementation (last fallback).

Public Key Algorithms
^^^^^^^^^^^^^^^^^^^^^^^

The following interfaces support using providers for
:doc:`public key algorithms <pubkey>`. The interfaces are used
in a similar way as the interfaces for symmetric algorithms
described above.

* ``PK_Signer``
* ``PK_Verifier``
* ``PK_Key_Agreement``
* ``PK_Encryptor_EME``
* ``PK_Decryptor_EME``
* ``PK_KEM_Encryptor``
* ``PK_KEM_Decryptor``

Each of the interfaces provides a constructor which takes a key object,
optional parameters, and a string specifying the provider to be used.
For example, the following code signs a message using an RSA key with the
*CommonCrypto* provider:

.. note:: No integrated provider currently supports using any public key algorithm
    in the way described above, so the example is purely for illustrative purposes.

.. code:: cpp

    #include <botan/auto_rng.h>
    #include <botan/pk_algs.h>
    #include <botan/pubkey.h>

    Botan::AutoSeeded_RNG rng;
    auto key = Botan::create_private_key("RSA", rng, "3072");

    Botan::PK_Signer signer(key, rng, "EMSA3(SHA-256)", Botan::Signature_Format::Standard, "CommonCrypto");

    signer.update("Hello");
    signer.update(" ");
    signer.update("World");
    auto signature = signer.signature(rng);

To create a key object, use ``Botan::create_private_key()``, which takes
a string specifying the algorithm and the provider to be used. For example, to
create a 3072 bit RSA key with the *CommonCrypto* provider:

.. note:: No integrated provider currently supports creating any private key
    in the way described above, so the example is purely for illustrative purposes.

.. code:: cpp

    #include <botan/auto_rng.h>
    #include <botan/pk_algs.h>

    Botan::AutoSeeded_RNG rng;

    auto key = Botan::create_private_key("RSA", rng, "3072", "CommonCrypto");

Another way to implement a provider for public key algorithms is to implement
the ``Private_Key`` and ``Public_Key`` interfaces. This allows for different
use cases, e.g., to use a key stored in a hardware security module, handled
by a different operating system process (to avoid leaking the key material),
or even implement an algorithm not supported by Botan. The resulting key class
can be stored outside Botan and still be used with the ``PK_Signer``,
``PK_Verifier``, ``PK_Key_Agreement``, ``PK_Encryptor_EME``, ``PK_Decryptor_EME``,
``PK_KEM_Encryptor``, and ``PK_KEM_Decryptor`` interfaces.

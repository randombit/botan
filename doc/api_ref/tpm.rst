Trusted Platform Module (TPM)
==========================================

Some computers come with a TPM, which is a small side processor which can
perform certain operations which include RSA key generation and signing, a
random number generator, accessing a small amount of NVRAM, and a set of PCRs
which can be used to measure software state (this is TPMs most famous use, for
authenticating a boot sequence).

The TPM NVRAM and PCR APIs are not supported by Botan at this time, patches welcome.

Currently, we support TPM v1.2 as well as v2.0 systems via independent wrappers
of TrouSerS (http://trousers.sourceforge.net/) for TPM v1.2 and tpm2-tss
(https://github.com/tpm2-software/tpm2-tss) for TPM v2.0. Note however that
the support for TPM v1.2 is deprecated as of Botan 3.5.0 and will be removed in
a future release.

TPM 2.0 Wrappers
----------------

.. versionadded:: 3.6.0

Botan's TPM v2.0 support is currently based on a wrapper of the tpm2-tss
library (https://github.com/tpm2-software/tpm2-tss). The code is tested in CI
against the swtpm simulator (https://github.com/stefanberger/swtpm).

Support for TPM v2.0 is provided by the ``tpm2`` module which is not built by
default as it requires an external dependency. Use the ``BOTAN_HAS_TPM2`` macro
to ensure that support for TPM v2.0 is available in your build of Botan.

The entire implementation is wrapped into the ``Botan::TPM2`` namespace. The
remainder of this section will omit the namespace prefix for brevity.

TPM 2.0 Context
~~~~~~~~~~~~~~~

The TPM context is the main entry point for all TPM operations. Also, it
provides authorative information about the TPM's capabilities and allows
persisting and evicting keys into the TPM's NVRAM.

.. cpp:class:: Botan::TPM2::Context

    .. cpp:function:: std::shared_ptr<Context> create(const std::string& tcti)

        Create a TPM2 context and connect to it via the given TPM Command
        Transmission Interface (TCTI). The TCTI string is a colon-separated specifier
        of the form ``tcti_name[:tcti_options=value,...]``.

    .. cpp:function:: std::shared_ptr<Context> create(std::optional<std::string> tcti, std::optional<std::string> conf)

        Create a TPM2 context and connect to it via the given TPM Command
        Transmission Interface (TCTI). The configuration string is passed to the
        TCTI. Both values may by empty, in which case the TPM-TSS2 will try to
        determine them from default values.

    .. cpp:function:: std::shared_ptr<Context> create(ESYS_CONTEXT* ctx)

        Create a TPM2 context from an already set up TPM2-TSS ESYS_CONTEXT*
        to enable usage of Botan's TPM2 functionalities via an outside
        ESYS Context.
        If the Botan TPM2 Context was created this way, the destructor will
        not finalize the underlying ESYS_CONTEXT.

    .. cpp:function:: TPM2_HANDLE persist(TPM2::PrivateKey& key, const SessionBundle& sessions, std::span<const uint8_t> auth_value, std::optional<TPM2_HANDLE> persistent_handle)

        Persists the given ``key`` in the TPM's NVRAM. The returned handle can be
        used to load the key back into the TPM after a reboot. The ``auth_value``
        is used to re-authenticate operations after transforming it to a persistent
        key.

    .. cpp:function:: void evict(std::unique_ptr<TPM2::PrivateKey> key, const SessionBundle& sessions)

        Evicts the ``key`` from the TPM's NVRAM. The key must be a persistent key
        and won't be available for any further use after the eviction. In particular
        it won't be re-transformed into a transient key either.

    .. cpp:function:: bool supports_botan_crypto_backend()

        Returns whether the current configuration supports the Botan crypto backend.
        This might return false if Botan was not built with the ``tpm2_crypto_backend``
        enabled or the TPM2-TSS library is too old (3.x or older).

    .. cpp:function:: void use_botan_crypto_backend(std::shared_ptr<Botan::RandomNumberGenerator> rng)

        Enables the Botan crypto backend for this context. The RNG is needed to
        generate key material for the communication with the TPM. It is crucial that
        this RNG *does not* depend on the TPM for its entropy as this would create a
        chicken-and-egg problem.

    .. cpp:function:: bool supports_algorithm(std::string_view algo_name)

        Returns whether the TPM supports the given algorithm. The ``algo_name`` is
        the name of the algorithm as used in Botan. Eg. "RSA", "SHA-256", "AES-128",
        "OAEP(SHA-256)", etc.

For further information about the functionality of the TPM context, please refer
to the doxygen comments in ``tpm2_context.h``.

TPM 2.0 Sessions
~~~~~~~~~~~~~~~~

TPM v2.0 uses sessions to authorize actions on the TPM, encrypt the
communication between the application and the TPM and perform audits of the
operations performed.

Botan provides a ``Session`` class to handle the creation of sessions and
comes with a ``SessionBundle`` helper to manage multiple sessions to be passed
to the TPM commands.

.. cpp:class:: Botan::TPM2::Session

    .. cpp:function:: std::shared_ptr<Session> unauthenticated_session(const std::shared_ptr<Context>& ctx, std::string_view sym_algo, std::string_view hash_algo)

        Creates an unauthenticated session, i.e. does not provide protection against
        man-in-the-middle attacks by adversaries who can intercept and modify the
        communication between the application and the TPM.

        The ``sym_algo`` and ``hash_algo`` parameters specify the symmetric cipher
        used to encrypt parameters flowing to and from the TPM and the hash of the
        HMAC algorithm used to protect the integrity of the communication.

    .. cpp:function:: std::shared_ptr<Session> authenticated_session(const std::shared_ptr<Context>& ctx, const PrivateKey& tpm_key, std::string_view sym_algo, std::string_view hash_algo)

        Creates an authenticated session, i.e. it does provide protection against
        man-in-the-middle attacks by adversaries who can intercept and modify the
        communication between the application and the TPM, under the assumption that
        the ``tpm_key`` is trustworthy and known only to the TPM.

        The ``sym_algo`` and ``hash_algo`` parameters specify the symmetric cipher
        used to encrypt parameters flowing to and from the TPM and the hash of the
        HMAC algorithm used to protect the integrity of the communication.

Currently, there's no support for other TPM sessions.

TPM 2.0 Random Number Generator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``RandomNumberGenerator`` is an adapter to use the TPM's random number
generator as a source of entropy. It behaves exactly like any other RNG in
Botan.

.. cpp:class:: Botan::TPM2::RandomNumberGenerator

    .. cpp:function:: RandomNumberGenerator(std::shared_ptr<Context> ctx, SessionBundle sessions)

        Creates a new RNG object which uses the TPM's random number generator as a
        source of entropy. The ``sessions`` parameter is a bundle of sessions to be
        used for the RNG operations.

Asymmetric Keys hosted by a TPM 2.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The TPM v2.0 supports RSA and ECC keys. Botan provides the classed
``PrivateKey`` and ``PublicKey`` in the ``TPM2`` namespace, to manage and use
asymmetric keys on the TPM. Additionally there are derived classes for RSA and ECC.
Currently, RSA keys can be used for signing and encryption, while ECC keys can only
be used for ECDSA signing (i.e., ECDH, ECSCHNORR, and SM2 are not supported).

Objects of these classes can be used throughout the Botan library to perform
cryptographic operations with TPM keys wherever an abstract
``Botan::Private_Key`` is expected.

.. cpp:class:: Botan::TPM2::PublicKey

     .. cpp:function:: std::unique_ptr<Public_Key> load_persistent(const std::shared_ptr<Context>& ctx, TPM2_HANDLE persistent_object_handle, const SessionBundle& sessions)

         Loads a public key that is persistent in the TPM's NVRAM given a
         ``persistent_object_handle``.

     .. cpp:function:: std::unique_ptr<Public_Key> load_transient(const std::shared_ptr<Context>& ctx, std::span<const uint8_t> public_blob, const SessionBundle& sessions)

         Loads a public key from the given ``public_blob`` which is essentially
         a serialization of a public key returned from a TPM key pair creation.

     .. cpp:function:: std::vector<uint8_t> raw_public_key_bits() const

         Returns a serialized representation of the public key. This blob can be
         loaded back into the TPM as a transient public key.

.. cpp:class:: Botan::TPM2::PrivateKey

     .. cpp:function:: std::unique_ptr<Private_Key> load_persistent(const std::shared_ptr<Context>& ctx, TPM2_HANDLE persistent_object_handle, std::span<const uint8_t> auth_value, const SessionBundle& sessions)

         Loads a private key that is persistent in the TPM's NVRAM given a
         ``persistent_object_handle`` and an ``auth_value`` (e.g. a password).

     .. cpp:function:: std::unique_ptr<Private_Key> load_transient(const std::shared_ptr<Context>& ctx, std::span<const uint8_t> auth_value, const TPM2::PrivateKey& parent, std::span<const uint8_t> public_blob, std::span<const uint8_t> private_blob, const SessionBundle& sessions)

         Loads a private key from the given ``public_blob`` and ``private_blob``
         returned from a TPM key pair creation. To decipher the
         ``private_blob``, a ``parent`` key is needed (the same as the one used
         to create the key). The ``auth_value`` is used to authenticate private
         operations.

     .. cpp:function:: std::unique_ptr<PrivateKey> create_transient_from_template(const std::shared_ptr<Context>& ctx, const SessionBundle& sessions, ESYS_TR parent, const TPMT_PUBLIC& key_template, const TPM2B_SENSITIVE_CREATE& sensitive_data);

         Creates a new transient key pair on the TPM using the given
         ``key_template`` and ``sensitive_data`` under the given ``parent`` key.
         This is a low-level function, and it assumes that the caller knows how
         to create valid ``key_template`` and ``sensitive_data`` structures.
         Typically, users should resort to using the creation functions in the
         derived private key classes.

     .. cpp:function:: secure_vector<uint8_t> raw_private_key_bits() const

         Returns an encrypted "private blob" of the TPM private key if it is a
         transient key. This blob can only be decrypted by the TPM that created
         it when loading the key back into the TPM.

Botan provides a set of derived classes for RSA keys, which are used to create
and manage RSA keys on the TPM.

.. cpp:class:: Botan::TPM2::RSA_PrivateKey

     .. cpp:function:: std::unique_ptr<TPM2::PrivateKey> create_unrestricted_transient(const std::shared_ptr<Context>& ctx, const SessionBundle& sessions, std::span<const uint8_t> auth_value, const TPM2::PrivateKey& parent, uint16_t keylength, std::optional<uint32_t> exponent);

         Creates a new RSA key pair on the TPM with the given ``keylength`` and
         an optional ``exponent``. Typical users should not specify the
         exponent, as support for any but the default exponent (65537) is
         optional in the TPM v2.0 specification.

         Keys generated with this function are not restricted in their usage.
         They may be used both for signing and data encryption with various
         padding schemes. Furthermore, they are transient, i.e. they are not
         stored in the TPM's NVRAM and must be loaded from their public and
         private blobs after a reboot.

Similarly, Botan provides a set of derived classes for ECC keys.

.. cpp:class:: Botan::TPM2::EC_PrivateKey

     .. cpp:function:: static std::unique_ptr<TPM2::PrivateKey> create_unrestricted_transient(const std::shared_ptr<Context>& ctx, const SessionBundle& sessions, std::span<const uint8_t> auth_value, const TPM2::PrivateKey& parent, const EC_Group& group);

         Creates a new ECC key pair on the TPM with the given ``group``. The
         group must be one of the supported curves by the TPM and currently
         must be one of the NIST curves (secp192r1, secp224r1, secp256r1,
         secp384r1, secp521r1).

         Keys generated with this function are not restricted in their usage.
         They may only be used for signing: Currently, Botan only supports creating
         ECDSA keys. Furthermore, they are transient, i.e. they are not stored in
         the TPM's NVRAM and must be loaded from their public and private blobs after
         a reboot.

Once a transient key pair was created on the TPM, it can be persisted into the
TPM's NVRAM to make it available across reboots independently of the "private
blob". This is done by passing the key pair to the ``Context::persist`` method.

Botan as a TPM2-TSS Crypto Backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The TPM2-TSS library (4.0 and later) provides a callback API to override its
default crypto backend (OpenSSL or mbedtls). Botan can optionally use this API
to provide a Botan-based crypto backend for TPM2-TSS and thus allowing to
avoid a dependency on another cryptographic library in applications.

Once a ``Context`` is created, the Botan-based crypto backend may be enabled for
it via the ``Context::use_botan_crypto_backend`` method. This will only succeed
if the method ``Context::supports_botan_crypto_backend`` returns true.

Alternatively, if one just wants to utilize the backend in a TPM2-TSS ESAPI
application without using Botan's wrappers, free-standing functions are provided
in ``tpm2_crypto_backend.h``. The ``use_botan_crypto_backend`` works similar to
the ``Context::use_botan_crypto_backend`` method but is given an ``ESYS_CONTEXT*``
and returns a ``TPM2::CryptoCallbackState`` that needs to stay alive as long
as the crypto backend is used. This will only succeed if the method
``supports_botan_crypto_backend`` returns true.

TPM 2.0 Example
~~~~~~~~~~~~~~~

The following example demonstrates how to create a TPM key pair and sign a
Certificate Signing Request (CSR) with it. This may be useful if one wants
to host a private key for TLS client authentication in a TPM, for example.

.. literalinclude:: /../src/examples/pkcs10_csr_on_tpm2.cpp
   :language: cpp


TPM 1.2 Wrappers
----------------

.. versionadded:: 1.11.26

Currently v1.2 TPMs are supported via a wrapper of the TrouSerS
(http://trousers.sourceforge.net/) library. However, this wrapper is deprecated
and will be removed in a future release. The current code has been tested with
an ST TPM running in a Lenovo laptop.

Test for TPM support with the macro ``BOTAN_HAS_TPM``, include ``<botan/tpm.h>``.

First, create a connection to the TPM with a ``TPM_Context``. The context is
passed to all other TPM operations, and should remain alive as long as any other
TPM object which the context was passed to is still alive, otherwise errors or
even an application crash are possible. In the future, the API may change to
using ``shared_ptr`` to remove this problem.

.. cpp:class:: TPM_Context

    .. cpp:function:: TPM_Context(pin_cb cb, const char* srk_password)

     The (somewhat improperly named) pin_cb callback type takes a std::string as
     an argument, which is an informative message for the user. It should return
     a string containing the password entered by the user.

     Normally the SRK password is null. Use nullptr to signal this.

The TPM contains a RNG of unknown design or quality. If that doesn't scare you
off, you can use it with ``TPM_RNG`` which implements the standard
``RandomNumberGenerator`` interface.

.. cpp:class:: TPM_RNG

   .. cpp:function:: TPM_RNG(TPM_Context& ctx)

      Initialize a TPM RNG object. After initialization, reading from
      this RNG reads from the hardware? RNG on the TPM.

The v1.2 TPM uses only RSA, but because this key is implemented completely in
hardware it uses a different private key type, with a somewhat different API to
match the TPM's behavior.

.. cpp:class:: TPM_PrivateKey

   .. cpp:function:: TPM_PrivateKey(TPM_Context& ctx, size_t bits, const char* key_password)

        Create a new RSA key stored on the TPM. The bits should be either 1024
        or 2048; the TPM interface hypothetically allows larger keys but in
        practice no v1.2 TPM hardware supports them.

        The TPM processor is not fast, be prepared for this to take a while.

        The key_password is the password to the TPM key ?

   .. cpp:function::  std::string register_key(TPM_Storage_Type storage_type)

        Registers a key with the TPM. The storage_type can be either
        `TPM_Storage_Type::User` or `TPM_Storage_Type::System`. If System, the
        key is stored on the TPM itself. If User, it is stored on the local hard
        drive in a database maintained by an intermediate piece of system
        software (which actual interacts with the physical TPM on behalf of any
        number of applications calling the TPM API).

        The TPM has only some limited space to store private keys and may reject
        requests to store the key.

        In either case the key is encrypted with an RSA key which was generated
        on the TPM and which it will not allow to be exported. Thus (so goes the
        theory) without physically attacking the TPM

        Returns a UUID which can be passed back to constructor below.

   .. cpp:function::  TPM_PrivateKey(TPM_Context& ctx, const std::string& uuid, \
                                      TPM_Storage_Type storage_type)

        Load a registered key. The UUID was returned by the ``register_key`` function.

   .. cpp:function::  std::vector<uint8_t> export_blob() const

        Export the key as an encrypted blob. This blob can later be presented
        back to the same TPM to load the key.

   .. cpp:function:: TPM_PrivateKey(TPM_Context& ctx, const std::vector<uint8_t>& blob)

        Load a TPM key previously exported as a blob with ``export_blob``.

   .. cpp:function::  std::unique_ptr<Public_Key> public_key() const

         Return the public key associated with this TPM private key.

         TPM does not store public keys, nor does it support signature verification.

   .. cpp:function:: TSS_HKEY handle() const

        Returns the bare TSS key handle. Use if you need to call the raw TSS API.

A ``TPM_PrivateKey`` can be passed to a ``PK_Signer`` constructor and used to
sign messages just like any other key. Only PKCS #1 v1.5 signatures are supported
by the v1.2 TPM.

.. cpp:function:: std::vector<std::string> TPM_PrivateKey::registered_keys(TPM_Context& ctx)

      This static function returns the list of all keys (in URL format)
      registered with the system

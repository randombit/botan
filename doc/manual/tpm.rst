Trusted Platform Module (TPM)
==========================================

.. versionadded:: 1.11.26

Some computers come with a TPM, which is a small side processor which can
perform certain operations which include RSA key generation and signing, a
random number generator, accessing a small amount of NVRAM, and a set of PCRs
which can be used to measure software state (this is TPMs most famous use, for
authenticating a boot sequence).

The TPM NVRAM and PCR APIs are not supported by Botan at this time, patches welcome.

Currently only v1.2 TPMs are supported, and the only TPM library supported is
TrouSerS (http://trousers.sourceforge.net/). Hopefully both of these limitations
will be removed in a future release, in order to support newer TPM v2.0 systems.
The current code has been tested with an ST TPM running in a Lenovo laptop.

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

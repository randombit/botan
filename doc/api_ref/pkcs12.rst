PKCS#12
========================================

PKCS#12 (also known as PFX) is a file format defined in :rfc:`7292` for
storing cryptographic objects - typically a private key and its associated
X.509 certificate chain - protected by a password. It is widely used for
importing and exporting credentials in TLS servers, browsers, and
certificate management tools.

This API is defined in ``botan/pkcs12.h``.

.. versionadded:: 3.13

PKCS12_Export_Options
-----------------------------------------

.. cpp:class:: PKCS12_Export_Options

   Options controlling how a PKCS#12 file is generated. Construct with the
   password (mandatory) and an optional friendly name; tweak individual
   fields with the chainable ``with_*`` mutators, or pick a preset via the
   static pseudo-constructors below.

   .. cpp:function:: explicit PKCS12_Export_Options(std::string_view password, \
                                                    std::optional<std::string> friendly_name = {})

      Constructs an options object with modern defaults: PBES2-SHA256-AES256
      key encryption, SHA-256 MAC, 100 000 KDF iterations, certificates
      stored unencrypted.

   .. cpp:function:: static PKCS12_Export_Options modern(std::string_view password, \
                                                         std::optional<std::string> friendly_name = {})

      Pseudo-constructor for modern defaults (identical to the regular
      constructor). Spelled out for clarity at call sites.

   .. cpp:function:: static PKCS12_Export_Options legacy_compat(std::string_view password, \
                                                                std::optional<std::string> friendly_name = {})

      Pseudo-constructor for legacy-compatible defaults: PBE-SHA1-3DES key
      encryption, SHA-1 MAC, 2 048 KDF iterations. Use when interoperability
      with old software (Java keytool pre-2019, legacy OpenSSL releases,
      pre-Windows-10) is required.

   .. cpp:function:: PKCS12_Export_Options& with_friendly_name(std::string name)

      Overrides the friendly name. If unset, the bundle-level friendly name
      (see :cpp:func:`PKCS12::set_friendly_name`) is used.

   .. cpp:function:: PKCS12_Export_Options& with_iterations(size_t n)

      Sets the KDF iteration count. Values of 0 or above 1 000 000
      (``PKCS12_MAX_ITERATIONS``) cause an ``Invalid_Argument`` exception at
      export time.

   .. cpp:function:: PKCS12_Export_Options& with_key_encryption_algo(std::string algo)

      Algorithm used to encrypt the private key (PKCS8ShroudedKeyBag).
      Supported values:

      - ``"PBES2-SHA256-AES256"`` - modern (default)
      - ``"PBES2-SHA256-AES128"`` - modern
      - ``"PBE-SHA1-3DES"`` - legacy
      - ``"PBE-SHA1-2DES"`` - legacy

   .. cpp:function:: PKCS12_Export_Options& with_cert_encryption_algo(std::string algo)

      Algorithm used to encrypt certificates. If the algo is empty (default),
      certificates are stored unencrypted. A non-empty value requires a
      non-empty password.

   .. cpp:function:: PKCS12_Export_Options& with_mac_digest(std::string algo)

      Hash algorithm for the integrity MAC. Supported: ``"SHA-1"``,
      ``"SHA-224"``, ``"SHA-256"``, ``"SHA-384"``, ``"SHA-512"``,
      ``"SHA-512-256"``. Default is ``"SHA-256"``.

   .. cpp:function:: PKCS12_Export_Options& without_mac()

      Disables the integrity MAC. Generally not recommended; required if the
      password is empty.

PKCS12
-----------------------------------------

.. cpp:class:: PKCS12

   PKCS#12/PFX bundle: parse, inspect, mutate, and export. The default
   constructor produces an empty bundle that the caller fills via the
   ``add_*`` / ``set_*`` mutators before invoking :cpp:func:`export_to`.

   .. cpp:function:: PKCS12()

      Constructs an empty bundle.

   .. cpp:function:: PKCS12(std::span<const uint8_t> data, std::string_view password)

      Parses a DER-encoded PFX file. Throws ``Decoding_Error`` if the file
      is malformed, or ``Invalid_Authentication_Tag`` if MAC verification
      fails.

   Accessors
   ^^^^^^^^^

   .. cpp:function:: const std::vector<std::shared_ptr<Private_Key>>& private_keys() const

      Private keys stored in the bundle, in storage order (parse-order for
      parsed PFX, insertion-order for built ones). PKCS#12 supports multiple
      keys per file.

   .. cpp:function:: const std::vector<X509_Certificate>& certificates() const

      All certificates stored in the bundle. The end-entity, if any, comes
      first when produced by parsing; insertion order is preserved for
      bundles built in memory.

   .. cpp:function:: std::optional<X509_Certificate> end_entity_certificate() const

      The first certificate whose ``subjectPublicKeyInfo`` matches one of
      the stored private keys, or ``nullopt`` if none match (e.g. a
      certificate-only or key-only bundle).

   .. cpp:function:: std::vector<X509_Certificate> ca_certificates() const

      Convenience helper: every certificate except the one returned by
      :cpp:func:`end_entity_certificate`. Returned in storage order. For a
      key-less bundle, returns all certificates after the first.

   .. cpp:function:: const std::optional<std::string>& friendly_name() const

      The ``friendlyName`` attribute, if present.

   .. cpp:function:: const std::optional<std::vector<uint8_t>>& local_key_id() const

      The ``localKeyId`` attribute, if present.

   .. cpp:function:: const std::vector<OID>& unknown_bag_types() const

      OIDs of bag types encountered during parsing but not handled by this
      implementation (e.g. ``SecretBag``). Empty for normal PKCS#12 files
      and for bundles constructed in-memory.

   Mutators
   ^^^^^^^^

   .. cpp:function:: void add_key(std::shared_ptr<Private_Key> key)

      Adds a private key to the bundle.

   .. cpp:function:: void add_certificate(X509_Certificate cert)

      Adds a certificate. End-entity vs CA is determined at export time by
      matching against stored keys.

   .. cpp:function:: void set_friendly_name(std::string name)
   .. cpp:function:: void clear_friendly_name()
   .. cpp:function:: void set_local_key_id(std::vector<uint8_t> id)
   .. cpp:function:: void clear_local_key_id()

      Set or clear the bundle-level friendly name / localKeyId attributes.

   Export
   ^^^^^^

   .. cpp:function:: std::vector<uint8_t> export_to(const PKCS12_Export_Options& options, \
                                                    RandomNumberGenerator& rng) const

      Serializes the bundle as a PKCS#12/PFX file.

      Throws ``Invalid_Argument`` if the options are inconsistent (e.g.
      unsupported algorithm, MAC enabled with empty password) or if a
      stored private key does not match any stored certificate.

      Iteration counts above ``PKCS12_MAX_ITERATIONS`` (1 000 000) and a
      SafeContentsBag nesting depth above ``PKCS12_MAX_NESTING`` (10) are
      rejected.

Examples
-----------------------------------------

Generating a PFX file from a freshly created key and self-signed certificate:

.. literalinclude:: /../src/examples/pkcs12_export.cpp
   :language: cpp

Parsing a PFX file with error handling:

.. literalinclude:: /../src/examples/pkcs12_parse.cpp
   :language: cpp

Building a PFX bundle that contains a CA certificate chain alongside the
end-entity key and certificate:

.. literalinclude:: /../src/examples/pkcs12_export_chain.cpp
   :language: cpp

.. note::

   The default encryption algorithm is ``PBES2-SHA256-AES256`` with
   ``SHA-256`` MAC and 100 000 KDF iterations. For maximum compatibility
   with legacy software (older Java keytool, legacy OpenSSL builds), use
   :cpp:func:`PKCS12_Export_Options::legacy_compat` or explicitly configure
   ``with_key_encryption_algo("PBE-SHA1-3DES")``,
   ``with_mac_digest("SHA-1")``, and ``with_iterations(2048)``.

Supported Algorithms
-----------------------------------------

The following algorithms are available depending on which Botan modules are built:

.. list-table::
   :header-rows: 1
   :widths: 25 30 25 20

   * - Field
     - Value
     - Required module
     - Notes
   * - ``with_key_encryption_algo``
     - ``"PBES2-SHA256-AES256"``
     - ``pbes2``, ``aes``
     - Default; recommended for modern use
   * - ``with_key_encryption_algo``
     - ``"PBES2-SHA256-AES128"``
     - ``pbes2``, ``aes``
     - Modern
   * - ``with_key_encryption_algo``
     - ``"PBE-SHA1-3DES"``
     - ``pkcs12_pbe``, ``des``
     - Legacy; widest compatibility
   * - ``with_key_encryption_algo``
     - ``"PBE-SHA1-2DES"``
     - ``pkcs12_pbe``, ``des``
     - Legacy
   * - ``with_cert_encryption_algo``
     - Same as above, or ``""``
     - -
     - Empty = certificates stored unencrypted
   * - ``with_mac_digest``
     - ``"SHA-256"``
     - ``sha2_32``
     - Default; required by OpenSSL 3.x default policy
   * - ``with_mac_digest``
     - ``"SHA-1"``
     - ``sha1``
     - Legacy; widest compatibility
   * - ``with_mac_digest``
     - ``"SHA-384"``, ``"SHA-512"``
     - ``sha2_64``
     - Uncommon; supported for parsing and generation

Command Line Interface
-----------------------------------------

Two CLI commands are available when Botan is built with filesystem support.

``pkcs12_export``
^^^^^^^^^^^^^^^^^

.. code-block:: none

   botan pkcs12_export [--pass=<pfx-password>] [--in-key-pass=<key-password>]
                       [--friendly-name=<name>]
                       [--key-cipher=<algo>]   (default: PBES2-SHA256-AES256)
                       [--cert-cipher=<algo>]  (default: unencrypted)
                       [--no-mac]
                       [--mac-digest=<digest>]  (SHA-256, SHA-1, SHA-224, SHA-384, SHA-512, SHA-512-256)
                       [--iterations=<n>]      (default: 100000)
                       <key-file> <cert-file> [ca-cert ...]

Exports a private key and certificate(s) to a PFX file written to stdout
or ``--output``.

``pkcs12_import``
^^^^^^^^^^^^^^^^^

.. code-block:: none

   botan pkcs12_import [--pass=<pfx-password>]
                       [--key-out=<file>]    (PEM private key)
                       [--cert-out=<file>]   (PEM end-entity certificate)
                       [--chain-out=<file>]  (PEM CA certificate chain)
                       [--out-key-pass=<password>]
                       [--out-key-cipher=<algo>]  (default: AES-256/CBC)
                       [--key-pbkdf-iter=<n>] (default: 100000)
                       <pfx-file>

Parses a PFX file. Without output file arguments, prints a summary of the
contents to stdout including subject, issuer, validity, serial number, and
both SHA-1 and SHA-256 fingerprints of the end-entity certificate.

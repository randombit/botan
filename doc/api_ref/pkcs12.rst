PKCS#12
========================================

PKCS#12 (also known as PFX) is a file format defined in :rfc:`7292` for
storing cryptographic objects — typically a private key and its associated
X.509 certificate chain — protected by a password. It is widely used for
importing and exporting credentials in TLS servers, browsers, and
certificate management tools.

This API is defined in ``botan/pkcs12.h`` and is available since Botan 3.11.

.. versionadded:: 3.11

PKCS12_Options
-----------------------------------------

.. cpp:class:: PKCS12_Options

   Options controlling how a PKCS#12 file is generated.

   .. cpp:member:: std::string password

      Password used to encrypt the private key and optionally the
      certificates. If empty, no encryption is applied (not recommended for
      production use).

   .. cpp:member:: std::string friendly_name

      Optional human-readable label attached to the key and end-entity
      certificate as a ``friendlyName`` PKCS#9 attribute.

   .. cpp:member:: size_t iterations = 2048

      Number of KDF iterations for PKCS#12 key derivation. Higher values
      slow down brute-force attacks. Default: 2048.

   .. cpp:member:: std::string key_encryption_algo

      Algorithm used to encrypt the private key (PKCS8ShroudedKeyBag).
      Supported values:

      - ``"PBE-SHA1-3DES"`` — default, widest compatibility
      - ``"PBE-SHA1-2DES"``
      - ``"PBES2-SHA256-AES256"`` — modern, requires PBES2 module
      - ``"PBES2-SHA256-AES128"`` — modern, requires PBES2 module

   .. cpp:member:: std::string cert_encryption_algo

      Algorithm used to encrypt the certificates. If empty (default),
      certificates are stored unencrypted. Accepts the same values as
      ``key_encryption_algo``.

   .. cpp:member:: bool include_mac = true

      Whether to include a PKCS#12 MAC for integrity protection.
      Recommended to keep enabled.

   .. cpp:member:: std::string mac_digest

      Hash algorithm for the MAC. Default is ``"SHA-1"`` for compatibility.
      Use ``"SHA-256"`` to match the behaviour of OpenSSL 3.x.

PKCS12_Data
-----------------------------------------

.. cpp:class:: PKCS12_Data

   Result of parsing a PKCS#12 file. Holds the extracted key and
   certificates.

   .. cpp:function:: const std::shared_ptr<Private_Key>& private_key() const

      Returns the private key, or ``nullptr`` if not present.

   .. cpp:function:: const std::shared_ptr<X509_Certificate>& certificate() const

      Returns the end-entity certificate, or ``nullptr`` if not present.

   .. cpp:function:: const std::vector<std::shared_ptr<X509_Certificate>>& ca_certificates() const

      Returns the intermediate/CA certificates included in the file.

   .. cpp:function:: std::vector<std::shared_ptr<X509_Certificate>> all_certificates() const

      Returns all certificates: end-entity (if present) followed by the CA chain.

   .. cpp:function:: const std::string& friendly_name() const

      Returns the ``friendlyName`` attribute, or an empty string if absent.

   .. cpp:function:: bool has_private_key() const
   .. cpp:function:: bool has_certificate() const
   .. cpp:function:: bool has_ca_certificates() const
   .. cpp:function:: bool has_friendly_name() const

      Convenience predicates.

PKCS12
-----------------------------------------

.. cpp:class:: PKCS12

   Static-only class providing PKCS#12 parsing and generation. Cannot be
   instantiated.

   Parsing
   ^^^^^^^

   .. cpp:function:: static PKCS12_Data parse(std::span<const uint8_t> data, std::string_view password)

      Parse a DER-encoded PFX file from a byte span.

      Throws ``Decoding_Error`` if the file is malformed, or
      ``Invalid_Authentication_Tag`` if MAC verification fails.

   .. cpp:function:: static PKCS12_Data parse(DataSource& source, std::string_view password)

      Parse a PFX file from a :cpp:class:`DataSource`.

   Creation
   ^^^^^^^^

   .. cpp:function:: static std::vector<uint8_t> create(const Private_Key& key, const X509_Certificate& cert, const PKCS12_Options& options, RandomNumberGenerator& rng)

      Create a PFX containing a key and its end-entity certificate.
      Throws ``Invalid_Argument`` if the key does not correspond to the
      certificate.

   .. cpp:function:: static std::vector<uint8_t> create(const Private_Key& key, const X509_Certificate& cert, const std::vector<X509_Certificate>& ca_certs, const PKCS12_Options& options, RandomNumberGenerator& rng)

      Create a PFX with a key, end-entity certificate, and a CA chain.

   .. cpp:function:: static std::vector<uint8_t> create(const Private_Key* key, const X509_Certificate* cert, const std::vector<X509_Certificate>& ca_certs, const PKCS12_Options& options, RandomNumberGenerator& rng)

      Low-level overload accepting nullable pointers. At least one of *key*,
      *cert*, or *ca_certs* must be non-null/non-empty.

Example
-----------------------------------------

Generating a PFX file:

.. code-block:: cpp

   #include <botan/pkcs12.h>
   #include <botan/rsa.h>
   #include <botan/x509self.h>

   Botan::AutoSeeded_RNG rng;
   Botan::RSA_PrivateKey key(rng, 2048);

   Botan::X509_Cert_Options opts;
   opts.common_name = "example.com";
   auto cert = Botan::X509::create_self_signed_cert(opts, key, "SHA-256", rng);

   Botan::PKCS12_Options p12_opts;
   p12_opts.password      = "secret";
   p12_opts.friendly_name = "My Key";

   std::vector<uint8_t> pfx = Botan::PKCS12::create(key, cert, p12_opts, rng);

Parsing a PFX file:

.. code-block:: cpp

   #include <botan/pkcs12.h>

   // pfx_bytes loaded from file
   Botan::PKCS12_Data data = Botan::PKCS12::parse(pfx_bytes, "secret");

   if(data.has_private_key()) {
      auto& key = data.private_key();
   }
   if(data.has_certificate()) {
      auto& cert = data.certificate();
   }

.. note::

   Key encryption defaults to ``PBE-SHA1-3DES`` for maximum interoperability.
   For modern deployments, prefer ``PBES2-SHA256-AES256`` when all consumers
   support PBES2.

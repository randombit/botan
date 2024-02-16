Botan 2.x to 3.x Migration
==============================

This is a guide on migrating applications from Botan 2.x to 3.0.

This guide attempts to be, but is not, complete. If you run into a problem while
converting code that does not seem to be described here, please open an issue on
`GitHub <https://github.com/randombit/botan/issues>`_.

Headers
--------

Many headers have been removed from the public API.

In some cases, such as ``datastor.h`` or ``tls_blocking.h``, the functionality
presented was entirely deprecated, in which case it has been removed.

In other cases (such as ``loadstor.h`` or ``rotate.h``) the header was really an
implementation header of the library and not intended to be consumed as a public
API. In these cases the header is still used internally, but not installed for
application use.

However in most cases there is a better way of performing the same operations,
which usually works in both 2.x and 3.x. For example, in 3.0 all of the
algorithm headers (such as ``aes.h``) have been removed. Instead you should
create objects via the factory methods (in the case of AES,
``BlockCipher::create``) which works in both 2.x and 3.0

Errata: ``pk_ops.h``
^^^^^^^^^^^^^^^^^^^^

Between Botan 3.0 and 3.2 the public header ``pk_ops.h`` was removed
accidentally. This header is typically required for specialized applications
that interface with dedicated crypto hardware. If you are migrating such an
application, please make sure to use Botan 3.3 or newer.

Build Artifacts
---------------

For consistency with other platforms the DLL is now suffixed with the library's
major version on Windows as well.

TLS
---

Starting with Botan 3.0 TLS 1.3 is supported.
This development required a number of backward-incompatible changes to
accomodate the protocol differences to TLS 1.2, which is still supported.

Build modules
^^^^^^^^^^^^^

The build module ``tls`` is now internal and contains common TLS helpers. Users
have to explicitly enable ``tls12`` and/or ``tls13``. Note that for Botan 3.0 it
is not (yet) possible to exclusively enable TLS 1.3 at build time.

Removed Functionality
^^^^^^^^^^^^^^^^^^^^^

Functionality removed from the TLS implementation includes

* TLS 1.0, 1.1 and DTLS 1.0
* DSA ciphersuites
* anonymous ciphersuites
* SRP ciphersuites
* SEED ciphersuites
* Camellia CBC ciphersuites
* AES-128 OCB ciphersuites
* DHE_PSK ciphersuites
* CECPQ1 ciphersuites

enum classes
^^^^^^^^^^^^

The publicly available C++ enums in the TLS namespace are now `enum class` and
their member naming scheme was converted from `SHOUTING_SNAKE_CASE` to
`CamelCase`.

Callbacks
^^^^^^^^^

A number of new callbacks were added with TLS 1.3. None of those new callbacks
is mandatory to implement by applications, though. Additionally there are a few
backward incompatible changes in callbacks that might require attention by some
applications:

tls_record_received() / tls_emit_data()
"""""""""""""""""""""""""""""""""""""""

Those callbacks now take `std::span<const uint8_t>` instead of `const uint8_t*`
with a `size_t` buffer length.

tls_session_established()
"""""""""""""""""""""""""

This callback provides a summary of the just-negotiated connection. It used to
have a bool return value letting an application decide to store or discard the
connection's resumption information. This use case is now provided via:
`tls_should_persist_resumption_information()` which might be called more than
once for a single TLS 1.3 connection.

`tls_session_established` is not a mandatory callback anymore but still allows
applications to abort a connection given a summary of the negotiated
characteristics. Note that this summary is not a persistable `Session` anymore.

tls_verify_cert_chain()
"""""""""""""""""""""""

The parameter `ocsp_responses`, which was previously
`std::shared_ptr<OCSP::Response>`, is now `std::optional<OCSP::Response>`.

tls_modify_extensions() / tls_examine_extensions()
""""""""""""""""""""""""""""""""""""""""""""""""""

These callbacks now have an additional parameter of type `Handshake_Type` that
identify the TLS handshake message the extensions in question are residing in.
TLS 1.3 makes much heavier use of such extensions in a wider range of messages
to implement core protocol functionality.

tls_dh_agree() / tls_ecdh_agree() / tls_decode_group_param()
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

These callbacks were used as customization points for the TLS 1.2 key exchange
in the TLS client. To allow similar (and more) customizations with the
introduction of TLS 1.3, these callbacks were replaced with a more generic
approach.

Key agreement is split into two callbacks, namely `tls_generate_ephemeral_key()`
and `tls_ephemeral_key_agreement()`. Those are used in both clients and servers
and in all protocol versions. `tls_decode_group_param()` is removed as it became
obsolete by the replacement of the other two callbacks.

Policy
^^^^^^

choose_key_exchange_group()
"""""""""""""""""""""""""""

The new parameter `offered_by_peer` identifies the key exchange groups a peer
has sent public exchange offerings for (in TLS 1.3 handshakes only).
Choosing a key exchange group that is not listed is legal but will result in an
additional network round trip (cf. "Hello Retry Request").
In TLS 1.2, this vector is always empty and can be ignored.

session_ticket_lifetime()
"""""""""""""""""""""""""

Now returns `std::chrono::seconds` rather than a bare `uint32_t`.

Credentials Manager
^^^^^^^^^^^^^^^^^^^

find_cert_chain(), cert_chain() and cert_chain_single_type()
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

These methods now have a `cert_signature_schemes` parameter that identifies
a list of signature schemes the peer is willing to accept for signatures
in certificates.
Notably, this *does not necessarily* mean that the leaf certificate must feature
a public key type able to generate one of those schemes.

private_key_for()
"""""""""""""""""

Applications must now provide a `std::shared_ptr<>` to the requested private key
object instead of a raw pointer to better communicate the implementation's
life-time expectations of this private key object.

.. _tls_session_manager_migration:

Session and Ticket Handling
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Old (pre-Botan 3.0) sessions won't load in Botan 3.0 anymore and should be
discarded.
For applications using `Session_Manager_SQL` or `Session_Manager_SQLite`
discarding happens automatically on first access after the update.

With Botan 3.0 the session manager now is responsible for stateful session
handling (backed by a database) and creation and management of stateless session
tickets.
The latter was previously handled transparently by the TLS implementation itself.

Therefore, TLS server applications that relied on Botan's default session
management implementations (most notably `Session_Manager_SQLite` or
`Session_Manager_In_Memory`) are advised to re-evaluate their choice.
Have a look at `Session_Manager_Hybrid` to retain support for both stateful and
stateless TLS sessions.
TLS client applications may safely keep relying on the above-mentioned default
implementations.

Applications implementing their own `Session_Manager` will need to adapt to the
new base class API.

New API of Session Manager
""""""""""""""""""""""""""

TLS 1.3 removed the legacy resumption procedures based on session IDs or session
tickets and combined them under the protocol's Pre-Shared Key mechanism.
This new approach allows TLS servers to handle sessions both stateless (as
self-contained encrypted and authenticated tickets) and stateful (identified
with unique database handles).

To accomodates this flexibility the `Session_Manager` base class API has changed
drastically and is now responsible for creation, storage and management of both
stateful sessions and stateless session tickets.
Sub-classes therefore gain full control over the session ticket's structure and
content.

API details are documented in the class' doxygen comments.

The Session Object and its Handle
"""""""""""""""""""""""""""""""""

Objects of class `Session` are not aware of their "session ID" or their "session
ticket" anymore.
Instead, the new class `Session_Handle` encapsulates the session's identifier or
ticket and accompanies the `Session` object where necessary.

Algorithms Removed
-------------------

The algorithms CAST-256, MISTY1, Kasumi, DESX, XTEA, PBKDF1, MCEIES, CBC-MAC,
Tiger, CECPQ1, and NewHope have been removed.

Certificate API shared_ptr
----------------------------

Previously the certificate store used ``shared_ptr<X509_Certificate>`` in
various APIs. However starting in 2.4.0, ``X509_Certificate`` itself is a pimpl
to a ``shared_ptr``, making the outer shared pointer pointless. In 3.0 the
certificate interfaces have changed to just consume and return ``X509_Certificate``.

All Or Nothing Package Transform
----------------------------------

This code was deprecated and has been removed.

Exception Changes
-------------------

Several exceptions, mostly ones not used by the library, were removed.

A few others that were very specific (such as Illegal_Point) were replaced
by throws of their immediate base class exception type.

The base class of Encoding_Error and Decoding_Error changed from
Invalid_Argument to Exception. If you are explicitly catching Invalid_Argument,
verify that you do not need to now also explicitly catch Encoding_Error and/or
Decoding_Error.

X.509 Certificate Info Access
-------------------------------

Previously ``X509_Certificate::subject_info`` and ``issuer_info`` could be used
to query information about extensions. This is not longer the case; instead you
should either call a specific function on ``X509_Certificate`` which returns the
same information, or lacking that, iterate over the result of
``X509_Certificate::v3_extensions``.

OCSP Response Validation
------------------------

After mitigating CVE-2022-43705 the OCSP response signature validation was refactored.
This led to the removal of the `OCSP::Response::check_signature()` method. If you
must validate OCSP responses directly in your application please use the new method
`OCSP::Response::find_signing_certificate()` and `OCSP::Response::verify_signature()`.

Use of ``enum class``
--------------------------------

Several enumerations where modified to become ``enum class``, including
``DL_Group::Format``, ``CRL_Code``, ``EC_Group_Encoding``, ``Signature_Format``,
``Cipher_Dir``, ``TLS::Extension_Code``, ``TLS::Connection_Side``,
``TLS::Record_Type``, and ``TLS::Handshake_Type``

In many cases the enumeration values were renamed from ``SHOUTING_CASE`` to
``CamelCase``. In some cases where the enumeration was commonly used by
applications (for example ``Signature_Format`` and ``Cipher_Dir``) the old
enumeration names are retained as deprecated variants.

ASN.1 enums
---------------

The enum ``ASN1_Tag`` has been split into ``ASN1_Type`` and ``ASN1_Class``.
Unlike ``ASN1_Tag``, these new enums are ``enum class``. The members of the
enums have changed from ``SHOUTING_CASE`` to ``CamelCase``, eg ``CONSTRUCTED``
is now ``Constructed``.

Also an important change related to ``ASN1_Tag::PRIVATE``. This enum value was
incorrect, and actually was used for explicitly tagged context specific values.
Now, ``ASN1_Class::Private`` refers to the correct class, but would lead to a
different encoding vs 2.x's ``ASN1_Tag::PRIVATE``. The correct value to use in
3.0 to match ``ASN1_Tag::PRIVATE`` is ``ASN1_Class::ExplicitContextSpecific``.

Cipher Mode Granularity
-------------------------

Previously Cipher_Mode::update_granularity specified the minimum buffer size
that must be provided during processing. However the value returned was often
much larger than what was strictly required. In particular some modes can easily
accept inputs as small as 1 byte, but their update_granularity was much larger
to encourage best performance.

Now update_granularity returns the true minimum value, and the new
Cipher_Mode::ideal_granularity returns a value which is a multiple of
update_granularity sized for good performance.

If you are sizing buffers on the basis of update_granularity consider
using ideal_granularity instead. Otherwise you may encounter performance
regressions due to creating and processing very small buffers.

"SHA-160" and "SHA1"
---------------------

Previously the library accepted "SHA-160" and "SHA1" alternative names
for "SHA-1". This is no longer the case, you must use "SHA-1". Botan
2.x also recognizes "SHA-1".

PointGFp
------------

This type is now named ``EC_Point``

X509::load_key
-------------------

Previously these functions returned a raw pointer. They now return
a std::unique_ptr

PKCS11_Request::subject_public_key and X509_Certificate::subject_public_key
-----------------------------------------------------------------------------

These functions now return a unique_ptr

choose_sig_format removed
---------------------------

The freestanding functions choose_sig_format have been removed.
Use X509_Object::choose_sig_format

DLIES Constructors
--------------------

Previously the constructors to the DLIES classes took raw pointers,
and retained ownership of them. They now consume std::unique_ptrs

Credentials_Manager::private_key_for
-------------------------------------

Previously this function returned a raw pointer, which the Credentials_Manager
implementation had to keep alive "forever", since there was no way for it to
know when or if the TLS layer had completed using the returned key.

Now this function returns std::shared_ptr<Private_Key>

OID operator+
------------------------

OID operator+ allowed concatenating new fields onto an object identifier. This
was not used at all within the library or the tests, and seems of marginal
value, so it was removed.

If necessary in your application, this can be done by retrieving the
vector of components from your source OID, push the new element onto the vector
and create an OID from the result.

RSA with "EMSA1" padding
-------------------------

EMSA1 indicates that effectively the plain hash is signed, with no other
padding. It is typically used for algorithms like ECSDA, but was allowed for
RSA. This is now no longer implemented.

If you must generate such signatures for some horrible reason, you can pre-hash
the message using a hash function as usual, and then sign using a "Raw" padding,
which will allow you to sign any arbitrary bits with no preprocessing.

ECDSA/DSA with "EMSA1" padding
---------------------------------

Previous versions of Botan required using a hash specifier like "EMSA1(SHA-256)"
when generating or verifying ECDSA/DSA signatures, with the specified hash. The
"EMSA1" was a reference to a now obsolete IEEE standard.

In Botan 3 the "EMSA1" notation is still accepted, but now also it is possible
to simply use the name of the hash, eg "EMSA1(SHA-256)" becomes "SHA-256".

Signature Algorithm OIDs
-----------------------------

In line with the previous entries, previously Botan used a string like
"ECDSA/EMSA1(SHA-256)" to identify the OID 1.2.840.10045.4.3.2. Now it
uses the string "ECDSA/SHA-256" instead, and does not recognize the
EMSA1 variant at all (for example in ``OID::from_string``).

Public Key Signature Padding
-----------------------------

In previous versions Botan was somewhat lenient about allowing the application
to specify using a hash which was in fact incompatible with the algorithm. For
example, Ed25519 signatures are *always* generated using SHA-512; there is no
choice in the matter. In the past, requesting using some other hash, say
SHA-256, would be silently ignored. Now an exception is thrown, indicating the
desired hash is not compatible with the algorithm.

In previous versions, various APIs required that the application specify the
hash function to be used. In most cases this can now be omitted (passing an
empty string) and a suitable default will be chosen.

Discrete Logarithm Key Changes
--------------------------------

Keys based on the discrete logarithm problem no longer derive from the
DL_Scheme_PrivateKey and DL_Scheme_PublicKey classes; these classes
have been removed.

Functions to access DL algorithm internal fields (such as the integer value of
the private key using ``get_x``) have been removed. If you need access to this
information you can use the new ``get_int_field`` function.

The constructors of the DL scheme private keys have changed. Previously, loading
and creating a key used the same constructor, namely one taking arguments
``(DL_Group, RandomNumberGenerator&, BigInt x = 0)`` and then the behavior of
the constructor depend on if ``x`` was zero (in which case a new key was
created) or otherwise if ``x`` was non-zero then it was taken as the private
key. Now there are two constructors, one taking a random number generator and a
group, which generates a new key, and a second taking a group and an integer,
which loads an existing key.

XMSS Signature Changes
------------------------

The logic to derive WOTS+ private keys from the seed contained in the XMSS
private key has been updated according to the recommendations in
NIST SP 800-208. While signatures created with old private keys are still valid using
the old public key, new valid signatures cannot be created. To still support legacy
private XMSS keys, they can be used by passing ``WOTS_Derivation_Method::Botan2x`` to
the constructor of the ``XMSS_PrivateKey``.

Private XMSS keys created this way use the old derivation logic and can therefore
generate new valid signatures. It is recommended to use
``WOTS_Derivation_Method::NIST_SP800_208`` (default) when creating new XMSS keys.

Random Number Generator
-----------------------

Fetching a large number of bytes via `randomize_with_input()` from a stateful
RNG will now incorporate the provided "input" data in the first request to the
underlying DRBG only. This applies to such DRBGs that pose a limit on the number
of bytes per request (most notable ``HMAC_DRBG`` with a 64kB default). Botan 2.x
(erroneously) applied the input to *all* underlying DRBG requests in such cases.

Applications that rely on a static seed for deterministic RNG output might
observe a different byte stream in such cases. As a workaround, users are
advised to "mimick" the legacy behaviour by manually pulling from the RNG in
"byte limit"-sized chunks and provide the "input" with each invocation.

Botan 2.x to 3.x Migration
==============================

This is a guide on migrating applications from Botan 2.x to 3.0.

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

TLS Functionality Removed
---------------------------

Functionality removed from the TLS implementation includes

* TLS 1.0, 1.1 and DTLS 1.0
* DSA ciphersuites
* anonymous ciphersuites
* SRP ciphersuites
* SEED ciphersuites
* Camellia CBC ciphersuites
* AES-128 OCB ciphersuites
* DHE_PSK ciphersuites

TLS 1.3 API adaptions
---------------------

Sessions
^^^^^^^^

Old (pre-Botan 3.0) sessions won't load in Botan 3.0 anymore and should be
discarded.

``Session::session_id()`` is equal to the "session ticket" for TLS 1.3 sessions.
This ticket might be longer than a typical ID (up to 64kB). If your application
depends on a short ID for each session, it is safe to just hash the returned
buffer.


Algorithms Removed
-------------------

The algorithms CAST-256, MISTY1, Kasumi, DESX, XTEA, PBKDF1, MCEIES, CBC-MAC and
Tiger have been removed. The expectation is that literally nobody was using any
of these algorithms for anything. All are obscure, and many are broken.

Certificate API shared_ptr
----------------------------

Previously the certificate store returned ``shared_ptr<X509_Certificate>`` to
avoid copies. However starting in 2.4.0, ``X509_Certificate`` itself is a pimpl
to a ``shared_ptr``, making the outer shared pointer pointless. In 3.0 the
certificate store interface has been changed to just consume and return
``X509_Certificate``.

This change similarly affects some of the functions involved in certificate
path building.

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

Use of ``enum class``
--------------------------------

Several enumerations where modified to become ``enum class``, including
``DL_Group::Format``, ``CRL_Code``, ``EC_Group_Encoding``,

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


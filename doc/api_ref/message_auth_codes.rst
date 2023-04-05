
.. _mac:

Message Authentication Codes (MAC)
===================================

A Message Authentication Code algorithm computes a tag over a message utilizing
a shared secret key. Thus a valid tag confirms the authenticity and integrity of
the message. Only entities in possession of the shared secret key are able to
verify the tag.

.. note::

    When combining a MAC with unauthenticated encryption mode, prefer to first
    encrypt the message and then MAC the ciphertext. The alternative is to MAC
    the plaintext, which depending on exact usage can suffer serious security
    issues. For a detailed discussion of this issue see the paper "The Order of
    Encryption and Authentication for Protecting Communications" by Hugo
    Krawczyk

The Botan MAC computation is split into five stages.

#. Instantiate the MAC algorithm.
#. Set the secret key.
#. Process IV.
#. Process data.
#. Finalize the MAC computation.

Code Examples
------------------------

The following example computes an HMAC with a random key then verifies the tag.

.. literalinclude:: /../src/examples/hmac.cpp
   :language: cpp

The following example code computes a AES-256 GMAC and subsequently verifies the
tag.  Unlike most other MACs, GMAC requires a nonce *which must not repeat or
all security is lost*.

.. literalinclude:: /../src/examples/gmac.cpp
   :language: cpp

The following example code computes a valid AES-128 CMAC tag and modifies the
data to demonstrate a MAC verification failure.

.. literalinclude:: /../src/examples/cmac.cpp
   :language: cpp

API Overview
------------

.. doxygenclass:: Botan::MessageAuthenticationCode
   :members: create,create_or_throw,set_key,minimum_keylength,maximum_keylength,start,update,final,verify_mac

Available MACs
------------------------------------------

Currently the following MAC algorithms are available in Botan. In new code,
default to HMAC with a strong hash like SHA-256 or SHA-384.

CMAC
~~~~~~~~~~~~

A modern CBC-MAC variant that avoids the security problems of plain CBC-MAC.
Approved by NIST. Also sometimes called OMAC.

Available if ``BOTAN_HAS_CMAC`` is defined.

GMAC
~~~~~~~~~~~~

GMAC is related to the GCM authenticated cipher mode. It is quite slow unless
hardware support for carryless multiplications is available. A new nonce
must be used with **each** message authenticated, or otherwise all security is
lost.

Available if ``BOTAN_HAS_GMAC`` is defined.

.. warning::
   Due to the nonce requirement, GMAC is exceptionally fragile. Avoid it unless
   absolutely required.

HMAC
~~~~~~~~~~~~

A message authentication code based on a hash function. Very commonly used.

Available if ``BOTAN_HAS_HMAC`` is defined.

Poly1305
~~~~~~~~~~~~

A polynomial mac (similar to GMAC). Very fast, but tricky to use safely. Forms
part of the ChaCha20Poly1305 AEAD mode. A new key must be used for **each**
message, or all security is lost.

Available if ``BOTAN_HAS_POLY1305`` is defined.

.. warning::
   Due to the nonce requirement, Poly1305 is exceptionally fragile. Avoid it unless
   absolutely required.

SipHash
~~~~~~~~~~~~

A modern and very fast PRF. Produces only a 64-bit output. Defaults to
"SipHash(2,4)" which is the recommended configuration, using 2 rounds for each
input block and 4 rounds for finalization.

Available if ``BOTAN_HAS_SIPHASH`` is defined.

X9.19-MAC
~~~~~~~~~~~~

A CBC-MAC variant sometimes used in finance. Always uses DES.
Sometimes called the "DES retail MAC", also standardized in ISO 9797-1.

It is slow and has known attacks. Avoid unless required.

Available if ``BOTAN_HAS_X919_MAC`` is defined.
